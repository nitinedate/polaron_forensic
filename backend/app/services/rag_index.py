"""GPU-accelerated RAG indexing over extracted MinIO disk artifacts."""

from __future__ import annotations

import io
import json
import logging
import tarfile
from pathlib import PurePosixPath

import zstandard as zstd

from app.config import get_settings
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.embedding_gpu import embed_texts, resolve_device
from app.services.storage import get_bytes

log = logging.getLogger("rag_index")

from app.services.forensic_handbook_scope import handbook_text_index_extensions

TEXT_EXTENSIONS = handbook_text_index_extensions() | frozenset({
    ".sql", ".c", ".cpp", ".h", ".cs", ".php",
})

CHUNK_SIZE = 800
CHUNK_OVERLAP = 100
MAX_TEXT_BYTES = 2_000_000


def _is_interesting(path: str) -> bool:
    from app.services.forensic_handbook_scope import is_handbook_evidence_path

    norm = path.replace("\\", "/")
    ext = PurePosixPath(norm).suffix.lower()
    if ext in TEXT_EXTENSIONS:
        return True
    # Handbook extensionless sources (Maildir, Thunderbird mbox, browser JSON, etc.)
    if is_handbook_evidence_path(norm):
        return True
    return False


def _chunk_text(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= CHUNK_SIZE:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + CHUNK_SIZE)
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - CHUNK_OVERLAP, start + 1)
    return chunks


def _load_index_entries(manifest: dict) -> list[dict]:
    index_uri = manifest.get("index_uri") or ""
    raw = get_bytes(index_uri)
    if not raw:
        raise ValueError("Could not read disk index from storage")
    decompressed = zstd.ZstdDecompressor().decompress(raw)
    entries: list[dict] = []
    for line in decompressed.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def _iter_text_files_from_part(part_uri: str) -> list[tuple[str, str]]:
    """Return (path, text) pairs extracted from one tar.zst part."""
    raw = get_bytes(part_uri)
    if not raw:
        return []
    out: list[tuple[str, str]] = []
    try:
        decompressed = zstd.ZstdDecompressor().decompress(raw)
        with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r|") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                path = member.name.replace("\\", "/")
                if not _is_interesting(path):
                    continue
                if member.size > MAX_TEXT_BYTES:
                    continue
                f = tar.extractfile(member)
                if not f:
                    continue
                data = f.read()
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = data.decode("utf-8", errors="replace")
                if text.strip():
                    out.append((path, text))
    except Exception as exc:
        log.warning("Failed reading part %s: %s", part_uri, exc)
    return out


def _update_progress(
    db,
    job_id: str,
    *,
    completed: int,
    total: int,
    device_label: str,
    gpu_enabled: bool,
    extracted: int,
    pending: int,
) -> None:
    from app.services.pipeline_progress import write_merged_pipeline_progress

    extract_coverage = {
        "interesting_total": total,
        "extracted": extracted,
        "pending": pending,
        "next_batch_size": min(500, pending),
        "batch_cap": 500,
    }
    pct = min(99, int(100 * completed / total)) if total else 0
    write_merged_pipeline_progress(
        db,
        job_id,
        {
            "phase": "rag",
            "completed": completed,
            "total": total,
            "label": "chunks embedded",
        },
        writer="rag",
        progress_pct=pct,
        extra_sets="extract_coverage=CAST(:ec AS jsonb)",
        extra_params={"ec": json.dumps(extract_coverage)},
    )


def build_rag_index_gpu(db, job_id: str, *, schema_name: str) -> dict:
    """Embed text artifacts from MinIO extracted disk using GPU when available."""
    settings = get_settings()
    if not getattr(settings, "rag_embedding_enabled", False):
        from app.services.dual_rag_index import append_job_evidence_rag

        write_disk_log(
            db,
            job_id,
            "RAG chunking — text chunks only (embeddings optional and off)",
            stage="rag_index",
        )
        db.commit()
        added = append_job_evidence_rag(db, job_id, schema_name=schema_name)
        return {"status": "ok", "chunks": added}
    row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        raise ValueError("Job not found")

    disk_source = row.get("disk_source")
    if isinstance(disk_source, str):
        disk_source = json.loads(disk_source)
    if not disk_source:
        raise ValueError("Job has no extracted disk manifest")

    device_label, gpu_enabled = resolve_device(settings.rag_embedding_device)
    write_disk_log(
        db,
        job_id,
        f"GPU RAG indexing started — device={device_label}",
        stage="rag_index",
        metadata={"gpu_enabled": gpu_enabled, "embedding_device": device_label},
    )
    execute(db, "UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()

    parts: list[str] = disk_source.get("parts") or []
    if not parts:
        raise ValueError("Manifest has no extracted disk parts")

    index_entries = _load_index_entries(disk_source)
    interesting_paths = {e["path"] for e in index_entries if _is_interesting(e["path"])}
    total_files = len(interesting_paths)

    write_disk_log(
        db,
        job_id,
        f"Scanning {len(parts)} MinIO shard(s) — {total_files:,} text-like files for GPU embedding",
        stage="rag_index",
        metadata={"parts": len(parts), "interesting_files": total_files},
    )
    db.commit()

    execute(db, "DELETE FROM rag_chunks WHERE job_id=:job_id", {"job_id": job_id})
    db.flush()

    batch_texts: list[str] = []
    batch_meta: list[tuple[str, int, str]] = []
    files_done = 0
    chunks_done = 0
    log_every = max(settings.rag_batch_size, 32)

    def flush_batch() -> None:
        nonlocal chunks_done
        if not batch_texts:
            return
        vectors = embed_texts(
            batch_texts,
            model_name=settings.rag_embedding_model,
            device=settings.rag_embedding_device,
            batch_size=settings.rag_batch_size,
        )
        for (path, cidx, content), vec in zip(batch_meta, vectors):
            vec_str = "[" + ",".join(f"{v:.8f}" for v in vec) + "]"
            execute(
                db,
                """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding)
                   VALUES (:job_id, :path, :cidx, :content, CAST(:emb AS vector))""",
                {
                    "job_id": job_id,
                    "path": path,
                    "cidx": cidx,
                    "content": content[:4000],
                    "emb": vec_str,
                },
            )
        chunks_done += len(batch_texts)
        batch_texts.clear()
        batch_meta.clear()
        db.commit()

    for part_uri in parts:
        for path, text in _iter_text_files_from_part(part_uri):
            if path not in interesting_paths:
                continue
            files_done += 1
            for cidx, chunk in enumerate(_chunk_text(text)):
                batch_texts.append(chunk)
                batch_meta.append((path, cidx, chunk))
                if len(batch_texts) >= log_every:
                    flush_batch()
                    write_disk_log(
                        db,
                        job_id,
                        f"RAG progress [{chunks_done:,}/{max(total_files, 1):,}] on GPU ({device_label})",
                        stage="rag_index",
                        metadata={"chunks_embedded": chunks_done, "files_processed": files_done},
                    )
                    _update_progress(
                        db,
                        job_id,
                        completed=chunks_done,
                        total=max(total_files, 1),
                        device_label=device_label,
                        gpu_enabled=gpu_enabled,
                        extracted=files_done,
                        pending=max(0, total_files - files_done),
                    )
                    db.commit()

    flush_batch()

    chunk_count_row = fetchone(
        db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:job_id", {"job_id": job_id}
    )
    total_chunks = int(chunk_count_row["c"]) if chunk_count_row else chunks_done

    extract_coverage = {
        "interesting_total": total_files,
        "extracted": files_done,
        "pending": 0,
        "next_batch_size": 0,
        "batch_cap": 500,
    }
    pipeline_progress = {
        "phase": "rag",
        "completed": total_chunks,
        "total": total_chunks,
        "label": "chunks embedded",
    }
    from app.services.pipeline_orchestrator import record_pipeline_milestone

    record_pipeline_milestone(
        db,
        job_id,
        status="indexed",
        writer="rag",
        progress=pipeline_progress,
        extract_coverage=extract_coverage,
        clear_error=True,
    )
    write_disk_log(
        db,
        job_id,
        f"GPU RAG indexing complete — {total_chunks:,} chunks embedded from {files_done:,} files on {device_label}",
        stage="rag_index",
        metadata={
            "gpu_enabled": gpu_enabled,
            "embedding_device": device_label,
            "chunks_indexed": total_chunks,
            "files_indexed": files_done,
        },
    )
    db.flush()
    return {
        "status": "indexed",
        "gpu_enabled": gpu_enabled,
        "embedding_device": device_label,
        "chunks_indexed": total_chunks,
        "files_indexed": files_done,
    }
