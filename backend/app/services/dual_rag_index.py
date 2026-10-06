"""Phase 3 dual RAG indexing — encyclopedia knowledge + job evidence."""

from __future__ import annotations

import json
import logging
import os

from app.config import get_settings
from app.db.session import apply_firm_search_path, platform_session
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.embedding_gpu import embed_texts, resolve_device
from app.services.encyclopedia_ingest import load_encyclopedia_from_jsonl
from app.services.rag_index import TEXT_EXTENSIONS, _is_interesting
from app.services.tar_cache import read_file_from_part

log = logging.getLogger("dual_rag_index")


def _chunk_text(text: str, size: int, overlap: int) -> list[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def _index_encyclopedia(db, settings) -> int:
    existing = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id IS NULL AND chunk_type IN ('encyclopedia','field_row')")
    if existing and int(existing["c"]) > 0:
        return 0

    with platform_session() as pdb:
        load_encyclopedia_from_jsonl(pdb, force=False)
        arts = pdb.execute(
            __import__("sqlalchemy").text(
                "SELECT artifact_id, artifact_name, default_paths, evidence_value, search_text, category, operating_system FROM public.encyclopedia_artifacts"
            )
        ).mappings().all()
        fields = pdb.execute(
            __import__("sqlalchemy").text(
                "SELECT artifact_id, field_name, where_found, source_artifact, notes, search_text FROM public.encyclopedia_field_rows"
            )
        ).mappings().all()

    texts: list[str] = []
    meta: list[dict] = []
    for a in arts:
        content = f"Artifact {a['artifact_id']}: {a['artifact_name']}\nPath: {a['default_paths']}\nValue: {a['evidence_value']}\n{a['search_text']}"
        texts.append(content)
        meta.append({
            "artifact_id": a["artifact_id"],
            "chunk_type": "encyclopedia",
            "metadata": {"os": a["operating_system"], "category": a["category"]},
        })
    for f in fields:
        content = f"Field {f['field_name']}: found at {f['where_found']} in {f['source_artifact']}. {f['notes']}"
        texts.append(content)
        meta.append({
            "artifact_id": f["artifact_id"],
            "chunk_type": "field_row",
            "metadata": {"supplement": True},
        })

    if not texts:
        return 0

    device_label, gpu = resolve_device(settings.rag_embedding_device)
    vectors = embed_texts(texts, model_name=settings.rag_embedding_model, device=settings.rag_embedding_device, batch_size=settings.rag_batch_size)

    count = 0
    for m, vec, content in zip(meta, vectors, texts):
        vec_str = "[" + ",".join(f"{v:.8f}" for v in vec) + "]"
        execute(
            db,
            """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
               artifact_id, chunk_type, metadata)
               VALUES (NULL, :path, 0, :content, NULL, CAST(:emb AS vector), :aid, :ctype, CAST(:meta AS jsonb))""",
            {
                "path": f"encyclopedia/{m['artifact_id']}",
                "content": content[:8000],
                "emb": vec_str,
                "aid": m["artifact_id"],
                "ctype": m["chunk_type"],
                "meta": json.dumps(m["metadata"]),
            },
        )
        count += 1
    return count


def _extract_text_from_normalized(normalized) -> str:
    if not normalized:
        return ""
    if isinstance(normalized, str):
        return normalized[:8000]
    if isinstance(normalized, list):
        parts = []
        for rec in normalized:
            if isinstance(rec, dict):
                if rec.get("text"):
                    parts.append(str(rec["text"]))
                elif rec.get("preview"):
                    parts.append(str(rec["preview"]))
                else:
                    # Structured forensic fields → searchable prose
                    sub = []
                    for key in (
                        "executable", "target", "event_id", "event_kind", "registry_key",
                        "registry_value_name", "table", "user_profile", "target_paths",
                        "username", "last_logon", "password_last_set", "last_logoff",
                        "event_time", "profile_image_path", "sid", "rid",
                        "ntuser_last_write", "profile_key_last_write", "record_type",
                        "product_name", "display_version", "current_build", "edition_id",
                        "computer_name", "install_date", "url", "device_name", "serial",
                        "message_count", "text_body", "text_preview", "path", "size_bytes",
                    ):
                        if rec.get(key):
                            val = rec[key]
                            sub.append(
                                f"{key}: {val}"
                                if not isinstance(val, list)
                                else f"{key}: {', '.join(str(v) for v in val)}"
                            )
                    if sub:
                        parts.append("\n".join(sub))
                    else:
                        parts.append(json.dumps(rec, ensure_ascii=False)[:2000])
            else:
                parts.append(str(rec)[:2000])
        return "\n".join(parts)
    return json.dumps(normalized, ensure_ascii=False)[:8000]


def _sanitize_chunk_text(text: str) -> str:
    return text.replace("\x00", "")


def chunk_rows_for_embedding(
    rows: list,
    settings,
    index_map: dict | None = None,
) -> tuple[list[str], list[dict], list[str], int]:
    """CPU-only: turn artifact rows into embed texts. Safe to run off the DB thread."""
    texts: list[str] = []
    meta: list[dict] = []
    skip_ids: list[str] = []
    fallback_count = 0
    for r in rows:
        parts = []
        norm_text = _extract_text_from_normalized(r.get("normalized"))
        if norm_text:
            parts.append(norm_text[:4000])
        if r.get("ocr_text"):
            parts.append(r["ocr_text"][:4000])
        if not parts and index_map and _is_interesting(r["file_path"]):
            part_uri = index_map.get(r["file_path"])
            if part_uri:
                raw = read_file_from_part(part_uri, r["file_path"])
                if raw:
                    try:
                        text = raw.decode("utf-8", errors="replace")[:50_000]
                        if text.strip():
                            parts.append(text)
                            fallback_count += 1
                    except Exception:
                        pass
        if not parts:
            skip_ids.append(str(r["id"]))
            continue
        body = _sanitize_chunk_text("\n".join(parts))
        for idx, chunk in enumerate(_chunk_text(body, settings.rag_chunk_size, settings.rag_chunk_overlap)):
            texts.append(_sanitize_chunk_text(f"Evidence file {r['file_path']}\n{chunk}"))
            meta.append(
                {
                    "file_path": r["file_path"],
                    "artifact_id": r.get("encyclopedia_artifact_id"),
                    "job_artifact_id": str(r["id"]),
                    "chunk_index": idx,
                }
            )
    return texts, meta, skip_ids, fallback_count


def _insert_evidence_text_chunks(
    db,
    job_id: str,
    texts: list[str],
    meta: list[dict],
    *,
    vectors: list | None = None,
) -> int:
    """Persist a vector batch with one PostgreSQL round trip.

    Older builds executed one INSERT per chunk and committed again after nearly every
    embedding mini-batch.  With tens of thousands of chunks that made PostgreSQL/
    Python transaction overhead a material part of RAG wall time even when the GPU
    was under-utilised.  psycopg2 ``execute_values`` stays inside the Session's
    current transaction/search_path and collapses the batch to one INSERT statement.
    """
    rows: list[tuple] = []
    for i, (m, content) in enumerate(zip(meta, texts)):
        vec_str = None
        if vectors is not None and i < len(vectors) and vectors[i] is not None:
            vec_str = "[" + ",".join(f"{v:.8f}" for v in vectors[i]) + "]"
        rows.append(
            (
                str(job_id),
                m["file_path"],
                int(m["chunk_index"]),
                (content or "").replace("\x00", "")[:8000],
                vec_str,
                m.get("artifact_id"),
                json.dumps({"job_artifact_id": m["job_artifact_id"]}),
            )
        )
    if not rows:
        return 0

    try:
        from psycopg2.extras import execute_values

        raw = db.connection().connection
        cursor = raw.cursor()
        try:
            execute_values(
                cursor,
                """INSERT INTO rag_chunks
                   (job_id, file_path, chunk_index, content, embedding, embedding_v2,
                    artifact_id, chunk_type, metadata)
                   VALUES %s""",
                rows,
                template="(%s,%s,%s,%s,NULL,%s::vector,%s,'evidence',%s::jsonb)",
                page_size=min(max(len(rows), 1), 512),
            )
        finally:
            cursor.close()
        return len(rows)
    except (ImportError, AttributeError):
        # Compatibility fallback for non-psycopg2 test/runtime environments.
        for jid, path, cidx, content, emb, aid, metadata_json in rows:
            execute(
                db,
                """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
                   artifact_id, chunk_type, metadata)
                   VALUES (:jid, :path, :cidx, :content, NULL, CAST(:emb AS vector), :aid, 'evidence', CAST(:meta AS jsonb))""",
                {
                    "jid": jid, "path": path, "cidx": cidx, "content": content,
                    "emb": emb, "aid": aid, "meta": metadata_json,
                },
            )
        return len(rows)


def _baseline_rag_met(chunk_count: int) -> bool:
    return int(chunk_count) >= BASELINE_RAG_CHUNK_TARGET


def _touch_rag_progress(
    db,
    job_id: str,
    *,
    completed: int,
    total: int,
    label: str,
    schema_name: str | None = None,
    baseline_complete: bool = False,
    chunk_count: int | None = None,
) -> None:
    """Keep UI progress honest while preserving chunk-based Q&A baseline logic.

    ``completed``/``total`` are progress units (artifacts in v1.5 streaming RAG).
    ``chunk_count`` remains the number of searchable evidence chunks used by the
    baseline/enrichment gates.  Legacy callers that count chunks remain unchanged.
    """
    from app.config import get_settings
    from app.services.disk_build_log import write_disk_log

    settings = get_settings()
    searchable_chunks = int(completed if chunk_count is None else chunk_count)
    baseline_only = _baseline_rag_met(searchable_chunks) and not settings.rag_background_after_baseline
    if baseline_only:
        baseline_complete = True

    done = int(completed) >= int(total) and int(total) > 0
    rag_pct = 100 if done or baseline_complete else min(99, int(100 * completed / max(int(total), 1)))
    job_progress = 100 if done or baseline_complete else 80 + min(19, int(19 * completed / max(int(total), 1)))
    new_status = "indexed" if done or baseline_complete else "indexing"
    rag_incomplete = (
        not done
        and not baseline_complete
        and settings.rag_background_after_baseline
        and int(total) > 0
        and int(completed) < int(total)
    )

    from app.services.pipeline_progress import write_merged_pipeline_progress

    # Merge so concurrent inventory progress (inventory_ui_pct / orchestration) is not wiped.
    write_merged_pipeline_progress(
        db,
        job_id,
        {
            "phase": "rag" if not baseline_complete else "parse",
            "completed": int(completed),
            "total": max(int(total), 1),
            "label": label if not (done or baseline_complete) else "Q&A ready — baseline indexed",
        },
        writer="rag",
        status_sql="""status = CASE
             WHEN status = 'building_disk' THEN status
             WHEN :rag_incomplete AND status IN ('indexed', 'ready') THEN 'indexing'
             WHEN status IN ('indexed', 'ready', 'completed', 'classified', 'report_ready') AND NOT :done
               THEN status
             ELSE :st
           END""",
        extra_sets="""progress_pct = CASE
             WHEN :rag_incomplete THEN :prog
             ELSE GREATEST(COALESCE(progress_pct, 0), :prog)
           END""",
        extra_params={
            "done": done or baseline_complete,
            "rag_incomplete": rag_incomplete,
            "st": new_status,
            "prog": job_progress,
        },
    )
    if schema_name:
        apply_firm_search_path(db, schema_name)
    # Throttled log every ~500 chunks
    if completed == 0 or completed % 500 < 50 or completed >= total:
        if baseline_complete and not done:
            log_msg = (
                f"RAG baseline ready — {searchable_chunks:,} evidence chunks searchable; "
                f"{completed:,} / {max(total, 1):,} artifacts indexed ({rag_pct}%)"
            )
        elif chunk_count is not None:
            log_msg = (
                f"RAG indexing — {completed:,} / {max(total, 1):,} artifacts indexed "
                f"({rag_pct}%); {searchable_chunks:,} chunks searchable"
            )
        else:
            log_msg = (
                f"RAG indexing — {completed:,} / {max(total, 1):,} evidence chunks embedded ({rag_pct}%)"
            )
        write_disk_log(
            db,
            job_id,
            log_msg,
            stage="rag_index",
            metadata={"completed": completed, "total": total, "baseline_complete": baseline_complete},
        )
    mode = str(getattr(settings, "perf_policy_mode", "throughput") or "throughput").strip().lower()
    strict_stage_order = bool(getattr(settings, "pipeline_sequential_agents", False)) and mode in {
        "sequential", "respect_env"
    }
    if not strict_stage_order or done:
        _maybe_queue_baseline_enrichment(db, job_id, completed=searchable_chunks, schema_name=schema_name)


_RAG_INDEXABLE_FILTER = """
(
  EXISTS (
    SELECT 1 FROM artifact_parse_results apr2
    WHERE apr2.job_artifact_id = ja.id AND coalesce(apr2.record_count, 0) > 0
  )
  OR EXISTS (
    SELECT 1 FROM ocr_results ocr2
    WHERE ocr2.job_artifact_id = ja.id
      AND length(trim(coalesce(ocr2.ocr_text, ''))) > 10
  )
  OR coalesce(ja.metadata, '{}'::jsonb) @> '{"job_kind": "image_evidence"}'::jsonb
)
"""

_RAG_NOT_SKIPPED = "NOT (coalesce(ja.metadata, '{}'::jsonb) @> '{\"rag_skip\": true}'::jsonb)"

_RAG_CHUNK_SATISFIED = """
NOT EXISTS (
  SELECT 1 FROM rag_chunks rc
  WHERE rc.job_id = :jid AND rc.file_path = ja.file_path
    AND rc.chunk_type IN ('evidence', 'evidence_skip')
)
"""

BASELINE_RAG_CHUNK_TARGET = 500
# Image-evidence jobs are small — become searchable after a thin text baseline.
IMAGE_EVIDENCE_BASELINE_CHUNK_TARGET = 10


def baseline_chunk_target_for_job(db, job_id: str) -> int:
    try:
        from app.services.rag_image_evidence import is_image_evidence_job

        if is_image_evidence_job(db, job_id):
            return IMAGE_EVIDENCE_BASELINE_CHUNK_TARGET
    except Exception:
        pass
    return BASELINE_RAG_CHUNK_TARGET


def _mark_artifact_rag_skip(db, artifact_id: str, *, reason: str) -> None:
    execute(
        db,
        """UPDATE job_artifacts
           SET metadata = coalesce(metadata, '{}'::jsonb) || CAST(:meta AS jsonb),
               updated_at = NOW()
           WHERE id = :id""",
        {"id": artifact_id, "meta": json.dumps({"rag_skip": True, "rag_skip_reason": reason})},
    )


def _resolve_unembeddable_rag_artifacts(db, job_id: str, *, limit: int = 500) -> int:
    """Mark parsed artifacts that cannot produce embeddable text — stops infinite RAG retries."""
    rows = fetchall(
        db,
        f"""SELECT ja.id FROM job_artifacts ja
            WHERE ja.job_id = :jid
              AND (ja.parse_status = 'parsed' OR ja.ocr_status = 'done')
              AND {_RAG_INDEXABLE_FILTER}
              AND {_RAG_NOT_SKIPPED}
              AND {_RAG_CHUNK_SATISFIED}""",
        {"jid": job_id},
    )
    rows = rows[:limit]
    for row in rows:
        _mark_artifact_rag_skip(db, str(row["id"]), reason="no_embeddable_text")
    return len(rows)


def _placeholder_rag_stragglers(db, job_id: str, *, limit: int = 500) -> int:
    """Insert skip placeholders so straggler artifacts stop blocking RAG completion."""
    rows = fetchall(
        db,
        f"""SELECT ja.id, ja.file_path FROM job_artifacts ja
            WHERE ja.job_id = :jid
              AND (ja.parse_status = 'parsed' OR ja.ocr_status = 'done')
              AND {_RAG_INDEXABLE_FILTER}
              AND {_RAG_CHUNK_SATISFIED}
            LIMIT :lim""",
        {"jid": job_id, "lim": limit},
    )
    placed = 0
    for row in rows:
        _mark_artifact_rag_skip(db, str(row["id"]), reason="rag_straggler_placeholder")
        execute(
            db,
            """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, chunk_type, metadata)
               SELECT :jid, :path, 0, :content, 'evidence_skip', CAST(:meta AS jsonb)
               WHERE NOT EXISTS (
                 SELECT 1 FROM rag_chunks rc
                 WHERE rc.job_id = :jid AND rc.file_path = :path
                   AND rc.chunk_type IN ('evidence', 'evidence_skip')
               )""",
            {
                "jid": job_id,
                "path": row["file_path"],
                "content": "[RAG skip — no embeddable forensic text]",
                "meta": json.dumps({"job_artifact_id": str(row["id"]), "rag_skip": True}),
            },
        )
        placed += 1
    return placed


def _clear_rag_stragglers(db, job_id: str, *, batch_limit: int = 5000) -> dict[str, int]:
    """Remove indexable artifacts that block RAG completion after baseline is ready."""
    marked_total = 0
    placed_total = 0
    for _ in range(max(1, batch_limit // 5000)):
        marked = _resolve_unembeddable_rag_artifacts(db, job_id, limit=batch_limit)
        marked_total += marked
        remaining = _count_indexable_without_chunks(db, job_id)
        placed = 0
        if remaining > 0:
            placed = _placeholder_rag_stragglers(db, job_id, limit=batch_limit)
        placed_total += placed
        if remaining <= 0 or (marked == 0 and placed == 0):
            break
    return {
        "marked_skip": marked_total,
        "placeholders": placed_total,
        "remaining": _count_indexable_without_chunks(db, job_id),
    }


def _supervisor_rag_resume_count(db, job_id: str, *, within_sec: float = 1200.0) -> int:
    row = fetchone(
        db,
        """SELECT count(*) c FROM disk_build_logs
           WHERE job_id = :jid AND stage = 'supervisor'
             AND message LIKE '%rag_agent%'
             AND message LIKE '%resume RAG%'
             AND timestamp > NOW() - (:sec * interval '1 second')""",
        {"jid": job_id, "sec": within_sec},
    )
    return int(row["c"]) if row else 0


def rag_stuck_in_retry_loop(db, job_id: str, *, rag_remaining: int, chunk_n: int) -> bool:
    """True only for a tiny straggler set after many resume attempts.

    Large remaining counts mean real corpus embedding work — never force-finish those.
    """
    if rag_remaining <= 0 or chunk_n < BASELINE_RAG_CHUNK_TARGET:
        return False
    # Only treat as stuck when leftovers are tiny; thousands pending is normal backlog.
    if rag_remaining > 50:
        return False
    return _supervisor_rag_resume_count(db, job_id, within_sec=1800.0) >= 5


def force_finish_rag_enrichment(
    db,
    job_id: str,
    *,
    schema_name: str | None,
    chunk_count: int | None = None,
    reason: str = "RAG stragglers cleared — baseline complete",
) -> bool:
    """Force RAG to 100% when baseline is usable but stragglers cause a retry loop."""
    from app.services.disk_build_log import write_disk_log

    chunks_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
        {"jid": job_id},
    )
    chunk_n = int(chunk_count if chunk_count is not None else (chunks_row["c"] if chunks_row else 0))
    if chunk_n < BASELINE_RAG_CHUNK_TARGET:
        return False

    before = _count_indexable_without_chunks(db, job_id)
    if before <= 0:
        _maybe_finalize_artifact_inventory(db, job_id, schema_name=schema_name)
        return False

    cleared = _clear_rag_stragglers(db, job_id, batch_limit=50000)
    write_disk_log(
        db,
        job_id,
        f"{reason} — skipped {cleared['marked_skip']:,}, "
        f"placeholders {cleared['placeholders']:,}, "
        f"{before:,} straggler(s) cleared (chunks {chunk_n:,})",
        stage="rag_index",
    )
    db.commit()
    if schema_name:
        apply_firm_search_path(db, schema_name)

    _mark_rag_baseline_complete(
        db,
        job_id,
        schema_name=schema_name,
        chunk_count=chunk_n,
        label="Q&A ready — baseline indexed",
    )
    _maybe_finalize_artifact_inventory(db, job_id, schema_name=schema_name)
    db.commit()
    if schema_name:
        apply_firm_search_path(db, schema_name)
    return True


def _maybe_finalize_artifact_inventory(db, job_id: str, *, schema_name: str | None) -> None:
    if not schema_name:
        return
    from app.services.axiom_artifact_runner import axiom_inventory_progress, finalize_job_after_pipeline, parse_pending_count

    inv = axiom_inventory_progress(db, job_id)
    if inv["total"] > 0 and not inv["done"] and parse_pending_count(db, job_id) <= 0:
        finalize_job_after_pipeline(db, job_id, schema_name=schema_name)


def _count_indexable_artifacts(db, job_id: str) -> int:
    row = fetchone(
        db,
        f"""SELECT count(*) c FROM job_artifacts ja
            WHERE ja.job_id=:jid
              AND (ja.parse_status='parsed' OR ja.ocr_status='done')
              AND {_RAG_INDEXABLE_FILTER}
              AND {_RAG_NOT_SKIPPED}""",
        {"jid": job_id},
    )
    return int(row["c"]) if row else 0


def _count_indexable_without_chunks(db, job_id: str) -> int:
    row = fetchone(
        db,
        f"""SELECT count(*) c FROM job_artifacts ja
            WHERE ja.job_id=:jid
              AND (ja.parse_status='parsed' OR ja.ocr_status='done')
              AND {_RAG_INDEXABLE_FILTER}
              AND {_RAG_NOT_SKIPPED}
              AND {_RAG_CHUNK_SATISFIED}""",
        {"jid": job_id},
    )
    return int(row["c"]) if row else 0


def _mark_rag_baseline_complete(
    db,
    job_id: str,
    *,
    schema_name: str | None,
    chunk_count: int,
    label: str = "Q&A ready — baseline indexed",
) -> None:
    from app.services.disk_build_log import write_disk_log

    remaining_embed = _count_indexable_without_chunks(db, job_id)
    indexable_total = _count_indexable_artifacts(db, job_id)
    target = baseline_chunk_target_for_job(db, job_id)
    baseline_met = chunk_count >= target

    # Image-evidence: honest continuing-embed label once thin baseline is met.
    try:
        from app.services.rag_image_evidence import is_image_evidence_job, mark_image_evidence_searchable

        if is_image_evidence_job(db, job_id) and baseline_met and remaining_embed > 0:
            label = "Searchable — embedding continuing safely"
            mark_image_evidence_searchable(db, job_id, label=label)
    except Exception:
        pass

    if remaining_embed > 0:
        _resolve_unembeddable_rag_artifacts(db, job_id, limit=5000)
        db.commit()
        if schema_name:
            apply_firm_search_path(db, schema_name)
        remaining_embed = _count_indexable_without_chunks(db, job_id)

    if remaining_embed > 0 and baseline_met:
        # Forensic (500): clear stragglers. Image-evidence keeps embedding under thermal governor.
        skip_placeholders = False
        try:
            from app.services.rag_image_evidence import is_image_evidence_job

            skip_placeholders = is_image_evidence_job(db, job_id)
        except Exception:
            skip_placeholders = False
        if not skip_placeholders:
            placed = _placeholder_rag_stragglers(db, job_id, limit=5000)
            if placed:
                write_disk_log(
                    db,
                    job_id,
                    f"RAG baseline met ({chunk_count:,} chunks) — cleared {placed:,} straggler artifact(s)",
                    stage="rag_index",
                )
                db.commit()
                if schema_name:
                    apply_firm_search_path(db, schema_name)
            remaining_embed = _count_indexable_without_chunks(db, job_id)

    if remaining_embed > 0 and not baseline_met and chunk_count < max(indexable_total, 1):
        _touch_rag_progress(
            db,
            job_id,
            completed=chunk_count,
            total=max(indexable_total, chunk_count, 1),
            label=f"RAG embedding on GPU — {remaining_embed:,} artifacts remaining",
            schema_name=schema_name,
        )
        write_disk_log(
            db,
            job_id,
            f"RAG embedding incomplete — {chunk_count:,} chunks so far, "
            f"{remaining_embed:,} parsed artifacts still need vectors (resumable)",
            stage="rag_index",
            level="warning",
        )
        db.commit()
        if schema_name:
            apply_firm_search_path(db, schema_name)
        return

    pending = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
        {"jid": job_id},
    )
    pending_n = int(pending["c"]) if pending else 0
    # "indexed" = Q&A baseline is searchable. It is NOT pipeline completion:
    # background parse / chunking / enrichment / inventory may still be running,
    # so never force progress_pct=100 or wipe the orchestration block here.
    from app.services.pipeline_orchestrator import record_pipeline_milestone

    record_pipeline_milestone(
        db,
        job_id,
        status="indexed",
        writer="rag",
        progress={
            "phase": "parse" if pending_n > 0 else "rag",
            "completed": chunk_count,
            "total": max(chunk_count, 1),
            "label": label,
        },
        extract_coverage={
            "interesting_total": chunk_count,
            "extracted": chunk_count,
            "pending": pending_n,
        },
    )
    write_disk_log(
        db,
        job_id,
        f"RAG baseline complete — {chunk_count:,} evidence chunks searchable"
        + (f" ({pending_n:,} forensic files still parsing in background)" if pending_n else ""),
        stage="rag_index",
    )
    db.commit()
    if schema_name:
        apply_firm_search_path(db, schema_name)
    if pending_n > 0 and schema_name:
        try:
            from app.tasks import parse_drain_task

            parse_drain_task.delay(schema_name, job_id)
        except Exception as exc:
            log.warning("Parse drain queue after baseline failed: %s", exc)
    _maybe_finalize_artifact_inventory(db, job_id, schema_name=schema_name)


def _maybe_queue_baseline_enrichment(
    db,
    job_id: str,
    *,
    completed: int,
    schema_name: str | None,
) -> None:
    """After baseline chunk count, queue Neo4j graph sync on agent worker (parallel to GPU embed)."""
    if completed < 500 or not schema_name:
        return
    row = fetchone(db, "SELECT status FROM graph_sync_state WHERE job_id=:jid", {"jid": job_id})
    if row and (row.get("status") or "") in ("ok", "queued", "syncing"):
        return
    try:
        from app.services.disk_build_log import write_disk_log

        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, status)
               VALUES (:jid, 'queued')
               ON CONFLICT (job_id) DO UPDATE SET status='queued'
               WHERE graph_sync_state.status IS DISTINCT FROM 'ok'""",
            {"jid": job_id},
        )
        db.commit()
        apply_firm_search_path(db, schema_name)
        from app.tasks import graph_sync_task

        graph_sync_task.delay(schema_name, job_id)
        write_disk_log(
            db,
            job_id,
            f"Queued Neo4j graph sync ({completed:,} chunks embedded — runs in parallel with RAG)",
            stage="graph_sync",
        )
        db.commit()
        apply_firm_search_path(db, schema_name)
    except Exception as exc:
        log.warning("Baseline graph sync queue failed: %s", exc)


def _baseline_embed_limit(settings) -> int | None:
    """When background corpus embed is off, stop after baseline chunk count."""
    if getattr(settings, "rag_background_after_baseline", False):
        return None
    return BASELINE_RAG_CHUNK_TARGET


def _index_job_evidence(
    db,
    job_id: str,
    settings,
    *,
    index_map: dict[str, str] | None = None,
    file_paths: list[str] | None = None,
    skip_indexed: bool = False,
    progress_total: int | None = None,
    schema_name: str | None = None,
) -> int:
    base_sql = """SELECT ja.id, ja.file_path, ja.encyclopedia_artifact_id, apr.normalized, ocr.ocr_text
           FROM job_artifacts ja
           LEFT JOIN LATERAL (
             SELECT normalized FROM artifact_parse_results WHERE job_artifact_id=ja.id ORDER BY created_at DESC LIMIT 1
           ) apr ON true
           LEFT JOIN LATERAL (
             SELECT ocr_text FROM ocr_results WHERE job_artifact_id=ja.id ORDER BY created_at DESC LIMIT 1
           ) ocr ON true
           WHERE ja.job_id=:jid"""
    filters = " AND (ja.parse_status='parsed' OR ja.ocr_status='done')"
    filters += f" AND {_RAG_INDEXABLE_FILTER} AND {_RAG_NOT_SKIPPED}"
    embed_on = bool(getattr(settings, "rag_embedding_enabled", False))
    if file_paths:
        filters += " AND ja.file_path = ANY(:paths)"
    if skip_indexed:
        filters += """ AND NOT EXISTS (
            SELECT 1 FROM rag_chunks rc
            WHERE rc.job_id=:jid AND rc.file_path=ja.file_path
              AND rc.chunk_type IN ('evidence', 'evidence_skip')
        )"""
        remaining = _count_indexable_without_chunks(db, job_id)
        if remaining <= 0:
            existing = fetchone(
                db,
                "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
                {"jid": job_id},
            )
            return int(existing["c"]) if existing else 0

    # Estimate total indexable artifacts (excludes empty parse shells that never produce chunks).
    count_row = fetchone(
        db,
        f"""SELECT count(*) c FROM job_artifacts ja
           WHERE ja.job_id=:jid
             AND (ja.parse_status='parsed' OR ja.ocr_status='done')
             AND {_RAG_INDEXABLE_FILTER}
             AND {_RAG_NOT_SKIPPED}""",
        {"jid": job_id},
    )
    if progress_total is None:
        progress_total = int(count_row["c"]) if count_row else 0

    remaining_at_start = _count_indexable_without_chunks(db, job_id) if skip_indexed else progress_total
    progress_completed = max(int(progress_total or 0) - int(remaining_at_start or 0), 0)

    embed_limit = _baseline_embed_limit(settings) if embed_on else None
    progress_display_total = progress_total
    if embed_limit is not None:
        progress_display_total = min(progress_total, embed_limit)

    existing = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
        {"jid": job_id},
    )
    total_added = int(existing["c"]) if existing and skip_indexed else 0
    if embed_limit is not None and total_added >= embed_limit:
        _mark_rag_baseline_complete(
            db,
            job_id,
            schema_name=schema_name,
            chunk_count=total_added,
            label="Q&A ready — baseline indexed",
        )
        return total_added

    last_id = "00000000-0000-0000-0000-000000000000"
    try:
        batch_size = max(100, min(int(os.environ.get("RAG_DB_FETCH_BATCH", "500")), 2000))
    except Exception:
        batch_size = 500
    device_label, _ = resolve_device(settings.rag_embedding_device)
    from app.services.disk_build_log import write_disk_log

    write_disk_log(
        db,
        job_id,
        f"Loading {settings.rag_embedding_model} on {device_label} — "
        f"{progress_display_total:,} evidence chunks to embed"
        + (f" (baseline cap; {progress_total:,} parsed total deferred)" if embed_limit and progress_total > embed_limit else ""),
        stage="rag_index",
    )
    db.commit()
    if schema_name:
        apply_firm_search_path(db, schema_name)
    from contextlib import ExitStack

    from app.services.gpu_thermal import gpu_work_log_message, prepare_gpu_for_heavy_work, reset_embed_duty_counter
    from app.services.job_locks import gpu_heavy_slot

    reset_embed_duty_counter()
    # V45.1: only reserve the exclusive GPU lane when this pass will actually embed.
    # With RAG_EMBEDDING_ENABLED=false the pass is CPU chunking only, but the old
    # test (device == cuda) still took the single GPU permit, collided with OCR,
    # failed the one-shot acquire and re-queued itself every 120 s:
    #   "RAG deferred — GPU slot busy (GPU local slot wait timed out ... after 0s)"
    embed_enabled = bool(getattr(settings, "rag_embedding_enabled", False))
    use_cuda = embed_enabled and (settings.rag_embedding_device or "").lower() in ("cuda", "gpu", "auto")
    if not embed_enabled:
        write_disk_log(
            db,
            job_id,
            "RAG chunking on CPU — embeddings disabled (RAG_EMBEDDING_ENABLED=false); no GPU lane needed, "
            "runs alongside OCR",
            stage="rag_index",
        )
        db.commit()
        if schema_name:
            apply_firm_search_path(db, schema_name)

    with ExitStack() as stack:
        if use_cuda:
            try:
                # Exclusive vs OCR — fail-closed (never overlap GPU workers).
                stack.enter_context(gpu_heavy_slot("job_evidence_rag", fail_closed=True))
                from app.services.gpu_thermal import release_gpu_model_after_task_enabled
                if release_gpu_model_after_task_enabled():
                    from app.services.embedding_gpu import unload_embedder
                    # ExitStack callbacks run before the GPU lease context exits, so
                    # VRAM is returned while this worker still owns the GPU permit.
                    stack.callback(unload_embedder)
                prep = prepare_gpu_for_heavy_work(
                    reason="job_evidence_rag",
                    unload_ollama=bool(getattr(settings, "gpu_thermal_unload_ollama_before_rag", True)),
                )
                if prep.get("waited_sec") or prep.get("ollama_unloaded"):
                    write_disk_log(
                        db,
                        job_id,
                        gpu_work_log_message(
                            f"GPU thermal prep — waited {prep.get('waited_sec', 0):.0f}s, "
                            f"temp={((prep.get('stats') or {}).get('temperature_c'))}°C "
                            f"(exclusive GPU slot held)"
                        ),
                        stage="rag_index",
                        metadata=prep,
                    )
                    db.commit()
                    if schema_name:
                        apply_firm_search_path(db, schema_name)
            except Exception as exc:
                from app.services.job_locks import GpuHeavySlotTimeout

                if isinstance(exc, GpuHeavySlotTimeout):
                    write_disk_log(
                        db,
                        job_id,
                        f"RAG deferred — GPU slot busy ({exc})",
                        stage="rag_index",
                        level="warning",
                    )
                    db.commit()
                    raise
                log.debug("GPU thermal prep skipped: %s", exc)

        _touch_rag_progress(
            db,
            job_id,
            completed=progress_completed if skip_indexed else total_added,
            total=max(progress_total if skip_indexed else progress_display_total, 1),
            label=(
                f"RAG indexing — {progress_completed:,} / {max(progress_total, 1):,} artifacts; "
                f"{total_added:,} chunks searchable"
                if skip_indexed else f"RAG embedding on {device_label}"
            ),
            schema_name=schema_name,
            chunk_count=total_added if skip_indexed else None,
        )
        db.commit()
        if schema_name:
            apply_firm_search_path(db, schema_name)

        from concurrent.futures import ThreadPoolExecutor

        def _fetch_evidence_batch(after_id: str):
            params: dict = {"jid": job_id, "last_id": after_id}
            if file_paths:
                params["paths"] = file_paths
            return fetchall(
                db,
                f"{base_sql}{filters} AND ja.id > :last_id ORDER BY ja.id LIMIT {batch_size}",
                params,
            )

        chunk_pool = stack.enter_context(
            ThreadPoolExecutor(max_workers=1, thread_name_prefix="rag-chunk")
        )
        chunk_fut = None
        pending_rows = None

        while True:
            if schema_name:
              from app.services.job_control import pipeline_should_stop

              if pipeline_should_stop(db, job_id):
                  from app.services.job_control import mark_job_paused

                  mark_job_paused(db, job_id, message="RAG paused — stopped by user or supervisor")
                  write_disk_log(db, job_id, "RAG embedding paused — resumable from checkpoint", stage="rag_index", level="warning")
                  db.commit()
                  apply_firm_search_path(db, schema_name)
                  _touch_rag_progress(
                      db,
                      job_id,
                      completed=total_added,
                      total=max(progress_total, total_added, 1),
                      label="RAG paused — click Resume or wait for supervisor",
                      schema_name=schema_name,
                  )
                  db.commit()
                  return total_added
            if chunk_fut is None:
                rows = pending_rows if pending_rows is not None else _fetch_evidence_batch(last_id)
                pending_rows = None
                if not rows:
                    break
                last_id = str(rows[-1]["id"])
                chunk_fut = chunk_pool.submit(
                    chunk_rows_for_embedding, list(rows), settings, index_map
                )
            # Fetch the next SQL page on this thread while CPU chunks the current one.
            pending_rows = _fetch_evidence_batch(last_id)
            texts, meta, skip_ids, fallback_count = chunk_fut.result()
            chunk_fut = None
            for sid in skip_ids:
                _mark_artifact_rag_skip(db, sid, reason="no_embeddable_text")
            if fallback_count:
                log.info("Text fallback indexed %d files for job %s", fallback_count, job_id)
            if pending_rows:
                last_id = str(pending_rows[-1]["id"])
                chunk_fut = chunk_pool.submit(
                    chunk_rows_for_embedding, list(pending_rows), settings, index_map
                )
                pending_rows = None
            page_artifact_ids = {str(m.get("job_artifact_id")) for m in meta if m.get("job_artifact_id")}
            page_artifact_ids.update(str(sid) for sid in skip_ids)
            if not texts:
                if skip_indexed and page_artifact_ids:
                    progress_completed = min(progress_total, progress_completed + len(page_artifact_ids))
                    _touch_rag_progress(
                        db, job_id, completed=progress_completed, total=max(progress_total, 1),
                        label=(
                            f"RAG indexing — {progress_completed:,} / {max(progress_total, 1):,} artifacts; "
                            f"{total_added:,} chunks searchable"
                        ),
                        schema_name=schema_name, chunk_count=total_added,
                    )
                    db.commit()
                    if schema_name:
                        apply_firm_search_path(db, schema_name)
                continue

            if not embed_on:
                total_added += _insert_evidence_text_chunks(db, job_id, texts, meta)
                db.commit()
                if schema_name:
                    apply_firm_search_path(db, schema_name)
                _touch_rag_progress(
                    db,
                    job_id,
                    completed=total_added,
                    total=max(progress_display_total, total_added, 1),
                    label=f"RAG chunking — {total_added:,} text chunks",
                    schema_name=schema_name,
                )
                db.commit()
                if schema_name:
                    apply_firm_search_path(db, schema_name)
                continue

            embed_batch = max(int(settings.rag_batch_size or 16), 1)
            try:
                # Embed in thermal-safe CUDA mini-batches, but persist/progress once per
                # fetched evidence page.  This removes thousands of tiny transactions.
                for start in range(0, len(texts), embed_batch):
                    batch_texts = texts[start : start + embed_batch]
                    batch_meta = meta[start : start + embed_batch]
                    vectors = embed_texts(
                        batch_texts,
                        model_name=settings.rag_embedding_model,
                        device=settings.rag_embedding_device,
                        batch_size=settings.rag_batch_size,
                    )
                    total_added += _insert_evidence_text_chunks(
                        db, job_id, batch_texts, batch_meta, vectors=vectors
                    )

                if skip_indexed and page_artifact_ids:
                    progress_completed = min(progress_total, progress_completed + len(page_artifact_ids))
                    progress_done = progress_completed
                    progress_den = max(progress_total, 1)
                else:
                    progress_done = total_added
                    progress_den = max(progress_display_total, total_added, 1)
                _touch_rag_progress(
                    db,
                    job_id,
                    completed=progress_done,
                    total=progress_den,
                    label=(
                        f"RAG indexing — {progress_done:,} / {progress_den:,} artifacts; "
                        f"{total_added:,} chunks searchable"
                        if skip_indexed else f"RAG embedding on {device_label}"
                    ),
                    schema_name=schema_name,
                    chunk_count=total_added if skip_indexed else None,
                )
                db.commit()
                if schema_name:
                    apply_firm_search_path(db, schema_name)

                if embed_limit is not None and total_added >= embed_limit:
                    write_disk_log(
                        db,
                        job_id,
                        f"RAG baseline reached — {total_added:,} chunks embedded "
                        f"({progress_total:,} parsed artifacts deferred to background)",
                        stage="rag_index",
                    )
                    db.commit()
                    if schema_name:
                        apply_firm_search_path(db, schema_name)
                    _mark_rag_baseline_complete(
                        db,
                        job_id,
                        schema_name=schema_name,
                        chunk_count=total_added,
                        label="Q&A ready — baseline indexed",
                    )
                    return total_added
                log.info(
                    "RAG evidence page committed — %d chunks total, %d/%d artifacts indexed for job %s",
                    total_added, progress_done, progress_den, job_id,
                )
            except Exception as exc:
                from app.services.gpu_thermal import GpuThermalAbort
                from app.services.job_control import mark_job_paused

                if isinstance(exc, (GpuThermalAbort,)):
                    mark_job_paused(
                        db,
                        job_id,
                        message=str(exc)[:500],
                    )
                    from app.services.gpu_thermal import gpu_work_log_message

                    write_disk_log(
                        db,
                        job_id,
                        gpu_work_log_message(f"RAG paused — thermal safety: {exc}"),
                        stage="rag_index",
                        level="warning",
                    )
                    db.commit()
                    if schema_name:
                        apply_firm_search_path(db, schema_name)
                    return total_added
                log.warning("RAG evidence batch failed (continuing): %s", exc)
                try:
                    db.rollback()
                except Exception:
                    pass
                if schema_name:
                    apply_firm_search_path(db, schema_name)
                continue

        _mark_rag_baseline_complete(
            db,
            job_id,
            schema_name=schema_name,
            chunk_count=total_added,
        )
        return total_added


def ensure_encyclopedia_indexed(db, schema_name: str | None = None) -> int:
    settings = get_settings()
    n = _index_encyclopedia(db, settings)
    if schema_name:
        apply_firm_search_path(db, schema_name)
    return n


def append_job_evidence_rag(
    db,
    job_id: str,
    *,
    file_paths: list[str] | None = None,
    index_map: dict[str, str] | None = None,
    schema_name: str | None = None,
) -> int:
    """Append evidence chunks without deleting existing RAG data (streaming pipeline)."""
    settings = get_settings()
    added = _index_job_evidence(
        db,
        job_id,
        settings,
        index_map=index_map,
        file_paths=file_paths,
        skip_indexed=True,
        schema_name=schema_name,
    )
    try:
        from app.services.forensic_profile_index import ensure_os_fact_chunks, ensure_profile_fact_chunks

        ensure_profile_fact_chunks(db, job_id, refresh_critical=False)
        ensure_os_fact_chunks(db, job_id, refresh_hives=True)
        if schema_name:
            apply_firm_search_path(db, schema_name)
    except Exception:
        pass
    return added


def build_dual_rag_index(db, job_id: str, *, schema_name: str, index_map: dict[str, str] | None = None) -> dict:
    settings = get_settings()
    if not getattr(settings, "rag_embedding_enabled", False):
        write_disk_log(
            db,
            job_id,
            "RAG chunking — text chunks only (embeddings optional and off)",
            stage="rag_index",
        )
        db.commit()
        ev_count = _index_job_evidence(
            db, job_id, settings, index_map=index_map, skip_indexed=True, schema_name=schema_name
        )
        return {
            "status": "ok",
            "chunks_total": ev_count,
            "evidence_chunks": ev_count,
            "encyclopedia_chunks": 0,
        }
    device_label, gpu = resolve_device(settings.rag_embedding_device)

    from app.services.gpu_thermal import gpu_work_log_message

    write_disk_log(
        db,
        job_id,
        gpu_work_log_message(f"Phase 3 dual RAG indexing — embed={settings.rag_embedding_model}"),
        stage="rag_index",
    )
    execute(db, "UPDATE jobs SET status='indexing', updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()
    apply_firm_search_path(db, schema_name)

    execute(db, "DELETE FROM rag_chunks WHERE job_id=:jid", {"jid": job_id})
    db.commit()
    apply_firm_search_path(db, schema_name)

    enc_count = _index_encyclopedia(db, settings)
    apply_firm_search_path(db, schema_name)
    ev_count = _index_job_evidence(db, job_id, settings, index_map=index_map, schema_name=schema_name)

    from app.services.forensic_profile_index import ensure_profile_fact_chunks

    profile_count = ensure_profile_fact_chunks(db, job_id)
    from app.services.forensic_profile_index import ensure_os_fact_chunks

    os_count = ensure_os_fact_chunks(db, job_id, refresh_hives=True)
    db.commit()
    total = enc_count + ev_count + profile_count + os_count

    from app.services.opensearch_sync import bulk_index_chunks, opensearch_available

    if opensearch_available():
        chunks = fetchall(
            db,
            """SELECT id, job_id, file_path, content, artifact_id, chunk_type
               FROM rag_chunks WHERE job_id=:jid OR job_id IS NULL LIMIT 5000""",
            {"jid": job_id},
        )
        bulk_index_chunks([{**dict(c), "chunk_id": str(c["id"])} for c in chunks], job_id=job_id)

    pipeline_progress = {
        "phase": "rag",
        "completed": total,
        "total": max(total, 1),
        "label": "chunks embedded",
        "encyclopedia_chunks": enc_count,
        "evidence_chunks": ev_count,
    }
    extract_coverage = {
        "interesting_total": ev_count,
        "extracted": ev_count,
        "pending": 0,
        "encyclopedia_chunks": enc_count,
    }
    from app.services.pipeline_orchestrator import record_pipeline_milestone

    record_pipeline_milestone(
        db,
        job_id,
        status="indexed",
        writer="rag",
        progress=pipeline_progress,
        extract_coverage=extract_coverage,
    )
    write_disk_log(
        db,
        job_id,
        f"Dual RAG complete — {ev_count:,} evidence chunks + {enc_count:,} encyclopedia chunks on {device_label}",
        stage="rag_index",
        metadata={"evidence_chunks": ev_count, "encyclopedia_chunks": enc_count, "device": device_label},
    )
    db.commit()
    return {"status": "indexed", "chunks_total": total, "evidence_chunks": ev_count, "encyclopedia_chunks": enc_count}
