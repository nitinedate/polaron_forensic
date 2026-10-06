"""Incremental Phase 3 while extraction is still running (per-shard pipeline)."""

from __future__ import annotations

import json
import logging

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.artifact_materialize import materialize_index_entries
from app.services.disk_build_log import write_disk_log
from app.services.disk_manifest import build_index_map
from app.services.dual_rag_index import append_job_evidence_rag, ensure_encyclopedia_indexed
from app.services.job_control import load_extraction_checkpoint, save_extraction_checkpoint
from app.services.ocr_gpu import run_ocr_for_job
from app.services.tar_cache import read_file_from_part

log = logging.getLogger("stream_phase3")


def _shard_index_entries(checkpoint: dict, shard_id: int) -> list[dict]:
    shard_indexes = checkpoint.get("shard_indexes") or {}
    uri = shard_indexes.get(str(shard_id)) or shard_indexes.get(shard_id)
    if uri:
        from app.services.disk_manifest import load_index_entries

        return load_index_entries({"shard_indexes": {str(shard_id): uri}})
    for shard in checkpoint.get("completed_shards") or []:
        if int(shard.get("shard_id", -1)) == shard_id:
            return list(shard.get("index_entries") or [])
    return []


def _update_streaming_progress(
    db,
    job_id: str,
    *,
    phase: str,
    completed: int,
    total: int,
    label: str,
) -> None:
    """Update pipeline_progress while extraction continues (status stays building_disk)."""
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW()
           WHERE id=:id AND status IN ('building_disk', 'indexing', 'artifacts_registered', 'parsed')""",
        {
            "pp": json.dumps({"phase": phase, "completed": completed, "total": total, "label": label}),
            "id": job_id,
        },
    )


def _reset_skipped_artifacts_for_retry(db, job_id: str) -> int:
    """Re-queue artifacts that were skipped when tar shards were not yet readable."""
    from app.db.sql_helpers import fetchone

    execute(
        db,
        """UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
           WHERE job_id=:jid AND parse_status='skipped'""",
        {"jid": job_id},
    )
    row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
        {"jid": job_id},
    )
    return int(row["c"]) if row else 0


def _rebind_firm(db, schema_name: str) -> None:
    """Re-apply firm search_path after commits (pooled connections can lose it)."""
    from app.db.session import apply_firm_search_path

    apply_firm_search_path(db, schema_name)


def process_extracted_shard(db, job_id: str, *, schema_name: str, shard_id: int) -> dict:
    """Materialize → parse → OCR → RAG append for one finished extraction shard."""
    from app.services.forensic_serial_policy import serial_enabled

    if serial_enabled():
        from app.services.forensic_serial_pipeline import start_serial_pipeline

        return start_serial_pipeline(db, job_id, schema_name=schema_name)
    settings = get_settings()
    checkpoint = load_extraction_checkpoint(db, job_id) or {}
    phase3_done = {int(x) for x in (checkpoint.get("phase3_completed_shards") or [])}
    if shard_id in phase3_done:
        return {"status": "skipped", "reason": "already_processed", "shard_id": shard_id}

    entries = _shard_index_entries(checkpoint, shard_id)
    if not entries:
        return {"status": "skipped", "reason": "no_index_entries", "shard_id": shard_id}

    row = fetchone(db, "SELECT disk_source, files_total FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else None
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    if not isinstance(manifest, dict):
        manifest = {}

    paths = [e["path"] for e in entries if e.get("path")]
    total_files = int(row.get("files_total") or checkpoint.get("nodes_total") or len(paths))

    _update_streaming_progress(
        db,
        job_id,
        phase="materialize",
        completed=int(checkpoint.get("files_extracted") or 0),
        total=total_files,
        label=f"materializing shard {shard_id} ({len(entries):,} files)",
    )
    db.commit()
    _rebind_firm(db, schema_name)

    mat = materialize_index_entries(db, job_id, entries, update_status=False)
    index_map = build_index_map(manifest, extra_entries=entries)

    fmt = str(
        (manifest or {}).get("format")
        or (manifest or {}).get("disk_format")
        or (manifest or {}).get("evidence_format")
        or ""
    ).lower()
    from app.services.mobile_segments import is_mobile_evidence_format

    mobile_zip_extract = is_mobile_evidence_format(fmt) or any(
        ".zip/" in str(p).replace("\\", "/").lower() or ".part-" in str(p).lower()
        for p in paths[:20]
    )
    # Zip-only mobile extract is I/O bound; overlap GPU RAG with remaining shards.
    stream_rag = bool(settings.phase3_stream_rag_during_extract or mobile_zip_extract)
    deferred_gpu = not stream_rag
    finalize_queued = bool(manifest.get("phase3_finalize_queued"))

    # CPU parse uses a dedicated product-local queue so post-processing cannot
    # occupy extraction worker processes. It remains independent of GPU RAG/OCR.
    from app.forensic_common.pipeline_routing import parse_queue
    from app.tasks import parse_shard_task

    parse_queue_name = parse_queue()

    try:
        parse_shard_task.delay(schema_name, job_id, shard_id)
        parse_queued = True
    except Exception as exc:
        log.warning("Parse shard queue failed shard=%s job=%s: %s", shard_id, job_id, exc)
        parse_queued = False

    ocr_queued = False
    if settings.ocr_enabled and settings.phase3_stream_ocr_during_extract:
        try:
            from app.tasks import ocr_drain_task

            ocr_drain_task.delay(schema_name, job_id)
            ocr_queued = True
        except Exception as exc:
            log.warning("OCR drain queue failed job=%s: %s", job_id, exc)

    if finalize_queued:
        phase3_done.add(shard_id)
        if checkpoint:
            checkpoint["phase3_completed_shards"] = sorted(phase3_done)
            save_extraction_checkpoint(db, job_id, checkpoint)
        label = (
            f"shard {shard_id} materialized — parse queued on {parse_queue_name}"
            if parse_queued
            else f"shard {shard_id} materialized — parse queue failed"
        )
        if ocr_queued:
            label += ", GPU OCR queued"
        _update_streaming_progress(
            db,
            job_id,
            phase="parse",
            completed=0,
            total=len(paths),
            label=label,
        )
        write_disk_log(
            db,
            job_id,
            f"Streaming Phase 3 — shard {shard_id}: {mat.get('artifacts_total', 0):,} materialized; "
            f"parse {'queued' if parse_queued else 'NOT queued'} on {parse_queue_name}",
            stage="phase3",
            metadata={"shard_id": shard_id, "materialize": mat, "parse_queued": parse_queued},
        )
        db.commit()
        return {
            "status": "ok" if parse_queued else "partial",
            "reason": "finalize_queued",
            "shard_id": shard_id,
            "materialize": mat,
            "parsed": 0,
            "parse_queued": parse_queued,
            "rag_added": 0,
        }

    _update_streaming_progress(
        db,
        job_id,
        phase="parse",
        completed=0,
        total=len(paths),
        label=f"parsing shard {shard_id} on {parse_queue_name}",
    )
    db.commit()
    _rebind_firm(db, schema_name)

    parsed = 0
    pr = {"parsed": 0, "skipped": 0, "queued": parse_queued}

    ocr_count = 1 if ocr_queued else 0
    rag_added = 0

    if stream_rag and getattr(settings, "rag_embedding_enabled", False):
        _update_streaming_progress(
            db,
            job_id,
            phase="rag",
            completed=0,
            total=len(paths),
            label=f"RAG indexing shard {shard_id}",
        )
        db.commit()
        _rebind_firm(db, schema_name)

        ensure_encyclopedia_indexed(db, schema_name=schema_name)
        _rebind_firm(db, schema_name)
        rag_added = append_job_evidence_rag(
            db, job_id, file_paths=paths, index_map=index_map, schema_name=schema_name,
        )
    elif deferred_gpu:
        checkpoint.setdefault("phase3_deferred_gpu_shards", [])
        if shard_id not in checkpoint["phase3_deferred_gpu_shards"]:
            checkpoint["phase3_deferred_gpu_shards"].append(shard_id)
        _update_streaming_progress(
            db,
            job_id,
            phase="materialize",
            completed=int(checkpoint.get("files_extracted") or 0),
            total=total_files,
        label=f"shard {shard_id} materialized — parse on disk worker, RAG deferred until finalize",
        )
        db.commit()
        _rebind_firm(db, schema_name)

    phase3_done.add(shard_id)
    checkpoint["phase3_completed_shards"] = sorted(phase3_done)
    save_extraction_checkpoint(db, job_id, checkpoint)

    artifacts_total = fetchone(
        db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id},
    )
    chunks_total = fetchone(
        db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid", {"jid": job_id},
    )
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {
            "pp": json.dumps({
                "phase": "rag",
                "completed": int(chunks_total["c"]) if chunks_total else rag_added,
                "total": max(int(artifacts_total["c"]) if artifacts_total else 0, 1),
                "label": f"streaming — shard {shard_id} indexed",
            }),
            "id": job_id,
        },
    )
    write_disk_log(
        db,
        job_id,
        f"Streaming Phase 3 — shard {shard_id}: {mat.get('artifacts_total', 0):,} materialized"
        + (f", parse queued on disk worker" if pr.get("queued") else ", parse inline"),
        stage="phase3",
        metadata={
            "shard_id": shard_id,
            "materialize": mat,
            "parsed": parsed,
            "rag_added": rag_added,
            "ocr_count": ocr_count,
            "gpu_deferred": deferred_gpu,
        },
    )
    db.commit()
    return {
        "status": "ok",
        "shard_id": shard_id,
        "materialize": mat,
        "parsed": parsed,
        "rag_added": rag_added,
    }


def run_phase3_finalize(db, job_id: str, *, schema_name: str) -> dict:
    """Finish Phase 3 after extraction completes (remaining artifacts + graph sync)."""
    from app.services.forensic_serial_policy import serial_enabled

    if serial_enabled():
        from app.services.forensic_serial_pipeline import start_serial_pipeline

        return start_serial_pipeline(db, job_id, schema_name=schema_name)
    from app.services.neo4j_sync import sync_job_graph
    from app.services.phase3_pipeline import run_phase3_pipeline

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    if not isinstance(manifest, dict):
        manifest = {}

    streamed = bool(manifest.get("streaming") or manifest.get("phase3_completed_shards"))
    if not streamed:
        checkpoint = load_extraction_checkpoint(db, job_id) or {}
        streamed = bool(checkpoint.get("phase3_completed_shards"))
    # extraction_checkpoint is cleared on disk_ready — detect prior streamed work via DB.
    if not streamed:
        prior = fetchone(
            db,
            """SELECT
                 (SELECT count(*) FROM job_artifacts WHERE job_id=:jid) AS arts,
                 (SELECT count(*) FROM rag_chunks WHERE job_id=:jid) AS chunks""",
            {"jid": job_id},
        )
        if prior and (int(prior.get("arts") or 0) > 100 or int(prior.get("chunks") or 0) > 0):
            streamed = True
            write_disk_log(
                db,
                job_id,
                "Finalize using streamed path (artifacts/chunks already present; checkpoint was cleared)",
                stage="phase3",
                metadata={"arts": prior.get("arts"), "chunks": prior.get("chunks")},
            )
            db.commit()

    if streamed:
        settings = get_settings()
        index_map = build_index_map(manifest)

        execute(
            db,
            """UPDATE jobs SET status='indexing', pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW()
               WHERE id=:id""",
            {"pp": json.dumps({"phase": "parse", "completed": 0, "total": 0, "label": "finalizing pipeline"}), "id": job_id},
        )
        db.commit()

        files_total_row = fetchone(db, "SELECT files_total FROM jobs WHERE id=:id", {"id": job_id})
        files_total = int((files_total_row or {}).get("files_total") or 0)
        arts = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})
        art_count = int(arts["c"]) if arts else 0
        parsed_n = fetchone(
            db,
            """SELECT count(*) c FROM job_artifacts
               WHERE job_id=:jid AND (parse_status='parsed' OR ocr_status='done')""",
            {"jid": job_id},
        )
        parsed_count = int(parsed_n["c"]) if parsed_n else 0

        # Always upsert registry hives / EVTX — streaming shards can omit SOFTWARE.
        from app.services.artifact_materialize import (
            materialize_critical_forensic_paths,
            materialize_missing_critical_from_disk,
        )

        write_disk_log(
            db,
            job_id,
            "Finalizing — materialize critical forensic paths (SOFTWARE/SYSTEM/SAM/EVTX)…",
            stage="phase3",
        )
        db.commit()
        _rebind_firm(db, schema_name)
        # Hold CPU-heavy slot so OCR/RAG cannot overlap finalize (thermal shutdown).
        from app.services.job_locks import CpuHeavySlotTimeout, cpu_heavy_slot

        try:
            with cpu_heavy_slot("phase3_finalize"):
                critical_mat = materialize_critical_forensic_paths(db, job_id)
                disk_fetch = materialize_missing_critical_from_disk(db, job_id)
        except CpuHeavySlotTimeout as exc:
            write_disk_log(
                db,
                job_id,
                f"Finalize deferred — chassis busy ({exc})",
                stage="phase3",
                level="warning",
            )
            db.commit()
            raise
        if critical_mat.get("added") or disk_fetch.get("fetched"):
            write_disk_log(
                db,
                job_id,
                f"Materialized {critical_mat.get('added', 0):,} critical forensic artifacts"
                + (f", fetched {disk_fetch.get('fetched', 0)} from disk" if disk_fetch.get("fetched") else ""),
                stage="phase3",
                metadata={**critical_mat, "disk_fetch": disk_fetch},
            )
            db.commit()
            _rebind_firm(db, schema_name)
            manifest_row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
            manifest = manifest_row.get("disk_source") if manifest_row else manifest
            if isinstance(manifest, str):
                import json as _json
                manifest = _json.loads(manifest)
            index_map = build_index_map(manifest or {})

        # Streamed Phase 3 often finishes only a subset of shards — fill gaps from full index.
        need_rematerialize = art_count < 500 or (
            files_total > 0 and art_count < int(files_total * 0.95)
        )
        if need_rematerialize:
            from app.services.artifact_materialize import rematerialize_missing_from_index

            write_disk_log(
                db,
                job_id,
                f"Finalizing — rematerialize missing index paths "
                f"({art_count:,}/{files_total or '?'} artifacts)…",
                stage="phase3",
            )
            db.commit()
            _rebind_firm(db, schema_name)
            filled = rematerialize_missing_from_index(db, job_id, update_status=False)
            if filled.get("added"):
                write_disk_log(
                    db,
                    job_id,
                    f"Rematerialized {filled['added']:,} missing artifacts from full disk index",
                    stage="phase3",
                    metadata=filled,
                )
                db.commit()
                _rebind_firm(db, schema_name)
                index_map = build_index_map(manifest)
            arts = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})
            art_count = int(arts["c"]) if arts else art_count
        else:
            write_disk_log(
                db,
                job_id,
                f"Finalizing — skip full rematerialize ({art_count:,} artifacts, {parsed_count:,} parsed)",
                stage="phase3",
            )
            db.commit()
            _rebind_firm(db, schema_name)

        pending_now = fetchone(
            db,
            "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
            {"jid": job_id},
        )
        pending_count = int(pending_now["c"]) if pending_now else 0
        if pending_count < 5000:
            pending = _reset_skipped_artifacts_for_retry(db, job_id)
            if pending:
                write_disk_log(
                    db,
                    job_id,
                    f"Re-queued {pending:,} previously skipped artifacts for parse/RAG",
                    stage="phase3",
                )
                db.commit()
                _rebind_firm(db, schema_name)
                pending_count = pending
        else:
            write_disk_log(
                db,
                job_id,
                f"Finalizing — skip re-queue of skipped ({pending_count:,} already pending)",
                stage="phase3",
            )
            db.commit()
            _rebind_firm(db, schema_name)

        from app.services.artifact_parse import drain_pending_parse

        # Large pending sets (post rematerialize) would block for hours — unlock Q&A via RAG
        # on already-parsed evidence, then continue parse in background on rag-index.
        coverage_ok = files_total <= 0 or art_count >= int(files_total * 0.95)
        background_parse = pending_count >= 2000
        if parsed_count >= 2000 and pending_count < 500 and coverage_ok:
            write_disk_log(
                db,
                job_id,
                f"Finalizing — skip parse drain ({parsed_count:,} already parsed); GPU RAG next",
                stage="phase3",
            )
            db.commit()
            _rebind_firm(db, schema_name)
            drain = {"parsed": 0, "skipped": 0, "rounds": 0}
        elif background_parse:
            # Queue parse drain on the disk worker IMMEDIATELY — do not wait for
            # multi-hour GPU RAG. Parse is CPU-bound and must run in parallel.
            parse_queued = False
            try:
                from app.tasks import parse_drain_task

                parse_drain_task.delay(schema_name, job_id)
                parse_queued = True
                write_disk_log(
                    db,
                    job_id,
                    f"Finalizing — parallel background parse queued now "
                    f"({pending_count:,} pending on disk worker); GPU RAG continues separately",
                    stage="parse",
                )
                db.commit()
                _rebind_firm(db, schema_name)
            except Exception as exc:
                log.warning("Queue background parse before RAG failed: %s", exc)
                write_disk_log(
                    db,
                    job_id,
                    f"Finalizing — GPU RAG on {parsed_count:,} parsed now; "
                    f"{pending_count:,} pending will continue in background",
                    stage="phase3",
                )
                db.commit()
                _rebind_firm(db, schema_name)
            drain = {
                "parsed": 0,
                "skipped": 0,
                "rounds": 0,
                "deferred_pending": pending_count,
                "parse_queued": parse_queued,
            }
        else:
            write_disk_log(
                db,
                job_id,
                f"Finalizing — parse drain then GPU RAG "
                f"(pending={pending_count:,}, arts={art_count:,}/{files_total or '?'})…",
                stage="phase3",
            )
            db.commit()
            _rebind_firm(db, schema_name)
            drain = drain_pending_parse(
                db,
                job_id,
                index_map=index_map,
                requeue_no_parser=False,
                max_rounds=int(getattr(settings, "parse_drain_max_rounds", 0) or 0) or None,
                update_job_status=False,
            )
            write_disk_log(
                db,
                job_id,
                f"Parse drain finished — {drain.get('parsed', 0):,} parsed, "
                f"{drain.get('skipped', 0):,} skipped ({drain.get('rounds', 0)} rounds)",
                stage="parse",
                metadata=drain,
            )
            db.commit()
            _rebind_firm(db, schema_name)

        if settings.ocr_enabled:
            try:
                from app.tasks import ocr_drain_task

                ocr_drain_task.delay(schema_name, job_id)
                write_disk_log(
                    db,
                    job_id,
                    "Queued GPU OCR on rag-gpu (finalize stays on disk worker)",
                    stage="ocr",
                )
                db.commit()
            except Exception as exc:
                log.warning("Queue GPU OCR after finalize failed: %s", exc)

        rag_added = 0
        graph = {"status": "queued"}
        write_disk_log(
            db,
            job_id,
            "Queued GPU RAG on rag-gpu — disk finalize will not wait for embeddings",
            stage="rag_index",
        )
        db.commit()
        _rebind_firm(db, schema_name)
        try:
            from app.tasks import rag_append_task

            rag_append_task.delay(schema_name, job_id)
        except Exception as exc:
            log.warning("Queue GPU RAG after finalize failed: %s", exc)
        try:
            from app.tasks import graph_sync_task

            graph_sync_task.delay(schema_name, job_id)
        except Exception as exc:
            log.warning("Queue graph sync after finalize failed: %s", exc)
            graph = sync_job_graph(db, job_id, schema_name=schema_name)

        # Parse was already queued before RAG when background_parse — avoid double-queue.
        if background_parse and not drain.get("parse_queued"):
            from app.tasks import parse_drain_task

            parse_drain_task.delay(schema_name, job_id)
            write_disk_log(
                db,
                job_id,
                f"Parallel background parse queued on disk worker ({pending_count:,} pending, forensic-only)",
                stage="parse",
            )
            db.commit()
            _rebind_firm(db, schema_name)

        from app.services.opensearch_sync import bulk_index_chunks, opensearch_available

        if opensearch_available():
            os_chunks = fetchall(
                db,
                """SELECT id, job_id, file_path, content, artifact_id, chunk_type
                   FROM rag_chunks WHERE job_id=:jid OR job_id IS NULL""",
                {"jid": job_id},
            )
            if os_chunks:
                bulk_index_chunks([{**dict(c), "chunk_id": str(c["id"])} for c in os_chunks], job_id=job_id)
                write_disk_log(
                    db,
                    job_id,
                    f"OpenSearch BM25 index synced — {len(os_chunks):,} chunks",
                    stage="rag_index",
                )
                db.commit()
                _rebind_firm(db, schema_name)

        chunks = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid", {"jid": job_id})
        total_chunks = int(chunks["c"]) if chunks else rag_added
        from app.services.dual_rag_index import _count_indexable_without_chunks

        rag_remaining = _count_indexable_without_chunks(db, job_id)
        rag_done = rag_remaining <= 0
        label = "chunks embedded (streamed pipeline)"
        if background_parse:
            label = f"Q&A ready — background parse ({pending_count:,} pending)"
        if not rag_done:
            label = f"RAG embedding — {total_chunks:,} chunks, {rag_remaining:,} artifacts remaining"
        from app.services.axiom_artifact_runner import PIPELINE_PROGRESS_CAP, finalize_job_after_pipeline

        if rag_done:
            fin = finalize_job_after_pipeline(db, job_id, schema_name=schema_name)
            if fin.get("queued_axiom_inventory"):
                prog = PIPELINE_PROGRESS_CAP
                pp_phase = "artifact_inventory"
                pp_completed = fin.get("completed", 0)
                pp_total = fin.get("total", 1)
                label = f"Pipeline complete — artifact inventory queued ({pp_total:,} {fin.get('platform', '')} artifacts)"
                job_status = "indexing"
            else:
                prog = 100
                pp_phase = "rag" if not background_parse else "parse"
                pp_completed = total_chunks
                pp_total = max(total_chunks + rag_remaining, total_chunks, 1)
                job_status = "indexed"
        else:
            prog = min(PIPELINE_PROGRESS_CAP - 1, 80 + int(19 * total_chunks / max(total_chunks + rag_remaining, 1)))
            pp_phase = "rag"
            pp_completed = total_chunks
            pp_total = max(total_chunks + rag_remaining, total_chunks, 1)
            job_status = "indexing"
        execute(
            db,
            """UPDATE jobs SET status=:st, progress_pct=:prog,
               pipeline_progress=CAST(:pp AS jsonb),
               extract_coverage=CAST(:ec AS jsonb), updated_at=NOW() WHERE id=:id""",
            {
                "st": job_status,
                "prog": prog,
                "pp": json.dumps({
                    "phase": pp_phase,
                    "completed": pp_completed,
                    "total": pp_total,
                    "label": label,
                }),
                "ec": json.dumps({
                    "interesting_total": total_chunks + rag_remaining,
                    "extracted": total_chunks,
                    "pending": (pending_count if background_parse else 0) + rag_remaining,
                }),
                "id": job_id,
            },
        )
        write_disk_log(
            db,
            job_id,
            f"Phase 3 finalize complete — {total_chunks:,} RAG chunks"
            + (f" ({rag_remaining:,} still embedding)" if not rag_done else "")
            + (
                f"; background parse on disk worker ({pending_count:,} pending, forensic-only)"
                if background_parse
                else ""
            ),
            stage="phase3",
            metadata={"rag_added": rag_added, "graph": graph, "drain": drain, "rag_remaining": rag_remaining},
        )
        db.commit()

        if not rag_done:
            try:
                from app.tasks import rag_append_task

                rag_append_task.delay(schema_name, job_id)
                write_disk_log(db, job_id, "Re-queued GPU RAG append (finalize interrupted or incomplete)", stage="rag_index")
                db.commit()
            except Exception as exc:
                log.warning("RAG re-queue after finalize failed: %s", exc)

        return {
            "status": "ok",
            "streamed": True,
            "rag_added": rag_added,
            "chunks": total_chunks,
            "drain": drain,
            "graph": graph,
            "background_parse": background_parse,
        }

    return run_phase3_pipeline(db, job_id, schema_name=schema_name)
