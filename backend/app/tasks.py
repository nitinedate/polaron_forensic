"""Background tasks — disk build, Phase 3 pipeline, report generation."""

from __future__ import annotations

import logging
import time

from app.celery_app import celery
from app.db.session import firm_session
from app.services.disk import build_extracted_disk
from app.services.phase3_pipeline import run_phase3_pipeline
from app.services.rag_index import build_rag_index_gpu
from app.services.report_generator import generate_report
from app.services.neo4j_sync import sync_job_graph

log = logging.getLogger("tasks")



def _serial_handoff(schema_name: str, job_id: str, *, retry_failed: bool = False) -> dict | None:
    from app.services.forensic_serial_policy import serial_enabled, current_stage

    if not serial_enabled() or current_stage() is not None:
        return None
    from app.services.forensic_serial_pipeline import start_serial_pipeline
    from app.services.rag_image_evidence import is_image_evidence_job

    with firm_session(schema_name) as db:
        if is_image_evidence_job(db, job_id):
            return None
        return start_serial_pipeline(db, job_id, schema_name=schema_name, retry_failed=retry_failed)


def _responsive_sequential_mode() -> bool:
    """True only for an explicit one-stage-at-a-time policy.

    Throughput / responsive / stage_aware keep extract, parse, and GPU OCR overlapping.
    """
    try:
        from app.config import get_settings

        settings = get_settings()
        mode = str(getattr(settings, "perf_policy_mode", "throughput") or "throughput").strip().lower()
        return bool(getattr(settings, "pipeline_sequential_agents", False)) and mode in {
            "sequential", "respect_env"
        }
    except Exception:
        return False


def _cpu_followup_ready(schema_name: str, job_id: str) -> tuple[bool, dict]:
    """Graph / enrich are CPU work. Start after parse (or a RAG baseline).

    Embeddings are optional. Waiting for rag_chunks when RAG_EMBEDDING_ENABLED=false
    left entity/Neo4j queued behind a stage that never had to run.
    """
    from app.db.sql_helpers import fetchone
    from app.services.dual_rag_index import BASELINE_RAG_CHUNK_TARGET

    embed_on = True
    try:
        from app.config import get_settings

        embed_on = bool(getattr(get_settings(), "rag_embedding_enabled", False))
    except Exception:
        embed_on = True

    with firm_session(schema_name) as db:
        try:
            from app.services.ocr_gpu import skip_ocr_noise_pending

            skip_ocr_noise_pending(db, job_id)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        row = fetchone(
            db,
            "SELECT count(*)::int AS c FROM rag_chunks WHERE job_id=:jid",
            {"jid": job_id},
        )
        chunks = int((row or {}).get("c") or 0)
        parsed = fetchone(
            db,
            """SELECT count(*)::int AS c
               FROM artifact_parse_results apr
               JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
               WHERE ja.job_id=:jid""",
            {"jid": job_id},
        )
        parse_n = int((parsed or {}).get("c") or 0)
    if chunks > 0:
        return True, {
            "chunks": chunks,
            "baseline": BASELINE_RAG_CHUNK_TARGET,
            "parse_rows": parse_n,
        }
    if not embed_on and parse_n > 0:
        return True, {
            "chunks": 0,
            "parse_rows": parse_n,
            "embeddings_off": True,
            "baseline": BASELINE_RAG_CHUNK_TARGET,
        }
    return False, {"reason": "no_rag_chunks_yet", "chunks": 0, "parse_rows": parse_n}


def _gpu_stage_busy() -> bool:
    """Best-effort check used to keep CPU parse from competing with active GPU work."""
    try:
        from app.services.job_locks import gpu_heavy_slot_held

        return bool(gpu_heavy_slot_held())
    except Exception:
        return False


def _retry_transient_db(task, exc: Exception) -> None:
    from app.services.db_resilience import TransientDatabaseError, is_transient_db_error, wait_for_database

    if not (isinstance(exc, TransientDatabaseError) or is_transient_db_error(exc)):
        return
    wait_for_database(timeout_sec=90)
    countdown = min(15 * (int(getattr(task.request, "retries", 0)) + 1), 90)
    raise task.retry(exc=exc, countdown=countdown, max_retries=10)


def _client_intake_hold(schema_name: str, job_id: str, stage: str) -> dict | None:
    """Fail closed for client-uploaded disk images until the full manifest is verified.

    This is a task-level safety net in addition to the API/huddle/supervisor gates.
    Server-local, server-network and removable-drive sources never enter this hold.
    """
    from app.db.sql_helpers import fetchone
    from app.services.host_evidence import is_client_upload_pending
    from app.services.mobile_os import load_job_disk_source

    with firm_session(schema_name) as db:
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
        if not row:
            return None
        ds = load_job_disk_source(row)
        if not is_client_upload_pending(ds):
            return None
        try:
            expected = max(0, int(ds.get("upload_expected_files") or 0))
        except (TypeError, ValueError):
            expected = 0
        try:
            received = max(0, int(ds.get("upload_received_files") or 0))
        except (TypeError, ValueError):
            received = 0
        status = str(ds.get("upload_status") or "receiving")
        log.info(
            "Pipeline held for incomplete client intake job=%s stage=%s files=%s/%s status=%s",
            job_id, stage, received, expected or "?", status,
        )
        return {
            "status": "held",
            "reason": "client_upload_incomplete",
            "stage": stage,
            "upload_status": status,
            "received_files": received,
            "expected_files": expected,
        }


def build_extracted_disk_sync(schema_name: str, job_id: str) -> dict:
    held = _client_intake_hold(schema_name, job_id, "extract")
    if held:
        return held
    from celery import current_task

    from app.services.db_resilience import wait_for_database
    from app.services.job_control import set_celery_task_id

    wait_for_database(timeout_sec=120)
    task_id = current_task.request.id if current_task and current_task.request else None
    with firm_session(schema_name) as db:
        if task_id:
            set_celery_task_id(db, job_id, task_id)
            db.commit()
        return build_extracted_disk(db, job_id, schema_name=schema_name)


def phase3_pipeline_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id, retry_failed=True)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "phase3")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            return run_phase3_pipeline(db, job_id, schema_name=schema_name)
    except Exception as exc:
        from app.services.db_resilience import TransientDatabaseError, is_transient_db_error

        if is_transient_db_error(exc):
            log.warning("Phase 3 hit recoverable database outage job=%s: %s", job_id, exc)
            raise TransientDatabaseError(str(exc)[:500]) from exc
        log.exception("Phase 3 pipeline failed job=%s", job_id)
        with firm_session(schema_name) as db:
            from app.db.sql_helpers import execute
            from app.services.disk_build_log import write_disk_log

            write_disk_log(db, job_id, f"Phase 3 pipeline failed: {exc}", stage="phase3", level="error")
            execute(
                db,
                "UPDATE jobs SET status='failed', error=:err, updated_at=NOW() WHERE id=:id",
                {"err": str(exc)[:500], "id": job_id},
            )
            db.commit()
        raise


def rag_index_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "rag_index")
    if held:
        return held
    from app.config import get_settings

    if get_settings().phase3_auto_after_disk:
        return phase3_pipeline_sync(schema_name, job_id)
    try:
        with firm_session(schema_name) as db:
            return build_rag_index_gpu(db, job_id, schema_name=schema_name)
    except Exception as exc:
        log.exception("RAG indexing failed job=%s", job_id)
        with firm_session(schema_name) as db:
            from app.db.sql_helpers import execute
            from app.services.disk_build_log import write_disk_log

            write_disk_log(db, job_id, f"GPU RAG indexing failed: {exc}", stage="rag_index", level="error")
            execute(
                db,
                "UPDATE jobs SET status='failed', error=:err, updated_at=NOW() WHERE id=:id",
                {"err": str(exc)[:500], "id": job_id},
            )
            db.commit()
        raise


def report_gen_sync(schema_name: str, job_id: str, report_run_id: str | None = None) -> dict:
    held = _client_intake_hold(schema_name, job_id, "report")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            return generate_report(db, job_id, schema_name=schema_name, report_run_id=report_run_id)
    except Exception as exc:
        log.exception("Report generation failed job=%s", job_id)
        with firm_session(schema_name) as db:
            from app.db.sql_helpers import execute

            execute(
                db,
                """UPDATE report_runs SET status='failed', error=:err, completed_at=NOW()
                   WHERE job_id=:jid AND status='running'""",
                {"err": str(exc)[:500], "jid": job_id},
            )
            execute(
                db,
                "UPDATE jobs SET status='failed', error=:err, updated_at=NOW() WHERE id=:id",
                {"err": str(exc)[:500], "id": job_id},
            )
            db.commit()
        raise


def graph_sync_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "graph")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            ready, info = _cpu_followup_ready(schema_name, job_id)
            if not ready:
                log.info("Graph sync waiting for RAG baseline job=%s %s", job_id, info)
                from app.db.sql_helpers import execute

                execute(
                    db,
                    """INSERT INTO graph_sync_state (job_id, status, error)
                       VALUES (:jid, 'pending', :err)
                       ON CONFLICT (job_id) DO UPDATE
                       SET status='pending', error=:err""",
                    {
                        "jid": job_id,
                        "err": info.get("reason") or "no_rag_chunks_yet",
                    },
                )
                db.commit()
                return {"status": "deferred", "reason": info.get("reason") or "no_rag_chunks_yet", **info}
            from app.db.sql_helpers import execute

            execute(
                db,
                """INSERT INTO graph_sync_state (job_id, status, error)
                   VALUES (:jid, 'syncing', NULL)
                   ON CONFLICT (job_id) DO UPDATE
                   SET status='syncing', error=NULL""",
                {"jid": job_id},
            )
            db.commit()
            return sync_job_graph(db, job_id, schema_name=schema_name)
    except Exception as exc:
        log.exception("Graph sync failed job=%s", job_id)
        raise


def _write_parse_progress(db, job_id: str, *, label: str | None = None) -> None:
    """Keep the parse card moving while buckets/shards run (no 10-min frozen %)."""
    from app.db.sql_helpers import execute, fetchone
    from app.services.artifact_parse import count_pending_parse
    import json

    parsed_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
        {"jid": job_id},
    )
    parsed_n = int((parsed_row or {}).get("c") or 0)
    pending_n = count_pending_parse(db, job_id)
    total = max(parsed_n + pending_n, 1)
    execute(
        db,
        """UPDATE jobs SET status='indexing', error=NULL,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {
            "pp": json.dumps({
                "phase": "parse",
                "completed": parsed_n,
                "total": total,
                "label": label or f"Parse forensic files — {parsed_n:,} / {total:,}",
            }),
            "id": job_id,
        },
    )


def parse_drain_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "parse")
    if held:
        return held
    # Parse is CPU/IO on worker-disk. GPU OCR/RAG on worker-rag-gpu must not
    # stall forensic parse — only an explicit sequential policy defers it.
    if _responsive_sequential_mode() and _gpu_stage_busy():
        log.info("Parse drain deferred while GPU-heavy stage is active job=%s", job_id)
        try:
            from app.tasks import parse_drain_task

            parse_drain_task.apply_async(args=(schema_name, job_id), countdown=20)
        except Exception:
            pass
        return {"status": "deferred", "reason": "gpu_stage_active", "requeued": True}

    from app.services.job_locks import (
        DEFAULT_PARSE_LOCK_TTL_SEC,
        parse_job_lock,
        parse_task_in_flight,
        refresh_job_lock,
    )

    with firm_session(schema_name) as probe_db:
        if parse_task_in_flight(probe_db, job_id):
            log.info("Parse drain skipped — another parse drain in flight job=%s", job_id)
            return {"status": "skipped", "reason": "parse_in_flight"}

    with parse_job_lock(job_id, ttl_sec=DEFAULT_PARSE_LOCK_TTL_SEC) as acquired:
        if not acquired:
            log.info("Parse drain skipped — another parse drain in flight job=%s", job_id)
            return {"status": "skipped", "reason": "parse_in_flight"}
        last_hb = time.time()

        def _parse_heartbeat() -> None:
            nonlocal last_hb
            now = time.time()
            if now - last_hb >= 45:
                refresh_job_lock("parse", job_id, ttl_sec=DEFAULT_PARSE_LOCK_TTL_SEC)
                last_hb = now

        try:
            with firm_session(schema_name) as db:
                from app.config import get_settings
                from app.services.artifact_parse import (
                    count_pending_parse,
                    drain_pending_parse,
                    prepare_forensic_parse_queue,
                )
                from app.services.disk_build_log import write_disk_log
                from app.services.disk_manifest import build_index_map
                from app.db.sql_helpers import execute, fetchone
                import json

                settings = get_settings()

                row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
                manifest = row.get("disk_source") if row else {}
                if isinstance(manifest, str):
                    manifest = json.loads(manifest)
                index_map = build_index_map(manifest or {})

                forensic_only = bool(getattr(settings, "parse_drain_forensic_only", True))
                if forensic_only:
                    cleaned = prepare_forensic_parse_queue(db, job_id)
                    if cleaned.get("skipped_low_value") or cleaned.get("skipped_media"):
                        write_disk_log(
                            db,
                            job_id,
                            f"Cleared leftover non-forensic pending before drain "
                            f"({cleaned.get('skipped_low_value', 0):,} + "
                            f"{cleaned.get('skipped_media', 0):,})",
                            stage="parse",
                        )
                pending_n = count_pending_parse(db, job_id, forensic_only=forensic_only)
                db.commit()

                from app.services.dual_rag_index import _count_indexable_without_chunks

                rag_remaining = _count_indexable_without_chunks(db, job_id)
                parsed_row = fetchone(
                    db,
                    "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
                    {"jid": job_id},
                )
                parsed_n = int(parsed_row["c"]) if parsed_row else 0
                if pending_n > 0:
                    execute(
                        db,
                        """UPDATE jobs SET status='indexing', error=NULL,
                           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
                        {
                            "pp": json.dumps({
                                "phase": "parse",
                                "completed": parsed_n,
                                "total": max(parsed_n + pending_n, 1),
                                "label": f"Background parse — {parsed_n:,} / {parsed_n + pending_n:,} forensic files",
                            }),
                            "id": job_id,
                        },
                    )
                else:
                    chunks_row = fetchone(
                        db,
                        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
                        {"jid": job_id},
                    )
                    chunk_n = int(chunks_row["c"]) if chunks_row else 0
                    execute(
                        db,
                        """UPDATE jobs SET status='indexing', error=NULL,
                           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
                        {
                            "pp": json.dumps({
                                "phase": "rag",
                                "completed": chunk_n,
                                "total": max(chunk_n + rag_remaining, 1),
                                "label": f"GPU RAG in progress — parse continues in background",
                            }),
                            "id": job_id,
                        },
                    )
                write_disk_log(
                    db,
                    job_id,
                    f"Background parse on disk worker — {pending_n:,} pending "
                    f"(forensic-only={settings.parse_drain_forensic_only}, "
                    f"workers={max(int(getattr(settings, 'parse_workers', 12) or 12), 1)}, "
                    f"parallel={getattr(settings, 'parse_parallel_enabled', True)})",
                    stage="parse",
                )
                db.commit()
                _parse_heartbeat()

                min_pending = int(getattr(settings, "parse_bucket_min_pending", 2000) or 2000)
                num_buckets = max(int(getattr(settings, "parse_parallel_buckets", 0) or 0), 0)
                if pending_n >= min_pending and num_buckets > 1:
                    from app.services.artifact_parse import queue_parallel_parse_buckets

                    queued = queue_parallel_parse_buckets(schema_name, job_id, num_buckets=num_buckets)
                    write_disk_log(
                        db,
                        job_id,
                        f"Parallel background parse — {queued} workers, {pending_n:,} pending "
                        f"({max(int(getattr(settings, 'parse_workers', 12) or 12), 1)} threads each)",
                        stage="parse",
                    )
                    db.commit()
                    return {"status": "ok", "parallel_buckets": queued, "pending": pending_n}

                drain = drain_pending_parse(
                    db,
                    job_id,
                    index_map=index_map,
                    requeue_no_parser=settings.parse_drain_requeue_no_parser,
                    update_job_status=True,
                    schema_name=schema_name,
                )
                _parse_heartbeat()
                write_disk_log(
                    db,
                    job_id,
                    f"Background parse drain — {drain.get('parsed', 0):,} parsed, "
                    f"{drain.get('skipped', 0):,} skipped",
                    stage="parse",
                    metadata=drain,
                )
                db.commit()

                pending_left = count_pending_parse(db, job_id, forensic_only=forensic_only)

                if pending_left > 0:
                    from app.services.pipeline_orchestrator import merge_orchestration_into_progress

                    merge_orchestration_into_progress(db, job_id)
                    parsed_row = fetchone(
                        db,
                        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
                        {"jid": job_id},
                    )
                    parsed_now = int(parsed_row["c"]) if parsed_row else 0
                    execute(
                        db,
                        """UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW(),
                           pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id""",
                        {
                            "pp": json.dumps({
                                "phase": "parse",
                                "completed": parsed_now,
                                "total": max(parsed_now + pending_left, 1),
                                "label": f"Background parse — {parsed_now:,} / {parsed_now + pending_left:,} forensic files",
                            }),
                            "id": job_id,
                        },
                    )
                    write_disk_log(
                        db,
                        job_id,
                        f"Parse drain batch complete — {drain.get('parsed', 0):,} parsed this run, "
                        f"{pending_left:,} still pending; re-queuing",
                        stage="parse",
                        metadata=drain,
                    )
                    db.commit()
                    if settings.parse_drain_interleave_rag:
                        try:
                            from app.services.rag_image_evidence import is_image_evidence_job
                            from app.tasks import rag_append_task

                            # Do not interleave RAG onto the GPU while image-evidence OCR is running.
                            interleave = True
                            try:
                                from app.services.ocr_gpu import count_pending_ocr as _cpo

                                interleave = not (
                                    is_image_evidence_job(db, job_id) and int(_cpo(db, job_id) or 0) > 0
                                )
                            except Exception:
                                interleave = True
                            if interleave:
                                rag_append_task.delay(schema_name, job_id)
                        except Exception as exc:
                            log.warning("Interleaved RAG append queue failed: %s", exc)
                    min_pending = int(getattr(settings, "parse_bucket_min_pending", 2000) or 2000)
                    num_buckets = max(int(getattr(settings, "parse_parallel_buckets", 0) or 0), 0)
                    if pending_left >= min_pending and num_buckets > 1:
                        from app.services.artifact_parse import queue_parallel_parse_buckets

                        queue_parallel_parse_buckets(schema_name, job_id, num_buckets=num_buckets)
                    else:
                        parse_drain_task.apply_async(args=(schema_name, job_id), countdown=2)
                    return {
                        "status": "ok",
                        "drain": drain,
                        "pending_left": pending_left,
                        "requeued": True,
                    }

                # Kick GPU OCR (images/PDFs) then GPU embed — both on rag-index / CUDA.
                try:
                    from app.services.ocr_gpu import count_pending_ocr
                    from app.tasks import ocr_drain_task

                    ocr_pending = count_pending_ocr(db, job_id)
                    if ocr_pending > 0 and settings.ocr_enabled:
                        ocr_drain_task.delay(schema_name, job_id)
                        write_disk_log(
                            db,
                            job_id,
                            f"Queued GPU OCR after parse — {ocr_pending:,} documents pending",
                            stage="ocr",
                        )
                        db.commit()
                except Exception as exc:
                    log.warning("OCR drain queue after parse failed: %s", exc)

                rag_remaining = _count_indexable_without_chunks(db, job_id)
                queued_rag = False
                if rag_remaining > 0:
                    try:
                        from app.services.rag_image_evidence import is_image_evidence_job
                        from app.tasks import rag_append_task

                        # v1.5 strict stage-aware GPU XOR: when OCR is pending, do
                        # not queue text RAG beside it.  OCR completion already
                        # queues RAG, so this avoids duplicate GPU tasks and queue churn.
                        skip_rag = False
                        try:
                            from app.services.ocr_gpu import count_pending_ocr as _cpo

                            _ocr_left = int(_cpo(db, job_id) or 0)
                            skip_rag = _ocr_left > 0 and (
                                _responsive_sequential_mode() or is_image_evidence_job(db, job_id)
                            )
                        except Exception:
                            skip_rag = False
                        if not skip_rag:
                            rag_append_task.delay(schema_name, job_id)
                            queued_rag = True
                            write_disk_log(
                                db,
                                job_id,
                                f"Queued GPU RAG after parse drain — {rag_remaining:,} artifacts pending embed",
                                stage="rag_index",
                            )
                            db.commit()
                    except Exception as exc:
                        log.warning("RAG append queue after parse drain failed: %s", exc)

                chunks = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid", {"jid": job_id})
                chunk_n = int(chunks["c"]) if chunks else 0
                pending_left = count_pending_parse(db, job_id, forensic_only=forensic_only)
                from app.services.catalog_artifact_runner import PIPELINE_PROGRESS_CAP, finalize_job_after_pipeline

                if queued_rag:
                    execute(
                        db,
                        """UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW(),
                           pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id""",
                        {
                            "pp": json.dumps({
                                "phase": "rag",
                                "completed": chunk_n,
                                "total": max(chunk_n + rag_remaining, 1),
                                "label": f"GPU RAG queued — {rag_remaining:,} artifacts to embed",
                            }),
                            "id": job_id,
                        },
                    )
                    db.commit()
                    return {
                        "status": "ok",
                        "drain": drain,
                        "rag_queued": True,
                        "rag_remaining": rag_remaining,
                        "chunks": chunk_n,
                    }

                fin = finalize_job_after_pipeline(db, job_id, schema_name=schema_name)
                if fin.get("queued_axiom_inventory"):
                    prog = PIPELINE_PROGRESS_CAP
                    phase = "artifact_inventory"
                    status = "indexing"
                    label = f"Enrichment complete — artifact inventory running ({fin.get('total', 0):,} artifacts)"
                else:
                    prog = 100
                    phase = "rag" if pending_left <= 0 else "parse"
                    status = "indexed"
                    label = "enrichment complete" if pending_left <= 0 else f"{pending_left:,} forensic pending"
                execute(
                    db,
                    """UPDATE jobs SET status=:st, progress_pct=:prog, updated_at=NOW(),
                       pipeline_progress=CAST(:pp AS jsonb),
                       extract_coverage=CAST(:ec AS jsonb) WHERE id=:id""",
                    {
                        "st": status,
                        "prog": prog,
                        "pp": json.dumps({
                            "phase": phase,
                            "completed": fin.get("completed", 0) if fin.get("queued_axiom_inventory") else max(chunk_n, 1),
                            "total": max(fin.get("total", 1) if fin.get("queued_axiom_inventory") else chunk_n, 1),
                            "label": label,
                        }),
                        "ec": json.dumps({
                            "interesting_total": max(chunk_n, 1),
                            "extracted": max(chunk_n, 1),
                            "pending": pending_left,
                        }),
                        "id": job_id,
                    },
                )
                db.commit()
                return {"status": "ok", "drain": drain, "chunks": chunk_n, "pending_left": pending_left}
        except Exception as exc:
            log.exception("Parse drain failed job=%s", job_id)
            with firm_session(schema_name) as db:
                from app.db.sql_helpers import execute
                from app.services.disk_build_log import write_disk_log
                import json

                try:
                    # Never convert a parser/database exception into a false 100% success.
                    # Preserve persisted progress and keep the job recoverable; the Celery
                    # task wrapper retries transient failures with bounded backoff.
                    execute(
                        db,
                        """UPDATE jobs SET status='indexing', error=:err, updated_at=NOW()
                           WHERE id=:id""",
                        {
                            "err": (f"Parse drain retrying after error: {exc}")[:2000],
                            "id": job_id,
                        },
                    )
                    write_disk_log(
                        db, job_id, f"Parse drain paused after error; automatic retry scheduled: {exc}",
                        stage="parse", level="error"
                    )
                    db.commit()
                except Exception:
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise


def parse_shard_sync(schema_name: str, job_id: str, shard_id: int) -> dict:
    """Parse artifacts for one extraction shard on the disk-build worker (parallel CPU)."""
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "parse_shard")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            from app.config import get_settings
            from app.db.sql_helpers import fetchone
            from app.services.artifact_parse import parse_job_artifacts_for_paths
            from app.services.disk_build_log import write_disk_log
            from app.services.disk_manifest import build_index_map
            from app.services.job_control import load_extraction_checkpoint
            from app.services.stream_phase3 import _shard_index_entries

            settings = get_settings()
            checkpoint = load_extraction_checkpoint(db, job_id) or {}
            entries = _shard_index_entries(checkpoint, shard_id)
            paths = [e["path"] for e in entries if e.get("path")]
            if not paths:
                row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
                manifest = row.get("disk_source") if row else {}
                if isinstance(manifest, str):
                    import json as _json

                    manifest = _json.loads(manifest)
                index_map = build_index_map(manifest or {})
                return {"status": "skipped", "reason": "no_paths", "shard_id": shard_id}

            row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
            manifest = row.get("disk_source") if row else {}
            if isinstance(manifest, str):
                import json as _json

                manifest = _json.loads(manifest)
            index_map = build_index_map(manifest or {}, extra_entries=entries)

            workers = max(int(getattr(settings, "parse_workers", 12) or 12), 1)
            write_disk_log(
                db,
                job_id,
                f"Parse shard {shard_id} started — {len(paths):,} paths ({workers} parallel workers)",
                stage="parse",
            )
            db.commit()

            # Drain the whole shard in rounds — a single batch_limit left 95%+ pending.
            batch_limit = int(getattr(settings, "parse_drain_batch_limit", 2500) or 2500)
            total_parsed = 0
            total_skipped = 0
            rounds = 0
            max_rounds = max(int(getattr(settings, "parse_drain_max_rounds", 40) or 40), 1)
            while rounds < max_rounds:
                pr = None
                last_exc = None
                for attempt in range(4):
                    try:
                        pr = parse_job_artifacts_for_paths(
                            db,
                            job_id,
                            paths=paths,
                            index_map=index_map,
                            update_status=False,
                            batch_limit=batch_limit,
                            forensic_only=bool(getattr(settings, "parse_drain_forensic_only", True)),
                        )
                        last_exc = None
                        break
                    except Exception as exc:
                        last_exc = exc
                        from app.db.sql_helpers import is_retryable_db_error, rollback_aborted_transaction

                        rollback_aborted_transaction(db)
                        if not is_retryable_db_error(exc) or attempt >= 3:
                            raise
                        time.sleep(0.4 * (attempt + 1))
                if last_exc is not None:
                    raise last_exc
                rounds += 1
                batch_parsed = int(pr.get("parsed", 0) or 0)
                batch_skipped = int(pr.get("skipped", 0) or 0)
                total_parsed += batch_parsed
                total_skipped += batch_skipped
                _write_parse_progress(
                    db,
                    job_id,
                    label=f"Parse shard {shard_id} — {total_parsed:,} parsed this shard",
                )
                db.commit()
                if batch_parsed + batch_skipped <= 0:
                    break

            from app.services.pipeline_orchestrator import merge_orchestration_into_progress

            merge_orchestration_into_progress(db, job_id)
            write_disk_log(
                db,
                job_id,
                f"Parse shard {shard_id} complete — {total_parsed:,} parsed, "
                f"{total_skipped:,} skipped ({rounds} rounds)",
                stage="parse",
                metadata={
                    "shard_id": shard_id,
                    "parsed": total_parsed,
                    "skipped": total_skipped,
                    "rounds": rounds,
                },
            )
            db.commit()
            return {
                "status": "ok",
                "shard_id": shard_id,
                "parsed": total_parsed,
                "skipped": total_skipped,
                "rounds": rounds,
            }
    except Exception as exc:
        log.exception("Parse shard failed job=%s shard=%s", job_id, shard_id)
        try:
            with firm_session(schema_name) as db:
                from app.services.disk_build_log import write_disk_log

                write_disk_log(
                    db,
                    job_id,
                    f"Parse shard {shard_id} failed: {exc}",
                    stage="parse",
                    level="error",
                )
                db.commit()
        except Exception:
            pass
        raise


def parse_bucket_sync(schema_name: str, job_id: str, bucket_id: int, num_buckets: int) -> dict:
    """Parse one path-hash bucket — runs in parallel with other buckets on disk-build workers."""
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "parse_bucket")
    if held:
        return held
    from app.services.parse_lock import parse_job_lock

    lock_id = f"{job_id}:bucket:{bucket_id}"
    with parse_job_lock(lock_id) as acquired:
        if not acquired:
            log.info("Parse bucket skipped — in flight job=%s bucket=%s", job_id, bucket_id)
            try:
                parse_bucket_task.apply_async(
                    args=(schema_name, job_id, bucket_id, num_buckets), countdown=20,
                )
            except Exception:
                pass
            return {"status": "skipped", "reason": "bucket_in_flight", "bucket_id": bucket_id, "requeued": True}
        try:
            with firm_session(schema_name) as db:
                from app.config import get_settings
                from app.services.artifact_parse import (
                    count_pending_in_bucket,
                    count_pending_parse,
                    drain_pending_parse,
                    prepare_forensic_parse_queue,
                )
                from app.services.disk_build_log import write_disk_log
                from app.services.disk_manifest import build_index_map
                from app.db.sql_helpers import fetchone
                import json

                settings = get_settings()
                row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
                manifest = row.get("disk_source") if row else {}
                if isinstance(manifest, str):
                    manifest = json.loads(manifest)
                index_map = build_index_map(manifest or {})

                pending_in_bucket = count_pending_in_bucket(
                    db, job_id, bucket_id=bucket_id, num_buckets=num_buckets,
                )
                if pending_in_bucket <= 0:
                    cleaned = prepare_forensic_parse_queue(db, job_id)
                    forensic_left = count_pending_parse(db, job_id)
                    if forensic_left <= 0:
                        parse_drain_task.apply_async(args=(schema_name, job_id), countdown=2)
                    return {
                        "status": "ok",
                        "bucket_id": bucket_id,
                        "parsed": 0,
                        "skipped": int(cleaned.get("skipped_low_value", 0))
                        + int(cleaned.get("skipped_media", 0)),
                        "rounds": 0,
                        "forensic_left": forensic_left,
                        "finalizing": forensic_left <= 0,
                    }

                write_disk_log(
                    db,
                    job_id,
                    f"Parse bucket {bucket_id + 1}/{num_buckets} — {pending_in_bucket:,} pending",
                    stage="parse",
                )
                _write_parse_progress(
                    db,
                    job_id,
                    label=f"Parse bucket {bucket_id + 1}/{num_buckets} — {pending_in_bucket:,} pending",
                )
                db.commit()

                drain = drain_pending_parse(
                    db,
                    job_id,
                    index_map=index_map,
                    requeue_no_parser=settings.parse_drain_requeue_no_parser,
                    update_job_status=False,
                    schema_name=schema_name,
                    parse_bucket=bucket_id,
                    parse_buckets=num_buckets,
                    max_rounds=int(getattr(settings, "parse_drain_max_rounds", 25) or 25),
                )
                pending_left = count_pending_in_bucket(
                    db, job_id, bucket_id=bucket_id, num_buckets=num_buckets,
                )
                if pending_left > 0:
                    parse_bucket_task.apply_async(
                        args=(schema_name, job_id, bucket_id, num_buckets), countdown=2,
                    )
                elif count_pending_parse(db, job_id) > 0:
                    parse_drain_task.apply_async(args=(schema_name, job_id), countdown=5)
                else:
                    prepare_forensic_parse_queue(db, job_id)
                    parse_drain_task.apply_async(args=(schema_name, job_id), countdown=2)

                return {
                    "status": "ok",
                    "bucket_id": bucket_id,
                    "pending_left": pending_left,
                    **drain,
                }
        except Exception as exc:
            log.exception("Parse bucket failed job=%s bucket=%s", job_id, bucket_id)
            raise


@celery.task(name="app.tasks.parse_bucket_task")
def parse_bucket_task(schema_name: str, job_id: str, bucket_id: int, num_buckets: int) -> dict:
    log.info("Parse bucket job=%s bucket=%s/%s schema=%s", job_id, bucket_id, num_buckets, schema_name)
    return parse_bucket_sync(schema_name, job_id, bucket_id, num_buckets)


@celery.task(
    bind=True,
    name="app.tasks.parse_shard_task",
    max_retries=6,
    default_retry_delay=20,
)
def parse_shard_task(self, schema_name: str, job_id: str, shard_id: int) -> dict:
    log.info("Parse shard job=%s shard=%s schema=%s attempt=%s", job_id, shard_id, self.request.retries + 1)
    try:
        return parse_shard_sync(schema_name, job_id, shard_id)
    except Exception as exc:
        from app.db.sql_helpers import is_retryable_db_error

        if is_retryable_db_error(exc):
            raise self.retry(exc=exc)
        raise


@celery.task(
    bind=True,
    name="app.tasks.parse_drain_task",
    max_retries=8,
    default_retry_delay=30,
)
def parse_drain_task(self, schema_name: str, job_id: str) -> dict:
    log.info("Parse drain job=%s schema=%s attempt=%s", job_id, schema_name, self.request.retries + 1)
    try:
        return parse_drain_sync(schema_name, job_id)
    except Exception as exc:
        # DB disconnects/lock pressure/resource stalls should not strand a job at
        # an arbitrary percentage. Retry up to eight times with bounded backoff.
        countdown = min(8 * (2 ** int(self.request.retries or 0)), 30)
        log.warning(
            "Parse drain retry job=%s schema=%s in %ss after %s",
            job_id, schema_name, countdown, type(exc).__name__,
        )
        raise self.retry(exc=exc, countdown=countdown)


@celery.task(name="app.tasks.parse_drain_mobile_task")
def parse_drain_mobile_task(schema_name: str, job_id: str) -> dict:
    """Mobile-only parse drain — runs on mobile-build queue."""
    log.info("Mobile parse drain job=%s schema=%s", job_id, schema_name)
    return parse_drain_sync(schema_name, job_id)


@celery.task(name="app.tasks.rag_append_task")
def rag_append_task(schema_name: str, job_id: str) -> dict:
    """Incremental GPU embed for newly parsed artifacts (skip already-indexed)."""
    log.info("RAG append job=%s schema=%s", job_id, schema_name)
    result = rag_append_sync(schema_name, job_id)
    try:
        from app.config import get_settings
        from app.db.session import firm_session
        from app.services.ocr_gpu import count_pending_ocr
        from app.services.rag_image_evidence import is_image_evidence_job

        settings = get_settings()
        with firm_session(schema_name) as db:
            want = bool(getattr(settings, "rag_image_embed_enabled", False)) or is_image_evidence_job(db, job_id)
            ocr_left = int(count_pending_ocr(db, job_id) or 0)
        # CLIP only after OCR queue is clear (strict GPU XOR).
        if want and ocr_left <= 0 and result.get("status") not in ("deferred_for_ocr",):
            image_embed_task.delay(schema_name, job_id)
    except Exception as exc:
        log.warning("image_embed enqueue skipped: %s", exc)
    return result


@celery.task(name="app.tasks.image_embed_task")
def image_embed_task(schema_name: str, job_id: str) -> dict:
    """Optional CLIP embeddings for rag_image_assets (post embed_agent hook)."""
    held = _client_intake_hold(schema_name, job_id, "image_embed")
    if held:
        return held
    from pathlib import Path

    from app.db.session import firm_session
    from app.db.sql_helpers import execute, fetchall, fetchone
    from app.services.gpu_thermal import (
        GpuThermalAbort,
        gpu_heavy_session,
        thermal_guard_after_batch,
        thermal_guard_before_batch,
    )
    from app.services.image_embed import embed_images, model_fingerprint
    from app.config import get_settings
    from app.services.ocr_gpu import count_pending_ocr

    settings = get_settings()
    model_name, model_ver = model_fingerprint()
    dim = int(getattr(settings, "rag_image_embed_dim", 512) or 512)

    with firm_session(schema_name) as db:
        # Strict XOR — wait for OCR to finish before CLIP.
        if int(count_pending_ocr(db, job_id) or 0) > 0:
            return {"status": "deferred_for_ocr", "embedded": 0}

        rows = fetchall(
            db,
            """SELECT a.id, a.source_object_uri, a.job_artifact_id, a.sha256, ja.metadata
               FROM rag_image_assets a
               LEFT JOIN job_artifacts ja ON ja.id = a.job_artifact_id
               WHERE a.job_id = CAST(:jid AS uuid)
                 AND NOT EXISTS (
                   SELECT 1 FROM rag_image_embeddings e
                   WHERE e.image_id = a.id AND e.modality = 'image'
                     AND e.model_name = :m AND e.model_version = :v
                 )
               ORDER BY a.created_at
               LIMIT 64""",
            {"jid": job_id, "m": model_name, "v": model_ver},
        )
        if not rows:
            return {"status": "ok", "embedded": 0}

        try:
            from PIL import Image
        except ImportError:
            return {"status": "skipped", "reason": "pillow_missing"}

        embedded = 0
        reused = 0
        try:
            with gpu_heavy_session("image_embed", unload_ollama=True):
                batch_imgs = []
                batch_ids = []
                for row in rows:
                    # Reuse CLIP vector by sha256 + model (multi-folder duplicates).
                    sha = (row.get("sha256") or "").strip()
                    if sha:
                        prior = fetchone(
                            db,
                            """SELECT e.embedding::text AS emb
                               FROM rag_image_embeddings e
                               JOIN rag_image_assets a ON a.id = e.image_id
                               WHERE a.sha256 = :sha
                                 AND e.modality = 'image'
                                 AND e.model_name = :m AND e.model_version = :v
                                 AND e.image_id <> CAST(:iid AS uuid)
                               LIMIT 1""",
                            {"sha": sha, "m": model_name, "v": model_ver, "iid": str(row["id"])},
                        )
                        if prior and prior.get("emb"):
                            execute(
                                db,
                                """INSERT INTO rag_image_embeddings (
                                     image_id, modality, model_name, model_version, dimensions, embedding
                                   ) VALUES (
                                     CAST(:iid AS uuid), 'image', :m, :v, :dim, CAST(:emb AS vector)
                                   )
                                   ON CONFLICT (image_id, modality, model_name, model_version) DO NOTHING""",
                                {
                                    "iid": str(row["id"]),
                                    "m": model_name,
                                    "v": model_ver,
                                    "dim": dim,
                                    "emb": prior["emb"],
                                },
                            )
                            reused += 1
                            embedded += 1
                            continue

                    src = row.get("source_object_uri")
                    meta = row.get("metadata") or {}
                    if isinstance(meta, str):
                        import json as _json

                        try:
                            meta = _json.loads(meta)
                        except Exception:
                            meta = {}
                    if not src:
                        src = (meta or {}).get("source_object_uri") or (meta or {}).get(
                            "source_absolute_path"
                        )
                    try:
                        from io import BytesIO

                        from app.services.storage import get_bytes

                        img = None
                        raw = str(src or "").strip()
                        if raw.startswith(("s3://", "file://")):
                            data = get_bytes(raw)
                            if data:
                                img = Image.open(BytesIO(data)).convert("RGB")
                        elif raw and Path(raw).is_file():
                            img = Image.open(raw).convert("RGB")
                        if img is None:
                            local = (meta or {}).get("source_absolute_path")
                            if local and Path(str(local)).is_file():
                                img = Image.open(str(local)).convert("RGB")
                        if img is None:
                            continue
                    except Exception:
                        continue
                    batch_imgs.append(img)
                    batch_ids.append(str(row["id"]))
                if batch_imgs:
                    thermal_guard_before_batch(reason="image_embed")
                    vectors = embed_images(batch_imgs, dim=dim)
                    thermal_guard_after_batch(reason="image_embed")
                    for image_id, vec in zip(batch_ids, vectors):
                        vec_str = "[" + ",".join(f"{v:.8f}" for v in vec) + "]"
                        execute(
                            db,
                            """INSERT INTO rag_image_embeddings (
                                 image_id, modality, model_name, model_version, dimensions, embedding
                               ) VALUES (
                                 CAST(:iid AS uuid), 'image', :m, :v, :dim, CAST(:emb AS vector)
                               )
                               ON CONFLICT (image_id, modality, model_name, model_version) DO NOTHING""",
                            {
                                "iid": image_id,
                                "m": model_name,
                                "v": model_ver,
                                "dim": dim,
                                "emb": vec_str,
                            },
                        )
                        embedded += 1
                if embedded:
                    execute(
                        db,
                        """UPDATE rag_image_assets SET stage_status='embedded', updated_at=NOW()
                           WHERE job_id = CAST(:jid AS uuid)
                             AND EXISTS (
                               SELECT 1 FROM rag_image_embeddings e WHERE e.image_id = rag_image_assets.id
                             )""",
                        {"jid": job_id},
                    )
                db.commit()
        except GpuThermalAbort as exc:
            db.rollback()
            return {"status": "paused", "reason": str(exc), "embedded": embedded, "reused": reused}

    return {"status": "ok", "embedded": embedded, "reused": reused, "model": model_name}


def should_requeue_ocr_drain(
    *,
    pending_left: int,
    gpu_deferred: bool = False,
    is_cpu_bucket: bool = False,
) -> bool:
    """CPU buckets leave scans pending for the GPU drain instead of looping."""
    if int(pending_left or 0) <= 0:
        return False
    if is_cpu_bucket and gpu_deferred:
        return False
    return True


def _requeue_ocr(
    schema_name: str,
    job_id: str,
    *,
    countdown: int,
    bucket_id: int | None = None,
    num_buckets: int | None = None,
) -> None:
    if bucket_id is None:
        ocr_drain_task.apply_async(args=(schema_name, job_id), countdown=countdown)
        return
    ocr_bucket_task.apply_async(
        args=(schema_name, job_id, bucket_id, num_buckets or 1), countdown=countdown
    )


def ocr_drain_sync(
    schema_name: str,
    job_id: str,
    bucket_id: int | None = None,
    num_buckets: int | None = None,
) -> dict:
    """OCR drain — CUDA GLM on worker-ocr-gpu only. CPU buckets are not used."""
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "ocr")
    if held:
        return held
    from app.config import get_settings
    from app.services.job_locks import DEFAULT_OCR_LOCK_TTL_SEC, ocr_job_lock, reclaim_stale_ocr_lock
    from app.services.ocr_gpu import ocr_is_gpu_only

    settings = get_settings()
    if not settings.ocr_enabled:
        return {"status": "skipped", "reason": "ocr_disabled"}

    if ocr_is_gpu_only() and bucket_id is not None:
        log.info("OCR GPU-only — ignoring CPU bucket %s/%s job=%s", bucket_id, num_buckets, job_id)
        bucket_id = None
        num_buckets = None

    if bucket_id is None:
        lock_id = job_id
        with ocr_job_lock(lock_id, ttl_sec=DEFAULT_OCR_LOCK_TTL_SEC) as acquired:
            if not acquired:
                if reclaim_stale_ocr_lock(job_id):
                    with ocr_job_lock(lock_id, ttl_sec=DEFAULT_OCR_LOCK_TTL_SEC) as retry:
                        if retry:
                            return _ocr_drain_locked(
                                schema_name, job_id, settings, lock_id=lock_id
                            )
                log.info("OCR drain skipped — another drain in flight job=%s", job_id)
                return {"status": "skipped", "reason": "ocr_in_flight"}
            return _ocr_drain_locked(schema_name, job_id, settings, lock_id=lock_id)

    lock_id = f"{job_id}:bucket:{bucket_id}" if bucket_id is not None else job_id
    with ocr_job_lock(lock_id, ttl_sec=DEFAULT_OCR_LOCK_TTL_SEC) as acquired:
        if not acquired:
            if reclaim_stale_ocr_lock(job_id, bucket_id=bucket_id):
                with ocr_job_lock(lock_id, ttl_sec=DEFAULT_OCR_LOCK_TTL_SEC) as retry:
                    if retry:
                        return _ocr_drain_locked(
                            schema_name,
                            job_id,
                            settings,
                            lock_id=lock_id,
                            ocr_bucket=bucket_id,
                            ocr_buckets=num_buckets,
                        )
            log.info(
                "OCR drain skipped — another drain in flight job=%s bucket=%s",
                job_id,
                bucket_id,
            )
            return {"status": "skipped", "reason": "ocr_in_flight", "bucket_id": bucket_id}
        return _ocr_drain_locked(
            schema_name,
            job_id,
            settings,
            lock_id=lock_id,
            ocr_bucket=bucket_id,
            ocr_buckets=num_buckets,
        )


def _ocr_drain_locked(
    schema_name: str,
    job_id: str,
    settings,
    *,
    lock_id: str | None = None,
    ocr_bucket: int | None = None,
    ocr_buckets: int | None = None,
) -> dict:
    from app.services.disk_build_log import write_disk_log
    from app.services.disk_manifest import build_index_map
    from app.services.job_locks import DEFAULT_OCR_LOCK_TTL_SEC, refresh_job_lock
    from app.services.ocr_gpu import (
        count_pending_ocr,
        ocr_should_use_gpu,
        reopen_failed_ocr_without_results,
        reopen_skipped_forensic_ocr,
        run_ocr_for_job,
        skip_ocr_noise_pending,
        write_ocr_live_progress,
    )
    from app.services.tar_cache import iter_files_from_part, read_file_from_part
    from app.db.sql_helpers import execute, fetchone
    import json

    with firm_session(schema_name) as db:
        from app.services.job_control import is_stop_requested
        from app.services.mobile_platform_agents import current_service_owns_job

        if is_stop_requested(db, job_id):
            return {"status": "stopped", "reason": "stop_requested", "ocr_count": 0, "pending_left": 0}
        if not current_service_owns_job(db, job_id):
            log.info("OCR drain skipped — another product owns job=%s", job_id)
            return {"status": "skipped", "reason": "other_product", "ocr_count": 0, "pending_left": 0}
        # Image-evidence jobs stay parse-then-OCR. Forensic disks OCR in parallel
        # as soon as eligible PDFs/images are materialized.
        try:
            from app.services.rag_image_evidence import is_image_evidence_job

            image_ev = is_image_evidence_job(db, job_id)
        except Exception:
            image_ev = False
        if image_ev:
            parse_pending = fetchone(
                db,
                "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
                {"jid": job_id},
            )
            parse_pending_n = int((parse_pending or {}).get("c") or 0)
            if parse_pending_n > 0:
                write_disk_log(
                    db,
                    job_id,
                    f"OCR deferred — {parse_pending_n:,} parse artifacts still pending",
                    stage="ocr",
                )
                db.commit()
                from app.tasks import parse_drain_task

                parse_drain_task.apply_async(args=(schema_name, job_id), countdown=2)
                return {
                    "status": "deferred_for_parse",
                    "parse_pending": parse_pending_n,
                }

        skipped = skip_ocr_noise_pending(db, job_id)
        if skipped:
            write_disk_log(
                db,
                job_id,
                f"OCR — skipped {skipped:,} cache/photo/OS-vendor file(s); GLM only for scans",
                stage="ocr",
            )
            db.commit()

        queued = reopen_skipped_forensic_ocr(db, job_id)
        if queued:
            write_disk_log(
                db,
                job_id,
                f"OCR — queued {queued:,} never-attempted document(s)",
                stage="ocr",
            )
            db.commit()

        if ocr_should_use_gpu():
            row_pp = fetchone(
                db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id}
            )
            raw_pp = (row_pp or {}).get("pipeline_progress")
            if isinstance(raw_pp, str):
                try:
                    pp = json.loads(raw_pp)
                except Exception:
                    pp = {}
            elif isinstance(raw_pp, dict):
                pp = dict(raw_pp)
            else:
                pp = {}
            if not pp.get("ocr_gpu_healed_failed"):
                from app.services.pipeline_progress import write_merged_pipeline_progress

                healed = reopen_failed_ocr_without_results(db, job_id)
                write_merged_pipeline_progress(
                    db,
                    job_id,
                    {"ocr_gpu_healed_failed": True},
                    writer="ocr",
                )
                if healed:
                    write_disk_log(
                        db,
                        job_id,
                        f"OCR agent — GPU free, re-queued {healed:,} file(s) that CPU drain skipped",
                        stage="ocr",
                    )
                db.commit()

        pending = count_pending_ocr(db, job_id)
        write_ocr_live_progress(
            db,
            job_id,
            label=(
                f"OCR starting — {pending:,} pending"
                if pending > 0
                else "OCR — no documents need GLM"
            ),
        )
        db.commit()
        if pending <= 0:
            return {"status": "ok", "ocr_count": 0, "pending_left": 0, "skipped_noise": skipped}

        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
        manifest = row.get("disk_source") if row else {}
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        index_map = build_index_map(manifest or {})

        # One streaming pass per shard for the whole batch. Reading each file
        # alone restarts a multi-GB tar from the beginning and the OCR card
        # sits still for the entire scan.
        part_bytes: dict[str, bytes | None] = {}

        def preload_part_bytes(paths: list[str]) -> None:
            groups: dict[str, set[str]] = {}
            for raw in paths:
                norm = str(raw or "").replace("\\", "/")
                if not norm or norm in part_bytes:
                    continue
                uri = index_map.get(norm) or index_map.get(raw)
                if not uri:
                    continue
                groups.setdefault(str(uri), set()).add(norm)
            if groups:
                nfiles = sum(len(v) for v in groups.values())
                write_disk_log(
                    db,
                    job_id,
                    f"OCR reading {nfiles} file(s) from the extract in one pass",
                    stage="ocr",
                )
                db.commit()
            for uri, wanted in groups.items():
                for norm, content in iter_files_from_part(uri, wanted):
                    part_bytes[norm] = content

        def read_fn(path: str) -> bytes | None:
            norm = path.replace("\\", "/")
            if norm in part_bytes:
                data = part_bytes[norm]
                if data is not None:
                    return data
            part_uri = index_map.get(norm) or index_map.get(path)
            if part_uri:
                data = read_file_from_part(part_uri, path)
                if data is not None:
                    return data
            # Image-evidence: host path or client-uploaded object
            try:
                from pathlib import Path

                from app.db.sql_helpers import fetchone
                from app.services.storage import get_bytes

                row = fetchone(
                    db,
                    """SELECT
                         metadata->>'source_absolute_path' AS src,
                         metadata->>'source_object_uri' AS uri
                       FROM job_artifacts WHERE job_id=:jid AND file_path=:path LIMIT 1""",
                    {"jid": job_id, "path": path},
                )
                src = (row or {}).get("src") if row else None
                uri = (row or {}).get("uri") if row else None
                if src and Path(src).is_file():
                    return Path(src).read_bytes()
                if uri:
                    data = get_bytes(str(uri))
                    if data:
                        return data
            except Exception:
                pass
            return None

        read_fn.preload = preload_part_bytes  # type: ignore[attr-defined]

        total_done = 0
        last_deferred = False
        is_cpu_bucket = ocr_bucket is not None
        max_rounds = max(int(getattr(settings, "ocr_drain_max_rounds", 25) or 25), 1)
        for round_i in range(max_rounds):
            if is_stop_requested(db, job_id):
                write_disk_log(
                    db,
                    job_id,
                    "OCR stopped — pipeline halt kept the last checkpoint",
                    stage="ocr",
                )
                db.commit()
                return {"status": "stopped", "reason": "stop_requested", "ocr_count": total_done, "pending_left": 0}
            try:
                result = run_ocr_for_job(
                    db,
                    job_id,
                    schema_name=schema_name,
                    read_file_fn=read_fn,
                    ocr_bucket=ocr_bucket,
                    ocr_buckets=ocr_buckets,
                )
            except Exception as exc:
                from app.services.gpu_thermal import GpuThermalAbort
                from app.services.job_locks import GpuHeavySlotTimeout

                if isinstance(exc, (GpuThermalAbort, GpuHeavySlotTimeout)):
                    pending_left = count_pending_ocr(db, job_id)
                    label = (
                        "OCR waiting for worker slot"
                        if isinstance(exc, GpuHeavySlotTimeout)
                        else f"OCR paused — {pending_left:,} pending"
                    )
                    write_ocr_live_progress(db, job_id, label=label)
                    write_disk_log(
                        db,
                        job_id,
                        f"OCR paused — {exc}; will resume",
                        stage="ocr",
                        level="warning",
                    )
                    db.commit()
                    _requeue_ocr(
                        schema_name,
                        job_id,
                        countdown=20,
                        bucket_id=ocr_bucket,
                        num_buckets=ocr_buckets,
                    )
                    return {
                        "status": "thermal_pause",
                        "ocr_count": total_done,
                        "pending_left": pending_left,
                        "requeued": True,
                    }
                raise
            batch = int(result.get("ocr_count") or 0)
            total_done += batch
            pending_left = int(
                result.get("pending_left")
                or count_pending_ocr(
                    db, job_id, ocr_bucket=ocr_bucket, ocr_buckets=ocr_buckets
                )
            )
            refresh_job_lock("ocr", lock_id or job_id, ttl_sec=DEFAULT_OCR_LOCK_TTL_SEC)
            write_ocr_live_progress(db, job_id)
            db.commit()
            if result.get("status") == "retry":
                _requeue_ocr(
                    schema_name, job_id, countdown=15, bucket_id=ocr_bucket, num_buckets=ocr_buckets
                )
                return {"status": "retry", "ocr_count": total_done, "pending_left": pending_left, "requeued": True}
            last_deferred = bool(result.get("gpu_deferred"))
            if pending_left <= 0:
                break
            if batch == 0 and last_deferred:
                if should_requeue_ocr_drain(
                    pending_left=pending_left,
                    gpu_deferred=True,
                    is_cpu_bucket=is_cpu_bucket,
                ):
                    _requeue_ocr(
                        schema_name, job_id, countdown=8, bucket_id=ocr_bucket, num_buckets=ocr_buckets
                    )
                    return {
                        "status": "retry",
                        "ocr_count": total_done,
                        "pending_left": pending_left,
                        "requeued": True,
                        "reason": "gpu_deferred",
                    }
                write_disk_log(
                    db,
                    job_id,
                    f"CPU OCR bucket done — {pending_left:,} scan(s) left for GLM",
                    stage="ocr",
                )
                db.commit()
                return {
                    "status": "ok",
                    "ocr_count": total_done,
                    "pending_left": pending_left,
                    "requeued": False,
                    "reason": "gpu_deferred",
                }

        pending_left = count_pending_ocr(
            db, job_id, ocr_bucket=ocr_bucket, ocr_buckets=ocr_buckets
        )
        if should_requeue_ocr_drain(
            pending_left=pending_left,
            gpu_deferred=last_deferred,
            is_cpu_bucket=is_cpu_bucket,
        ):
            delay = 20 if total_done <= 0 else 5
            _requeue_ocr(
                schema_name, job_id, countdown=delay, bucket_id=ocr_bucket, num_buckets=ocr_buckets
            )
            write_disk_log(
                db,
                job_id,
                f"OCR drain requeued — {total_done:,} this run, {pending_left:,} still pending",
                stage="ocr",
            )
            db.commit()
            return {
                "status": "ok",
                "ocr_count": total_done,
                "pending_left": pending_left,
                "requeued": True,
            }
        if pending_left > 0 and is_cpu_bucket:
            write_disk_log(
                db,
                job_id,
                f"CPU OCR bucket parked — {pending_left:,} scan(s) waiting for GLM",
                stage="ocr",
            )
            db.commit()
            return {
                "status": "ok",
                "ocr_count": total_done,
                "pending_left": pending_left,
                "requeued": False,
                "reason": "gpu_deferred",
            }

        # OCR produced text → feed GPU embedder
        try:
            from app.services.dual_rag_index import _count_indexable_without_chunks
            from app.services.rag_image_evidence import is_image_evidence_job, mark_image_evidence_searchable

            if is_image_evidence_job(db, job_id):
                mark_image_evidence_searchable(
                    db,
                    job_id,
                    label="Searchable — OCR text ready; embedding continuing safely",
                )
                db.commit()

            if _count_indexable_without_chunks(db, job_id) > 0:
                rag_append_task.delay(schema_name, job_id)
            elif is_image_evidence_job(db, job_id):
                image_embed_task.delay(schema_name, job_id)
        except Exception as exc:
            log.warning("Queue RAG after OCR failed: %s", exc)

        write_disk_log(
            db,
            job_id,
            f"OCR drain complete — {total_done:,} document(s)",
            stage="ocr",
        )
        db.commit()
        return {"status": "ok", "ocr_count": total_done, "pending_left": 0}


@celery.task(
    bind=True,
    name="app.tasks.ocr_drain_task",
    max_retries=8,
    default_retry_delay=30,
)
def ocr_drain_task(self, schema_name: str, job_id: str) -> dict:
    """OCR drain on the dedicated `ocr` queue (GPU GLM when free)."""
    log.info("OCR drain job=%s schema=%s", job_id, schema_name)
    try:
        return ocr_drain_sync(schema_name, job_id)
    except Exception as exc:
        _retry_transient_db(self, exc)
        raise


@celery.task(
    bind=True,
    name="app.tasks.ocr_bucket_task",
    max_retries=8,
    default_retry_delay=30,
)
def ocr_bucket_task(self, schema_name: str, job_id: str, bucket_id: int, num_buckets: int) -> dict:
    """Legacy CPU shard. GPU-only OCR redirects to the CUDA drain."""
    from app.services.ocr_gpu import ocr_is_gpu_only

    if ocr_is_gpu_only():
        log.info("OCR GPU-only — redirecting bucket %s/%s to CUDA drain job=%s", bucket_id, num_buckets, job_id)
        try:
            return ocr_drain_sync(schema_name, job_id)
        except Exception as exc:
            _retry_transient_db(self, exc)
            raise
    log.info("OCR bucket job=%s bucket=%s/%s schema=%s", job_id, bucket_id, num_buckets, schema_name)
    try:
        return ocr_drain_sync(schema_name, job_id, bucket_id=bucket_id, num_buckets=num_buckets)
    except Exception as exc:
        _retry_transient_db(self, exc)
        raise


def rag_append_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "rag_append")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            import json

            from app.services.disk_build_log import write_disk_log
            from app.services.disk_manifest import build_index_map
            from app.services.dual_rag_index import (
                append_job_evidence_rag,
                _count_indexable_artifacts,
                _count_indexable_without_chunks,
            )
            from app.db.sql_helpers import execute, fetchone

            from app.config import get_settings as _get_settings

            embed_on = bool(getattr(_get_settings(), "rag_embedding_enabled", False))
            before = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid", {"jid": job_id})
            before_n = int(before["c"]) if before else 0
            remaining = _count_indexable_without_chunks(db, job_id)
            if remaining <= 0:
                return {"status": "skipped", "reason": "nothing_to_index", "added": 0, "chunks": before_n}

            from app.config import get_settings
            from app.services.dual_rag_index import BASELINE_RAG_CHUNK_TARGET, force_finish_rag_enrichment
            from app.services.ocr_gpu import count_pending_ocr

            settings = get_settings()

            # v1.5 stage-aware scheduler: RAG must not overlap pending parse work
            # in responsive mode.  The old v1.4 supervisor gated recommendations,
            # but parse tasks also self-requeue, so parse and RAG could still run
            # together (exactly what the UI showed).
            pending_parse_row = fetchone(
                db,
                "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
                {"jid": job_id},
            )
            pending_parse_n = int((pending_parse_row or {}).get("c") or 0)
            if _responsive_sequential_mode() and pending_parse_n > 0:
                write_disk_log(
                    db,
                    job_id,
                    f"RAG deferred — {pending_parse_n:,} parse artifacts still pending; finishing parse first",
                    stage="rag_index",
                )
                db.commit()
                from app.tasks import parse_drain_task

                parse_drain_task.apply_async(args=(schema_name, job_id), countdown=2)
                return {
                    "status": "deferred_for_parse",
                    "added": 0,
                    "chunks": before_n,
                    "parse_pending": pending_parse_n,
                }
            # Throughput: parse and RAG chunking overlap. Embeddings still yield to OCR.

            # Strict GPU XOR: never run text embed while OCR still holds the laptop GPU.
            # Forensic jobs keep post-baseline defer; image-evidence defers from the first OCR pending.
            from app.services.rag_image_evidence import is_image_evidence_job

            image_ev = False
            try:
                image_ev = is_image_evidence_job(db, job_id)
            except Exception:
                image_ev = False
            ocr_left = int(count_pending_ocr(db, job_id) or 0)
            defer_for_ocr = (
                embed_on
                and bool(getattr(settings, "defer_background_rag_while_ocr", True))
                and ocr_left > 0
                and (
                    _responsive_sequential_mode()
                    or image_ev
                    or before_n >= BASELINE_RAG_CHUNK_TARGET
                )
            )
            if defer_for_ocr:
                write_disk_log(
                    db,
                    job_id,
                    f"Background RAG skipped — {ocr_left:,} OCR docs pending "
                    f"(GPU XOR; {before_n:,} chunks already searchable)"
                    if before_n > 0
                    else f"Background RAG deferred — {ocr_left:,} OCR docs pending (GPU XOR)",
                    stage="rag_index",
                    level="warning",
                )
                db.commit()
                from app.tasks import ocr_drain_task

                ocr_drain_task.apply_async(args=(schema_name, job_id), countdown=2)
                return {
                    "status": "deferred_for_ocr",
                    "added": 0,
                    "chunks": before_n,
                    "ocr_pending": ocr_left,
                }
            target = BASELINE_RAG_CHUNK_TARGET
            try:
                from app.services.dual_rag_index import baseline_chunk_target_for_job

                target = baseline_chunk_target_for_job(db, job_id)
            except Exception:
                target = BASELINE_RAG_CHUNK_TARGET
            if embed_on and before_n >= target and not settings.rag_background_after_baseline and not image_ev:
                force_finish_rag_enrichment(
                    db,
                    job_id,
                    schema_name=schema_name,
                    chunk_count=before_n,
                    reason="Baseline RAG complete — background corpus embed disabled",
                )
                db.commit()
                return {
                    "status": "skipped",
                    "reason": "baseline_only",
                    "added": 0,
                    "chunks": before_n,
                }

            indexable_total = int(_count_indexable_artifacts(db, job_id) or 0)
            # Progress must compare like-for-like units.  Previous builds used
            # chunk count as completed and artifact count as total, so the UI could
            # fall from 59% to 29% even while work advanced.
            indexed_artifacts = max(indexable_total - int(remaining or 0), 0)
            execute(
                db,
                """UPDATE jobs SET status='indexing', error=NULL,
                   pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
                {
                    "pp": json.dumps({
                        "phase": "rag",
                        "completed": indexed_artifacts,
                        "total": max(indexable_total, 1),
                        "label": (
                            f"RAG indexing — {indexed_artifacts:,} / {indexable_total:,} artifacts; "
                            f"{before_n:,} chunks searchable"
                        ),
                    }),
                    "id": job_id,
                },
            )
            write_disk_log(
                db,
                job_id,
                f"Resuming GPU RAG — {before_n:,} chunks embedded, {remaining:,} artifacts pending",
                stage="rag_index",
            )
            db.commit()

            row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
            manifest = row.get("disk_source") if row else {}
            if isinstance(manifest, str):
                manifest = json.loads(manifest)
            index_map = build_index_map(manifest or {})
            try:
                added = append_job_evidence_rag(
                    db, job_id, file_paths=None, index_map=index_map, schema_name=schema_name,
                )
            except Exception as exc:
                from app.services.gpu_thermal import GpuThermalAbort
                from app.services.job_locks import GpuHeavySlotTimeout

                if isinstance(exc, (GpuThermalAbort, GpuHeavySlotTimeout)):
                    write_disk_log(
                        db,
                        job_id,
                        f"RAG deferred — {exc}; will resume when GPU slot/temps allow",
                        stage="rag_index",
                        level="warning",
                    )
                    db.commit()
                    # Prefer OCR after baseline; do not keep re-queueing background RAG.
                    ocr_left = 0
                    try:
                        ocr_left = int(count_pending_ocr(db, job_id) or 0)
                    except Exception:
                        pass
                    if before_n >= BASELINE_RAG_CHUNK_TARGET and ocr_left > 0:
                        from app.tasks import ocr_drain_task

                        ocr_drain_task.apply_async(args=(schema_name, job_id), countdown=30)
                    else:
                        from app.tasks import rag_append_task

                        rag_append_task.apply_async(args=(schema_name, job_id), countdown=120)
                    return {
                        "status": "thermal_pause",
                        "added": 0,
                        "chunks": before_n,
                        "requeued": True,
                    }
                raise
            db.commit()
            after = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid", {"jid": job_id})
            after_n = int(after["c"]) if after else before_n + added
            remaining_after = int(_count_indexable_without_chunks(db, job_id) or 0)
            indexed_after = max(indexable_total - remaining_after, 0)
            execute(
                db,
                """UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW(),
                   pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id""",
                {
                    "id": job_id,
                    "pp": json.dumps({
                        "phase": "rag",
                        "completed": indexed_after,
                        "total": max(indexable_total, 1),
                        "label": (
                            f"RAG indexing — {indexed_after:,} / {indexable_total:,} artifacts; "
                            f"{after_n:,} chunks searchable"
                        ),
                    }),
                },
            )
            db.commit()
            if after_n > before_n:
                write_disk_log(
                    db,
                    job_id,
                    f"Incremental RAG — +{after_n - before_n:,} chunks ({after_n:,} total); "
                    f"{remaining_after:,} artifacts still to embed",
                    stage="rag_index",
                )
                db.commit()
            elif remaining_after > 0 and before_n >= 500:
                # One no-progress pass is not "done" — only clear true stragglers when the
                # leftover set is tiny. Never abandon thousands of pending embeds.
                if remaining_after <= 50:
                    from app.services.dual_rag_index import force_finish_rag_enrichment

                    force_finish_rag_enrichment(
                        db,
                        job_id,
                        schema_name=schema_name,
                        chunk_count=after_n,
                        reason="RAG stragglers cleared after no-progress pass",
                    )
                    db.commit()
                    remaining_after = _count_indexable_without_chunks(db, job_id)
                else:
                    write_disk_log(
                        db,
                        job_id,
                        f"RAG append made no progress this pass — "
                        f"{remaining_after:,} artifacts still pending embed (will retry)",
                        stage="rag_index",
                        level="warning",
                    )
                    db.commit()
            from app.services.dual_rag_index import _maybe_finalize_artifact_inventory

            _maybe_finalize_artifact_inventory(db, job_id, schema_name=schema_name)
            db.commit()
            # Keep embedding until the corpus is finished (chunking alone is not enough).
            if remaining_after > 0 and settings.rag_background_after_baseline:
                ocr_left = 0
                try:
                    ocr_left = int(count_pending_ocr(db, job_id) or 0)
                except Exception:
                    pass
                if ocr_left > 0 and bool(getattr(settings, "defer_background_rag_while_ocr", True)):
                    from app.tasks import ocr_drain_task

                    ocr_drain_task.apply_async(args=(schema_name, job_id), countdown=2)
                else:
                    from app.tasks import rag_append_task

                    rag_append_task.apply_async(args=(schema_name, job_id), countdown=5)
                return {
                    "status": "ok",
                    "added": max(0, after_n - before_n),
                    "chunks": after_n,
                    "remaining": remaining_after,
                    "requeued": True,
                }
            return {
                "status": "ok",
                "added": max(0, after_n - before_n),
                "chunks": after_n,
                "remaining": remaining_after,
            }
    except Exception as exc:
        log.exception("RAG append failed job=%s", job_id)
        raise


@celery.task(name="app.tasks.rag_enrich_task")
def rag_enrich_task(schema_name: str, job_id: str) -> dict:
    log.info("RAG enrich job=%s schema=%s", job_id, schema_name)
    return rag_enrich_sync(schema_name, job_id)


def rag_enrich_sync(schema_name: str, job_id: str) -> dict:
    """Entity / annotation / ontology enrichment pass after parse (or RAG baseline)."""
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "rag_enrich")
    if held:
        return held
    ready, info = _cpu_followup_ready(schema_name, job_id)
    if not ready:
        chunks = int(info.get("chunks") or 0)
        parse_n = int(info.get("parse_rows") or 0)
        if chunks <= 0 and parse_n <= 0:
            from app.services.rag_enrich import mark_empty_corpus_enrichment_complete

            with firm_session(schema_name) as db:
                mark_empty_corpus_enrichment_complete(db, job_id)
            log.info("RAG enrich skipped — empty corpus job=%s", job_id)
            return {"status": "skipped", "reason": "empty_corpus", **info}
        log.info("RAG enrich waiting for parse/RAG baseline job=%s %s", job_id, info)
        return {"status": "deferred", "reason": info.get("reason") or "no_rag_chunks_yet", **info}

    from app.services.disk_build_log import write_disk_log_committed
    from app.services.job_locks import job_lock, refresh_job_lock
    from app.services.pipeline_orchestrator import format_agent_log_message, merge_orchestration_into_progress
    from app.services.rag_enrich import run_rag_enrichment_until_complete, seed_enrichment_progress

    enrich_lock_ttl = 1800
    with job_lock("rag_enrich", job_id, ttl_sec=enrich_lock_ttl) as acquired:
        if not acquired:
            from app.services.job_locks import reclaim_stale_enrich_lock

            if reclaim_stale_enrich_lock(job_id):
                with job_lock("rag_enrich", job_id, ttl_sec=enrich_lock_ttl) as retry:
                    if retry:
                        return _rag_enrich_locked(
                            schema_name, job_id, enrich_lock_ttl=enrich_lock_ttl
                        )
            log.info("RAG enrich skipped — already in flight job=%s", job_id)
            return {"status": "skipped", "reason": "enrich_in_flight"}
        return _rag_enrich_locked(schema_name, job_id, enrich_lock_ttl=enrich_lock_ttl)


def _rag_enrich_locked(schema_name: str, job_id: str, *, enrich_lock_ttl: int) -> dict:
    from app.services.disk_build_log import write_disk_log_committed
    from app.services.job_locks import refresh_job_lock
    from app.services.pipeline_orchestrator import format_agent_log_message, merge_orchestration_into_progress
    from app.services.rag_enrich import run_rag_enrichment_until_complete, seed_enrichment_progress

    write_disk_log_committed(
        schema_name,
        job_id,
        format_agent_log_message("entity_agent", "Extracting structured entities…"),
        stage="rag_enrich",
    )
    with firm_session(schema_name) as progress_db:
        seed_enrichment_progress(progress_db, job_id)
        merge_orchestration_into_progress(progress_db, job_id)
        progress_db.commit()

    last_merge = 0.0

    def _on_progress(_batch_stats: dict) -> None:
        refresh_job_lock("rag_enrich", job_id, ttl_sec=enrich_lock_ttl)

    def _on_batch(batch_stats: dict) -> None:
        nonlocal last_merge
        refresh_job_lock("rag_enrich", job_id, ttl_sec=enrich_lock_ttl)
        scanned_b = int(batch_stats.get("scanned") or 0)
        total_b = int(batch_stats.get("parse_total") or 0)
        mentions_b = int(batch_stats.get("entity_mentions") or 0)
        write_disk_log_committed(
            schema_name,
            job_id,
            format_agent_log_message(
                "entity_agent",
                f"{mentions_b:,} structured entities from {scanned_b:,} / {max(total_b, 1):,} parsed files",
            ),
            stage="rag_enrich",
        )
        now = time.time()
        if now - last_merge < 3:
            return
        last_merge = now
        with firm_session(schema_name) as progress_db:
            from app.services.rag_enrich import persist_enrichment_stats

            persist_enrichment_stats(progress_db, job_id, batch_stats)
            merge_orchestration_into_progress(progress_db, job_id)
            progress_db.commit()

    with firm_session(schema_name) as db:
        stats = run_rag_enrichment_until_complete(
            db, job_id, on_batch=_on_batch, on_progress=_on_progress
        )
        db.commit()

    scanned = int(stats.get("scanned") or 0)
    total = int(stats.get("parse_total") or 0)
    mentions = int(stats.get("entity_mentions") or 0)
    mapped = int(stats.get("ontology_mapped") or 0)
    complete = bool(stats.get("complete"))
    write_disk_log_committed(
        schema_name,
        job_id,
        format_agent_log_message(
            "annotation_agent",
            f"{mentions:,} evidence spans annotated",
        ),
        stage="rag_enrich",
    )
    write_disk_log_committed(
        schema_name,
        job_id,
        format_agent_log_message(
            "ontology_agent",
            f"{mapped:,} artifacts mapped to encyclopedia",
        ),
        stage="rag_enrich",
    )
    if complete:
        write_disk_log_committed(
            schema_name,
            job_id,
            format_agent_log_message(
                "ontology_agent",
                f"Entity / annotation / ontology enrichment complete — {mentions:,} entities, {mapped:,} ontology links",
            ),
            stage="rag_enrich",
        )
    with firm_session(schema_name) as db:
        merge_orchestration_into_progress(db, job_id)
        db.commit()
    if not complete and (total > 0 or bool(stats.get("truncated"))):
        from app.forensic_common.pipeline_routing import followup_queue

        rag_enrich_task.apply_async(args=(schema_name, job_id), queue=followup_queue())
    return {"status": "ok" if complete else "running", **stats}


@celery.task(name="app.tasks.axiom_artifact_inventory_task")
def axiom_artifact_inventory_task(schema_name: str, job_id: str) -> dict:
    log.info("Artifact inventory job=%s schema=%s", job_id, schema_name)
    return axiom_artifact_inventory_sync(schema_name, job_id)


@celery.task(name="app.tasks.axiom_artifact_inventory_mobile_task")
def axiom_artifact_inventory_mobile_task(schema_name: str, job_id: str) -> dict:
    """Mobile-only inventory — runs on mobile-build queue (no disk census path)."""
    log.info("Mobile artifact inventory job=%s schema=%s", job_id, schema_name)
    return axiom_artifact_inventory_sync(schema_name, job_id)


@celery.task(name="app.tasks.mobile_analysis_task")
def mobile_analysis_task(schema_name: str, job_id: str) -> dict:
    """Normalized examiner artifacts — mobile-build, after inventory on large dumps."""
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "mobile_analysis")
    if held:
        return held
    log.info("Mobile analysis pipeline job=%s schema=%s", job_id, schema_name)
    from app.db.session import firm_session
    from app.services.mobile_forensic.pipeline import run_mobile_analysis_pipeline

    with firm_session(schema_name) as db:
        result = run_mobile_analysis_pipeline(db, job_id, force=True)
        db.commit()
        return result


def axiom_artifact_inventory_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "inventory")
    if held:
        return held
    from app.services.job_locks import DEFAULT_INVENTORY_LOCK_TTL_SEC, inventory_job_lock, refresh_job_lock

    # Inventory is CPU catalog work on already-materialized artifacts. Do not
    # wait for GPU RAG/OCR — that left the inventory card frozen for 10-15 min.

    with inventory_job_lock(job_id, ttl_sec=DEFAULT_INVENTORY_LOCK_TTL_SEC) as acquired:
        if not acquired:
            log.info("Artifact inventory skipped — another inventory in flight job=%s", job_id)
            return {"status": "skipped", "reason": "inventory_in_flight"}
        try:
            with firm_session(schema_name) as db:
                from app.services.catalog_artifact_runner import run_axiom_artifact_inventory

                refresh_job_lock("inventory", job_id, ttl_sec=DEFAULT_INVENTORY_LOCK_TTL_SEC)
                return run_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
        except Exception as exc:
            log.exception("Artifact inventory failed job=%s", job_id)
            try:
                with firm_session(schema_name) as db:
                    from app.services.catalog_artifact_runner import INVENTORY_STAGE
                    from app.services.disk_build_log import write_disk_log

                    write_disk_log(
                        db,
                        job_id,
                        f"Artifact inventory failed — {str(exc)[:500]}",
                        stage=INVENTORY_STAGE,
                        level="error",
                    )
                    db.commit()
            except Exception:
                log.exception("Failed to persist artifact inventory error log job=%s", job_id)
            raise


@celery.task(name="app.tasks.graph_sync_task")
def graph_sync_task(schema_name: str, job_id: str) -> dict:
    log.info("Graph sync job=%s schema=%s", job_id, schema_name)
    return graph_sync_sync(schema_name, job_id)


@celery.task(bind=True, name="app.tasks.build_extracted_disk_task")
def build_extracted_disk_task(self, schema_name: str, job_id: str) -> dict:
    log.info("Building extracted disk job=%s schema=%s", job_id, schema_name)
    try:
        return build_extracted_disk_sync(schema_name, job_id)
    except Exception as exc:
        from app.services.job_locks import CpuHeavySlotTimeout

        if isinstance(exc, CpuHeavySlotTimeout):
            log.info("Disk extract capacity busy job=%s; retrying without failing the job", job_id)
            raise self.retry(exc=exc, countdown=15, max_retries=480)
        _retry_transient_db(self, exc)
        raise


@celery.task(bind=True, name="app.tasks.build_extracted_mobile_task")
def build_extracted_mobile_task(self, schema_name: str, job_id: str) -> dict:
    """Mobile-only extraction task; never enters the Disk orchestration backend."""
    from app.services.mobile_forensic.extraction import build_extracted_mobile_sync

    log.info("Building extracted mobile image job=%s schema=%s", job_id, schema_name)
    try:
        return build_extracted_mobile_sync(schema_name, job_id)
    except Exception as exc:
        from app.services.job_locks import CpuHeavySlotTimeout

        if isinstance(exc, CpuHeavySlotTimeout):
            log.info("Mobile extract capacity busy job=%s; retrying without failing the job", job_id)
            raise self.retry(exc=exc, countdown=15, max_retries=480)
        _retry_transient_db(self, exc)
        raise


def phase3_finalize_sync(schema_name: str, job_id: str) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "phase3_finalize")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            from app.services.stream_phase3 import run_phase3_finalize

            return run_phase3_finalize(db, job_id, schema_name=schema_name)
    except Exception as exc:
        log.exception("Phase 3 finalize failed job=%s", job_id)
        with firm_session(schema_name) as db:
            from app.db.sql_helpers import execute
            from app.services.disk_build_log import write_disk_log

            write_disk_log(db, job_id, f"Phase 3 finalize failed: {exc}", stage="phase3", level="error")
            execute(
                db,
                "UPDATE jobs SET status='failed', error=:err, updated_at=NOW() WHERE id=:id",
                {"err": str(exc)[:500], "id": job_id},
            )
            db.commit()
        raise


def phase3_shard_sync(schema_name: str, job_id: str, shard_id: int) -> dict:
    serial = _serial_handoff(schema_name, job_id)
    if serial is not None:
        return serial
    held = _client_intake_hold(schema_name, job_id, "phase3_shard")
    if held:
        return held
    try:
        with firm_session(schema_name) as db:
            from app.services.stream_phase3 import process_extracted_shard

            return process_extracted_shard(db, job_id, schema_name=schema_name, shard_id=shard_id)
    except Exception as exc:
        log.exception("Phase 3 shard %s failed job=%s", shard_id, job_id)
        with firm_session(schema_name) as db:
            from app.services.disk_build_log import write_disk_log

            write_disk_log(
                db,
                job_id,
                f"Streaming Phase 3 shard {shard_id} failed: {exc}",
                stage="phase3",
                level="error",
            )
            db.commit()
        raise


@celery.task(name="app.tasks.phase3_shard_task")
def phase3_shard_task(schema_name: str, job_id: str, shard_id: int) -> dict:
    log.info("Phase 3 shard job=%s shard=%s schema=%s", job_id, shard_id, schema_name)
    return phase3_shard_sync(schema_name, job_id, shard_id)


@celery.task(name="app.tasks.phase3_finalize_task")
def phase3_finalize_task(schema_name: str, job_id: str) -> dict:
    log.info("Phase 3 finalize job=%s schema=%s", job_id, schema_name)
    return phase3_finalize_sync(schema_name, job_id)


@celery.task(
    bind=True,
    name="app.tasks.phase3_pipeline_task",
    max_retries=8,
    default_retry_delay=30,
)
def phase3_pipeline_task(self, schema_name: str, job_id: str) -> dict:
    log.info("Phase 3 pipeline job=%s schema=%s", job_id, schema_name)
    try:
        return phase3_pipeline_sync(schema_name, job_id)
    except Exception as exc:
        _retry_transient_db(self, exc)
        raise


@celery.task(name="app.tasks.rag_index_task")
def rag_index_task(schema_name: str, job_id: str) -> dict:
    log.info("RAG/Phase3 indexing job=%s schema=%s", job_id, schema_name)
    return rag_index_sync(schema_name, job_id)


@celery.task(bind=True, name="app.tasks.report_gen_task", reject_on_worker_lost=True)
def report_gen_task(self, schema_name: str, job_id: str, report_run_id: str | None = None) -> dict:
    log.info("Report generation job=%s schema=%s run=%s", job_id, schema_name, report_run_id or "new")
    from app.services.forensic_stage_worker import run_isolated_report
    return run_isolated_report(schema_name,job_id,report_run_id,task_id=self.request.id)


@celery.task(bind=True, name="app.tasks.forensic_serial_stage_task", reject_on_worker_lost=True)
def forensic_serial_stage_task(self, schema_name: str, job_id: str, stage: str) -> dict:
    from app.services.forensic_serial_pipeline import run_serial_stage

    return run_serial_stage(schema_name, job_id, stage, task_id=self.request.id)


def nessus_scan_sync_run(schema_name: str, scan_job_id: str) -> dict:
    from app.services.nessus_sync import nessus_scan_sync

    return nessus_scan_sync(schema_name, scan_job_id)


@celery.task(
    bind=True,
    name="app.tasks.nessus_scan_sync_task",
    max_retries=120,
    default_retry_delay=45,
)
def nessus_scan_sync_task(self, schema_name: str, scan_job_id: str) -> dict:
    """Dedicated nessus-sync queue — capacity-gated parallel premise scans."""
    from app.db.session import firm_session
    from app.services.vuln_capacity import vuln_scan_can_start

    from celery.exceptions import MaxRetriesExceededError

    log.info("Nessus scan sync job=%s schema=%s", scan_job_id, schema_name)
    try:
        with firm_session(schema_name) as db:
            ok, reason = vuln_scan_can_start(db, scan_job_id)
            if not ok:
                log.info("Deferring scan job %s (%s)", scan_job_id, reason)
                raise self.retry(countdown=45, exc=RuntimeError(reason))
    except MaxRetriesExceededError:
        log.error("Scan job %s exhausted capacity retries", scan_job_id)
        raise
    return nessus_scan_sync_run(schema_name, scan_job_id)


@celery.task(name="app.tasks.vuln_brd_maintenance_task")
def vuln_brd_maintenance_task(schema_name: str) -> dict:
    """Expire exceptions, mark stale agents, evaluate alert thresholds (nessus-sync queue)."""
    from app.db.session import firm_session
    from app.services.vuln_brd import evaluate_alert_thresholds, escalate_sla_overdue, expire_exceptions, mark_stale_agents

    with firm_session(schema_name) as db:
        expired = expire_exceptions(db)
        stale = mark_stale_agents(db, stale_hours=72)
        sla_overdue = escalate_sla_overdue(db)
        fired = evaluate_alert_thresholds(db)
        kev_result = {}
        try:
            from app.services.vuln_kev_feed import sync_kev_catalog

            kev_result = sync_kev_catalog(db)
        except Exception as exc:
            kev_result = {"status": "failed", "error": str(exc)}
        retried_scans = 0
        try:
            from app.db.sql_helpers import fetchall

            stale_scans = fetchall(
                db,
                """SELECT id FROM vuln_scan_jobs
                   WHERE lower(status) = 'running'
                     AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = false
                     AND updated_at < NOW() - INTERVAL '3 minutes'""",
            )
            from app.tasks import nessus_scan_sync_task

            for row in stale_scans or []:
                nessus_scan_sync_task.delay(schema_name, str(row["id"]))
                retried_scans += 1
        except Exception:
            retried_scans = 0
        db.commit()
        return {
            "schema": schema_name,
            "expired": expired,
            "stale_agents": stale,
            "sla_overdue": sla_overdue,
            "alerts_fired": fired,
            "kev_sync": kev_result,
            "retried_stale_scans": retried_scans,
        }


@celery.task(name="app.tasks.pentest_job_task")
def pentest_job_task(schema_name: str, job_id: str) -> dict:
    from app.db.session import firm_session
    from app.services.vuln_pentest import run_pentest_job

    with firm_session(schema_name) as db:
        result = run_pentest_job(db, job_id=job_id)
        db.commit()
        return result


@celery.task(name="app.tasks.forensic_agent_chat_task")
def forensic_agent_chat_task(
    schema_name: str,
    job_id: str,
    query: str,
    user_id: str | None = None,
    thread_id: str | None = None,
) -> dict:
    """Dedicated agent-orchestration queue — never disk-build / rag-index / nessus-sync."""
    from app.agent.orchestrator import run_investigator
    from app.db.session import firm_session

    log.info("Forensic agent chat job=%s schema=%s", job_id, schema_name)
    with firm_session(schema_name) as db:
        return run_investigator(
            db, job_id=job_id, query=query, user_id=user_id, thread_id=thread_id
        )


@celery.task(name="app.tasks.progress_agent_task")
def progress_agent_task(schema_name: str | None = None) -> dict:
    """The only scheduled Disk/Mobile monitor, isolated from processing queues."""
    from app.config import get_settings
    from app.db.session import SessionLocal, firm_session
    from app.models.platform import Firm
    from app.services.progress_agent import supervise_progress
    from sqlalchemy import select

    settings = get_settings()
    if not settings.pipeline_supervisor_enabled:
        return {'status':'disabled','coordinator':'progressAgent','results':[],'enabled':False}
    schemas: list[str] = []
    if schema_name:
        schemas = [schema_name]
    else:
        with SessionLocal() as db:
            firms = db.execute(select(Firm)).scalars().all()
            schemas = [f.schema_name for f in firms if f.schema_name]

    results = []
    for schema in schemas:
        try:
            with firm_session(schema) as db:
                results.append(supervise_progress(db, schema_name=schema))
        except Exception as exc:
            log.warning("progressAgent failed schema=%s: %s", schema, exc)
            results.append({"status": "error", "schema": schema, "error": str(exc)[:200]})
    return {"status": "ok", "results": results, "enabled": settings.pipeline_supervisor_enabled}


@celery.task(name="app.tasks.pipeline_supervisor_task")
def pipeline_supervisor_task(schema_name: str | None = None) -> dict:
    """Consume an old delivery without scheduling another monitoring process."""
    from app.services.retired_agents import retired_huddle_result
    return retired_huddle_result()
