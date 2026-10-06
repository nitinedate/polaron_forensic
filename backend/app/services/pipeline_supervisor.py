"""Agentic pipeline supervisor — monitors jobs and dispatches stage agents."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.config import get_settings
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.job_control import extraction_is_stale, pipeline_is_stale

log = logging.getLogger("pipeline_supervisor")

# Stage agents: disk and mobile extract/parse/inventory are isolated; RAG/graph stay shared.

from app.services.action_agents import list_all_process_agents
PIPELINE_STAGE_AGENTS = {agent['id']:{**agent,'description':agent.get('action','')} for agent in list_all_process_agents()}



def list_pipeline_stage_agents() -> list[dict]:
    from app.services.action_agents import list_all_process_agents
    return list_all_process_agents()


def _is_auto_resumable_pause(row: dict | None) -> bool:
    """Paused jobs the supervisor may resume without user action."""
    if not row or (row.get("status") or "") != "paused":
        return False
    err = (row.get("error") or "").lower()
    return (
        "thermal" in err
        or ("gpu" in err and "°c" in err)
        or "stalled" in err
        or "worker stalled" in err
        or "database was recovering" in err
        or "not yet accepting connections" in err
        or "consistent recovery" in err
    )


def _job_age_sec(row: dict | None) -> float:
    if not row:
        return 0.0
    updated = row.get("updated_at")
    if not updated:
        return float("inf")
    if getattr(updated, "tzinfo", None) is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - updated).total_seconds()


def _stall_resume_sec() -> float:
    """Resume window: try within 1 minute (never wait longer than 60s)."""
    settings = get_settings()
    raw = float(settings.pipeline_stale_sec or 55.0)
    return min(max(raw, 20.0), 60.0)


def _should_redispatch(
    db,
    job_id: str,
    agent_key: str,
    row: dict | None,
    *,
    stale_threshold: float,
    within_sec: float = 45.0,
) -> bool:
    """Allow re-queue when no recent dispatch, or job stale 2× threshold (worker likely dead)."""
    if not _recent_supervisor_action(db, job_id, agent_key, within_sec=within_sec):
        return True
    return _job_age_sec(row) > stale_threshold * 2


def _recent_supervisor_action(db, job_id: str, action: str, *, within_sec: float = 120.0) -> bool:
    row = fetchone(
        db,
        """SELECT timestamp FROM disk_build_logs
           WHERE job_id=:jid AND stage='supervisor' AND message LIKE :pat
           ORDER BY timestamp DESC LIMIT 1""",
        {"jid": job_id, "pat": f"%{action}%"},
    )
    if not row or not row.get("timestamp"):
        return False
    ts = row["timestamp"]
    if getattr(ts, "tzinfo", None) is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() < within_sec


def _gpu_too_hot_for_rag() -> bool:
    """True only at chassis abort — CPU throttle with a cool GPU must not freeze RAG/OCR."""
    settings = get_settings()
    if not settings.gpu_thermal_enabled:
        return False
    try:
        from app.services.agent_duties import assess_chassis_for_ocr
        from app.services.gpu_thermal import get_gpu_stats
        from app.services.host_capacity import probe_host

        stats = get_gpu_stats()
        gpu_c = stats.temperature_c if stats.available else None
        cpu_c = probe_host().cpu_temp_c
        return not bool(assess_chassis_for_ocr(gpu_c, cpu_c)["ocr_may_run"])
    except Exception:
        return False


def _sequential_gate(db, job_id: str, recommendation: dict | None) -> dict | None:
    """When sequential mode is on, only allow the next agent group after prior groups are done.

    The serial stage controller owns post-acquisition dispatch.
    """
    if not recommendation:
        return None
    settings = get_settings()
    agent_id = recommendation.get("agent_id")
    if agent_id in (None, "pipeline_supervisor"):
        return recommendation
    if not settings.pipeline_sequential_agents:
        return recommendation
    from app.services.pipeline_orchestrator import prior_supervisor_keys_done, sync_orchestration_from_job

    # Graph / enrich / inventory are CPU work. After a RAG baseline they must
    # not wait for leftover chunking or OCR-noise rows (that left Neo4j at 0%).
    if agent_id in ("graph_agent", "rag_enrich_agent", "inventory_agent"):
        try:
            chunks = fetchone(
                db,
                "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid",
                {"jid": job_id},
            )
            if int((chunks or {}).get("c") or 0) > 0:
                return recommendation
        except Exception:
            pass

    orch = sync_orchestration_from_job(db, job_id)
    if not prior_supervisor_keys_done(orch["agents"], agent_id):
        return None
    return recommendation


def _gate_inventory_recommendation(db, job_id: str, recommendation: dict | None) -> dict | None:
    """Inventory is CPU/IO — after RAG baseline it must not wait on enrich/GPU work.

    While mobile extract is still far from complete, skip inventory heals — they steal
    I/O from the zip dump readers and make the 34GB path feel stalled.
    """
    if not recommendation:
        return None
    try:
        from app.services.catalog_artifact_runner import artifacts_ready_for_inventory

        ready, _wait_reason = artifacts_ready_for_inventory(db, job_id)
        if not ready:
            return None
    except Exception:
        pass
    try:
        from app.forensic_common.job_types import is_mobile_job

        if is_mobile_job(db, job_id):
            row = fetchone(
                db,
                """SELECT files_total, files_extracted, status FROM jobs WHERE id=:id""",
                {"id": job_id},
            )
            if row:
                total = int(row.get("files_total") or 0)
                done = int(row.get("files_extracted") or 0)
                status = (row.get("status") or "").lower()
                if total > 0 and done < max(int(total * 0.5), 1) and status in (
                    "processing",
                    "building_disk",
                    "extracting",
                    "indexing",
                ):
                    return None
            return recommendation
    except Exception:
        pass
    settings = get_settings()
    mode = str(getattr(settings, "perf_policy_mode", "responsive") or "responsive").strip().lower()
    if settings.pipeline_sequential_agents and mode in {"responsive", "respect_env", "sequential", "stage_aware"}:
        return _sequential_gate(db, job_id, recommendation)
    # Throughput mode only: once Q&A baseline exists, inventory may run beside graph/enrich.
    try:
        chunks = fetchone(
            db,
            "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
            {"jid": job_id},
        )
        if int((chunks or {}).get("c") or 0) >= 500:
            return recommendation
    except Exception:
        pass
    return _sequential_gate(db, job_id, recommendation)


def _observe_stalled_inventory(db, job_id: str, row: dict, *, stale_sec: float) -> dict | None:
    """progressAgent — resume artifact inventory when batches stall mid-run."""
    from app.services.catalog_artifact_runner import (
        INVENTORY_PHASE,
        axiom_inventory_progress,
        inventory_task_in_flight,
    )

    inv = axiom_inventory_progress(db, job_id)
    if inv["total"] <= 0 or inv["done"]:
        return None
    status = row.get("status") or ""
    if status == "paused":
        return None
    # Inventory is a CPU/IO lane — run it beside parse. Do not idle waiting for parse.
    pp = row.get("pipeline_progress") or {}
    if isinstance(pp, str):
        pp = json.loads(pp)
    phase = (pp or {}).get("phase") or ""
    if status in ("ready", "completed", "classified", "report_ready"):
        return None
    inventory_active = (
        status in ("indexing", "indexed")
        or phase in (INVENTORY_PHASE, "axiom_artifacts")
    )
    if not inventory_active:
        return None
    if inventory_task_in_flight(db, job_id):
        return None
    if not _should_redispatch(db, job_id, "inventory_agent", row, stale_threshold=stale_sec, within_sec=45.0):
        return None
    recommendation = {
        "agent_id": "inventory_agent",
        "action": "artifact_inventory",
        "reason": f"progressAgent — artifact inventory stalled ({inv['completed']:,} / {inv['total']:,})",
    }
    return _gate_inventory_recommendation(db, job_id, recommendation)


def analyze_job_pipeline(db, job_id: str) -> dict | None:
    """Return recommended stage-agent action for a job, or None if healthy / busy."""
    from app.services.forensic_serial_pipeline import stage_rows

    if stage_rows(db, job_id):
        return None
    row = fetchone(
        db,
        """SELECT id, status, error, updated_at, stop_requested, disk_source, extracted_disk_uri,
                  pipeline_progress, celery_task_id, extraction_checkpoint
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    if not row or row.get("stop_requested"):
        return None
    try:
        from app.services.host_evidence import is_client_upload_pending
        from app.services.mobile_os import load_job_disk_source

        if is_client_upload_pending(load_job_disk_source(row)):
            return None
    except Exception:
        pass
    status = row["status"] or ""
    if status in ("completed", "classified", "created", "registered"):
        return None
    if status in ("report_ready", "ready"):
        # Report can seal before GLM finishes. Keep draining leftover OCR so the
        # bar cannot freeze at ~25% with CUDA idle.
        leftover = 0
        try:
            from app.services.ocr_gpu import count_pending_ocr

            leftover = int(count_pending_ocr(db, job_id) or 0)
        except Exception:
            leftover = 0
        if leftover <= 0:
            return None
        return _sequential_gate(
            db,
            job_id,
            {
                "agent_id": "ocr_agent",
                "action": "ocr_drain",
                "reason": f"OCR leftover after report ({leftover:,} documents) — CUDA drain",
            },
        )
    if status == "failed":
        err = (row.get("error") or "").lower()
        transient_db = any(
            marker in err
            for marker in (
                "not yet accepting connections",
                "consistent recovery",
                "database system is starting up",
                "database was recovering",
                "connection refused",
            )
        )
        if not transient_db:
            return None
    if status == "paused" and not _is_auto_resumable_pause(row):
        return None

    settings = get_settings()
    stale_sec = _stall_resume_sec()

    # Extraction is an explicit hard barrier.  A previous streaming run can
    # leave status=indexing and even partial parse/RAG/inventory rows while the
    # image is still being walked/copied.  Those rows are not permission to run
    # downstream work: only a finalized extracted_disk_uri opens the barrier.
    files_total = 0
    files_done = 0
    try:
        fr = fetchone(
            db,
            "SELECT files_total, files_extracted FROM jobs WHERE id=:id",
            {"id": job_id},
        )
        files_total = int((fr or {}).get("files_total") or 0)
        files_done = int((fr or {}).get("files_extracted") or 0)
    except Exception:
        pass
    extract_uri = bool(row.get("extracted_disk_uri"))
    extract_unfinished = (not extract_uri) and (
        status in ("processing", "building_disk", "extracting")
        or (files_total > 0 and files_done < files_total)
        or (
            status in ("indexing", "paused", "failed")
            and files_total > 0
            and files_done < files_total
        )
    )
    extract_complete = extract_uri and (files_total <= 0 or files_done >= files_total)
    heartbeat_stale = _job_age_sec(row) > stale_sec
    # V45.5: a worker heartbeating its CPU lease is alive regardless of updated_at.
    try:
        from app.services.job_locks import cpu_heavy_lease_for_job

        _lease = cpu_heavy_lease_for_job(job_id)
        if _lease and float(_lease.get("heartbeat_age_sec") or 0) <= 180.0:
            heartbeat_stale = False
    except Exception:
        pass
    if extract_complete and status in ("processing", "building_disk", "extracting"):
        from app.services.disk import restore_status_if_extract_complete

        restored = restore_status_if_extract_complete(db, job_id)
        if restored:
            status = restored
            row["status"] = restored
            db.commit()
    if (not extract_complete) and (
        status in ("processing", "building_disk", "extracting")
        or extract_unfinished
        or (status == "paused" and "stalled" in (row.get("error") or "").lower())
    ):
        # Only redispatch when the extract worker looks dead (no updated_at heartbeat).
        if extraction_is_stale(row, threshold_sec=stale_sec) or status in {"paused", "failed"} or (
            extract_unfinished and heartbeat_stale
        ):
            if not _should_redispatch(db, job_id, "extract_agent", row, stale_threshold=stale_sec):
                return None
            return _sequential_gate(
                db,
                job_id,
                {
                    "agent_id": "extract_agent",
                    "action": "resume_extraction",
                    "reason": (
                        f"Resuming unfinished extract ({files_done:,} / {files_total:,} files)"
                        if extract_unfinished and status not in ("processing", "building_disk", "paused")
                        else (
                            "Extraction stalled — no heartbeat for 1 minute"
                            if status != "paused"
                            else "Resuming extraction after worker stall"
                        )
                    ),
                },
            )
        # Healthy extraction owns the machine.  Do not let Supervisor start
        # materialize/OCR/parse/RAG/inventory while the image is still active.
        if bool(getattr(settings, "extract_then_process", True)):
            return None

    observed = _observe_stalled_inventory(db, job_id, row, stale_sec=stale_sec)
    if observed:
        return observed

    if status == "disk_ready" and (row.get("extracted_disk_uri") or files_done > 0):
        art = fetchone(
            db,
            "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )
        art_n = int((art or {}).get("c") or 0)
        if art_n <= 0 and _should_redispatch(
            db, job_id, "materialize_agent", row, stale_threshold=60.0
        ):
            return {
                "agent_id": "materialize_agent",
                "action": "start_phase3",
                "reason": "Extract finished — materialize never started",
            }

    from app.services.dual_rag_index import (
        _count_indexable_without_chunks,
        rag_stuck_in_retry_loop,
    )

    rag_remaining = _count_indexable_without_chunks(db, job_id)
    chunks_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
        {"jid": job_id},
    )
    chunk_n = int(chunks_row["c"]) if chunks_row else 0

    embed_on = bool(getattr(settings, "rag_embedding_enabled", False))
    if status in ("indexed", "indexing") and (chunk_n >= 500 or not embed_on):
        from app.services.catalog_artifact_runner import (
            axiom_inventory_progress,
            inventory_task_in_flight,
            parse_pending_count,
        )

        inv = axiom_inventory_progress(db, job_id)
        inv_early = inv
        if (
            embed_on
            and rag_remaining > 0
            and not settings.rag_background_after_baseline
            and inv_early.get("done")
        ):
            return _sequential_gate(
                db,
                job_id,
                {
                    "agent_id": "rag_agent",
                    "action": "force_finish_rag",
                    "reason": f"Baseline RAG complete — skipping background embed ({rag_remaining:,} deferred)",
                },
            )

        if embed_on and rag_remaining > 0 and rag_stuck_in_retry_loop(
            db, job_id, rag_remaining=rag_remaining, chunk_n=chunk_n
        ):
            return _sequential_gate(
                db,
                job_id,
                {
                    "agent_id": "rag_agent",
                    "action": "force_finish_rag",
                    "reason": f"RAG retry loop — clearing {rag_remaining:,} straggler(s) at {chunk_n:,} chunks",
                },
            )

        if inv["total"] > 0 and not inv["done"] and parse_pending_count(db, job_id) <= 0:
            # Prefer inventory over re-queueing enrich/RAG when baseline is ready —
            # especially while GPU is thermally throttled (inventory is CPU/IO).
            if not inventory_task_in_flight(db, job_id) and not _recent_supervisor_action(
                db, job_id, "inventory_agent", within_sec=45.0
            ):
                return _gate_inventory_recommendation(
                    db,
                    job_id,
                    {
                        "agent_id": "inventory_agent",
                        "action": "artifact_inventory",
                        "reason": f"Artifact inventory pending ({inv['completed']:,} / {inv['total']:,})",
                    },
                )

        # Graph + enrich need Q&A baseline only — do NOT wait for full corpus RAG
        # (47k+ background embeds would leave entity/annotation/ontology at 0% forever).
        gs = fetchone(db, "SELECT status, last_sync_at FROM graph_sync_state WHERE job_id=:jid", {"jid": job_id})
        graph_status = (gs or {}).get("status") or ""
        stale_queued = graph_status in ("queued", "syncing") and not (gs or {}).get("last_sync_at")
        if graph_status not in ("ok", "skipped") and (
            graph_status not in ("queued", "syncing") or stale_queued
        ):
            if not _recent_supervisor_action(db, job_id, "graph_agent"):
                gated = _sequential_gate(
                    db,
                    job_id,
                    {
                        "agent_id": "graph_agent",
                        "action": "graph_sync",
                        "reason": "Neo4j graph sync pending after RAG baseline",
                    },
                )
                if gated:
                    return gated

        if graph_status in ("ok", "skipped"):
            from app.services.pipeline_orchestrator import _rag_enrich_status

            rag_enrich_complete, rag_enrich_in_flight = _rag_enrich_status(db, job_id)
            if not rag_enrich_complete and not rag_enrich_in_flight:
                if not _recent_supervisor_action(db, job_id, "rag_enrich_agent"):
                    gated = _sequential_gate(
                        db,
                        job_id,
                        {
                            "agent_id": "rag_enrich_agent",
                            "action": "rag_enrich",
                            "reason": "Entity / annotation / ontology enrichment (baseline ready)",
                        },
                    )
                    if gated:
                        return gated

        # Re-check inventory after graph/enrich (in case they were already done).
        inv = axiom_inventory_progress(db, job_id)
        if inv["total"] > 0 and not inv["done"] and parse_pending_count(db, job_id) <= 0:
            if not inventory_task_in_flight(db, job_id) and not _recent_supervisor_action(
                db, job_id, "inventory_agent", within_sec=45.0
            ):
                return _gate_inventory_recommendation(
                    db,
                    job_id,
                    {
                        "agent_id": "inventory_agent",
                        "action": "artifact_inventory",
                        "reason": f"Artifact inventory pending ({inv['completed']:,} / {inv['total']:,})",
                    },
                )

    baseline_ready = (not embed_on) or chunk_n >= 500
    try:
        from app.services.rag_image_evidence import is_image_evidence_job
        from app.services.dual_rag_index import IMAGE_EVIDENCE_BASELINE_CHUNK_TARGET

        if embed_on and is_image_evidence_job(db, job_id):
            baseline_ready = chunk_n >= IMAGE_EVIDENCE_BASELINE_CHUNK_TARGET
    except Exception:
        pass
    ocr_pending = 0
    if status in ("indexing", "indexed", "parsed", "artifacts_registered", "processing") and settings.ocr_enabled:
        try:
            from app.services.ocr_gpu import (
                count_pending_ocr,
                enqueue_eligible_ocr,
                reopen_failed_ocr_without_results,
                reopen_skipped_forensic_ocr,
            )

            queued = enqueue_eligible_ocr(db, job_id)
            queued += reopen_skipped_forensic_ocr(db, job_id)
            queued += reopen_failed_ocr_without_results(db, job_id)
            if queued:
                db.commit()
            ocr_pending = count_pending_ocr(db, job_id)
        except Exception:
            ocr_pending = 0

    prefer_ocr_over_bg_rag = baseline_ready and ocr_pending > 0 and bool(
        getattr(settings, "defer_background_rag_while_ocr", True)
    )

    from app.services.artifact_parse import count_pending_parse

    pending_n = count_pending_parse(db, job_id)
    perf_mode = str(getattr(settings, "perf_policy_mode", "throughput") or "throughput").strip().lower()
    strict_stage_order = bool(getattr(settings, "pipeline_sequential_agents", False)) and perf_mode in {
        "sequential", "respect_env"
    }
    if (
        pending_n > 0
        and status in ("indexing", "indexed", "parsed", "artifacts_registered", "processing", "building_disk")
        and not _recent_supervisor_action(db, job_id, "parse_agent", within_sec=45.0)
    ):
        if pipeline_is_stale(row, threshold_sec=stale_sec) or pending_n >= 200:
            return _sequential_gate(
                db,
                job_id,
                {
                    "agent_id": "parse_agent",
                    "action": "parse_drain",
                    "reason": f"Background parse pending ({pending_n:,} forensic files)",
                },
            )

    # OCR FIRST after baseline (or always for image-evidence) — never let RAG starve OCR.
    prefer_image_ev_ocr = False
    try:
        from app.services.rag_image_evidence import is_image_evidence_job

        prefer_image_ev_ocr = is_image_evidence_job(db, job_id) and ocr_pending > 0
    except Exception:
        prefer_image_ev_ocr = False
    if (
        ocr_pending > 0
        and status in (
            "indexing",
            "indexed",
            "parsed",
            "artifacts_registered",
            "processing",
            "building_disk",
            "extracting",
            "ready",
            "report_ready",
        )
        and settings.ocr_enabled
        and (baseline_ready or rag_remaining <= 0 or prefer_image_ev_ocr)
        and (
            pipeline_is_stale(row, threshold_sec=stale_sec)
            or not _recent_supervisor_action(db, job_id, "ocr_agent", within_sec=45.0)
            or prefer_ocr_over_bg_rag
            or prefer_image_ev_ocr
        )
        and _should_redispatch(db, job_id, "ocr_agent", row, stale_threshold=stale_sec, within_sec=45.0)
    ):
        return _sequential_gate(
            db,
            job_id,
            {
                "agent_id": "ocr_agent",
                "action": "ocr_drain",
                "reason": (
                    f"OCR pending ({ocr_pending:,} documents) — GPU if free, else text-layer CPU"
                    if baseline_ready
                    else f"OCR pending ({ocr_pending:,} documents)"
                ),
            },
        )

    rag_statuses = ("indexing", "indexed", "extracted", "disk_ready", "parsed", "artifacts_registered")
    thermal_pause = status == "paused" and _is_auto_resumable_pause(row) and "thermal" in (row.get("error") or "").lower()
    if (
        not embed_on
        and rag_remaining > 0
        and status in rag_statuses
        and _should_redispatch(db, job_id, "rag_agent", row, stale_threshold=stale_sec)
    ):
        return _sequential_gate(
            db,
            job_id,
            {
                "agent_id": "rag_agent",
                "action": "resume_rag",
                "reason": f"RAG chunking pending ({chunk_n:,} chunks, {rag_remaining:,} artifacts left)",
            },
        )

    if (
        embed_on
        and rag_remaining > 0
        and settings.rag_background_after_baseline
        and (status in rag_statuses or thermal_pause)
        and not prefer_ocr_over_bg_rag
        and not prefer_image_ev_ocr
        and (not strict_stage_order or (pending_n <= 0 and ocr_pending <= 0))
    ):
        # After parse+OCR are clear, finish corpus embedding promptly — do not wait
        # for a 10-minute stall. Chunk baseline alone is not pipeline completion.
        parse_and_ocr_clear = pending_n <= 0 and ocr_pending <= 0
        if baseline_ready:
            # Inventory is CPU/IO; background RAG is GPU-only. Run them in parallel
            # after OCR (prefer_ocr_over_bg_rag already blocks dual GPU load).
            try:
                from app.services.perf_broadcast import live_defer_background_rag

                if live_defer_background_rag():
                    return {
                        "agent_id": "pipeline_supervisor",
                        "action": "thermal_wait",
                        "reason": f"Live perf plan — deferring background RAG ({rag_remaining:,} pending)",
                    }
            except Exception:
                pass
            if _gpu_too_hot_for_rag():
                return {
                    "agent_id": "pipeline_supervisor",
                    "action": "thermal_wait",
                    "reason": f"GPU too hot — deferring background RAG ({rag_remaining:,} pending)",
                }
            stall_sec = stale_sec
            redispatch_sec = 45.0
            rag_stalled = thermal_pause or pipeline_is_stale(row, threshold_sec=stall_sec) or parse_and_ocr_clear
            if rag_stalled and _should_redispatch(
                db, job_id, "rag_agent", row, stale_threshold=stall_sec, within_sec=redispatch_sec
            ):
                return _sequential_gate(
                    db,
                    job_id,
                    {
                        "agent_id": "rag_agent",
                        "action": "resume_rag",
                        "reason": (
                            f"Finish RAG embedding after chunk baseline "
                            f"({chunk_n:,} chunks, {rag_remaining:,} artifacts pending)"
                            if parse_and_ocr_clear
                            else f"Background RAG resume ({chunk_n:,} chunks, {rag_remaining:,} artifacts pending)"
                        ),
                    },
                )
        else:
            if _gpu_too_hot_for_rag():
                return {
                    "agent_id": "pipeline_supervisor",
                    "action": "thermal_wait",
                    "reason": f"GPU too hot — deferring RAG ({rag_remaining:,} artifacts pending)",
                }
            rag_stalled = thermal_pause or pipeline_is_stale(row, threshold_sec=stale_sec)
            if rag_stalled and _should_redispatch(db, job_id, "rag_agent", row, stale_threshold=stale_sec):
                return _sequential_gate(
                    db,
                    job_id,
                    {
                        "agent_id": "rag_agent",
                        "action": "resume_rag",
                        "reason": (
                            f"Resuming RAG after thermal cooldown ({chunk_n:,} chunks, {rag_remaining:,} pending)"
                            if thermal_pause
                            else f"RAG stalled at {chunk_n:,} chunks ({rag_remaining:,} artifacts remaining)"
                        ),
                    },
                )

    if baseline_ready and status in ("indexing", "indexed"):
        # Graph / enrich / inventory are CPU-bound. Run them in parallel with
        # leftover RAG so the pipeline does not sit at 99% with Neo4j at 0%.
        gs = fetchone(db, "SELECT status, last_sync_at FROM graph_sync_state WHERE job_id=:jid", {"jid": job_id})
        gs_status = (gs or {}).get("status") or ""
        stale_queued = gs_status in ("queued", "syncing") and not (gs or {}).get("last_sync_at")
        if (
            gs_status not in ("ok", "skipped")
            and (gs_status not in ("queued", "syncing") or stale_queued)
            and not _recent_supervisor_action(db, job_id, "graph_agent")
        ):
            return _sequential_gate(
                db,
                job_id,
                {
                    "agent_id": "graph_agent",
                    "action": "graph_sync",
                    "reason": "Neo4j graph sync not started",
                },
            )
        if gs_status in ("ok", "skipped") and not _recent_supervisor_action(db, job_id, "rag_enrich_agent"):
            from app.services.pipeline_orchestrator import _rag_enrich_status

            enrich_done, enrich_busy = _rag_enrich_status(db, job_id)
            if not enrich_done and not enrich_busy:
                gated = _sequential_gate(
                    db,
                    job_id,
                    {
                        "agent_id": "rag_enrich_agent",
                        "action": "rag_enrich",
                        "reason": "Entity / annotation / ontology after baseline (graph ready)",
                    },
                )
                if gated:
                    return gated

    return None


def _issue_code_for_action(action: str, agent_id: str) -> str:
    mapping = {
        "ocr_drain": "ocr_stalled",
        "resume_extraction": "extract_stalled",
        "resume_rag": "rag_stalled",
        "force_finish_rag": "rag_retry_loop",
        "parse_drain": "parse_stalled",
        "artifact_inventory": "inventory_stalled",
        "graph_sync": "graph_pending",
        "rag_enrich": "rag_enrich_pending",
        "thermal_wait": "gpu_thermal",
        "mount_drives": "drives_unmounted",
    }
    return mapping.get(action, f"{agent_id}_issue")


def dispatch_stage_agent(db, job_id: str, *, schema_name: str, recommendation: dict, coordinator=None) -> dict:
    if coordinator != 'progressAgent':
        from app.services.progress_agent import monitor_job,ensure_progress_schema
        ensure_progress_schema(db)
        return monitor_job(db,job_id,schema_name=schema_name)
    """Queue the appropriate Celery task for a stage agent recommendation."""
    from app.services.forensic_serial_pipeline import stage_rows, start_serial_pipeline

    if stage_rows(db, job_id):
        return start_serial_pipeline(db, job_id, schema_name=schema_name)
    from app.forensic_common.pipeline_routing import resolve_domain_agent_id, stage_key_for_recommendation
    from app.services.pipeline_heal import open_issue_for_code, record_heal_event, update_heal_event
    from app.services.pipeline_orchestrator import pipeline_intake_started

    gate_row = fetchone(
        db,
        """SELECT status, disk_source, segment_readiness, extracted_disk_uri,
                  files_total, files_extracted
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    if not pipeline_intake_started(gate_row):
        return {
            "status": "skipped",
            "reason": "awaiting_evidence_selection",
            "job_id": job_id,
        }

    raw_agent_id = recommendation["agent_id"]
    action = recommendation["action"]
    agent_id = resolve_domain_agent_id(db, job_id, raw_agent_id)
    stage_key = stage_key_for_recommendation(raw_agent_id, action)
    reason = recommendation.get("reason", "")
    issue_code = _issue_code_for_action(action, stage_key)

    # progressAgent: open/reuse acquisition recovery issue
    existing = open_issue_for_code(db, job_id, issue_code)
    if existing:
        event_id = str(existing["id"])
        update_heal_event(db, event_id, status="repairing")
    else:
        event_id = record_heal_event(
            db,
            job_id,
            agent="progressAgent",
            issue_code=issue_code,
            issue_detail=reason,
            stage=stage_key,
            status="detected",
            metadata={"agent_id": agent_id, "action": action},
        )
        if event_id:
            update_heal_event(db, event_id, status="repairing")
        write_disk_log(
            db,
            job_id,
            f"progressAgent inspected {issue_code} — {reason}",
            stage="progress",
            metadata={"issue_code": issue_code, "agent_id": agent_id},
        )

    workers = 1
    if action == "thermal_wait":
        write_disk_log(
            db,
            job_id,
            f"[Supervisor] thermal_wait — {reason}",
            stage="supervisor",
            level="warning",
        )
        if event_id:
            update_heal_event(
                db,
                event_id,
                status="resolved",
                remedy_code="defer_rag_thermal",
                remedy_detail=reason,
                resolve=True,
            )
        db.commit()
        return {"status": "deferred", "agent_id": agent_id, "action": action}

    if action == "mount_drives" or stage_key == "drive_mount_agent" or agent_id == "drive_mount_agent":
        from app.services.drive_mount_agent import ensure_all_drives_mounted, mounted_letters
        from app.services.pipeline_orchestrator import persist_drive_mount_complete

        already = mounted_letters()
        if already:
            mount = {
                "ok": True,
                "mounted": already,
                "skipped_refresh": True,
                "message": (
                    "Drive Mount Agent: Docker already mounted "
                    + ", ".join(already)
                    + " (already mounted — no remount)"
                ),
            }
        else:
            mount = ensure_all_drives_mounted(wait_sec=180.0)
        if mount.get("ok") or mount.get("mounted"):
            persist_drive_mount_complete(
                db,
                job_id,
                mounted=list(mount.get("mounted") or already or []),
                detail=mount.get("message"),
            )
        try:
            from app.services.pipeline_orchestrator import _parse_pp, _set_agent, _utc_now_iso

            row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
            pp = _parse_pp((row or {}).get("pipeline_progress"))
            orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
            existing = orch.get("agents") if isinstance(orch.get("agents"), dict) else None
            if not existing:
                pass
            else:
                states = existing
                letters = ", ".join(mount.get("mounted") or []) or "none"
                _set_agent(
                    states,
                    "drive_mount_agent",
                    state="done" if mount.get("ok") else "running",
                    pct=100 if mount.get("ok") else 40,
                    detail=mount.get("message") or letters,
                )
                if not states["drive_mount_agent"].get("started_at"):
                    states["drive_mount_agent"]["started_at"] = _utc_now_iso()
                if mount.get("ok"):
                    states["drive_mount_agent"]["finished_at"] = _utc_now_iso()
                orch = {**orch, "agents": states}
                if mount.get("ok") and orch.get("current_agent_id") in (None, "", "drive_mount_agent"):
                    orch["current_agent_id"] = "list_folder_agent"
                pp["orchestration"] = orch
                execute(
                    db,
                    "UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id",
                    {"pp": json.dumps(pp), "id": job_id},
                )
        except Exception:
            pass
        write_disk_log(
            db,
            job_id,
            f"[Drive Mount agent] {mount.get('message')}",
            stage="drive_mount",
            metadata=mount,
        )
        msg = f"[Supervisor] drive_mount_agent — {mount.get('message')}"
        if event_id:
            update_heal_event(
                db,
                event_id,
                status="resolved" if mount.get("ok") else "failed",
                remedy_code="mount_drives",
                remedy_detail=mount.get("message"),
                metadata=mount,
                resolve=True,
            )
        write_disk_log(db, job_id, msg, stage="supervisor", metadata={"agent_id": "drive_mount_agent"})
        write_disk_log(
            db,
            job_id,
            f"[progressAgent] applied mount_drives on drive_mount_agent — {reason}",
            stage="repair",
            metadata={"target_agent": "drive_mount_agent", "action": "mount_drives"},
        )
        db.commit()
        return {
            "status": "ok" if mount.get("ok") else "failed",
            "agent_id": "drive_mount_agent",
            "action": "mount_drives",
            "message": msg,
            "mount": mount,
        }

    if stage_key == "extract_agent":
        from app.forensic_common.job_types import is_mobile_job
        from app.services.job_locks import extract_is_live
        from app.services.mobile_platform_agents import PlatformMismatchError, assert_agent_owns_job
        from app.tasks import build_extracted_disk_task, build_extracted_mobile_task

        try:
            assert_agent_owns_job(db, job_id, agent_id)
        except PlatformMismatchError as exc:
            write_disk_log(db, job_id, f"[Supervisor] refuse extract — {exc}", stage="supervisor")
            db.commit()
            return {"status": "refused", "agent_id": agent_id, "action": action, "message": str(exc)}

        live_row = fetchone(
            db,
            """SELECT status, updated_at, files_total, files_extracted, extracted_disk_uri,
                      extraction_checkpoint FROM jobs WHERE id=:id""",
            {"id": job_id},
        )
        from app.services.disk import _extract_already_complete

        if _extract_already_complete(db, job_id):
            from app.services.disk import restore_status_if_extract_complete

            restored = restore_status_if_extract_complete(db, job_id)
            write_disk_log(
                db,
                job_id,
                f"[Supervisor] extract_agent — extract already complete, skip resume ({reason})"
                + (f"; status restored to {restored}" if restored else ""),
                stage="supervisor",
            )
            db.commit()
            return {
                "status": "already_complete",
                "agent_id": agent_id,
                "action": action,
                "message": "Extract already complete",
            }
        if extract_is_live(db, job_id, live_row):
            write_disk_log(
                db,
                job_id,
                f"[Supervisor] extract_agent — already running, skip duplicate resume ({reason})",
                stage="supervisor",
            )
            db.commit()
            return {
                "status": "already_running",
                "agent_id": agent_id,
                "action": action,
                "message": "Extract already running",
            }

        execute(
            db,
            """UPDATE jobs SET status='processing', stop_requested=FALSE, error=NULL, updated_at=NOW()
               WHERE id=:id""",
            {"id": job_id},
        )
        if is_mobile_job(db, job_id):
            from app.services.mobile_platform_agents import owner_agent_for_job, owner_agent_label
            from app.forensic_common.job_types import mobile_os_family

            owner = owner_agent_for_job(db, job_id)
            family = mobile_os_family(db, job_id) or "mobile"
            build_extracted_mobile_task.delay(schema_name, job_id)
            label = owner_agent_label(family) or "mobile agent"
            msg = f"[Supervisor] {owner or agent_id} ({label}) — resume {family} extract ({reason})"
        else:
            build_extracted_disk_task.delay(schema_name, job_id)
            msg = f"[Supervisor] {agent_id} — resume extraction ({reason})"
    elif action == "start_phase3" or stage_key == "materialize_agent":
        from app.tasks import phase3_pipeline_task

        execute(
            db,
            "UPDATE jobs SET status='indexing', error=NULL, stop_requested=FALSE, updated_at=NOW() WHERE id=:id",
            {"id": job_id},
        )
        phase3_pipeline_task.delay(schema_name, job_id)
        msg = f"[Supervisor] materialize_agent — start Phase 3 ({reason})"
    elif agent_id == "ocr_agent" or stage_key == "ocr_agent" or action == "ocr_drain":
        from app.services.ocr_gpu import dispatch_ocr_agent, ocr_should_use_gpu

        workers = dispatch_ocr_agent(schema_name, job_id)
        lane = "GPU" if ocr_should_use_gpu() else "GPU-queue"
        try:
            from app.services.ocr_gpu import _glm_micro_batch_size

            micro = _glm_micro_batch_size()
        except Exception:
            micro = 1
        msg = (
            f"[Supervisor] ocr_agent — resume {lane} OCR "
            f"({workers} CUDA worker, {micro}-page batches; {reason})"
        )
    elif agent_id == "rag_agent" or stage_key == "rag_agent":
        if action == "force_finish_rag":
            from app.services.dual_rag_index import force_finish_rag_enrichment

            chunks_row = fetchone(
                db,
                "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
                {"jid": job_id},
            )
            chunk_n = int(chunks_row["c"]) if chunks_row else 0
            force_finish_rag_enrichment(
                db,
                job_id,
                schema_name=schema_name,
                chunk_count=chunk_n,
                reason="Supervisor forced RAG completion after retry loop",
            )
            msg = f"[Supervisor] rag_agent — force finish RAG ({reason})"
        else:
            from app.services.dual_rag_index import _count_indexable_artifacts, _count_indexable_without_chunks
            from app.tasks import rag_append_task

            remaining = _count_indexable_without_chunks(db, job_id)
            chunks_row = fetchone(
                db,
                "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
                {"jid": job_id},
            )
            chunk_n = int(chunks_row["c"]) if chunks_row else 0
            total = _count_indexable_artifacts(db, job_id)
            execute(
                db,
                """UPDATE jobs SET status='indexing', error=NULL, stop_requested=FALSE,
                   pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
                {
                    "pp": json.dumps({
                        "phase": "rag",
                        "completed": chunk_n,
                        "total": max(total, chunk_n + remaining, 1),
                        "label": f"Supervisor resumed RAG — {remaining:,} pending",
                    }),
                    "id": job_id,
                },
            )
            rag_append_task.delay(schema_name, job_id)
            msg = f"[Supervisor] rag_agent — resume RAG ({reason})"
    elif stage_key == "parse_agent":
        from app.config import get_settings
        from app.forensic_common.job_types import is_mobile_job
        from app.services.artifact_parse import queue_parallel_parse_buckets
        from app.tasks import parse_drain_mobile_task, parse_drain_task

        if is_mobile_job(db, job_id):
            from app.services.mobile_platform_agents import PlatformMismatchError, assert_agent_owns_job, owner_agent_for_job

            try:
                assert_agent_owns_job(db, job_id, agent_id)
            except PlatformMismatchError as exc:
                write_disk_log(db, job_id, f"[Supervisor] refuse parse — {exc}", stage="supervisor")
                db.commit()
                return {"status": "refused", "agent_id": agent_id, "action": action, "message": str(exc)}
            parse_drain_mobile_task.delay(schema_name, job_id)
            workers = 1
            owner = owner_agent_for_job(db, job_id)
            agent_id = owner or agent_id
        else:
            buckets = max(int(getattr(get_settings(), "parse_parallel_buckets", 4) or 4), 1)
            if buckets > 1:
                workers = queue_parallel_parse_buckets(schema_name, job_id, num_buckets=buckets)
            else:
                parse_drain_task.delay(schema_name, job_id)
                workers = 1
        msg = f"[Supervisor] {agent_id} — background parse ({workers} worker(s); {reason})"
    elif agent_id == "graph_agent" or stage_key == "graph_agent":
        from app.tasks import graph_sync_task

        execute(
            db,
            """INSERT INTO graph_sync_state (job_id, status)
               VALUES (:jid, 'queued')
               ON CONFLICT (job_id) DO UPDATE SET status='queued'""",
            {"jid": job_id},
        )
        graph_sync_task.delay(schema_name, job_id)
        msg = f"[Supervisor] graph_agent — Neo4j sync ({reason})"
    elif stage_key == "inventory_agent":
        from app.services.catalog_artifact_runner import queue_axiom_artifact_inventory

        queued = queue_axiom_artifact_inventory(db, job_id, schema_name=schema_name)
        wait_reason = str(queued.get("reason") or "")
        if not queued.get("queued_axiom_inventory") and wait_reason.startswith("waiting_for_artifacts"):
            if event_id:
                update_heal_event(
                    db,
                    event_id,
                    status="resolved",
                    remedy_code="waiting_for_artifacts",
                    remedy_detail=wait_reason,
                    resolve=True,
                )
                db.commit()
            return {
                "status": "waiting",
                "agent_id": agent_id,
                "action": action,
                "message": wait_reason,
            }
        msg = f"[Supervisor] {agent_id} — artifact inventory queued ({reason})"
    elif agent_id == "rag_enrich_agent" or stage_key == "rag_enrich_agent":
        from app.forensic_common.pipeline_routing import followup_queue
        from app.tasks import rag_enrich_task

        rag_enrich_task.apply_async(args=(schema_name, job_id), queue=followup_queue())
        msg = f"[Supervisor] rag_enrich_agent — entity/annotation/ontology ({reason})"
    else:
        if event_id:
            update_heal_event(
                db,
                event_id,
                status="failed",
                remedy_code="unknown_agent",
                remedy_detail=f"unknown agent {agent_id}",
                resolve=True,
            )
            db.commit()
        return {"status": "skipped", "reason": f"unknown agent {agent_id}"}

    write_disk_log(db, job_id, msg, stage="supervisor", metadata={"agent_id": agent_id, "action": action})
    write_disk_log(
        db,
        job_id,
        f"[progressAgent] applied {action} on {agent_id} — {reason}",
        stage="repair",
        metadata={"target_agent": agent_id, "action": action, "issue_code": issue_code},
    )
    if event_id:
        update_heal_event(
            db,
            event_id,
            status="resolved",
            remedy_code=action,
            remedy_detail=f"Re-queued {agent_id}: {reason}",
            metadata={"agent_id": agent_id, "action": action},
            resolve=True,
        )
    db.commit()
    log.info("progressAgent dispatched %s for job %s: %s", agent_id, job_id, reason)
    return {
        "status": "queued",
        "agent_id": agent_id,
        "action": action,
        "message": msg,
        "workers": int(workers),
    }


def supervise_firm_jobs(db, *, schema_name: str) -> dict:
    """Compatibility entry point for the single progress coordinator."""
    from app.services.progress_agent import supervise_progress
    return supervise_progress(db, schema_name=schema_name)
