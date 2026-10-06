"""Forensic jobs API — Phase 2 host-drive registration and extracted disk build."""

from __future__ import annotations

import json
import time
import logging
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.db.tenant import get_tenant_context
from app.deps import CurrentUser, firm_db, require_firm_permission, require_firm_permission_released
from app.models.platform import Firm
from app.schemas.forensic import IngestPathBody, JobCreate, ListFolderBody, ResolveFolderBody
from app.service_identity import (
    ANDROID_JOB_TYPES,
    FORENSIC,
    IOS_JOB_TYPES,
    MOBILE_ANDROID,
    MOBILE_EXTRACT,
    MOBILE_IOS,
    MOBILE_JOB_TYPES,
    canonical_mobile_job_type,
    current_service,
    mobile_service_platform,
    service_allows_job_type,
)
from app.services.disk import segment_readiness
from app.services.disk_build_log import write_disk_log
from app.services.host_evidence import (
    browse as host_browse,
    find_folder_with_segment_files,
    is_client_upload_pending,
    list_folder_contents,
    mark_client_upload_progress,
    mount_info,
    preview_folder,
    register_segments,
    register_uploaded_intake,
)

router = APIRouter(prefix="/api", tags=["forensic"])
log = logging.getLogger(__name__)


def _ensure_job_case(db: Session, job_id: str) -> str | None:
    """Link job to a case record when none exists (auto-created on first evidence ingest)."""
    row = fetchone(db, "SELECT case_id FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        return None
    if row.get("case_id"):
        return str(row["case_id"])
    case_id = str(uuid.uuid4())
    execute(db, "UPDATE jobs SET case_id=:cid, updated_at=NOW() WHERE id=:jid", {"cid": case_id, "jid": job_id})
    return case_id


def _enrichment_snapshot(db, job_id: str) -> dict | None:
    """Live Phase 3 stats for UI (baseline Q&A vs background parse/RAG)."""
    from app.services.artifact_parse import forensic_parse_keep_sql

    forensic_filter = forensic_parse_keep_sql()
    row = fetchone(
        db,
        f"""SELECT
             count(*) AS files_registered,
             count(*) FILTER (WHERE parse_status = 'skipped') AS artifacts_skipped,
             count(*) FILTER (
               WHERE parse_status = 'parsed' OR ocr_status = 'done'
             ) AS artifacts_parsed,
             count(*) FILTER (WHERE parse_status = 'pending') AS artifacts_pending,
             count(*) FILTER (
               WHERE parse_status = 'pending' AND {forensic_filter}
             ) AS forensic_pending,
             count(*) FILTER (
               WHERE parse_status = 'parsed' OR ocr_status = 'done'
             ) AS forensic_parsed
           FROM job_artifacts WHERE job_id = :jid""",
        {"jid": job_id},
    )
    if not row or int(row.get("files_registered") or 0) <= 0:
        return None
    chunks_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id = :jid AND chunk_type = 'evidence'",
        {"jid": job_id},
    )
    job_row = fetchone(db, "SELECT status, coalesce(job_kind, 'forensic') AS job_kind FROM jobs WHERE id=:jid", {"jid": job_id})
    files_registered = int(row["files_registered"])
    artifacts_skipped = int(row["artifacts_skipped"] or 0)
    artifacts_parsed = int(row["artifacts_parsed"] or 0)
    forensic_pending = int(row["forensic_pending"] or 0)
    forensic_parsed = int(row["forensic_parsed"] or 0)
    parse_scope_total = max(forensic_parsed + forensic_pending, forensic_parsed, 1)
    rag_chunks = int(chunks_row["c"]) if chunks_row else 0
    job_status = (job_row or {}).get("status") or ""
    image_ev = str((job_row or {}).get("job_kind") or "").lower() == "image_evidence"
    if not image_ev:
        try:
            from app.services.rag_image_evidence import is_image_evidence_job

            image_ev = is_image_evidence_job(db, job_id)
        except Exception:
            image_ev = False
    from app.services.dual_rag_index import (
        IMAGE_EVIDENCE_BASELINE_CHUNK_TARGET,
        _count_indexable_artifacts,
        _count_indexable_without_chunks,
    )

    rag_pending = _count_indexable_without_chunks(db, job_id)
    rag_total = _count_indexable_artifacts(db, job_id)
    parse_done = forensic_pending <= 0
    rag_done = rag_pending <= 0
    from app.config import get_settings

    settings = get_settings()
    ocr_pending = 0
    ocr_done = 0
    try:
        from app.services.ocr_gpu import count_pending_ocr

        ocr_pending = int(count_pending_ocr(db, job_id) or 0)
        done_row = fetchone(
            db,
            "SELECT count(*)::int AS c FROM job_artifacts WHERE job_id=:jid AND ocr_status='done'",
            {"jid": job_id},
        )
        ocr_done = int((done_row or {}).get("c") or 0)
    except Exception:
        pass
    embed_on = bool(getattr(settings, "rag_embedding_enabled", False))
    if not embed_on:
        baseline_ready = rag_pending <= 0 and (rag_chunks > 0 or (parse_done and files_registered > 0))
    elif image_ev:
        baseline_ready = rag_chunks >= IMAGE_EVIDENCE_BASELINE_CHUNK_TARGET or ocr_done > 0
    else:
        baseline_ready = rag_chunks >= 500 and artifacts_parsed >= 500
    defer_bg_rag = bool(getattr(settings, "defer_background_rag_while_ocr", True)) and (
        (baseline_ready and ocr_pending > 0) or (image_ev and ocr_pending > 0)
    )
    baseline_only = baseline_ready and not settings.rag_background_after_baseline
    # Background enrichment only while real forensic parse or optional full-corpus RAG remains.
    enriching = (not parse_done and baseline_ready) or (
        embed_on
        and not rag_done
        and rag_chunks > 0
        and rag_pending > 0
        and settings.rag_background_after_baseline
        and not defer_bg_rag
    ) or (baseline_ready and ocr_pending > 0)
    if not embed_on:
        rag_done = rag_pending <= 0 and (rag_chunks > 0 or (parse_done and files_registered > 0))
        rag_indexing = rag_pending > 0
    elif baseline_only and parse_done:
        rag_done = True
        rag_indexing = False
    else:
        # Do not report "rag_indexing" while OCR owns the GPU after baseline.
        rag_indexing = (
            rag_pending > 0 and settings.rag_background_after_baseline and not defer_bg_rag
        )
    return {
        "files_registered": files_registered,
        "artifacts_skipped": artifacts_skipped,
        "artifacts_total": parse_scope_total,
        "artifacts_parsed": forensic_parsed,
        "artifacts_pending": forensic_pending,
        "rag_chunks": rag_chunks,
        "rag_total": rag_total,
        "rag_pending": rag_pending,
        "rag_indexing": rag_indexing,
        "ocr_pending": ocr_pending,
        "ocr_done": ocr_done,
        "baseline_ready": baseline_ready,
        "enriching": enriching,
        "parse_done": parse_done,
        "rag_done": rag_done,
        "rag_background_enabled": bool(embed_on and settings.rag_background_after_baseline),
        "rag_embedding_enabled": embed_on,
        "background_rag_deferred_for_ocr": defer_bg_rag,
    }


def _heal_unstarted_pipeline(db: Session, job_id: str, row: dict, schema: str) -> dict | None:
    """Force a newly-created job back to the canonical 0% pre-intake state.

    This also repairs rows polluted by older supervisor/huddle builds that marked
    Drive Mount, Download, Virtual Disk, Extraction, or RAG complete before the
    examiner selected any evidence.
    """
    try:
        import json as _json

        from app.db.session import apply_firm_search_path
        from app.services.pipeline_orchestrator import (
            build_orchestration_progress_snapshot,
            pipeline_intake_started,
        )

        if pipeline_intake_started(row):
            return None
        snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
        if not snapshot:
            return None
        fixed = dict(row)
        fixed["pipeline_progress"] = snapshot
        fixed["progress_pct"] = 0

        raw_pp = row.get("pipeline_progress")
        old_pp = _json.loads(raw_pp) if isinstance(raw_pp, str) else (raw_pp or {})
        old_orch = old_pp.get("orchestration") if isinstance(old_pp, dict) else {}
        old_agents = old_orch.get("agents") if isinstance(old_orch, dict) else {}
        dirty_agents = any(
            isinstance(st, dict)
            and (st.get("state") != "pending" or int(st.get("pct") or 0) != 0 or st.get("started_at"))
            for st in (old_agents or {}).values()
        )
        dirty = (
            int(row.get("progress_pct") or 0) != 0
            or (isinstance(old_pp, dict) and str(old_pp.get("phase") or "") not in ("", "idle"))
            or bool((old_orch or {}).get("current_agent_id"))
            or bool((old_orch or {}).get("pipeline_started_at"))
            or dirty_agents
        )
        if dirty:
            persist_pp = dict(snapshot)
            persist_pp.pop("progress_pct", None)
            execute(
                db,
                """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=0
                   WHERE id=:id""",
                {"id": job_id, "pp": _json.dumps(persist_pp)},
            )
            db.commit()
            apply_firm_search_path(db, schema)
            log.info("reset pre-intake pipeline to 0%% for job %s", job_id)
        return fixed
    except Exception:
        log.exception("pre-intake pipeline reset failed for job %s", job_id)
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _heal_contradictory_progress(db: Session, job_id: str, row: dict, schema: str) -> dict | None:
    """Repair a persisted job row that claims completion while stages still have work.

    Older stage writers forced ``progress_pct=100`` and replaced ``pipeline_progress``
    without its ``orchestration`` block. Normal polling returns the row as-is, so the
    UI showed "100% / Pipeline finished" with the running stage pinned at 99% and
    later stages at 0%. Detect exactly that contradiction, rebuild the snapshot once
    (which caps overall at 99 until every agent is done), persist it, and return the
    corrected row. Consistent rows return None and cost no extra queries.
    """
    try:
        import json as _json

        pct = int(row.get("progress_pct") or 0)
        status_l = (row.get("status") or "").lower()
        raw_pp = row.get("pipeline_progress")
        pp = _json.loads(raw_pp) if isinstance(raw_pp, str) else (raw_pp or {})
        if not isinstance(pp, dict):
            pp = {}
        orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else None
        phase = str(pp.get("phase") or "").lower()
        completed = int(pp.get("completed") or 0)
        total = int(pp.get("total") or 0)
        files_total = int(row.get("files_total") or 0)
        files_done = int(row.get("files_extracted") or 0)
        extract_running = status_l in ("processing", "building_disk", "extracting") or (
            files_total > 0 and files_done < files_total
        )
        agents = orch.get("agents") if isinstance(orch, dict) else None
        if extract_running and isinstance(agents, dict):
            for aid in (
                "ocr_agent",
                "parse_agent",
                "materialize_agent",
                "chunk_agent",
            ):
                if (agents.get(aid) or {}).get("state") == "done":
                    from app.db.session import apply_firm_search_path
                    from app.services.pipeline_orchestrator import build_orchestration_progress_snapshot

                    snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
                    if snapshot:
                        overall = int(snapshot.get("progress_pct") or 0)
                        execute(
                            db,
                            """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct,
                               updated_at=updated_at WHERE id=:id""",
                            {"id": job_id, "pp": _json.dumps(snapshot), "pct": overall},
                        )
                        db.commit()
                        apply_firm_search_path(db, schema)
                        fixed = dict(row)
                        fixed["pipeline_progress"] = snapshot
                        fixed["progress_pct"] = overall
                        log.info(
                            "healed false-complete %s during extract for job %s",
                            aid,
                            job_id,
                        )
                        return fixed
                    break
        # Finished extract-era cards snapped back to pending/0% while OCR or
        # indexing is still live. Rebuild from job counts so list/extract stay 100%.
        if (
            not extract_running
            and status_l in (
                "extracted",
                "artifacts_registered",
                "parsed",
                "indexing",
                "indexed",
                "ready",
            )
            and isinstance(agents, dict)
        ):
            early_pending = any(
                (agents.get(aid) or {}).get("state") == "pending"
                for aid in (
                    "list_folder_agent",
                    "segments_agent",
                    "virtual_disk_agent",
                    "extraction_agent",
                    "materialize_agent",
                )
            )
            later_live = any(
                (agents.get(aid) or {}).get("state") in ("running", "done")
                for aid in ("ocr_agent", "parse_agent", "chunk_agent")
            )
            if early_pending and (later_live or status_l in ("indexing", "indexed", "ready")):
                from app.db.session import apply_firm_search_path
                from app.services.pipeline_orchestrator import build_orchestration_progress_snapshot

                snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
                if snapshot:
                    overall = int(snapshot.get("progress_pct") or 0)
                    execute(
                        db,
                        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct,
                           updated_at=updated_at WHERE id=:id""",
                        {"id": job_id, "pp": _json.dumps(snapshot), "pct": overall},
                    )
                    db.commit()
                    apply_firm_search_path(db, schema)
                    fixed = dict(row)
                    fixed["pipeline_progress"] = snapshot
                    fixed["progress_pct"] = overall
                    log.info("healed pending 0%% early cards during %s for job %s", status_l, job_id)
                    return fixed
        # Entity/annotation/ontology 100% from the old log-only stub — no scan stats.
        if (
            not extract_running
            and isinstance(agents, dict)
            and (agents.get("entity_agent") or {}).get("state") == "done"
            and not (isinstance(pp.get("enrichment_stats"), dict) and pp["enrichment_stats"].get("complete"))
        ):
            from app.db.session import apply_firm_search_path
            from app.services.pipeline_orchestrator import build_orchestration_progress_snapshot

            snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
            if snapshot:
                overall = int(snapshot.get("progress_pct") or 0)
                execute(
                    db,
                    """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct,
                       updated_at=updated_at WHERE id=:id""",
                    {"id": job_id, "pp": _json.dumps(snapshot), "pct": overall},
                )
                db.commit()
                apply_firm_search_path(db, schema)
                fixed = dict(row)
                fixed["pipeline_progress"] = snapshot
                fixed["progress_pct"] = overall
                log.info("healed log-only entity/ontology complete for job %s", job_id)
                return fixed
        claims_done = pct >= 100 or status_l in ("ready", "indexed")
        if not claims_done:
            return None
        stage_has_work = phase in ("parse", "rag", "ocr") and total > 0 and completed < total
        orch_incomplete = orch is not None and int(orch.get("overall_pct") or 0) < 100
        if pct >= 100 and (orch is None or orch_incomplete or stage_has_work):
            contradictory = True
        elif orch is None and status_l in ("ready", "indexed") and phase not in ("complete",):
            contradictory = True
        else:
            contradictory = False
        if not contradictory:
            return None

        from app.db.session import apply_firm_search_path
        from app.services.pipeline_orchestrator import build_orchestration_progress_snapshot

        snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
        if not snapshot:
            return None
        overall = int(snapshot.get("progress_pct") or 0)
        execute(
            db,
            """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct,
               updated_at=updated_at WHERE id=:id""",
            {"id": job_id, "pp": _json.dumps(snapshot), "pct": overall},
        )
        db.commit()
        apply_firm_search_path(db, schema)
        fixed = dict(row)
        fixed["pipeline_progress"] = snapshot
        fixed["progress_pct"] = overall
        log.info("healed contradictory pipeline progress for job %s (%s%% -> %s%%)", job_id, pct, overall)
        return fixed
    except Exception:
        log.exception("progress self-heal failed for job %s", job_id)
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _heal_stuck_drive_mount(db: Session, job_id: str, row: dict, schema: str) -> dict | None:
    """If Docker already has /host letters, Drive Mount stays 100% and List Folder starts."""
    try:
        import json as _json

        status_l = (row.get("status") or "").lower()
        if status_l not in ("created", "registered", "pending", "uploaded"):
            return None
        from app.services.pipeline_orchestrator import pipeline_intake_started

        if not pipeline_intake_started(row):
            return None
        raw_pp = row.get("pipeline_progress")
        pp = _json.loads(raw_pp) if isinstance(raw_pp, str) else (raw_pp or {})
        if not isinstance(pp, dict):
            pp = {}
        orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
        agents = orch.get("agents") if isinstance(orch.get("agents"), dict) else {}
        mount = agents.get("drive_mount_agent") if isinstance(agents.get("drive_mount_agent"), dict) else {}
        ocr = agents.get("ocr_agent") if isinstance(agents.get("ocr_agent"), dict) else {}
        false_complete_ocr = ocr.get("state") == "done" and int(ocr.get("pct") or 0) >= 100
        # Mount already 100% is not enough: huddle used to persist OCR 100% on an
        # empty created job. Re-run persist so those cards go back to pending.
        if mount.get("state") == "done" and not false_complete_ocr:
            return None
        from app.services.drive_mount_agent import mounted_letters
        from app.services.pipeline_orchestrator import persist_drive_mount_complete
        from app.db.session import apply_firm_search_path

        letters = mounted_letters()
        if mount.get("state") != "done" and not letters:
            return None
        persist_drive_mount_complete(
            db,
            job_id,
            mounted=letters,
            detail="Drives already mounted (" + ", ".join(letters) + ") — no remount",
        )
        db.commit()
        apply_firm_search_path(db, schema)
        fixed = dict(_ensure_job(db, job_id))
        log.info("healed stuck drive mount for job %s letters=%s", job_id, letters)
        return fixed
    except Exception:
        log.exception("drive mount self-heal failed for job %s", job_id)
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _job_row(row: dict, *, enrichment: dict | None = None) -> dict:
    sr = row.get("segment_readiness")
    if isinstance(sr, str):
        sr = json.loads(sr)
    created = row["created_at"]
    updated = row["updated_at"]
    ec = row.get("extract_coverage")
    pp = row.get("pipeline_progress")
    ds = row.get("disk_source")
    if isinstance(ec, str):
        ec = json.loads(ec)
    if isinstance(pp, str):
        pp = json.loads(pp)
    if isinstance(ds, str):
        ds = json.loads(ds)
    from app.services.mobile_forensic.key_intake import redact_forensic_keys
    ds = redact_forensic_keys(ds)
    out = {
        "id": str(row["id"]),
        "type": row.get("type") or "host_disk",
        "status": row["status"],
        "domain_pack": row.get("domain_pack"),
        "created_by": str(row["created_by"]) if row.get("created_by") else None,
        "case_id": str(row["case_id"]) if row.get("case_id") else None,
        "progress_pct": row.get("progress_pct") or 0,
        "error": row.get("error"),
        "segment_readiness": sr,
        "extract_coverage": ec,
        "pipeline_progress": pp,
        "extracted_disk_uri": row.get("extracted_disk_uri"),
        "disk_source": ds,
        "files_total": row.get("files_total") or 0,
        "files_extracted": row.get("files_extracted") or 0,
        "bytes_extracted": row.get("bytes_extracted") or 0,
        "stop_requested": bool(row.get("stop_requested")),
        "evidence_count": int(row.get("evidence_count") or 0),
        "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
        "updated_at": updated.isoformat() if hasattr(updated, "isoformat") else str(updated),
    }
    # V45.5: let the UI see the worker's own heartbeat so it never auto-resumes a live job.
    try:
        from app.services.job_control import extract_worker_liveness

        liveness = extract_worker_liveness(row)
        if liveness is not None:
            out["worker_liveness"] = liveness
    except Exception:
        pass
    if enrichment:
        out["enrichment"] = enrichment
        if not out.get("extract_coverage") and (
            enrichment.get("enriching") or int(enrichment.get("artifacts_pending") or 0) > 0
        ):
            out["extract_coverage"] = {
                "interesting_total": enrichment.get("artifacts_total") or enrichment.get("files_registered"),
                "extracted": enrichment["artifacts_parsed"],
                "pending": enrichment["artifacts_pending"],
                "files_registered": enrichment.get("files_registered"),
                "artifacts_skipped": enrichment.get("artifacts_skipped"),
                "next_batch_size": 0,
                "batch_cap": 0,
            }
    return out


def _schema_name(db: Session, current: CurrentUser) -> str:
    if current.schema_name:
        return current.schema_name
    ctx = get_tenant_context()
    if ctx and ctx.schema_name:
        return ctx.schema_name
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    if firm and firm.schema_name:
        return firm.schema_name
    raise HTTPException(status_code=500, detail={"error": {"code": "no_schema", "message": "Tenant schema missing"}})


def _ensure_job(db: Session, job_id: str) -> dict:
    row = fetchone(db, "SELECT * FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    ds = row.get("disk_source") or {}
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    ds = ds if isinstance(ds, dict) else {}
    if not service_allows_job_type(
        str(row.get("type") or ""),
        str(ds.get("source_type") or ""),
        mobile_os=str(ds.get("mobile_os") or ""),
    ):
        # Deliberately return 404 instead of leaking that a sibling backend has
        # a job with this UUID. Runtime products are hard isolation boundaries.
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    return row


@router.get("/jobs")
def list_jobs(
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    type: str | None = None,
    case_id: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    offset = (max(page, 1) - 1) * page_size
    clauses: list[str] = []
    params: dict = {"limit": page_size, "offset": offset}
    if status:
        clauses.append("status=:status")
        params["status"] = status
    if type:
        clauses.append("type=:type")
        params["type"] = type
    if case_id:
        clauses.append("case_id=CAST(:case_id AS uuid)")
        params["case_id"] = case_id
    svc = current_service()
    if svc == MOBILE_ANDROID:
        clauses.append("type IN ('android_mobile','android_backup')")
    elif svc == MOBILE_IOS:
        clauses.append("type IN ('ios_mobile','ios_backup')")
    elif svc == MOBILE_EXTRACT:
        clauses.append("type IN ('mobile_extraction','android_mobile','ios_mobile','ios_backup','android_backup')")
    elif svc == FORENSIC:
        clauses.append("type NOT IN ('mobile_extraction','android_mobile','ios_mobile','ios_backup','android_backup')")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total_row = fetchone(db, f"SELECT count(*) c FROM jobs {where}", params)
    rows = fetchall(
        db,
        f"SELECT * FROM jobs {where} ORDER BY created_at DESC LIMIT :limit OFFSET :offset",
        params,
    )
    return {
        "items": [_job_row(r) for r in rows],
        "total": int(total_row["c"]) if total_row else 0,
        "page": page,
        "page_size": page_size,
    }


@router.post("/jobs")
def create_job(
    body: JobCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    import json

    svc = current_service()
    job_type = (body.type or "host_disk").strip()
    service_platform = mobile_service_platform(svc)
    # The compact Android/iOS UIs may still submit the legacy generic type.
    # Canonicalize at the API boundary so the DB can never mix platforms.
    if service_platform and job_type == "mobile_extraction":
        job_type = canonical_mobile_job_type(svc) or job_type
    is_mobile = job_type in MOBILE_JOB_TYPES or (
        (body.source_type or "").strip().lower() in {"mobile", "android_backup", "ios_backup"}
    )
    if not service_allows_job_type(
        job_type, body.source_type or "", mobile_os=body.mobile_os or ""
    ):
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "wrong_service",
                    "message": (
                        "This product does not accept that job type. "
                        "Use Disk Forensics for disk images, Android Forensics for Android "
                        "evidence, and iOS Forensics for Apple mobile evidence."
                    ),
                }
            },
        )
    disk_source = None
    if is_mobile:
        from app.services.mobile_capability import evaluate_mobile_capability
        from app.services.mobile_os import build_mobile_disk_source_seed, normalize_mobile_os

        mobile_os = normalize_mobile_os(body.mobile_os)
        if job_type in {"ios_backup", "ios_mobile"} and not mobile_os:
            mobile_os = "ios"
        if job_type in {"android_backup", "android_mobile"} and not mobile_os:
            mobile_os = "android"
        if service_platform:
            if mobile_os and mobile_os != service_platform:
                raise HTTPException(
                    status_code=403,
                    detail={"error": {
                        "code": "mobile_platform_mismatch",
                        "message": f"{service_platform.title()} backend cannot create a {mobile_os} job.",
                    }},
                )
            mobile_os = service_platform
        if not mobile_os:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "code": "mobile_os_required",
                        "message": "Mobile OS selection is required (android, ios, or other).",
                    }
                },
            )
        if not body.legal_authority_acknowledged and job_type in {"mobile_extraction", "android_mobile", "ios_mobile"}:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "code": "legal_ack_required",
                        "message": "Acknowledge legal authority before starting mobile extraction.",
                    }
                },
            )
        capability = evaluate_mobile_capability(
            mobile_os=mobile_os,
            acquisition_mode=body.acquisition_mode or "import",
        )
        disk_source = build_mobile_disk_source_seed(
            mobile_os=mobile_os,
            acquisition_mode=body.acquisition_mode or "import",
            source_type=body.source_type or "mobile",
            legal_authority_acknowledged=bool(body.legal_authority_acknowledged),
            capability=capability,
        )

    if disk_source is not None:
        row = fetchone(
            db,
            """INSERT INTO jobs(type, domain_pack, case_id, created_by, status, disk_source)
               VALUES (:type,:domain_pack,:case_id,:created_by,'created', CAST(:ds AS jsonb)) RETURNING *""",
            {
                "type": job_type,
                "domain_pack": body.domain_pack or "forensic",
                "case_id": body.case_id,
                "created_by": current.user_id,
                "ds": json.dumps(disk_source),
            },
        )
        try:
            from app.services.mobile_intake_defaults import ensure_mobile_intake_defaults

            ensure_mobile_intake_defaults(
                db,
                str(row["id"]),
                mobile_os=str(disk_source.get("mobile_os") or ""),
            )
        except Exception:
            pass
        evidence_path = (body.evidence_path or "").strip()
        if evidence_path:
            # Do NOT list/register synchronously here: a 100 GiB phone tree on a
            # bind mount used to hold this POST for hours and surface as gateway
            # 502s. Persist the folder; the job page registers it (fast path via
            # export_catalog.json) and the worker re-registers from the saved
            # folder if the UI never gets there.
            try:
                from app.services.host_evidence import persist_job_evidence_folder

                persist_job_evidence_folder(db, str(row["id"]), evidence_path)
            except Exception as exc:
                import logging

                logging.getLogger("jobs").warning(
                    "could not persist evidence folder for job %s: %s", row["id"], exc
                )
    else:
        row = fetchone(
            db,
            """INSERT INTO jobs(type, domain_pack, case_id, created_by, status)
               VALUES (:type,:domain_pack,:case_id,:created_by,'created') RETURNING *""",
            {
                "type": job_type,
                "domain_pack": body.domain_pack,
                "case_id": body.case_id,
                "created_by": current.user_id,
            },
        )
    db.commit()
    return _job_row(row)


@router.delete("/jobs/{job_id}")
def delete_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Hard-delete a job id and every related file, object, and database row."""
    from app.services.job_delete import hard_delete_job

    _ensure_job(db, job_id)
    try:
        return hard_delete_job(db, job_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": "Job not found"}},
        ) from None
    except Exception as exc:
        log.exception("hard delete failed for job %s", job_id)
        raise HTTPException(
            status_code=500,
            detail={
                "error": {
                    "code": "delete_failed",
                    "message": f"Job could not be deleted: {exc}",
                }
            },
        ) from exc


@router.get("/jobs/{job_id}")
def get_job(
    job_id: str,
    sync_progress: bool = Query(
        False,
        description="Run expensive inventory/enrichment reconciliation. Normal UI polling keeps this false.",
    ),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.db.session import apply_firm_search_path

    schema = _schema_name(db, current)
    row = dict(_ensure_job(db, job_id))
    files = fetchall(db, "SELECT original_name, status FROM evidence_files WHERE job_id=:job_id", {"job_id": job_id})
    row["segment_readiness"] = segment_readiness(files)
    row["evidence_count"] = len(files)

    # The detail page polls while extraction/parsing is active.  Historically this
    # GET executed multiple full-table COUNTs, inventory repair, progress merge and
    # commits on every poll.  With hundreds of thousands of artifacts that made a
    # read endpoint compete with Celery for PostgreSQL and could make the UI appear
    # hung.  Workers already persist status/progress; return that state by default.
    # Expensive reconciliation remains explicitly available for diagnostics/manual
    # refresh via ?sync_progress=true and the inventory refresh endpoint.
    if not sync_progress:
        return _job_row(row)

    enrichment = None
    try:
        enrichment = _enrichment_snapshot(db, job_id)
    except Exception:
        log.exception("enrichment snapshot failed for job %s", job_id)
        db.rollback()
        apply_firm_search_path(db, schema)

    skip_pipeline_sync = False
    try:
        from app.services.axiom_artifact_runner import should_skip_pipeline_sync_on_read

        skip_pipeline_sync = should_skip_pipeline_sync_on_read(db, job_id, row=row)
    except Exception:
        log.exception("pipeline sync skip check failed for job %s", job_id)
        db.rollback()
        apply_firm_search_path(db, schema)

    try:
        from app.services.axiom_artifact_runner import parse_pending_count
        from app.services.pipeline_orchestrator import build_orchestration_progress_snapshot

        pending_parse = parse_pending_count(db, job_id)
        status_l = (row.get("status") or "").lower()
        if skip_pipeline_sync or (pending_parse > 0 and status_l == "indexing"):
            snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
            if snapshot:
                row["pipeline_progress"] = snapshot
                row["progress_pct"] = int(snapshot.get("progress_pct") or row.get("progress_pct") or 0)
        elif not skip_pipeline_sync:
            from app.services.axiom_artifact_runner import (
                axiom_inventory_progress,
                ensure_artifact_inventory,
                sync_inventory_pipeline_progress,
            )
            from app.services.pipeline_orchestrator import merge_orchestration_into_progress

            synced = sync_inventory_pipeline_progress(db, job_id)
            if synced:
                db.commit()
                apply_firm_search_path(db, schema)
                row = dict(_ensure_job(db, job_id))
                row["segment_readiness"] = segment_readiness(files)
                row["pipeline_progress"] = synced
            # Resume counting when catalog still has pending artifacts after a premature ready/complete.
            inv_live = axiom_inventory_progress(db, job_id)
            if int(inv_live.get("total") or 0) > 0 and not inv_live.get("done"):
                try:
                    ensure_artifact_inventory(db, job_id, schema_name=schema)
                    apply_firm_search_path(db, schema)
                except Exception:
                    log.exception("ensure_artifact_inventory failed for job %s", job_id)
                    db.rollback()
                    apply_firm_search_path(db, schema)
            merged = merge_orchestration_into_progress(db, job_id)
            if merged:
                db.commit()
                apply_firm_search_path(db, schema)
                row = dict(_ensure_job(db, job_id))
                row["segment_readiness"] = segment_readiness(files)
                row["pipeline_progress"] = merged
    except Exception:
        log.exception("pipeline progress sync failed for job %s", job_id)
        db.rollback()
        apply_firm_search_path(db, schema)
        try:
            from app.services.pipeline_orchestrator import build_orchestration_progress_snapshot

            snapshot = build_orchestration_progress_snapshot(db, job_id, row=row)
            if snapshot:
                row["pipeline_progress"] = snapshot
                row["progress_pct"] = int(snapshot.get("progress_pct") or row.get("progress_pct") or 0)
        except Exception:
            log.exception("pipeline progress snapshot fallback failed for job %s", job_id)
            db.rollback()
            apply_firm_search_path(db, schema)

    return _job_row(row, enrichment=enrichment)


@router.get("/jobs/{job_id}/mobile/artifact-board")
def mobile_artifact_board(
    job_id: str,
    refresh: bool = False,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Mobile artifact inventory board: count, description, path, openable evidence ids."""
    from app.services.mobile_forensic.inventory import (
        build_mobile_inventory_snapshot,
        clear_mobile_inventory_cache,
        persist_mobile_inventory_snapshot,
    )

    _ensure_job(db, job_id)
    # Refresh re-scans .pas/.ufd/.ufdx/.zip packages; default GET stays cache-friendly.
    if refresh:
        clear_mobile_inventory_cache(job_id)
    snap = build_mobile_inventory_snapshot(db, job_id, force=bool(refresh))
    try:
        persist_mobile_inventory_snapshot(db, job_id, force=bool(refresh))
        db.commit()
    except Exception:
        db.rollback()
    counts = dict(snap.get("counts") or {})
    samples = snap.get("samples") or {}
    platform = str(snap.get("platform") or "iOS")

    # Normalized mobile artifacts are the authoritative post-parse counts.  Merge
    # them with package/file inventory counts so the board does not hide evidence
    # that was parsed from SQLite rows (WhatsApp/SMS/calls/deleted records).
    normalized_analysis: dict[str, Any] = {}
    try:
        from app.services.mobile_forensic.storage import artifact_counts_by_domain

        normalized_analysis = artifact_counts_by_domain(db, job_id)
        fam_counts = normalized_analysis.get("by_family") or {}
        recovered_by_family = normalized_analysis.get("recovered_by_family") or {}
        recovered_by_app = normalized_analysis.get("recovered_by_app") or {}
        family_map = {
            "whatsapp_messages": "whatsapp_messages",
            "whatsapp_chats": "whatsapp_chats",
            "whatsapp_contacts": "whatsapp_contacts",
            "whatsapp_calls": "whatsapp_calls",
            "whatsapp_media": "whatsapp_media",
            "whatsapp_encrypted_backups": "whatsapp_encrypted_backups",
            "deleted_whatsapp": "whatsapp_deleted_messages",
            "sms": "sms",
            "mms": "sms",
            "call_logs": "call_logs",
            "contacts": "contacts",
            "browser_history": "browser",
            "documents": "documents",
            "telegram_messages": "telegram",
            "signal_messages": "signal",
            "instagram_messages": "instagram",
            "facebook_messages": "facebook",
            "linkedin_messages": "linkedin",
        }
        # Theme/sticker .crypt14 files are stored in the same family as msgstore
        # backups. Only names that contain msgstore are chat databases.
        inventory_crypt = int(counts.get("whatsapp_encrypted_backups") or 0)
        for source_family, board_key in family_map.items():
            if source_family == "whatsapp_encrypted_backups":
                continue
            n = int(fam_counts.get(source_family) or 0)
            if n > int(counts.get(board_key) or 0):
                counts[board_key] = n
        msgstore_norm = 0
        try:
            from app.db.sql_helpers import fetchall as _crypt_fetchall

            crypt_rows = _crypt_fetchall(
                db,
                """SELECT count(*)::int AS c FROM mobile_normalized_artifacts
                   WHERE job_id=:jid
                     AND COALESCE(data->>'artifact_family','') = 'whatsapp_encrypted_backups'
                     AND (
                       lower(COALESCE(data->>'name','')) LIKE '%msgstore%'
                       OR lower(COALESCE(data->>'path','')) LIKE '%msgstore%'
                     )""",
                {"jid": job_id},
            )
            if crypt_rows:
                msgstore_norm = int(crypt_rows[0].get("c") or 0)
        except Exception:
            msgstore_norm = 0
        counts["whatsapp_encrypted_backups"] = max(inventory_crypt, msgstore_norm)

        # Deleted/recovered records are a separate examiner-facing count.  A live
        # family (for example whatsapp_messages) may contain rows explicitly marked
        # database_deleted, while residual-carve analyzers emit deleted_* families.
        deleted_family_map = {
            "deleted_whatsapp": "whatsapp_deleted_messages",
            "deleted_social": "deleted_social",
            "deleted_files": "deleted_files",
            "deleted_photos": "deleted_photos",
            "deleted_videos": "deleted_videos",
            "deleted_documents": "deleted_documents",
            "telegram_deleted": "telegram_deleted",
            "signal_deleted": "signal_deleted",
            "instagram_deleted": "instagram_deleted",
            "facebook_deleted": "facebook_deleted",
            "snapchat_deleted": "snapchat_deleted",
            "discord_deleted": "discord_deleted",
            "viber_deleted": "viber_deleted",
            "wechat_deleted": "wechat_deleted",
            "line_deleted": "line_deleted",
            "tiktok_deleted": "tiktok_deleted",
            "linkedin_deleted": "linkedin_deleted",
            "sms_deleted": "sms_deleted",
            "slack_deleted": "slack_deleted",
            "teams_deleted": "teams_deleted",
            "skype_deleted": "skype_deleted",
        }
        for source_family, board_key in deleted_family_map.items():
            n = int(recovered_by_family.get(source_family) or fam_counts.get(source_family) or 0)
            counts[board_key] = max(int(counts.get(board_key) or 0), n)

        # Explicitly deleted WhatsApp rows retain the whatsapp_messages family.
        wa_deleted_flagged = int(
            (normalized_analysis.get("by_family_state") or {}).get("whatsapp_messages::database_deleted") or 0
        )
        # unverified crypt backups are application=whatsapp. They are not deleted chats.
        counts["whatsapp_deleted_messages"] = max(
            int(counts.get("whatsapp_deleted_messages") or 0),
            wa_deleted_flagged,
        )
        app_deleted_map = {
            "telegram": "telegram_deleted", "signal": "signal_deleted",
            "instagram": "instagram_deleted", "facebook": "facebook_deleted",
            "facebook_messenger": "facebook_deleted", "snapchat": "snapchat_deleted",
            "discord": "discord_deleted", "viber": "viber_deleted",
            "wechat": "wechat_deleted", "line": "line_deleted",
            "tiktok": "tiktok_deleted", "linkedin": "linkedin_deleted",
            "sms": "sms_deleted", "slack": "slack_deleted",
            "teams": "teams_deleted", "skype": "skype_deleted",
        }
        for app_name, board_key in app_deleted_map.items():
            counts[board_key] = max(
                int(counts.get(board_key) or 0), int(recovered_by_app.get(app_name) or 0)
            )
    except Exception:
        normalized_analysis = {}
    # Map board family → likely AXIOM catalog artifact name for browse deep-link.
    _FAMILY_CATALOG_HINTS: dict[str, tuple[str, ...]] = {
        "whatsapp_messages": ("WhatsApp Messages", "WhatsApp", "WhatsApp Chats"),
        "whatsapp_chats": ("WhatsApp Chats", "WhatsApp Messages", "WhatsApp"),
        "whatsapp_calls": ("WhatsApp Calls", "WhatsApp"),
        "whatsapp_contacts": ("WhatsApp Contacts", "WhatsApp"),
        "whatsapp_groups": ("WhatsApp Groups", "WhatsApp"),
        "whatsapp_media": ("WhatsApp Media", "WhatsApp", "WhatsApp Messages"),
        "whatsapp_encrypted_backups": (
            "WhatsApp Encrypted Backups",
            "WhatsApp Media",
            "WhatsApp Messages",
        ),
        "whatsapp_deleted_messages": ("WhatsApp Messages", "WhatsApp"),
        "sms": ("SMS Messages", "Android SMS", "SMS/MMS", "iMessage"),
        "sms_chats": ("SMS Messages", "Android SMS", "iMessage"),
        "call_logs": ("Call Logs", "Android Call Logs"),
        "telegram": ("Telegram", "Telegram Messages"),
        "signal": ("Signal", "Signal Messages"),
        "linkedin": ("LinkedIn", "LinkedIn Messages"),
        "facebook": ("Facebook Messenger", "Facebook", "Messenger"),
        "instagram": ("Instagram", "Instagram Messages"),
        "emails": ("Email", "Emails", "Gmail", "Apple Mail"),
        "email_attachments": ("Email Attachments", "Email Attachment"),
        "sms_attachments": ("SMS Messages", "iMessage", "SMS/MMS"),
        "browser": ("Browser History", "Safari History", "Chrome History", "Web History"),
    }
    catalog_key_by_family: dict[str, str | None] = {}
    try:
        from app.db.sql_helpers import fetchall as _fetchall

        ax_rows = _fetchall(
            db,
            """SELECT artifact_id, artifact_name FROM public.axiom_artifacts
               WHERE platform=:p""",
            {"p": platform},
        )
        by_name = {
            str(r.get("artifact_name") or "").strip().lower(): str(r.get("artifact_id"))
            for r in ax_rows
        }
        for fam, hints in _FAMILY_CATALOG_HINTS.items():
            catalog_key_by_family[fam] = None
            for hint in hints:
                aid = by_name.get(hint.lower())
                if aid:
                    catalog_key_by_family[fam] = aid
                    break
            if not catalog_key_by_family[fam]:
                # Fuzzy: first artifact whose name contains the family token
                token = fam.split("_")[0]
                for n, aid in by_name.items():
                    if token in n:
                        catalog_key_by_family[fam] = aid
                        break
    except Exception:
        catalog_key_by_family = {}
    _BOARD_META = {
        "whatsapp_deleted_messages": (
            "WhatsApp Deleted Messages",
            "Deleted",
            "Deleted WhatsApp messages from DB flags/tables + freelist/WAL residuals",
        ),
        "deleted_photos": (
            "Deleted Photos",
            "Deleted",
            "Photos under trash / .trashed-* / deleted_recovery paths",
        ),
        "deleted_videos": (
            "Deleted Videos",
            "Deleted",
            "Videos under trash / .trashed-* / deleted_recovery paths",
        ),
        "deleted_documents": (
            "Deleted Documents",
            "Deleted",
            "Documents under trash / .trashed-* / deleted_recovery paths",
        ),
        "deleted_social": (
            "Deleted Social / Chat Data",
            "Deleted",
            "Deleted/residual chat evidence across messaging apps",
        ),
        "deleted_chat_residuals": (
            "Deleted Chat Residuals (all apps)",
            "Deleted",
            "Chat-like strings carved from messaging SQLite freelist/WAL pages",
        ),
        "deleted_files": (
            "Deleted Files (all types)",
            "Deleted",
            "Trashed / Recycle Bin / .trashed-* / freelist-recovered files",
        ),
        "critical_files": (
            "Deleted / Modified / Anomalous Files",
            "Deleted",
            "Cross-platform critical files: deleted, modified, extensionless, spoofed extensions (Win/iOS/Linux)",
        ),
        "anomalous_files": (
            "Anomalous Files (ext mismatch / extensionless)",
            "Deleted",
            "Extensionless, double-extension, or magic vs declared extension mismatches",
        ),
        "modified_files": (
            "Modified / Renamed / ADS Files",
            "Deleted",
            "Renamed recoveries, Zone.Identifier, MFT/unallocated, trash original-name diffs",
        ),
        "deleted_with_dates": (
            "Deleted Items With Dates",
            "Deleted",
            "Deleted items where a deletion timestamp was recovered",
        ),
        "telegram_deleted": ("Telegram Deleted / Residuals", "Deleted", "Telegram freelist/WAL residuals"),
        "signal_deleted": ("Signal Deleted / Residuals", "Deleted", "Signal freelist/WAL residuals"),
        "instagram_deleted": ("Instagram Deleted / Residuals", "Deleted", "Instagram freelist/WAL residuals"),
        "facebook_deleted": (
            "Facebook/Messenger Deleted / Residuals",
            "Deleted",
            "Facebook/Messenger freelist/WAL residuals",
        ),
        "snapchat_deleted": ("Snapchat Deleted / Residuals", "Deleted", "Snapchat freelist/WAL residuals"),
        "discord_deleted": ("Discord Deleted / Residuals", "Deleted", "Discord freelist/WAL residuals"),
        "viber_deleted": ("Viber Deleted / Residuals", "Deleted", "Viber freelist/WAL residuals"),
        "wechat_deleted": ("WeChat Deleted / Residuals", "Deleted", "WeChat freelist/WAL residuals"),
        "line_deleted": ("LINE Deleted / Residuals", "Deleted", "LINE deleted rows and freelist/WAL residuals"),
        "tiktok_deleted": ("TikTok Deleted / Residuals", "Deleted", "TikTok deleted rows and freelist/WAL residuals"),
        "linkedin_deleted": ("LinkedIn Deleted / Residuals", "Deleted", "LinkedIn deleted rows and freelist/WAL residuals"),
        "sms_deleted": ("Deleted SMS / MMS", "Deleted", "Deleted or residual SMS/MMS content recovered from message databases"),
        "slack_deleted": ("Slack Deleted / Residuals", "Deleted", "Slack deleted rows and SQLite residuals"),
        "teams_deleted": ("Teams Deleted / Residuals", "Deleted", "Teams deleted rows and SQLite residuals"),
        "skype_deleted": ("Skype Deleted / Residuals", "Deleted", "Skype deleted rows and SQLite residuals"),
    }
    _COMM = {
        "whatsapp_messages",
        "whatsapp_chats",
        "whatsapp_calls",
        "whatsapp_contacts",
        "whatsapp_groups",
        "whatsapp_media",
        "whatsapp_encrypted_backups",
        "whatsapp_deleted_messages",
        "sms",
        "sms_chats",
        "call_logs",
        "telegram",
        "signal",
        "instagram",
        "facebook",
        "linkedin",
        "deleted_social",
        "deleted_chat_residuals",
        "telegram_deleted",
        "signal_deleted",
        "instagram_deleted",
        "facebook_deleted",
        "snapchat_deleted",
        "discord_deleted",
        "viber_deleted",
        "wechat_deleted",
        "line_deleted",
        "tiktok_deleted",
        "linkedin_deleted",
        "sms_deleted",
        "slack_deleted",
        "teams_deleted",
        "skype_deleted",
    }
    # Path/token filters so Open can list the matching evidence set in the browse panel.
    _FAMILY_BROWSE_Q: dict[str, str] = {
        "deleted_files": "trashed",
        "deleted_photos": "trashed",
        "deleted_videos": "trashed",
        "deleted_documents": "trashed",
        "deleted_social": "whatsapp",
        "deleted_chat_residuals": "databases",
        "deleted_with_dates": "trashed",
        "whatsapp_deleted_messages": "whatsapp",
        "whatsapp_messages": "whatsapp",
        "whatsapp_chats": "whatsapp",
        "whatsapp_calls": "whatsapp",
        "whatsapp_contacts": "whatsapp",
        "whatsapp_groups": "whatsapp",
        "whatsapp_media": "whatsapp",
        "whatsapp_encrypted_backups": "whatsapp",
        "telegram": "telegram",
        "telegram_deleted": "telegram",
        "signal": "signal",
        "signal_deleted": "signal",
        "instagram": "instagram",
        "instagram_deleted": "instagram",
        "facebook": "facebook",
        "facebook_deleted": "facebook",
        "snapchat_deleted": "snapchat",
        "discord_deleted": "discord",
        "viber_deleted": "viber",
        "wechat_deleted": "wechat",
        "sms": "mmssms",
        "sms_chats": "mmssms",
        "call_logs": "calllog",
        "pictures": "DCIM",
        "videos": ".mp4",
        "audio": ".opus",
        "documents": ".pdf",
        "emails": "mail",
        "linkedin": "linkedin",
        "browser": "History",
    }

    def _browse_q_for(key: str, sample_paths: list[str]) -> str | None:
        hinted = _FAMILY_BROWSE_Q.get(key)
        if hinted:
            return hinted
        # Fall back to a distinctive path fragment from the sample so browse is never empty.
        for p in sample_paths or []:
            name = str(p).replace("\\", "/").rstrip("/").split("/")[-1]
            if name and len(name) >= 4:
                return name[:80]
        return None

    def _sample_pair(key: str) -> tuple[list[str], list[str]]:
        raw = samples.get(key, ([], []))
        if isinstance(raw, dict):
            return (
                [str(p) for p in (raw.get("paths") or []) if p],
                [str(i) for i in (raw.get("ids") or []) if i],
            )
        if isinstance(raw, (list, tuple)) and len(raw) >= 2:
            return list(raw[0] or []), list(raw[1] or [])
        if isinstance(raw, list):
            return list(raw), []
        return [], []

    rows = []
    family_keys_seen: set[str] = set()
    # WhatsApp / communication first — deleted zeros used to bury live media + backups.
    ordered_keys = list(counts.keys())
    _COMM_FIRST = (
        "whatsapp_messages",
        "whatsapp_chats",
        "whatsapp_encrypted_backups",
        "whatsapp_media",
        "whatsapp_calls",
        "whatsapp_contacts",
        "whatsapp_groups",
        "sms",
        "sms_chats",
        "call_logs",
        "telegram",
        "signal",
        "instagram",
        "facebook",
        "linkedin",
    )
    _MEDIA_FIRST = ("pictures", "videos", "audio", "documents")
    deleted_keys = [
        k
        for k in ordered_keys
        if k.startswith("deleted") or k.endswith("_deleted") or "deleted_" in k
    ]
    comm = [k for k in _COMM_FIRST if k in counts]
    media = [k for k in _MEDIA_FIRST if k in counts]
    seen_order = set(comm) | set(media) | set(deleted_keys)
    other = [k for k in ordered_keys if k not in seen_order]
    _HIDE_ZERO_APP_DELETED: set[str] = set()
    for key in comm + media + other + deleted_keys:
        family_keys_seen.add(key)
        val = counts.get(key)
        sample_paths, sample_ids = _sample_pair(key)
        # Last-chance id heal when paths exist (e.g. stale in-memory cache).
        if sample_paths and not sample_ids:
            try:
                from app.services.mobile_forensic.inventory import _heal_sample_ids

                snap = _heal_sample_ids(db, job_id, snap)
                samples = snap.get("samples") or samples
                sample_paths, sample_ids = _sample_pair(key)
            except Exception:
                pass
        _LIVE_META: dict[str, tuple[str, str, str]] = {
            "whatsapp_messages": (
                "WhatsApp Messages",
                "Communication",
                "Live WhatsApp chat messages from ChatStorage.sqlite / msgstore.db (not encrypted .enc backups)",
            ),
            "whatsapp_chats": (
                "WhatsApp Chats",
                "Communication",
                "WhatsApp conversations / chat sessions from the live message store",
            ),
            "whatsapp_calls": (
                "WhatsApp Calls",
                "Communication",
                "WhatsApp call-log rows from ChatStorage / CallHistory (plaintext SQLite only)",
            ),
            "whatsapp_contacts": (
                "WhatsApp Contacts",
                "Communication",
                "WhatsApp contact / JID identity rows from the live store",
            ),
            "whatsapp_groups": (
                "WhatsApp Groups",
                "Communication",
                "WhatsApp group chats recovered from the live message store",
            ),
            "whatsapp_media": (
                "WhatsApp Media",
                "Media",
                "Photos/videos/audio under WhatsApp media paths in this acquisition",
            ),
            "whatsapp_encrypted_backups": (
                "WhatsApp Encrypted Backups",
                "Communication",
                "Encrypted WhatsApp backups (.crypt12/14/15 or .enc) — need device key to decrypt",
            ),
            "sms": ("SMS / iMessage", "Communication", "SMS/MMS/iMessage rows from the device message database"),
            "sms_chats": ("SMS Conversations", "Communication", "SMS/iMessage conversation threads"),
            "sms_attachments": (
                "SMS / MMS Attachments",
                "Communication",
                "MMS / iMessage attachment records from sms.db (not email)",
            ),
            "email_attachments": (
                "Email Attachments",
                "Communication",
                "MIME / mail-store attachment files (not SMS/MMS attachment rows)",
            ),
            "call_logs": ("Call Logs", "Communication", "Phone call history from the telephony database"),
            "contacts": ("Contacts", "Accounts", "Address book / contacts from the device store"),
            "emails": ("Email", "Communication", "Cached email messages from Mail / Gmail indexes"),
            "pictures": ("Pictures", "Media", "Existing photo files (JPG/HEIC/PNG) — not trash; see Deleted Photos for recovered"),
            "videos": ("Videos", "Media", "Existing video files (MP4/MOV/…) — not trash; see Deleted Videos for recovered"),
            "audio": ("Audio", "Media", "Existing audio files recovered from the acquisition"),
            "documents": ("Documents", "Files", "Existing documents (PDF/Office/…) — not trash; see Deleted Documents for recovered"),
            "installed_apps": ("Installed Apps", "Device", "Installed application packages / app metadata"),
            "telegram": ("Telegram", "Communication", "Telegram message databases when present in the dump"),
            "signal": ("Signal", "Communication", "Signal message databases when present in the dump"),
            "instagram": ("Instagram", "Communication", "Instagram / social app databases when present"),
            "facebook": (
                "Facebook / Messenger",
                "Communication",
                "Facebook/Messenger databases (iOS fb-msys / Android orca) when present",
            ),
            "linkedin": (
                "LinkedIn",
                "Communication",
                "LinkedIn app databases when present in the dump",
            ),
            "browser": (
                "Browser History",
                "Activity",
                "Visited URLs from Safari/Chrome/Firefox/Google history and links in SMS/WhatsApp, with content type",
            ),
            "device_info": ("Device Info", "Device", "Device/OS metadata from the acquisition"),
        }
        # Collapse overlapping families so the board does not list the same evidence twice.
        # Prefer messages over "conversations/chats"; prefer deleted_social over residuals alias.
        label, category, description = _BOARD_META.get(key) or _LIVE_META.get(
            key,
            (
                key.replace("_", " ").title(),
                "Communication" if key in _COMM else "Mobile",
                "Parsed / counted from mobile evidence (.pas/.ufd/.ufdx/.zip FileDump)",
            ),
        )
        if key in _COMM and key not in _BOARD_META and key not in _LIVE_META:
            category = "Communication"
        # Fold conversation counts into the primary message-family description.
        if key == "sms" and int(counts.get("sms_chats") or 0) > 0:
            description = (
                f"{description} · {int(counts['sms_chats']):,} conversation thread(s)"
            )
        if key == "whatsapp_messages" and int(counts.get("whatsapp_chats") or 0) > 0:
            description = (
                f"{description} · {int(counts['whatsapp_chats']):,} chat conversation(s)"
            )
        if (
            key == "whatsapp_messages"
            and int(val or 0) == 0
            and int(counts.get("whatsapp_encrypted_backups") or 0) > 0
        ):
            try:
                from app.services.mobile_forensic.sqlite_counts import describe_whatsapp_key_gap

                description = describe_whatsapp_key_gap(
                    db,
                    job_id,
                    backup_count=int(counts["whatsapp_encrypted_backups"]),
                )
            except Exception:
                description = (
                    f"No plaintext chat rows yet — {int(counts['whatsapp_encrypted_backups']):,} "
                    "encrypted msgstore backup(s) collected. Device key "
                    "(/data/data/com.whatsapp/files/key) is required to decrypt chats."
                )
        rows.append(
            {
                "key": key,
                "label": label,
                "category": category,
                "count": int(val or 0),
                "description": description,
                "available": int(val or 0) > 0
                or key == "browser"
                or (
                    key == "whatsapp_messages"
                    and int(counts.get("whatsapp_encrypted_backups") or 0) > 0
                ),
                "sample_paths": list(sample_paths or []),
                "primary_path": (sample_paths or [None])[0],
                "artifact_ids": list(sample_ids or []),
                "primary_artifact_id": (sample_ids or [None])[0],
                "catalog_key": catalog_key_by_family.get(key),
                "browse_query": _browse_q_for(key, list(sample_paths or [])),
                "limitation": None if int(val or 0) > 0 else next(
                    (
                        x
                        for x in (snap.get("limitations") or [])
                        if key.split("_")[0] in x.lower() or (key == "browser" and "browser" in x.lower())
                    ),
                    (snap.get("limitations") or [None])[0],
                ),
            }
        )

    # Disk-parity: also surface AXIOM catalog artifacts (with persisted/mapped counts)
    # so Mobile inventory shows the same artifact set examiners use on disk jobs.
    try:
        from app.db.sql_helpers import fetchall as _fetchall
        from app.services.mobile_forensic.inventory import _map_axiom_name_to_key

        ax_catalog = _fetchall(
            db,
            """SELECT a.artifact_id, a.artifact_name, a.category, a.description,
                      COALESCE(r.artifact_count, 0) AS artifact_count
               FROM public.axiom_artifacts a
               LEFT JOIN job_axiom_artifact_results r
                 ON r.artifact_id = a.artifact_id AND r.job_id = :jid
               WHERE a.platform = :p
               ORDER BY a.category, a.artifact_name""",
            {"jid": job_id, "p": platform},
        )
        # Show every distinct mobile catalog artifact name, including zero-count rows.
        # Internal catalog identifiers remain implementation details and are not shown in UI.
        seen_labels = {str(r.get("label") or "").strip().lower() for r in rows}
        for ax in ax_catalog:
            name = str(ax.get("artifact_name") or "").strip()
            if not name:
                continue
            # Skip catalog rows that duplicate a live family label.
            if name.strip().lower() in seen_labels:
                continue
            fam = _map_axiom_name_to_key(name)
            stored_n = int(ax.get("artifact_count") or 0)
            mapped_n = int(counts.get(fam) or 0) if fam else 0
            n = max(stored_n, mapped_n)
            key = f"axiom:{ax.get('artifact_id')}"
            if key in family_keys_seen:
                continue
            family_keys_seen.add(key)
            sample_paths, sample_ids = _sample_pair(fam) if fam else ([], [])
            rows.append(
                {
                    "key": key,
                    "label": name,
                    "category": str(ax.get("category") or "Artifacts"),
                    "count": n,
                    "description": str(ax.get("description") or "Mobile forensic artifact"),
                    "available": n > 0,
                    "sample_paths": list(sample_paths or []),
                    "primary_path": (sample_paths or [None])[0],
                    "artifact_ids": list(sample_ids or []),
                    "primary_artifact_id": (sample_ids or [None])[0],
                    "catalog_key": str(ax.get("artifact_id")),
                    "browse_query": _browse_q_for(fam or key, list(sample_paths or [])),
                    "limitation": None,
                }
            )
    except Exception:
        pass

    return {
        "job_id": job_id,
        "total_files": snap.get("total_files") or 0,
        "families_available": sum(1 for r in rows if int(r.get("count") or 0) > 0),
        "families_total": len(rows),
        "acquisition_methods": [],
        "mtp_only": False,
        "rows": rows,
        "limitations": snap.get("limitations") or [],
        "db_paths": snap.get("db_paths") or {},
        "note": (
            "Counts use mobile forensic sources from .pas/.ufd/.ufdx/.zip packages and sealed "
            "extractions, including application databases, SQLite WAL/journal/freelist recovery, "
            "SMS/call-log tables, media inventory, and deleted/residual records when present. "
            "Logical acquisitions can only recover deleted content that still exists in the acquired data."
        ),
        "packages_scanned": int((snap.get("package") or {}).get("packages_scanned") or 0),
        "normalized_analysis": normalized_analysis or snap.get("normalized_analysis") or {},
        "coverage": (normalized_analysis or {}).get("coverage") or [],
    }


@router.get("/jobs/{job_id}/mobile/normalized-artifacts")
def mobile_normalized_artifacts(
    job_id: str,
    domain: str | None = None,
    state: str | None = None,
    ui_label: str | None = Query(None, description="CURRENT|HISTORICAL|RECOVERED|FRAGMENT|UNVERIFIED|…"),
    filter: str | None = Query(
        None,
        description="UI filter bucket: LIVE|HISTORICAL|RECOVERED|FRAGMENTS|UNVERIFIED",
    ),
    limit: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Normalized mobile artifacts with forensic state/provenance (examiner board)."""
    from app.services.mobile_forensic.models import UI_STATE_LABELS
    from app.services.mobile_forensic.storage import (
        artifact_counts_by_domain,
        ensure_mobile_case_schema,
        list_artifacts,
    )

    _ensure_job(db, job_id)
    ensure_mobile_case_schema(db)

    # Map examiner filter buckets → ui_label / state sets
    ui = ui_label
    st = state
    if filter:
        bucket = filter.strip().upper()
        if bucket == "LIVE":
            ui = "CURRENT"
            st = st or "allocated"
        elif bucket == "HISTORICAL":
            ui = "HISTORICAL"
        elif bucket == "RECOVERED":
            ui = "RECOVERED"
        elif bucket == "FRAGMENTS":
            ui = "FRAGMENT"
        elif bucket == "UNVERIFIED":
            ui = "UNVERIFIED"

    if filter and filter.strip().upper() == "RECOVERED":
        extra = []
        for lab in ("RECOVERED", "ORPHANED", "DELETED-SUPPORTED", "CACHE-DERIVED"):
            extra.extend(
                list_artifacts(db, job_id, domain=domain, ui_label=lab, limit=limit, offset=0)
            )
        seen: set[str] = set()
        rows = []
        for r in extra:
            aid = str(r.get("artifact_id") or "")
            if aid and aid not in seen:
                seen.add(aid)
                rows.append(r)
            if len(rows) >= limit:
                break
    else:
        rows = list_artifacts(
            db, job_id, domain=domain, state=st, ui_label=ui, limit=limit, offset=offset
        )

    return {
        "job_id": job_id,
        "filter": filter,
        "domain": domain,
        "state": st,
        "ui_label": ui,
        "ui_labels": UI_STATE_LABELS,
        "counts": artifact_counts_by_domain(db, job_id),
        "total": len(rows),
        "artifacts": rows,
    }


@router.get("/jobs/{job_id}/mobile/timeline")
def mobile_timeline(
    job_id: str,
    limit: int = Query(1000, ge=1, le=20000),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.services.mobile_forensic.storage import ensure_mobile_case_schema, timeline_rows

    _ensure_job(db, job_id)
    ensure_mobile_case_schema(db)
    events = timeline_rows(db, job_id, limit=limit)
    return {"job_id": job_id, "total": len(events), "events": events}


@router.post("/jobs/{job_id}/mobile/artifacts/{artifact_id}/review")
def mobile_artifact_review(
    job_id: str,
    artifact_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Examiner accept / reject / annotate a recovered or ambiguous artifact."""
    from app.services.mobile_forensic.storage import ensure_mobile_case_schema, save_examiner_review

    _ensure_job(db, job_id)
    ensure_mobile_case_schema(db)
    decision = str((body or {}).get("decision") or "").strip().lower()
    if decision not in ("accepted", "rejected", "annotated", "pending_review"):
        raise HTTPException(status_code=400, detail="decision must be accepted|rejected|annotated|pending_review")
    note = (body or {}).get("note")
    examiner = (body or {}).get("examiner") or getattr(current, "email", None) or getattr(current, "username", None)
    save_examiner_review(
        db,
        job_id,
        artifact_id,
        decision=decision,
        note=str(note) if note is not None else None,
        examiner=str(examiner) if examiner else None,
    )
    db.commit()
    return {"job_id": job_id, "artifact_id": artifact_id, "decision": decision}


@router.post("/jobs/{job_id}/mobile/analysis/run")
def mobile_analysis_run(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Queue discovery → domain parsers → recovery (mobile-build worker)."""
    from app.tasks import mobile_analysis_task

    _ensure_job(db, job_id)
    from app.services.forensic_serial_policy import serial_enabled

    if serial_enabled():
        from app.services.forensic_serial_pipeline import ensure_serial_schema, stage_rows, start_serial_pipeline

        ensure_serial_schema(db)
        if any(row.get("status") in {"queued", "running"} for row in stage_rows(db, job_id)):
            raise HTTPException(status_code=409, detail="Mobile evidence processing is active. Reprocess after it becomes idle so existing evidence work is not reset while running.")
        return start_serial_pipeline(db, job_id, schema_name=current.schema_name, retry_failed=True, reprocess=True)
    mobile_analysis_task.delay(current.schema_name, job_id)
    return {"status": "queued", "job_id": job_id}


@router.get("/jobs/{job_id}/mobile/case-package")
def mobile_case_package_export(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Download ZIP case package (manifest/source/inventory/parsed/recovered/reports)."""
    from pathlib import Path
    import tempfile

    from fastapi.responses import FileResponse

    from app.services.mobile_forensic.case_export import build_case_package_zip

    _ensure_job(db, job_id)
    tmp = Path(tempfile.gettempdir()) / f"aetheris_case_{job_id[:8]}.zip"
    meta = build_case_package_zip(db, job_id, tmp)
    return FileResponse(
        path=str(tmp),
        filename=f"mobile_case_{job_id[:8]}.zip",
        media_type="application/zip",
        headers={"X-Aetheris-Export-Files": str(meta.get("file_count") or 0)},
    )


@router.post("/jobs/{job_id}/artifact-inventory/refresh")
def refresh_artifact_inventory_progress(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Reload artifact inventory counts from the database without re-running inventory."""
    from app.services.axiom_artifact_runner import refresh_stored_artifact_progress

    _ensure_job(db, job_id)
    result = refresh_stored_artifact_progress(db, job_id)
    db.commit()
    row = dict(_ensure_job(db, job_id))
    files = fetchall(db, "SELECT original_name, status FROM evidence_files WHERE job_id=:job_id", {"job_id": job_id})
    row["segment_readiness"] = segment_readiness(files)
    enrichment = None
    try:
        enrichment = _enrichment_snapshot(db, job_id)
    except Exception:
        log.exception("enrichment snapshot failed for job %s", job_id)
        db.rollback()
    inv = result.get("inventory") or {}
    return {
        "job_id": job_id,
        "inventory": {
            "platform": inv.get("platform"),
            "total": int(inv.get("total") or 0),
            "completed": int(inv.get("completed") or 0),
            "done": bool(inv.get("done")),
        },
        "pipeline_progress": result.get("pipeline_progress"),
        "job": _job_row(row, enrichment=enrichment),
    }


@router.get("/jobs/{job_id}/logs")
def list_logs(
    job_id: str,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = 200,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _ensure_job(db, job_id)
    params: dict = {"job_id": job_id, "limit": limit}
    sql = """SELECT id, job_id, timestamp, stage, level, message, metadata
             FROM disk_build_logs WHERE job_id=:job_id"""
    from app.services.retired_agents import visible_pipeline_logs_sql
    sql += " AND " + visible_pipeline_logs_sql()
    if from_ts:
        sql += " AND timestamp >= CAST(:from_ts AS timestamptz)"
        params["from_ts"] = from_ts
    if to_ts:
        sql += " AND timestamp <= CAST(:to_ts AS timestamptz)"
        params["to_ts"] = to_ts
    # First page is a live tail, not the oldest history. Previously the UI started
    # at the first 200 rows and eventually accumulated/rendered thousands of logs.
    initial_tail = not from_ts and not to_ts
    sql += (" ORDER BY timestamp DESC LIMIT :limit" if initial_tail else " ORDER BY timestamp ASC LIMIT :limit")
    rows = fetchall(db, sql, params)
    if initial_tail:
        rows = list(reversed(rows))
    items = []
    for r in rows:
        ts = r["timestamp"]
        items.append({
            "id": str(r["id"]),
            "job_id": str(r["job_id"]),
            "file_id": None,
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
            "stage": r["stage"],
            "level": r["level"],
            "message": r["message"],
            "metadata": r.get("metadata"),
        })
    return {"items": items, "total": len(items)}


@router.get("/jobs/{job_id}/capture-logs")
def list_capture_logs(
    job_id: str,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Artifact materialization events for a job, optionally filtered by registration time."""
    _ensure_job(db, job_id)
    params: dict = {"job_id": job_id, "limit": limit}
    sql = """SELECT id, job_id, file_name, file_path, extension, encyclopedia_artifact_id,
                    minio_uri, created_at
             FROM job_artifacts WHERE job_id=:job_id"""
    if from_ts:
        sql += " AND created_at >= CAST(:from_ts AS timestamptz)"
        params["from_ts"] = from_ts
    if to_ts:
        sql += " AND created_at <= CAST(:to_ts AS timestamptz)"
        params["to_ts"] = to_ts
    count_row = fetchone(
        db,
        f"SELECT count(*) c FROM ({sql}) t",
        params,
    )
    sql += " ORDER BY created_at DESC LIMIT :limit"
    rows = fetchall(db, sql, params)
    items = []
    for r in rows:
        ts = r["created_at"]
        items.append({
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
            "event": "artifact_captured",
            "message": r.get("file_name"),
            "job_id": job_id,
            "artifact_id": str(r["id"]),
            "artifact_type": r.get("extension") or "file",
            "title": r.get("file_name"),
            "source_path": r.get("file_path"),
            "axiom_category": r.get("encyclopedia_artifact_id"),
            "storage_uri": r.get("minio_uri"),
        })
    return {
        "items": items,
        "total": int(count_row["c"]) if count_row else len(items),
        "storage_uri": None,
    }


@router.get("/jobs/{job_id}/evidence-search")
def search_job_evidence(
    job_id: str,
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    q: str | None = Query(None, description="Filter messages and paths"),
    scope: str = Query("artifacts", description="artifacts | all"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    limit: int | None = Query(None, ge=1, le=5000, deprecated=True),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Search forensic artifacts (default) or combined pipeline activity for a job."""
    _ensure_job(db, job_id)
    use_artifacts_only = (scope or "artifacts").lower() != "all"
    effective_page_size = page_size
    if limit is not None:
        effective_page_size = min(limit, 5000)
        page = 1

    art_params: dict = {"job_id": job_id}
    art_sql = """SELECT id, file_name, file_path, extension, size_bytes, sha256,
                        encyclopedia_artifact_id, parse_status, ocr_status, created_at
                 FROM job_artifacts WHERE job_id=:job_id"""
    if from_ts:
        art_sql += " AND created_at >= CAST(:from_ts AS timestamptz)"
        art_params["from_ts"] = from_ts
    if to_ts:
        art_sql += " AND created_at <= CAST(:to_ts AS timestamptz)"
        art_params["to_ts"] = to_ts
    if q:
        art_sql += " AND (file_name ILIKE :q OR file_path ILIKE :q OR encyclopedia_artifact_id ILIKE :q)"
        art_params["q"] = f"%{q}%"

    if use_artifacts_only:
        count_row = fetchone(db, f"SELECT count(*) c FROM ({art_sql}) t", art_params)
        total = int(count_row["c"]) if count_row else 0
        offset = (page - 1) * effective_page_size
        art_params["limit"] = effective_page_size
        art_params["offset"] = offset
        art_rows = fetchall(
            db,
            art_sql + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset",
            art_params,
        )
        items: list[dict] = []
        for r in art_rows:
            ts = r["created_at"]
            items.append({
                "id": str(r["id"]),
                "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                "activity_type": "artifact",
                "stage": "artifact",
                "level": "info",
                "message": r.get("file_name") or r.get("file_path"),
                "file_name": r.get("file_name"),
                "source_path": r.get("file_path"),
                "artifact_type": r.get("extension") or "file",
                "axiom_category": r.get("encyclopedia_artifact_id"),
                "parse_status": r.get("parse_status"),
                "ocr_status": r.get("ocr_status"),
                "size_bytes": int(r["size_bytes"]) if r.get("size_bytes") is not None else None,
                "sha256": r.get("sha256"),
            })
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": effective_page_size,
            "scope": "artifacts",
        }

    log_params: dict = {"job_id": job_id}
    log_sql = """SELECT id, timestamp, stage, level, message, metadata
                 FROM disk_build_logs WHERE job_id=:job_id"""
    from app.services.retired_agents import visible_pipeline_logs_sql
    log_sql += " AND " + visible_pipeline_logs_sql()
    if from_ts:
        log_sql += " AND timestamp >= CAST(:from_ts AS timestamptz)"
        log_params["from_ts"] = from_ts
    if to_ts:
        log_sql += " AND timestamp <= CAST(:to_ts AS timestamptz)"
        log_params["to_ts"] = to_ts
    if q:
        log_sql += " AND message ILIKE :q"
        log_params["q"] = f"%{q}%"
    log_rows = fetchall(db, log_sql + " ORDER BY timestamp DESC", log_params)
    art_rows = fetchall(db, art_sql + " ORDER BY created_at DESC", art_params)

    items = []
    for r in log_rows:
        ts = r["timestamp"]
        items.append({
            "id": str(r["id"]),
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
            "activity_type": "pipeline",
            "stage": r.get("stage"),
            "level": r.get("level"),
            "message": r.get("message"),
            "metadata": r.get("metadata"),
        })
    for r in art_rows:
        ts = r["created_at"]
        items.append({
            "id": str(r["id"]),
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
            "activity_type": "artifact",
            "stage": "artifact",
            "level": "info",
            "message": r.get("file_name") or r.get("file_path"),
            "file_name": r.get("file_name"),
            "source_path": r.get("file_path"),
            "artifact_type": r.get("extension") or "file",
            "axiom_category": r.get("encyclopedia_artifact_id"),
            "parse_status": r.get("parse_status"),
            "ocr_status": r.get("ocr_status"),
            "size_bytes": int(r["size_bytes"]) if r.get("size_bytes") is not None else None,
            "sha256": r.get("sha256"),
        })
    items.sort(key=lambda x: x["timestamp"], reverse=True)
    if len(items) > effective_page_size:
        items = items[:effective_page_size]
    return {
        "items": items,
        "total": len(items),
        "page": 1,
        "page_size": effective_page_size,
        "scope": "all",
    }


@router.get("/jobs/{job_id}/evidence/host-mount")
def get_host_mount(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _ensure_job(db, job_id)
    return mount_info()


@router.get("/jobs/{job_id}/evidence/host-browse")
def browse_host_evidence(
    job_id: str,
    path: str = "",
    drive: str = "",
    host_path: str | None = None,
    source_type: str = "disk",
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _ensure_job(db, job_id)
    return host_browse(drive=drive, browse_path=path, host_path=host_path, source_type=source_type)


@router.post("/jobs/{job_id}/evidence/resolve-folder")
def resolve_host_folder(
    job_id: str,
    payload: ResolveFolderBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _ensure_job(db, job_id)
    filenames = payload.filenames or payload.files or []
    relative_paths = payload.relative_paths or payload.paths or []
    folder_hint = payload.folder_hint or payload.folder or payload.relative_path
    return find_folder_with_segment_files(
        list(filenames),
        folder_hint=folder_hint,
        relative_paths=list(relative_paths),
        file_sizes=dict(payload.file_sizes or {}),
    )


@router.get("/jobs/{job_id}/evidence/host-preview")
def preview_host_evidence(
    job_id: str,
    path: str | None = None,
    source_type: str = "disk",
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _ensure_job(db, job_id)
    return preview_folder(path, source_type)


@router.post("/jobs/{job_id}/evidence/list-folder")
def list_host_folder(
    job_id: str,
    body: ListFolderBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """List every file in the evidence folder and write lines to extraction logs.

    Case-layout runs (export_catalog.json / payload shards) are listed inline —
    they are a single scandir. Anything that needs a deep walk is handed to a
    background thread and the client polls ``list-folder/status``; the request
    never holds an API thread for a multi-hour bind-mount walk again.
    """
    from app.services.folder_listing_jobs import is_running, snapshot, start_background_listing
    from app.services.host_evidence import folder_lists_fast, resolve_host_path

    _ensure_job(db, job_id)
    if is_running(job_id):
        snap = snapshot(job_id) or {}
        return {"status": "running", "path": snap.get("path"), "count": 0, "segment_count": 0, "entries": [], "segments": []}

    try:
        folder = resolve_host_path(body.path, drive=body.drive, browse_path=body.browse_path, strict=True, job_id=job_id)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "list_folder_failed", "message": str(e)}},
        )

    if folder_lists_fast(folder):
        try:
            result = list_folder_contents(
                db,
                job_id,
                path=body.path,
                drive=body.drive,
                browse_path=body.browse_path,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "list_folder_failed", "message": str(e)}},
            )
        db.commit()
        return {"status": "done", **result}

    db.commit()
    schema = _schema_name(db, current)
    run = start_background_listing(
        schema_name=schema,
        job_id=job_id,
        path=body.path,
        drive=body.drive,
        browse_path=body.browse_path,
    )
    return {"status": run.get("status", "running"), "path": run.get("path"), "count": 0, "segment_count": 0, "entries": [], "segments": []}


@router.get("/jobs/{job_id}/evidence/list-folder/status")
def list_host_folder_status(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Poll a background List folder run started by POST list-folder."""
    from app.services.folder_listing_jobs import snapshot
    from app.services.host_evidence import listing_complete

    _ensure_job(db, job_id)
    snap = snapshot(job_id)
    if snap is None:
        # API restarted or the listing ran inline — fall back to the DB marker.
        return {"status": "done" if listing_complete(db, job_id) else "idle"}
    if snap.get("status") == "error":
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "list_folder_failed", "message": str(snap.get("error") or "List folder failed")}},
        )
    if snap.get("status") == "done":
        return {"status": "done", **(snap.get("result") or {})}
    return {
        "status": "running",
        "path": snap.get("path"),
        "elapsed_sec": int(time.time() - float(snap.get("started_at") or time.time())),
    }


@router.post("/jobs/{job_id}/evidence/ingest-path")
def ingest_host_path(
    job_id: str,
    body: IngestPathBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    _ensure_job(db, job_id)
    # A phone job is always registered as "mobile" even when the panel state
    # still says "disk" (page reload, missing router state): the empty
    # 03_Working_Copy folder must resolve to the 05_Exports payload shards.
    source_type = body.source_type
    if _job_source_type(db, job_id) == "mobile" and source_type in (None, "", "disk"):
        source_type = "mobile"
    try:
        result = register_segments(
            db,
            job_id,
            path=body.path,
            drive=body.drive,
            browse_path=body.browse_path,
            selected_names=body.selected_names,
            source_type=source_type,
            skip_folder_list=bool(body.skip_folder_list),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"error": {"code": "register_failed", "message": str(e)}})

    processing_queued = False
    if body.auto_process and result["accepted"]:
        _ensure_job_case(db, job_id)
        row = fetchone(db, "SELECT status, files_total FROM jobs WHERE id=:id", {"id": job_id})
        already_building = row and row["status"] in ("building_disk", "processing") and (row.get("files_total") or 0) > 0
        if not already_building:
            schema = _schema_name(db, current)
            try:
                _queue_disk_build(db, schema, job_id)
                processing_queued = True
            except HTTPException:
                db.commit()
                raise
            except Exception as exc:
                import logging

                logging.getLogger("jobs").warning(
                    "Celery queue failed for job %s — worker may need restart: %s", job_id, exc
                )
                db.commit()
        else:
            db.commit()
    else:
        db.commit()

    return {
        "job_id": job_id,
        "status": "registered",
        "message": "Segments registered from host — no image bytes copied",
        "processing_queued": processing_queued,
        "accepted": result["accepted"],
        "skipped": result.get("skipped", []),
        "readiness": result.get("readiness"),
    }


def _job_source_type(db: Session, job_id: str) -> str:
    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    job_type = str(row.get("type") or "")
    from app.forensic_common.job_types import MOBILE_JOB_TYPES
    if job_type in MOBILE_JOB_TYPES:
        return "mobile"
    return "disk"


def _normalize_upload_paths(paths: list[str] | str | None) -> list[str] | None:
    if paths is None:
        return None
    if isinstance(paths, str):
        return [paths]
    return list(paths)


def _parse_expected_total(raw: int | str | None) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _stage_job_uploads(
    job_id: str,
    files: list[UploadFile],
    paths: list[str] | None,
    *,
    source_type: str = "disk",
) -> list[dict]:
    from app.services.client_intake import stage_upload_file

    staged: list[dict] = []
    paths = _normalize_upload_paths(paths)
    for idx, upload in enumerate(files or []):
        rel = ""
        if paths and idx < len(paths) and paths[idx]:
            rel = paths[idx]
        else:
            rel = getattr(upload, "filename", None) or f"file-{idx}"
        raw = upload.file
        staged.append(
            stage_upload_file(
                namespace=f"{job_id}/intake",
                relative_path=rel,
                src=raw,
                # Disk images can be hundreds of GB. The staging filesystem *is*
                # the server-side source, so do not duplicate each segment into
                # object storage before extraction. Mobile/RAG uploads retain
                # their existing object-store mirror.
                mirror_to_object_storage=(source_type != "disk"),
            )
        )
    return staged


def _finish_uploaded_registration(
    db: Session,
    job_id: str,
    *,
    current: CurrentUser,
    auto_process: bool,
    source_type: str,
    staged: list[dict],
    register: bool = True,
) -> dict:
    if not register:
        received_bytes = sum(int(s.get("size_bytes") or 0) for s in staged)
        from app.services.download_agent import note_segment_received

        first_name = None
        if staged:
            first_name = staged[0].get("relative_path") or staged[0].get("original_name")
        note_segment_received(
            db,
            job_id,
            name=first_name,
            received_delta=len(staged),
            received_bytes_delta=received_bytes,
        )
        db.commit()
        return {
            "job_id": job_id,
            "status": "staged",
            "message": "Files staged from the client browser — waiting for remaining images",
            "processing_queued": False,
            "accepted": [
                {
                    "id": "",
                    "job_id": job_id,
                    "group_id": None,
                    "relative_path": s.get("relative_path"),
                    "original_name": s.get("name"),
                    "storage_uri": s.get("storage_uri"),
                    "mime_type": s.get("mime_type"),
                    "sha256": s.get("sha256"),
                    "status": "staged",
                    "size_bytes": s.get("size_bytes"),
                    "created_at": "",
                }
                for s in staged
            ],
            "skipped": [],
            "readiness": None,
        }
    result = register_uploaded_intake(
        db, job_id, staged_files=staged, source_type=source_type
    )
    processing_queued = False
    if auto_process and result.get("accepted"):
        _ensure_job_case(db, job_id)
        row = fetchone(db, "SELECT status, files_total FROM jobs WHERE id=:id", {"id": job_id})
        already_building = row and row["status"] in ("building_disk", "processing") and (row.get("files_total") or 0) > 0
        if not already_building:
            schema = _schema_name(db, current)
            try:
                _queue_disk_build(db, schema, job_id)
                processing_queued = True
            except HTTPException:
                db.commit()
                raise
        else:
            db.commit()
    else:
        db.commit()
    return {
        "job_id": job_id,
        "status": "registered",
        "message": "Files uploaded from the client browser and registered",
        "processing_queued": processing_queued,
        "accepted": result.get("accepted") or [],
        "skipped": result.get("skipped") or [],
        "readiness": result.get("readiness"),
    }


def _upload_and_register(
    job_id: str,
    *,
    current: CurrentUser,
    files: list[UploadFile],
    paths: list[str] | None,
    auto_process: bool,
    register_now: bool,
    expected_total: int | None = None,
) -> dict:
    from app.db.session import firm_session
    from app.db.tenant import Scope, TenantContext, set_tenant_context

    schema = current.schema_name or ""
    if not schema:
        raise HTTPException(status_code=400, detail={"error": {"code": "no_firm", "message": "Firm schema required"}})
    with firm_session(schema) as db:
        set_tenant_context(TenantContext(slug=current.tenant, scope=Scope.FIRM, schema_name=schema))
        _ensure_job(db, job_id)
        source_type = _job_source_type(db, job_id)
        if expected_total:
            mark_client_upload_progress(db, job_id, expected_files=expected_total)
    try:
        staged = _stage_job_uploads(job_id, files, paths, source_type=source_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "upload_failed", "message": str(exc)}}) from exc
    with firm_session(schema) as db:
        set_tenant_context(TenantContext(slug=current.tenant, scope=Scope.FIRM, schema_name=schema))
        if expected_total:
            mark_client_upload_progress(db, job_id, expected_files=expected_total)
        return _finish_uploaded_registration(
            db,
            job_id,
            current=current,
            auto_process=auto_process,
            source_type=source_type,
            staged=staged,
            register=register_now,
        )


@router.post("/jobs/{job_id}/evidence")
def upload_job_evidence(
    job_id: str,
    files: list[UploadFile] = File(...),
    auto_process: bool = Form(False),
    register_now: bool = Form(True),
    expected_total: str | None = Form(None),
    current: CurrentUser = Depends(require_firm_permission_released("job:run")),
):
    return _upload_and_register(
        job_id,
        current=current,
        files=files,
        paths=None,
        auto_process=auto_process,
        register_now=register_now,
        expected_total=_parse_expected_total(expected_total),
    )


@router.post("/jobs/{job_id}/evidence/directory")
def upload_job_evidence_directory(
    job_id: str,
    files: list[UploadFile] = File(...),
    paths: list[str] | None = Form(None),
    auto_process: bool = Form(False),
    register_now: bool = Form(True),
    expected_total: str | None = Form(None),
    current: CurrentUser = Depends(require_firm_permission_released("job:run")),
):
    return _upload_and_register(
        job_id,
        current=current,
        files=files,
        paths=paths,
        auto_process=auto_process,
        register_now=register_now,
        expected_total=_parse_expected_total(expected_total),
    )


@router.post("/jobs/{job_id}/evidence/begin-client-upload")
def begin_client_upload(
    job_id: str,
    expected_files: int = Query(0),
    current: CurrentUser = Depends(require_firm_permission_released("job:run")),
):
    """Open Download Agent before the first byte so no other agent can start."""
    from app.db.session import firm_session
    from app.db.tenant import Scope, TenantContext, set_tenant_context
    from app.services.download_agent import DOWNLOAD_PARALLELISM, begin_client_download

    schema = current.schema_name or ""
    if not schema:
        raise HTTPException(status_code=400, detail={"error": {"code": "no_firm", "message": "Firm schema required"}})
    if int(expected_files or 0) <= 0:
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "expected_files_required",
                    "message": "Client intake must declare the complete image/segment count before the first upload starts.",
                }
            },
        )
    with firm_session(schema) as db:
        set_tenant_context(TenantContext(slug=current.tenant, scope=Scope.FIRM, schema_name=schema))
        _ensure_job(db, job_id)

        # Fail closed against accidental duplicate copies. Once this disk job has
        # been registered from a path the forensic server can read directly, a
        # stale/older browser must not be allowed to flip it back to
        # browser_upload and stream a multi-hundred-GB E01 over HTTP.
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
        try:
            from app.services.mobile_os import load_job_disk_source

            current_ds = load_job_disk_source(row)
        except Exception:
            raw_ds = row.get("disk_source")
            current_ds = raw_ds if isinstance(raw_ds, dict) else {}
        server_local_path = next(
            (
                str(current_ds.get(key) or "").strip()
                for key in ("evidence_folder", "host_path", "path", "last_host_path")
                if str(current_ds.get(key) or "").strip()
            ),
            "",
        )
        if (
            str(current_ds.get("source_residency") or "").strip().lower() == "server_local"
            or str(current_ds.get("intake") or "").strip().lower() == "server_local"
        ) and server_local_path:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "code": "server_local_zero_copy",
                        "message": (
                            "Client upload refused: this evidence is already registered on a "
                            "server-local HDD/SSD/USB path. Process the E01 in place; no download/copy is required."
                        ),
                    }
                },
            )

        ds = begin_client_download(db, job_id, expected_files=max(0, int(expected_files or 0)))
        db.commit()
        return {
            "job_id": job_id,
            "status": "receiving",
            "download_agent": "running",
            "expected_files": int(ds.get("upload_expected_files") or expected_files or 0),
            "received_files": int(ds.get("upload_received_files") or 0),
            "parallelism": DOWNLOAD_PARALLELISM,
            "message": (
                f"Download Agent is receiving segments ({DOWNLOAD_PARALLELISM} at a time). "
                "All other agents stay stopped until Download Agent signals complete."
            ),
        }


@router.post("/jobs/{job_id}/evidence/complete-upload")
def complete_client_upload(
    job_id: str,
    auto_process: bool = Query(False),
    current: CurrentUser = Depends(require_firm_permission_released("job:run")),
):
    """List and register only after every client image file is on the server."""
    from app.db.session import firm_session
    from app.db.tenant import Scope, TenantContext, set_tenant_context
    from app.services.client_intake import count_staged_files
    from app.services.mobile_os import load_job_disk_source

    schema = current.schema_name or ""
    if not schema:
        raise HTTPException(status_code=400, detail={"error": {"code": "no_firm", "message": "Firm schema required"}})
    with firm_session(schema) as db:
        set_tenant_context(TenantContext(slug=current.tenant, scope=Scope.FIRM, schema_name=schema))
        _ensure_job(db, job_id)
        source_type = _job_source_type(db, job_id)
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
        ds = load_job_disk_source(row)
        expected = int(ds.get("upload_expected_files") or 0)
        received = int(ds.get("upload_received_files") or 0)
        n_disk = count_staged_files(job_id)
        if expected <= 0:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "code": "upload_manifest_missing",
                        "message": "Client upload has no declared segment count. Restart the client intake so the Download Agent can gate the full set.",
                    }
                },
            )
        if n_disk < expected or received < expected:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "code": "upload_in_progress",
                        "message": (
                            f"Client upload is still in progress ({min(n_disk, received)}/{expected} fully received file(s); "
                            f"{n_disk} visible in staging). All other agents remain held until the complete set is received."
                        ),
                    }
                },
            )
        try:
            return _finish_uploaded_registration(
                db,
                job_id,
                current=current,
                auto_process=auto_process,
                source_type=source_type,
                staged=[],
                register=True,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "register_failed", "message": str(exc)}},
            ) from exc


@router.post("/jobs/{job_id}/evidence/register-segments")
def upload_job_evidence_segments(
    job_id: str,
    files: list[UploadFile] = File(...),
    current: CurrentUser = Depends(require_firm_permission_released("job:run")),
):
    return _upload_and_register(
        job_id,
        current=current,
        files=files,
        paths=None,
        auto_process=True,
        register_now=True,
    )


def _queue_disk_build(db: Session, schema: str, job_id: str, *, force: bool = False) -> None:
    from app.config import get_settings
    from app.forensic_common.job_types import is_mobile_job
    from app.services.host_evidence import ensure_folder_listed, is_client_upload_pending
    from app.services.job_control import clear_stop_request, extraction_is_stale, set_celery_task_id
    from app.services.mobile_os import load_job_disk_source
    from app.tasks import build_extracted_disk_task, build_extracted_mobile_task

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    if is_client_upload_pending(load_job_disk_source(row)):
        raise HTTPException(
            status_code=409,
            detail={
                "error": {
                    "code": "upload_in_progress",
                    "message": "Download Agent is still receiving segments. All other agents stay stopped until it signals complete.",
                }
            },
        )
    ensure_folder_listed(db, job_id)

    settings = get_settings()
    mobile = is_mobile_job(db, job_id)
    source = load_job_disk_source(row)
    if not service_allows_job_type(
        str(row.get("type") or ("mobile_extraction" if mobile else "host_disk")),
        str(source.get("source_type") or ("mobile" if mobile else "disk")),
        mobile_os=str(source.get("mobile_os") or ""),
    ):
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "wrong_service",
                    "message": "This extract belongs to a different Aetheris product.",
                }
            },
        )
    max_concurrent = max(int(getattr(settings, "max_concurrent_disk_builds", 3) or 3), 1)

    busy_rows = fetchall(
        db,
        """SELECT id, status, updated_at, files_total, files_extracted, type, disk_source FROM jobs
           WHERE id<>:job_id AND status IN ('building_disk', 'processing')
             AND coalesce(files_total, 0) > 0
           ORDER BY updated_at DESC""",
        {"job_id": job_id},
    )
    # Concurrency limit is per domain so mobile extract does not block disk E01 (and vice versa).
    domain_busy = []
    for r in busy_rows or []:
        if extraction_is_stale(r):
            continue
        other_mobile = is_mobile_job(db, str(r["id"]))
        if other_mobile == mobile:
            domain_busy.append(r)
    busy_count = len(domain_busy)
    if busy_count >= max_concurrent:
        ids = ", ".join(str(r["id"])[:8] for r in domain_busy[:5])
        domain_label = "mobile" if mobile else "disk"
        raise HTTPException(
            status_code=409,
            detail={
                "error": {
                    "code": "extract_busy",
                    "message": (
                        f"Already {busy_count} {domain_label} extract(s) running "
                        f"(limit={max_concurrent}: {ids}…). Wait for one to finish."
                    ),
                }
            },
        )

    for r in busy_rows or []:
        if extraction_is_stale(r):
            execute(
                db,
                """UPDATE jobs SET status='paused', celery_task_id=NULL,
                       error=COALESCE(NULLIF(error,''), 'Paused — worker stalled; click Resume to continue'),
                       updated_at=NOW()
                   WHERE id=:id AND status IN ('building_disk', 'processing')""",
                {"id": str(r["id"])},
            )

    clear_stop_request(db, job_id)
    row = fetchone(db, "SELECT status, updated_at FROM jobs WHERE id=:job_id", {"job_id": job_id})

    if not force and row and row["status"] in ("building_disk", "processing") and not extraction_is_stale(row):
        return
    execute(db, "UPDATE jobs SET status='processing', error=NULL, updated_at=NOW() WHERE id=:job_id", {"job_id": job_id})
    from app.config import get_settings
    from app.services.pipeline_orchestrator import init_pipeline_orchestration

    if get_settings().pipeline_sequential_agents:
        init_pipeline_orchestration(db, job_id)
    db.commit()
    try:
        task = build_extracted_mobile_task if mobile else build_extracted_disk_task
        async_result = task.delay(schema, job_id)
        set_celery_task_id(db, job_id, async_result.id)
        db.commit()
    except Exception as exc:
        import logging

        logging.getLogger("jobs").warning("Celery queue failed for job %s: %s", job_id, exc)
        raise


@router.post("/jobs/{job_id}/process")
def process_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.job_control import load_extraction_checkpoint

    _ensure_job(db, job_id)
    gate_row = fetchone(db, "SELECT status, files_total, stop_requested, disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    from app.services.host_evidence import is_client_upload_pending
    from app.services.mobile_os import load_job_disk_source

    if is_client_upload_pending(load_job_disk_source(gate_row)):
        raise HTTPException(
            status_code=409,
            detail={
                "error": {
                    "code": "upload_in_progress",
                    "message": "Client image intake is incomplete. Extraction, parsing, OCR, RAG and reporting remain held until every declared segment has been fully received and registered.",
                }
            },
        )
    row = gate_row
    ev_count = fetchone(db, "SELECT count(*) c FROM evidence_files WHERE job_id=:id", {"id": job_id})
    if not ev_count or int(ev_count.get("c") or 0) == 0:
        from app.services.host_evidence import reregister_job_evidence_from_saved_folder

        try:
            recovered = reregister_job_evidence_from_saved_folder(
                db, job_id, source_type=_job_source_type(db, job_id)
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "no_evidence", "message": str(exc)}},
            ) from exc
        ev_count = fetchone(db, "SELECT count(*) c FROM evidence_files WHERE job_id=:id", {"id": job_id})
        if recovered.get("recovered") and ev_count and int(ev_count.get("c") or 0) > 0:
            import logging

            logging.getLogger("jobs").info(
                "Re-registered %s segment(s) for job %s from %s",
                ev_count.get("c"),
                job_id,
                recovered.get("path"),
            )
        if not ev_count or int(ev_count.get("c") or 0) == 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "code": "no_evidence",
                        "message": (
                            "No disk segments registered. If you attached a new drive, wait "
                            "for it to mount, then Try again — the last folder will be remounted "
                            "and registered automatically."
                        ),
                    }
                },
            )
    if row and row["status"] in ("building_disk", "processing") and not row.get("stop_requested"):
        return {
            "job_id": job_id,
            "status": row["status"],
            "message": "Disk build already in progress — watch the extraction log for live updates",
        }
    cp = load_extraction_checkpoint(db, job_id)
    if cp and cp.get("completed_shards") and row and row["status"] == "paused":
        return {
            "job_id": job_id,
            "status": "paused",
            "message": "Extraction was paused — use Resume to continue from the last checkpoint",
        }
    if not (row and row["status"] == "paused"):
        execute(
            db,
            """UPDATE jobs SET extraction_checkpoint=NULL, files_extracted=0, bytes_extracted=0,
               files_total=0, progress_pct=0 WHERE id=:job_id""",
            {"job_id": job_id},
        )
        db.commit()
    schema = _schema_name(db, current)
    try:
        _queue_disk_build(db, schema, job_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "queue_unavailable",
                    "message": "Disk build could not be queued — ensure worker-disk is running.",
                }
            },
        ) from exc
    return {"job_id": job_id, "status": "processing", "message": "Disk build queued"}


@router.post("/jobs/{job_id}/stop")
def stop_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.disk_build_log import write_disk_log
    from app.services.job_control import request_job_stop

    _ensure_job(db, job_id)
    result = request_job_stop(db, job_id)
    if not result["ok"]:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "stop_not_allowed", "message": result["message"]}},
        )
    write_disk_log(
        db,
        job_id,
        result["message"],
        stage="supervisor" if "Pipeline stopped" in result["message"] else "extract",
        level="info",
    )
    db.commit()
    return {"job_id": job_id, "status": "stopping", "message": result["message"]}


@router.post("/jobs/{job_id}/resume")
def resume_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.job_control import extraction_is_stale, load_extraction_checkpoint

    row = _ensure_job(db, job_id)
    stale = extraction_is_stale(row)
    if row["status"] in ("building_disk", "processing") and not stale:
        from app.services.job_control import extract_worker_liveness

        live = extract_worker_liveness(row) or {}
        detail = (
            f" (worker alive, heartbeat {live.get('heartbeat_age_sec', 0):.0f}s ago)"
            if live.get("alive")
            else ""
        )
        # Keep updated_at fresh so the client-side 240 s detector stops looping.
        execute(db, "UPDATE jobs SET updated_at=NOW() WHERE id=:id", {"id": job_id})
        db.commit()
        return {
            "job_id": job_id,
            "status": row["status"],
            "message": "Disk build already in progress" + detail,
        }
    if row["status"] in ("building_disk", "processing") and stale:
        from app.services.disk_build_log import write_disk_log

        write_disk_log(
            db,
            job_id,
            "Extraction stalled (no progress) — re-queuing from last checkpoint",
            stage="extract",
            level="warning",
        )
        execute(
            db,
            """UPDATE jobs SET status='processing', stop_requested=FALSE, error=NULL, updated_at=NOW()
               WHERE id=:id""",
            {"id": job_id},
        )
        db.commit()
    if row["status"] == "disk_ready":
        art = fetchone(
            db,
            "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid",
            {"jid": job_id},
        )
        if int((art or {}).get("c") or 0) <= 0:
            from app.tasks import phase3_pipeline_task

            schema = _schema_name(db, current)
            execute(
                db,
                "UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:id",
                {"id": job_id},
            )
            write_disk_log(
                db,
                job_id,
                "Resume after extract — queueing Phase 3 materialize/parse",
                stage="phase3",
            )
            db.commit()
            try:
                phase3_pipeline_task.delay(schema, job_id)
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": {
                            "code": "queue_unavailable",
                            "message": "Materialize could not be queued — ensure the extract worker is running.",
                        }
                    },
                ) from exc
            return {
                "job_id": job_id,
                "status": "indexing",
                "message": "Extract already complete — materialize/parse queued",
            }
        return {"job_id": job_id, "status": "disk_ready", "message": "Extraction already complete"}
    cp = load_extraction_checkpoint(db, job_id)
    if not cp or not cp.get("completed_shards"):
        if row["status"] in ("created", "registered", "awaiting_segments", "failed"):
            schema = _schema_name(db, current)
            try:
                _queue_disk_build(db, schema, job_id)
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": {
                            "code": "queue_unavailable",
                            "message": "Disk build could not be queued — ensure worker-disk is running.",
                        }
                    },
                ) from exc
            return {"job_id": job_id, "status": "processing", "message": "Disk build queued"}
        raise HTTPException(
            status_code=400,
            detail={
                "error": {
                    "code": "nothing_to_resume",
                    "message": "No extraction checkpoint found — use Process to start",
                }
            },
        )
    schema = _schema_name(db, current)
    try:
        _queue_disk_build(db, schema, job_id, force=stale)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "queue_unavailable",
                    "message": "Resume could not be queued — ensure worker-disk is running.",
                }
            },
        ) from exc
    shards_done = len(cp.get("completed_shards") or [])
    return {
        "job_id": job_id,
        "status": "processing",
        "message": f"Resuming extraction from checkpoint ({shards_done} shard(s) already complete)",
    }


@router.get("/pipeline/agents")
def list_process_pipeline_agents(
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """One progressAgent coordinator and only the required process stages."""
    from app.services.action_agents import list_all_process_agents

    items = list_all_process_agents()
    return {"count": len(items), "items": items}


@router.get("/jobs/{job_id}/pipeline/progress-events")
def list_progress_events(job_id: str, limit: int = 100, db: Session = Depends(firm_db),
                         current: CurrentUser = Depends(require_firm_permission("job:read"))):
    from app.services.progress_agent import progress_events_page
    _ensure_job(db,job_id)
    return {'job_id':job_id,**progress_events_page(db,job_id,limit=limit)}


@router.get("/jobs/{job_id}/pipeline/heal-events")
def list_pipeline_heal_events(
    job_id: str,
    limit: int = 50,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Read historical recovery events; this endpoint performs no recovery."""
    from app.services.pipeline_heal import list_heal_events

    _ensure_job(db, job_id)
    exists = fetchone(db, "SELECT to_regclass('pipeline_heal_events') AS t")
    events = list_heal_events(db, job_id, limit=max(1, min(limit, 200))) if exists and exists['t'] else []
    return {"job_id": job_id, "count": len(events), "events": events}


@router.post("/jobs/{job_id}/pipeline/resume-rag")
def resume_rag_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Resume interrupted GPU RAG embedding without rebuilding the index."""
    from app.config import get_settings
    from app.services.dual_rag_index import _count_indexable_artifacts, _count_indexable_without_chunks
    from app.tasks import rag_append_task

    row = _ensure_job(db, job_id)
    if not row.get("disk_source") and not row.get("extracted_disk_uri"):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "not_ready", "message": "Extracted disk not ready — run disk build first"}},
        )
    remaining = _count_indexable_without_chunks(db, job_id)
    if remaining <= 0:
        return {"job_id": job_id, "status": "indexed", "message": "RAG indexing already complete"}
    chunks_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
        {"jid": job_id},
    )
    chunk_n = int(chunks_row["c"]) if chunks_row else 0
    from app.config import get_settings
    from app.services.ocr_gpu import count_pending_ocr

    settings = get_settings()
    ocr_pending = 0
    try:
        ocr_pending = int(count_pending_ocr(db, job_id) or 0)
    except Exception:
        pass
    if (
        chunk_n >= 500
        and ocr_pending > 0
        and bool(getattr(settings, "defer_background_rag_while_ocr", True))
    ):
        # Frontend auto-resume was thrashing OCR by re-queuing background RAG.
        from app.tasks import ocr_drain_task

        schema = _schema_name(db, current)
        write_disk_log(
            db,
            job_id,
            f"Background RAG deferred — {ocr_pending:,} OCR document(s) still pending "
            f"(baseline {chunk_n:,} chunks already searchable)",
            stage="rag_index",
            level="warning",
        )
        db.commit()
        try:
            ocr_drain_task.delay(schema, job_id)
        except Exception:
            pass
        return {
            "job_id": job_id,
            "status": "indexing",
            "message": (
                f"Baseline ready — finishing OCR first ({ocr_pending:,} docs). "
                "Background corpus RAG resumes after OCR."
            ),
            "deferred_for_ocr": True,
            "ocr_pending": ocr_pending,
            "rag_chunks": chunk_n,
        }
    indexable_total = _count_indexable_artifacts(db, job_id)
    schema = _schema_name(db, current)
    execute(
        db,
        """UPDATE jobs SET status='indexing', error=NULL, stop_requested=FALSE,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {
            "pp": json.dumps({
                "phase": "rag",
                "completed": chunk_n,
                "total": max(indexable_total, chunk_n + remaining, 1),
                "label": f"Resuming RAG — {remaining:,} artifacts to embed",
            }),
            "id": job_id,
        },
    )
    write_disk_log(
        db,
        job_id,
        f"RAG resume requested — {chunk_n:,} chunks embedded, {remaining:,} artifacts pending",
        stage="rag_index",
    )
    db.commit()
    try:
        rag_append_task.delay(schema, job_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "queue_unavailable",
                    "message": "RAG resume could not be queued — ensure worker-rag-gpu is running.",
                }
            },
        ) from exc
    return {
        "job_id": job_id,
        "status": "indexing",
        "message": f"GPU RAG resume queued ({remaining:,} artifacts remaining)",
    }


@router.post("/jobs/{job_id}/enrich")
def enrich_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Run (or re-run) Phase 3 pipeline on extracted disk artifacts."""
    from app.services.dual_rag_index import _count_indexable_without_chunks
    from app.tasks import phase3_pipeline_task

    row = _ensure_job(db, job_id)
    if not row.get("disk_source") and not row.get("extracted_disk_uri"):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "not_ready", "message": "Extracted disk not ready — run disk build first"}},
        )
    schema = _schema_name(db, current)
    chunks_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
        {"jid": job_id},
    )
    chunk_n = int(chunks_row["c"]) if chunks_row else 0
    rag_remaining = _count_indexable_without_chunks(db, job_id)
    if chunk_n > 0 and rag_remaining > 0:
        return resume_rag_job(job_id, db=db, current=current)
    execute(db, "UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()
    try:
        phase3_pipeline_task.delay(schema, job_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "queue_unavailable",
                    "message": "Phase 3 pipeline could not be queued — ensure worker-rag-gpu is running.",
                }
            },
        ) from exc
    return {"job_id": job_id, "status": "indexing", "message": "Phase 3 pipeline queued"}


@router.post("/jobs/{job_id}/parse-drain")
def parse_drain_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Parse all pending/no_parser artifacts (unlimited rounds) then append RAG chunks."""
    from app.tasks import parse_drain_task

    row = _ensure_job(db, job_id)
    if not row.get("disk_source") and not row.get("extracted_disk_uri"):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "not_ready", "message": "Extracted disk not ready — run disk build first"}},
        )
    schema = _schema_name(db, current)
    execute(db, "UPDATE jobs SET status='indexed', progress_pct=100, error=NULL, updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()
    try:
        parse_drain_task.delay(schema, job_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": {
                    "code": "queue_unavailable",
                    "message": "Parse drain could not be queued — ensure Celery workers are running.",
                }
            },
        ) from exc
    return {
        "job_id": job_id,
        "status": "indexed",
        "message": "Full artifact parse drain queued (Q&A available while parse continues)",
    }


@router.post("/jobs/{job_id}/reclassify-artifacts")
def reclassify_artifacts(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Re-match all job artifacts to encyclopedia categories (fixes unmatched / bad tags)."""
    from app.services.encyclopedia_match import reclassify_job_artifacts
    from app.services.disk_build_log import write_disk_log

    _ensure_job(db, job_id)
    result = reclassify_job_artifacts(db, job_id)
    write_disk_log(
        db,
        job_id,
        f"Reclassified artifacts — {result.get('updated', 0):,} updated, "
        f"{result.get('matched', 0):,} matched",
        stage="materialize",
        metadata=result,
    )
    db.commit()
    return {"job_id": job_id, "status": "ok", **result}


@router.post("/jobs/{job_id}/pipeline/continue-batches")
def continue_pipeline_batches(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Continue Phase 3 parse/OCR/RAG batches for jobs with pending artifacts."""
    from app.tasks import phase3_pipeline_task

    row = _ensure_job(db, job_id)
    if not row.get("disk_source") and not row.get("extracted_disk_uri"):
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "not_ready", "message": "Extracted disk not ready"}},
        )
    schema = _schema_name(db, current)
    execute(db, "UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:id", {"id": job_id})
    db.commit()
    try:
        phase3_pipeline_task.delay(schema, job_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": {"code": "queue_unavailable", "message": str(exc)}},
        ) from exc
    return {"job_id": job_id, "status": "indexing", "message": "Phase 3 batch continuation queued"}


@router.get("/jobs/{job_id}/inventory")
def job_inventory(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from datetime import datetime, timezone

    from app.services.embedding_gpu import resolve_device
    from app.services.neo4j_sync import neo4j_available
    from app.services.opensearch_sync import opensearch_available

    row = _ensure_job(db, job_id)
    chunk_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:id OR job_id IS NULL",
        {"id": job_id},
    )
    ev_chunk_row = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:id", {"id": job_id})
    enc_chunk_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id IS NULL AND chunk_type IN ('encyclopedia','field_row')",
        {},
    )
    chunks = int(chunk_row["c"]) if chunk_row else 0
    ev_chunks = int(ev_chunk_row["c"]) if ev_chunk_row else 0
    enc_chunks = int(enc_chunk_row["c"]) if enc_chunk_row else max(0, chunks - ev_chunks)

    art_row = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:id", {"id": job_id})
    art_total = int(art_row["c"]) if art_row else 0
    matched_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:id AND encyclopedia_artifact_id IS NOT NULL",
        {"id": job_id},
    )
    art_matched = int(matched_row["c"]) if matched_row else 0
    parsed_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:id AND parse_status='parsed'",
        {"id": job_id},
    )
    parsed_count = int(parsed_row["c"]) if parsed_row else 0
    ocr_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:id AND ocr_status='done'",
        {"id": job_id},
    )
    ocr_count = int(ocr_row["c"]) if ocr_row else 0

    by_type_rows = fetchall(
        db,
        """SELECT COALESCE(NULLIF(extension, ''), 'unknown') AS ext, count(*) c
           FROM job_artifacts WHERE job_id=:id GROUP BY ext ORDER BY c DESC LIMIT 20""",
        {"id": job_id},
    )
    by_type = {r["ext"]: int(r["c"]) for r in by_type_rows}

    ev_files = fetchall(
        db,
        "SELECT status, count(*) c FROM evidence_files WHERE job_id=:id GROUP BY status",
        {"id": job_id},
    )
    by_status = {r["status"]: int(r["c"]) for r in ev_files}
    ev_total = sum(by_status.values())
    bytes_row = fetchone(
        db,
        "SELECT COALESCE(sum(size_bytes), 0) s FROM evidence_files WHERE job_id=:id",
        {"id": job_id},
    )
    ev_bytes = int(bytes_row["s"]) if bytes_row else 0

    log_row = fetchone(db, "SELECT count(*) c FROM disk_build_logs WHERE job_id=:id", {"id": job_id})
    log_count = int(log_row["c"]) if log_row else 0
    cp_row = fetchone(
        db,
        "SELECT CASE WHEN extraction_checkpoint IS NOT NULL THEN 1 ELSE 0 END c FROM jobs WHERE id=:id",
        {"id": job_id},
    )
    has_cp = int(cp_row["c"]) if cp_row else 0

    graph_row = fetchone(db, "SELECT * FROM graph_sync_state WHERE job_id=:id", {"id": job_id})
    settings = __import__("app.config", fromlist=["get_settings"]).get_settings()
    device_label, gpu_enabled = resolve_device(settings.rag_embedding_device)
    ec = row.get("extract_coverage")
    if isinstance(ec, str):
        ec = json.loads(ec)
    files_total = row.get("files_total") or 0
    bytes_extracted = row.get("bytes_extracted") or 0
    os_ok = opensearch_available()
    neo_ok = neo4j_available()

    return {
        "job_id": job_id,
        "job_status": row["status"],
        "progress_pct": row.get("progress_pct") or 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "embedding_device": device_label,
        "gpu_enabled": gpu_enabled,
        "artifacts_annotated": art_matched,
        "postgres_entities": parsed_count + ocr_count,
        "extract_coverage": ec,
        "files": {
            "total": ev_total or files_total,
            "extracted": row.get("files_extracted") or 0,
            "by_status": by_status,
            "total_bytes": ev_bytes or bytes_extracted,
            "evidence_groups": len(by_status),
        },
        "disk_index": {
            "file_count": files_total,
            "dir_count": 0,
            "interesting_file_count": (ec or {}).get("interesting_total", ev_chunks),
            "total_nodes": files_total,
            "files_total": files_total,
            "bytes_extracted": bytes_extracted,
        },
        "artifacts": {
            "total": art_total,
            "parsed": parsed_count,
            "ocr_done": ocr_count,
            "by_type": by_type,
            "categories": [],
            "category_total": art_matched,
        },
        "pipeline": {"checkpoints": has_cp, "extraction_logs": log_count},
        "opensearch": {
            "available": os_ok,
            "artifacts": art_total,
            "chunks": chunks if os_ok else 0,
            "embeddings": ev_chunks if os_ok else 0,
            "embedding_coverage_pct": 100 if ev_chunks else 0,
            "embedding_providers": {"bge_m3": ev_chunks} if ev_chunks else {},
            "ollama_embeddings": 0,
            "hash_embeddings": 0,
        },
        "rag": {
            "artifacts_enriched": art_matched,
            "artifacts_annotated": art_matched,
            "postgres_entities": parsed_count + ocr_count,
            "chunks_indexed": ev_chunks,
            "encyclopedia_chunks": enc_chunks,
            "evidence_chunks": ev_chunks,
            "embeddings_indexed": ev_chunks + enc_chunks,
            "parsed_artifacts": parsed_count,
            "ocr_artifacts": ocr_count,
            "ollama_embeddings": 0,
            "hash_embeddings": 0,
            "embedding_coverage_pct": 100 if ev_chunks else 0,
            "embedding_device": device_label,
            "gpu_enabled": gpu_enabled,
            "extract_coverage": ec,
        },
        "neo4j": {
            "available": neo_ok,
            "artifacts": art_matched,
            "chunks": ev_chunks,
            "entities": graph_row.get("nodes_synced", 0) if graph_row else 0,
            "ontology_nodes": graph_row.get("nodes_synced", 0) if graph_row else 0,
            "relationships": graph_row.get("edges_synced", 0) if graph_row else 0,
            "error": None if neo_ok else "Neo4j unreachable",
        },
    }
