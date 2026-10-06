"""Report, intake, artifact-scope, and SSE streaming API."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.db.session import apply_firm_search_path
from app.db.sql_helpers import execute, fetchall, fetchone
from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.report_export import export_download_filename, export_report, store_preview_pdf
from app.services.report_generator import _intake_ready
from app.services.storage import get_bytes

from app.services.report_objectives_service import (
    list_objectives_for_report_type,
    list_report_types as catalog_report_types,
)
from app.services.case_type_catalog_service import (
    default_report_type_for_case,
    load_case_types,
    validate_case_type,
)

router = APIRouter(prefix="/api", tags=["report"])

# Prefer the in-flight run so Recreate is not hidden by an older completed draft.
_LATEST_REPORT_RUN_SQL = """
SELECT id FROM report_runs WHERE job_id=:jid
ORDER BY
  CASE status
    WHEN 'running' THEN 0
    WHEN 'completed' THEN 1
    WHEN 'failed' THEN 2
    ELSE 3
  END,
  created_at DESC
LIMIT 1
"""

GRADE_NUM = {"A": 0.95, "B": 0.8, "C": 0.65, "D": 0.45, "E": 0.25}


def _ensure_job(db: Session, job_id: str) -> dict:
    row = fetchone(db, "SELECT id FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    return dict(row)


def _export_api_row(row: dict, *, job_id: str | None = None) -> dict:
    created = row.get("created_at")
    jid = job_id or (str(row["job_id"]) if row.get("job_id") else None)
    return {
        "id": str(row["id"]),
        "job_id": jid,
        "report_run_id": str(row["report_run_id"]),
        "format": row["format"],
        "sha256": row.get("sha256"),
        "manifest_uri": row.get("manifest_uri"),
        "run_status": row.get("run_status"),
        "run_started_at": (
            row["run_started_at"].isoformat()
            if row.get("run_started_at") and hasattr(row["run_started_at"], "isoformat")
            else row.get("run_started_at")
        ),
        "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
    }


def _section_api(row: dict, citations: list | None = None) -> dict:
    created = row["created_at"]
    updated = row["updated_at"]
    grade = row.get("confidence_grade")
    return {
        "id": str(row["id"]),
        "job_id": str(row["job_id"]),
        "section_key": row["section_key"],
        "structured_json": row.get("structured_json"),
        "narrative_content": row.get("content_md"),
        "citations": citations or [],
        "section_confidence": GRADE_NUM.get(grade) if grade else None,
        "verification_status": "approved" if row.get("approved") else (row.get("status") or "pending"),
        "conflicts": [],
        "generator_meta": {
            "primary_model": row.get("primary_model"),
            "review_model": row.get("review_model"),
            "confidence_grade": grade,
        },
        "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
        "updated_at": updated.isoformat() if hasattr(updated, "isoformat") else str(updated),
    }


def _intake_api(row: dict | None, job_id: str, *, db: Session | None = None) -> dict:
    from app.services.mobile_report_service import is_mobile_intake
    from app.services.mobile_forensic.key_intake import key_capture_status

    job = (fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}) if db is not None else {}

    if not row:
        ready, missing = False, ["subjects", "case_type", "report_type", "objectives"]
        return {
            "case_id": job_id,
            "case_type": None,
            "organization": None,
            "address": None,
            "evidence_description": None,
            "seizure_date": None,
            "background": None,
            "incident_summary": None,
            "pre_seizure_consent": None,
            "evidence_handling": None,
            "scan_scope_json": {},
            "report_type": None,
            "objective_ids": [],
            "custom_objectives": [],
            "subjects": [],
            "report_ready": ready,
            "missing_fields": missing,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "forensic_key_status": _forensic_key_status(job),
            "whatsapp_key_capture": key_capture_status(job.get("disk_source")),
        }
    subjects = row.get("subjects") or []
    if isinstance(subjects, str):
        subjects = json.loads(subjects)
    objs = row.get("objective_ids") or []
    if isinstance(objs, str):
        objs = json.loads(objs)
    custom = row.get("custom_objectives") or []
    if isinstance(custom, str):
        custom = json.loads(custom)
    mobile = is_mobile_intake(dict(row), job)
    # Mobile case intake does not require examination objectives.
    if mobile:
        objs = []
        custom = []
    missing: list[str] = []
    if not subjects:
        missing.append("subjects")
    if not row.get("case_type"):
        missing.append("case_type")
    if not row.get("report_type"):
        missing.append("report_type")
    if not mobile and not objs and not custom:
        missing.append("objectives")
    ready = len(missing) == 0
    updated = row.get("updated_at")
    return {
        "case_id": str(row.get("case_id") or job_id),
        "case_type": row.get("case_type"),
        "organization": row.get("organization"),
        "address": None,
        "evidence_description": None,
        "seizure_date": None,
        "background": row.get("background"),
        "incident_summary": row.get("incident_summary"),
        "pre_seizure_consent": None,
        "evidence_handling": None,
        "scan_scope_json": row.get("scan_scope_json") or {},
        "report_type": row.get("report_type"),
        "objective_ids": objs,
        "custom_objectives": custom,
        "subjects": subjects,
        "report_ready": ready,
        "missing_fields": missing,
        "requesting_agency": row.get("requesting_agency"),
        "case_number": row.get("case_number"),
        "examiner_name": row.get("examiner_name"),
        "lab_location": row.get("lab_location"),
        "evidence_received_date": str(row.get("evidence_received_date") or "") or None,
        "chain_of_custody_ref": row.get("chain_of_custody_ref"),
        "vol18_form_json": row.get("vol18_form_json") or {},
        "updated_at": updated.isoformat() if hasattr(updated, "isoformat") else str(updated),
        "forensic_key_status": _forensic_key_status(job),
        "whatsapp_key_capture": key_capture_status(job.get("disk_source")),
    }


@router.get("/jobs/report/types")
def list_report_types_endpoint(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    return {"items": catalog_report_types(db)}


@router.get("/jobs/report/case-types")
def list_case_types_endpoint(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    return {"items": load_case_types(db)}


@router.get("/jobs/report/objectives")
def list_report_objectives(
    report_type: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.services.report_template_service import purge_duplicate_report_objectives

    purge_duplicate_report_objectives(db)
    result = list_objectives_for_report_type(db, report_type)
    db.commit()
    return result


@router.get("/jobs/report/template-artifacts")
def list_report_template_artifacts(
    report_type: str | None = None,
    platform: str = Query(default="Windows"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.services.report_template_service import list_template_artifacts

    items = list_template_artifacts(db, report_type, platform=platform)
    return {"items": items, "report_type": report_type, "platform": platform}


@router.get("/jobs/report/artifact-mapping")
def report_artifact_mapping(
    report_type: str | None = None,
    platform: str = Query(default="Windows"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Report name → AXIOM group (category) → artifact name, with axiom_artifacts join."""
    from app.services.report_template_service import get_report_artifact_mapping

    return get_report_artifact_mapping(db, report_type=report_type, platform=platform)


@router.get("/jobs/report/catalog-artifacts-by-group")
@router.get("/jobs/report/axiom-artifacts-by-group")
def catalog_artifacts_by_group(
    platform: str = Query(default="Windows"),
    category: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Full artifact catalog by group — use when extending report artifact mappings."""
    from app.services.report_template_service import list_axiom_artifacts_by_group

    rows = list_axiom_artifacts_by_group(db, platform=platform, category=category)
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        cat = str(row.get("category") or "Other")
        grouped.setdefault(cat, []).append(row)
    return {
        "platform": platform,
        "category_filter": category,
        "groups": [{"category": cat, "artifacts": arts} for cat, arts in sorted(grouped.items())],
        "total": len(rows),
    }


@router.get("/jobs/{job_id}/selected-job-artifacts")
def get_selected_job_artifacts_route(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.services.report_template_service import get_selected_job_artifacts

    _ensure_job(db, job_id)
    row = get_selected_job_artifacts(db, job_id)
    if not row:
        return {"job_id": job_id, "artifact_ids": [], "artifacts_json": [], "saved_at": None}
    saved = row.get("saved_at")
    return {
        "job_id": job_id,
        "report_type_id": row.get("report_type_id"),
        "artifact_ids": row.get("artifact_ids") or [],
        "artifacts_json": row.get("artifacts_json") or [],
        "saved_at": saved.isoformat() if saved and hasattr(saved, "isoformat") else saved,
    }


@router.put("/jobs/{job_id}/selected-job-artifacts")
def save_selected_job_artifacts_route(
    job_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.report_template_service import save_selected_job_artifacts

    _ensure_job(db, job_id)
    keys = body.get("artifact_ids") or body.get("enabled_keys") or []
    row = save_selected_job_artifacts(
        db,
        job_id,
        [str(k) for k in keys],
        report_type=body.get("report_type"),
    )
    db.commit()
    saved = row.get("saved_at")
    return {
        "job_id": job_id,
        "report_type_id": row.get("report_type_id"),
        "artifact_ids": row.get("artifact_ids") or [],
        "artifacts_json": row.get("artifacts_json") or [],
        "saved_at": saved.isoformat() if saved and hasattr(saved, "isoformat") else saved,
    }


@router.get("/jobs/{job_id}/selected-job-objectives-procedure")
def get_selected_job_objectives_route(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.services.report_template_service import get_selected_job_objectives

    _ensure_job(db, job_id)
    row = get_selected_job_objectives(db, job_id)
    if not row:
        return {"job_id": job_id, "objective_ids": [], "objectives_json": [], "saved_at": None}
    saved = row.get("saved_at")
    return {
        "job_id": job_id,
        "report_type_id": row.get("report_type_id"),
        "objective_ids": row.get("objective_ids") or [],
        "custom_objectives": row.get("custom_objectives") or [],
        "objectives_json": row.get("objectives_json") or [],
        "saved_at": saved.isoformat() if saved and hasattr(saved, "isoformat") else saved,
    }


def _forensic_key_status(job: dict | None) -> dict[str, bool]:
    from app.services.mobile_forensic.integrity import forensic_key_status_from_disk_source

    ds = (job or {}).get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    return forensic_key_status_from_disk_source(ds if isinstance(ds, dict) else {})


def _intake_row(db: Session, job_id: str, *, schema_name: str | None) -> dict | None:
    apply_firm_search_path(db, schema_name)
    return fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})


@router.get("/jobs/{job_id}/intake")
def get_intake(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    row = _intake_row(db, job_id, schema_name=current.schema_name)
    return _intake_api(row, job_id, db=db)


@router.patch("/jobs/{job_id}/intake")
def patch_intake(
    job_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    forensic_keys = body.get("forensic_keys") or {}
    if not isinstance(forensic_keys, dict):
        raise HTTPException(status_code=400, detail="forensic_keys must be an object")
    whatsapp_key = forensic_keys.get("whatsapp_key_hex")
    if whatsapp_key and str(whatsapp_key).strip():
        from app.services.mobile_forensic.whatsapp_crypt import parse_key_material

        if parse_key_material(str(whatsapp_key)) is None:
            raise HTTPException(status_code=400, detail="Invalid WhatsApp key. Enter the matching 64-character hex secret or complete collected key-file hex. CRYPT5 also accepts a 48-character derived secret. CRYPT15 uses encrypted_backup.key; CRYPT7/8/9/10/11/12/14 use files/key. ADB error text is not a key.")
    legacy_account = forensic_keys.get("whatsapp_legacy_account")
    if legacy_account and ("@" not in str(legacy_account) or len(str(legacy_account)) > 320 or any(ord(ch) < 32 for ch in str(legacy_account))):
        raise HTTPException(status_code=400, detail="CRYPT5 requires the original Android Google account email")
    apply_firm_search_path(db, current.schema_name)
    existing = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    case_type_raw = body.get("case_type")
    validated_case = validate_case_type(db, case_type_raw) if case_type_raw else None
    if case_type_raw and validated_case:
        case_type_raw = validated_case.get("case_type_id") or case_type_raw
    report_type_raw = body.get("report_type")
    if not report_type_raw and validated_case:
        report_type_raw = default_report_type_for_case(db, case_type_raw)
    fields = {
        "case_type": case_type_raw,
        "organization": body.get("organization"),
        "background": body.get("background"),
        "incident_summary": body.get("incident_summary"),
        "report_type": report_type_raw,
        "objective_ids": json.dumps(body.get("objective_ids") or []),
        "custom_objectives": json.dumps(body.get("custom_objectives") or []),
        "subjects": json.dumps(body.get("subjects") or []),
        "scan_scope_json": json.dumps(body.get("scan_scope_json") or {}),
        "requesting_agency": body.get("requesting_agency"),
        "case_number": body.get("case_number"),
        "examiner_name": body.get("examiner_name"),
        "lab_location": body.get("lab_location"),
        "evidence_received_date": body.get("evidence_received_date") or None,
        "chain_of_custody_ref": body.get("chain_of_custody_ref"),
        "vol18_form_json": json.dumps(body.get("vol18_form_json") or {}),
    }
    if existing:
        execute(
            db,
            """UPDATE case_intake SET case_type=:case_type, organization=:organization, background=:background,
               incident_summary=:incident_summary, report_type=:report_type, objective_ids=CAST(:objective_ids AS jsonb),
               custom_objectives=CAST(:custom_objectives AS jsonb), subjects=CAST(:subjects AS jsonb),
               scan_scope_json=CAST(:scan_scope_json AS jsonb),
               requesting_agency=:requesting_agency, case_number=:case_number, examiner_name=:examiner_name,
               lab_location=:lab_location, evidence_received_date=:evidence_received_date,
               chain_of_custody_ref=:chain_of_custody_ref,
               vol18_form_json=CAST(:vol18_form_json AS jsonb), updated_at=NOW()
               WHERE job_id=:jid""",
            {**fields, "jid": job_id},
        )
    else:
        execute(
            db,
            """INSERT INTO case_intake (job_id, case_type, organization, background, incident_summary,
               report_type, objective_ids, custom_objectives, subjects, scan_scope_json,
               requesting_agency, case_number, examiner_name, lab_location, evidence_received_date,
               chain_of_custody_ref, vol18_form_json)
               VALUES (:jid, :case_type, :organization, :background, :incident_summary, :report_type,
                       CAST(:objective_ids AS jsonb), CAST(:custom_objectives AS jsonb),
                       CAST(:subjects AS jsonb), CAST(:scan_scope_json AS jsonb),
                       :requesting_agency, :case_number, :examiner_name, :lab_location,
                       :evidence_received_date, :chain_of_custody_ref, CAST(:vol18_form_json AS jsonb))""",
            {**fields, "jid": job_id},
        )
    db.commit()
    try:
        from app.services.mobile_forensic.integrity import persist_forensic_keys_to_disk_source

        persist_forensic_keys_to_disk_source(db, job_id, body.get("forensic_keys"))
        db.commit()
    except Exception:
        db.rollback()
        apply_firm_search_path(db, current.schema_name)
    apply_firm_search_path(db, current.schema_name)
    try:
        from app.services.report_template_service import save_selected_job_objectives

        save_selected_job_objectives(
            db,
            job_id,
            report_type=report_type_raw,
            objective_ids=list(body.get("objective_ids") or []),
            custom_objectives=list(body.get("custom_objectives") or []),
        )
        try:
            from app.services.report_template_service import canonical_objective_ids

            scope_ids = canonical_objective_ids(
                db, [str(x) for x in (body.get("objective_ids") or []) if str(x).strip()]
            )
            execute(
                db,
                """INSERT INTO objective_procedure_scope (job_id, enabled_objective_ids, custom_objectives)
                   VALUES (:jid, CAST(:s AS jsonb), CAST(:c AS jsonb))
                   ON CONFLICT (job_id) DO UPDATE SET
                     enabled_objective_ids=EXCLUDED.enabled_objective_ids,
                     custom_objectives=EXCLUDED.custom_objectives,
                     updated_at=NOW()""",
                {
                    "jid": job_id,
                    "s": json.dumps(scope_ids),
                    "c": json.dumps(body.get("custom_objectives") or []),
                },
            )
        except Exception:
            pass
        db.commit()
    except Exception:
        db.rollback()
        apply_firm_search_path(db, current.schema_name)
    row = _intake_row(db, job_id, schema_name=current.schema_name)
    return _intake_api(row, job_id, db=db)


@router.post("/jobs/{job_id}/intake/whatsapp-key/capture")
def capture_whatsapp_key(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.mobile_forensic.key_intake import capture_registered_keys

    apply_firm_search_path(db, current.schema_name)
    _ensure_job(db, job_id)
    try:
        result = capture_registered_keys(db, job_id, include_case_folder=True)
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/jobs/{job_id}/intake/whatsapp-key/file")
async def upload_whatsapp_key_file(
    job_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.mobile_forensic.key_intake import attach_key_file

    apply_firm_search_path(db, current.schema_name)
    _ensure_job(db, job_id)
    material = await file.read(513)
    await file.close()
    try:
        result = attach_key_file(db, job_id, material, filename=file.filename or "key")
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _artifact_scope_payload(db: Session, job_id: str) -> dict:
    from app.services.artifact_export import artifact_scope_payload

    return artifact_scope_payload(db, job_id)


def _read_objective_procedure_scope_row(db: Session, job_id: str) -> dict | None:
    try:
        return fetchone(
            db,
            "SELECT enabled_objective_ids, custom_objectives FROM objective_procedure_scope WHERE job_id=:jid",
            {"jid": job_id},
        )
    except Exception:
        db.rollback()
        row = fetchone(
            db,
            "SELECT enabled_objective_ids FROM objective_procedure_scope WHERE job_id=:jid",
            {"jid": job_id},
        )
        if row is not None:
            row = dict(row)
            row["custom_objectives"] = []
        return row


def _objective_procedure_scope_payload(db: Session, job_id: str) -> dict:
    from app.services.artifact_selection_catalog import (
        default_enabled_objective_ids,
        get_objective_procedure_catalog,
    )
    from app.services.report_template_service import canonical_objective_ids

    catalog = get_objective_procedure_catalog(db)
    default_ids = default_enabled_objective_ids(catalog)
    row = _read_objective_procedure_scope_row(db, job_id)
    stored = row["enabled_objective_ids"] if row else []
    if isinstance(stored, str):
        stored = json.loads(stored)
    enabled = stored if isinstance(stored, list) and stored else default_ids
    enabled = canonical_objective_ids(db, [str(x) for x in enabled if str(x).strip()])
    custom = row.get("custom_objectives") if row else []
    if isinstance(custom, str):
        custom = json.loads(custom)
    if not isinstance(custom, list):
        custom = []
    return {
        "enabled_objective_ids": enabled,
        "custom_objectives": custom,
        "sections": catalog["sections"],
        "default_critical_ids": default_ids,
        "total": catalog.get("total", 0),
    }


@router.get("/jobs/{job_id}/artifact-scope/export")
def export_artifact_scope(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    from app.services.artifact_export import build_catalog_export_for_job, export_filename

    job = fetchone(
        db,
        """SELECT j.id, c.title AS case_title FROM jobs j
           LEFT JOIN forensic_cases c ON c.id = j.case_id
           WHERE j.id=:id""",
        {"id": job_id},
    )
    if not job:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Job not found"}})
    case_title = job.get("case_title")
    content = build_catalog_export_for_job(db, job_id, job_label=case_title or str(job_id))
    filename = export_filename(job_id, "artifacts", case_name=case_title)
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/jobs/{job_id}/artifact-scope")
def get_artifact_scope(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.services.artifact_export import artifact_scope_payload

    _ensure_job(db, job_id)
    return artifact_scope_payload(db, job_id, allow_zero_count=True, read_only=True)


@router.post("/jobs/{job_id}/artifact-scope/refresh")
def refresh_artifact_scope(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Recompute and persist AXIOM-aligned counts, then return stored catalog (slow — on demand)."""
    from app.services.artifact_export import artifact_scope_payload
    from app.services.axiom_artifact_runner import persist_collector_counts

    _ensure_job(db, job_id)
    persist_collector_counts(db, job_id)
    db.commit()
    return artifact_scope_payload(db, job_id, allow_zero_count=True, read_only=True)


@router.post("/jobs/{job_id}/artifact-inventory/ensure")
def ensure_artifact_inventory_endpoint(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Start artifact inventory only when no stored counts exist yet."""
    from app.services.axiom_artifact_runner import ensure_artifact_inventory

    _ensure_job(db, job_id)
    result = ensure_artifact_inventory(db, job_id, schema_name=current.schema_name)
    db.commit()
    return {"job_id": job_id, **result}


@router.put("/jobs/{job_id}/artifact-scope")
def update_artifact_scope(
    job_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    keys = body.get("enabled_keys") or []
    execute(
        db,
        """INSERT INTO artifact_scope (job_id, sections) VALUES (:jid, CAST(:s AS jsonb))
           ON CONFLICT (job_id) DO UPDATE SET sections=EXCLUDED.sections, updated_at=NOW()""",
        {"jid": job_id, "s": json.dumps(keys)},
    )
    from app.services.artifact_export import artifact_scope_payload
    from app.services.artifact_group_service import resolve_artifact_scope
    from app.services.artifact_selection_catalog import get_selection_artifact_catalog, resolve_job_axiom_platform
    from app.services.report_template_service import save_selected_job_artifacts

    platform = resolve_job_axiom_platform(db, job_id)
    catalog = get_selection_artifact_catalog(db, platform=platform, job_id=job_id)
    resolve_artifact_scope(
        db, job_id, catalog, stored_enabled=keys, persist=True, allow_zero_count=True,
    )
    save_selected_job_artifacts(
        db,
        job_id,
        [str(k) for k in keys],
        sync_scope=False,
    )
    db.commit()
    return artifact_scope_payload(db, job_id, allow_zero_count=True)


@router.post("/jobs/{job_id}/artifact-inventory/rerun")
def rerun_artifact_inventory_endpoint(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.services.axiom_artifact_runner import rerun_artifact_inventory

    return rerun_artifact_inventory(db, job_id, schema_name=current.schema_name)


@router.get("/jobs/{job_id}/objective-procedure-scope")
def get_objective_procedure_scope(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("artifact:read")),
):
    return _objective_procedure_scope_payload(db, job_id)


@router.put("/jobs/{job_id}/objective-procedure-scope")
def update_objective_procedure_scope(
    job_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    keys = body.get("enabled_objective_ids") or []
    from app.services.report_template_service import canonical_objective_ids

    keys = canonical_objective_ids(db, [str(x) for x in keys if str(x).strip()])
    custom = body.get("custom_objectives")
    if custom is None:
        existing = _read_objective_procedure_scope_row(db, job_id)
        custom = (existing or {}).get("custom_objectives") if existing else []
    try:
        execute(
            db,
            """INSERT INTO objective_procedure_scope (job_id, enabled_objective_ids, custom_objectives)
               VALUES (:jid, CAST(:s AS jsonb), CAST(:c AS jsonb))
               ON CONFLICT (job_id) DO UPDATE SET
                 enabled_objective_ids=EXCLUDED.enabled_objective_ids,
                 custom_objectives=EXCLUDED.custom_objectives,
                 updated_at=NOW()""",
            {"jid": job_id, "s": json.dumps(keys), "c": json.dumps(custom or [])},
        )
    except Exception:
        db.rollback()
        execute(
            db,
            """INSERT INTO objective_procedure_scope (job_id, enabled_objective_ids)
               VALUES (:jid, CAST(:s AS jsonb))
               ON CONFLICT (job_id) DO UPDATE SET
                 enabled_objective_ids=EXCLUDED.enabled_objective_ids,
                 updated_at=NOW()""",
            {"jid": job_id, "s": json.dumps(keys)},
        )
    db.commit()
    return _objective_procedure_scope_payload(db, job_id)


@router.post("/jobs/{job_id}/report/start")
def start_report(
    job_id: str,
    body: dict | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    from app.tasks import report_gen_task

    ready, missing = _intake_ready(db, job_id)
    if not ready:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "intake_incomplete", "message": f"Missing: {', '.join(missing)}"}},
        )
    schema = current.schema_name
    if not schema:
        raise HTTPException(status_code=500, detail={"error": {"code": "no_schema", "message": "Tenant schema missing"}})
    apply_firm_search_path(db, schema)
    body = body or {}
    recreate = bool(body.get("recreate") or body.get("force"))
    existing = fetchone(
        db,
        """SELECT rr.id, rr.status,
                  (SELECT count(*) FROM report_sections rs WHERE rs.report_run_id = rr.id) AS section_count
           FROM report_runs rr
           WHERE rr.job_id=:jid
           ORDER BY rr.created_at DESC LIMIT 1""",
        {"jid": job_id},
    )
    if existing and existing.get("status") == "running" and not recreate:
        sec_n = int(existing.get("section_count") or 0)
        from app.services.report_renderer import section_order_for_job

        sections_total = len(section_order_for_job(db, job_id))
        return {
            "job_id": job_id,
            "status": "already_generating",
            "report_run_id": str(existing["id"]),
            "sections_completed": sec_n,
            "sections_total": sections_total,
            "message": f"Report generation in progress ({sec_n}/{sections_total} sections)",
        }
    if recreate:
        execute(
            db,
            """UPDATE report_runs
               SET status='superseded', error='Report Generator Agent recreated from beginning', completed_at=COALESCE(completed_at, NOW())
               WHERE job_id=:jid AND status IN ('running', 'completed', 'failed', 'paused')""",
            {"jid": job_id},
        )
        db.commit()
        apply_firm_search_path(db, schema)
        # Keep superseded sections until the new run writes replacements.
        # Deleting them here blanks C. OBJECTIVE / annexure if generation is interrupted.
    report_gen_task.delay(schema, job_id, None)
    return {
        "job_id": job_id,
        "status": "generating",
        "message": "Report recreation queued from beginning" if recreate else "Report generation queued",
        "report_run_id": None,
    }


@router.get("/jobs/{job_id}/report")
def get_report_status(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Report run summary for clients polling /jobs/{id}/report (avoids 404)."""
    from app.services.report_renderer import section_order_for_job

    sections_total = len(section_order_for_job(db, job_id))
    # Prefer a completed run with sections over a newer failed/empty attempt.
    run = fetchone(
        db,
        """SELECT id, status, duration_ms, error, created_at, completed_at, started_at
           FROM report_runs WHERE job_id=:jid
           ORDER BY
             CASE status
               WHEN 'running' THEN 0
               WHEN 'completed' THEN 1
               WHEN 'failed' THEN 2
               ELSE 3
             END,
             created_at DESC
           LIMIT 1""",
        {"jid": job_id},
    )
    if not run:
        return {
            "job_id": job_id,
            "status": "none",
            "report_run_id": None,
            "sections_completed": 0,
            "sections_total": sections_total,
        }
    rid = run["id"]
    sec_count = fetchone(
        db,
        "SELECT count(*) c FROM report_sections WHERE report_run_id=:rid",
        {"rid": rid},
    )
    count = int(sec_count["c"]) if sec_count else 0
    return {
        "job_id": job_id,
        "status": run.get("status") or "unknown",
        "report_run_id": str(rid),
        "sections_completed": count,
        "sections_total": sections_total,
        "duration_ms": run.get("duration_ms"),
        "error": run.get("error"),
    }


@router.get("/jobs/{job_id}/report/stream")
async def stream_report(
    job_id: str,
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    from app.db.session import firm_session
    from app.services.report_renderer import section_order_for_job

    schema_name = current.schema_name
    if not schema_name:
        raise HTTPException(status_code=500, detail={"error": {"code": "no_schema", "message": "Tenant schema missing"}})

    with firm_session(schema_name) as db:
        expected_sections = section_order_for_job(db, job_id)
    sections_total = len(expected_sections)

    async def event_gen():
        last_payload = ""
        waiting_ticks = 0
        for _ in range(1800):  # up to ~30 minutes of heartbeats
            try:
                with firm_session(schema_name) as db:
                    apply_firm_search_path(db, schema_name)
                    try:
                        from app.services.report_generator import ensure_report_run_progress_schema

                        ensure_report_run_progress_schema(db)
                        db.commit()
                        apply_firm_search_path(db, schema_name)
                    except Exception:
                        try:
                            db.rollback()
                            apply_firm_search_path(db, schema_name)
                        except Exception:
                            pass
                    run = fetchone(
                        db,
                        """SELECT * FROM report_runs WHERE job_id=:jid
                            ORDER BY
                              CASE status
                                WHEN 'running' THEN 0
                                WHEN 'completed' THEN 1
                                WHEN 'failed' THEN 2
                                ELSE 3
                              END,
                              created_at DESC
                            LIMIT 1""",
                        {"jid": job_id},
                    )
                    if not run:
                        waiting_ticks += 1
                        # Worker may finish as blocked before creating a run — don't hang for 30 minutes.
                        if waiting_ticks >= 45:
                            yield (
                                "event: error\ndata: "
                                + json.dumps({
                                    "message": (
                                        "Report generation did not start within 45s. "
                                        "Check Case intake is complete, then click Generate report again."
                                    )
                                })
                                + "\n\n"
                            )
                            break
                        yield f"event: progress\ndata: {json.dumps({'stage': 'waiting', 'progress_pct': 0, 'sections_total': sections_total})}\n\n"
                        await asyncio.sleep(1)
                        continue
                    waiting_ticks = 0
                    sec_count = fetchone(
                        db,
                        "SELECT count(*) c FROM report_sections WHERE report_run_id=:rid",
                        {"rid": run["id"]},
                    )
                    count = int(sec_count["c"]) if sec_count else 0
                    latest = fetchone(
                        db,
                        """SELECT section_key, sort_order, primary_model, review_model, confidence_grade
                           FROM report_sections WHERE report_run_id=:rid
                           ORDER BY sort_order DESC LIMIT 1""",
                        {"rid": run["id"]},
                    )
                    # Prefer live worker progress (current section) over last completed section.
                    live = run.get("progress") or {}
                    if isinstance(live, str):
                        try:
                            live = json.loads(live)
                        except Exception:
                            live = {}
                    if not isinstance(live, dict):
                        live = {}

                    total = int(live.get("total_sections") or sections_total) or sections_total
                    run_status = (run.get("status") or "").lower()
                    live_stage = str(live.get("stage") or "")
                    if live.get("section_key") and run_status == "running":
                        section_key = str(live.get("section_key") or "")
                        section_idx = int(live.get("section_index") or max(count + 1, 1))
                    elif latest:
                        # Infer "next" section while a long step runs without progress writes.
                        completed_idx = int(latest.get("sort_order", 0)) + 1
                        if run_status == "running" and count < total:
                            section_idx = min(total, completed_idx + 1)
                            section_key = (
                                expected_sections[section_idx - 1]
                                if 0 <= section_idx - 1 < len(expected_sections)
                                else str(latest.get("section_key") or "")
                            )
                        else:
                            section_key = str(latest.get("section_key") or "")
                            section_idx = completed_idx
                    else:
                        section_key = ""
                        section_idx = max(count, 1)

                    # Percent tracks completed sections, plus intra-section objective progress.
                    if run_status == "completed":
                        pct = 100
                    elif total > 0:
                        pct = min(99, int((count / total) * 100))
                        if run_status == "running" and count < total:
                            sub_i = live.get("sub_index")
                            sub_n = live.get("sub_total")
                            try:
                                sub_i_n = int(sub_i) if sub_i is not None else 0
                                sub_n_n = int(sub_n) if sub_n is not None else 0
                            except (TypeError, ValueError):
                                sub_i_n, sub_n_n = 0, 0
                            if sub_n_n > 0:
                                section_span = max(1, int(100 / total))
                                pct = min(
                                    99,
                                    pct + int(section_span * min(1.0, max(0.0, sub_i_n / sub_n_n))),
                                )
                            else:
                                pct = min(99, pct + max(1, int(100 / (total * 2))))
                    else:
                        pct = 0

                    pipeline_stage = (
                        "complete"
                        if run_status == "completed"
                        else ("failed" if run_status == "failed" else (live_stage or "running"))
                    )
                    detail = str(live.get("detail") or "").strip()
                    stage_label = (
                        f"Section {section_idx}/{total} — {section_key}"
                        + (f" ({live_stage})" if live_stage and live_stage not in ("done", "running") else "")
                        + (f" · {detail}" if detail else "")
                        if section_key
                        else f"Section {count}/{total}"
                    )

                    event_data = {
                        "stage": stage_label,
                        "progress_pct": pct,
                        "section_key": section_key,
                        "section_index": section_idx,
                        "sections_total": total,
                        "sections_completed": count,
                        "pipeline_stage": pipeline_stage,
                        "run_status": run_status,
                        "primary_model": live.get("primary_model")
                        or (latest or {}).get("primary_model")
                        or run.get("primary_model"),
                        "review_model": live.get("review_model")
                        or (latest or {}).get("review_model")
                        or run.get("review_model"),
                        "confidence_grade": live.get("confidence_grade")
                        or (latest or {}).get("confidence_grade"),
                    }
                    payload = json.dumps(event_data)
                    # Heartbeat every tick so the UI never freezes on a long LLM/annexure step.
                    if payload != last_payload or run_status in ("completed", "failed"):
                        yield f"event: progress\ndata: {payload}\n\n"
                        last_payload = payload
                    elif run_status == "running":
                        yield f"event: progress\ndata: {payload}\n\n"
                    if run_status == "completed":
                        yield f"event: done\ndata: {json.dumps({'duration_ms': run.get('duration_ms'), 'sections_completed': count})}\n\n"
                        break
                    if run_status == "failed":
                        yield f"event: error\ndata: {json.dumps({'message': run.get('error') or 'Report generation failed'})}\n\n"
                        break
            except Exception as exc:
                yield f"event: error\ndata: {json.dumps({'message': str(exc)[:500]})}\n\n"
                break
            await asyncio.sleep(1)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.get("/reports/{job_id}/sections")
def list_sections(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    rows = fetchall(
        db,
        f"""SELECT rs.* FROM report_sections rs
           JOIN report_runs rr ON rr.id = rs.report_run_id
           WHERE rs.job_id=:jid
             AND rr.id = ({_LATEST_REPORT_RUN_SQL.strip()})
           ORDER BY rs.sort_order""",
        {"jid": job_id},
    )
    have = {str(r["section_key"]) for r in (rows or [])}
    older = fetchall(
        db,
        """SELECT rs.*
           FROM report_sections rs
           JOIN report_runs rr ON rr.id = rs.report_run_id
           WHERE rs.job_id=:jid
           ORDER BY rr.created_at DESC, rs.sort_order""",
        {"jid": job_id},
    ) or []
    extras = []
    for extra in older:
        key = str(extra.get("section_key") or "")
        if not key or key in have:
            continue
        extras.append(extra)
        have.add(key)
    if extras:
        rows = list(rows or []) + extras
    from app.services.artifact_report_service import hydrate_artifact_summary_section

    out = []
    for r in rows:
        row = dict(r)
        if row.get("section_key") == "artifact_summary":
            try:
                row = hydrate_artifact_summary_section(db, job_id, row)
            except Exception:
                pass
        cites = fetchall(
            db,
            "SELECT artifact_id, file_path, citation_label FROM report_citations WHERE report_section_id=:sid",
            {"sid": row["id"]},
        )
        out.append(_section_api(row, [dict(c) for c in cites]))
    return out


@router.patch("/reports/{job_id}/sections/{section_key}")
def patch_section(
    job_id: str,
    section_key: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    execute(
        db,
        f"""UPDATE report_sections SET
             content_md=COALESCE(:content, content_md),
             structured_json=COALESCE(CAST(:sj AS jsonb), structured_json),
             status=COALESCE(:status, status),
             approved=CASE
               WHEN :status = 'approved' THEN TRUE
               WHEN :status IN ('rejected', 'needs_review', 'pending') THEN FALSE
               ELSE approved
             END,
             updated_at=NOW()
           WHERE id = (
             SELECT rs.id FROM report_sections rs
             WHERE rs.job_id=:jid AND rs.section_key=:key
               AND rs.report_run_id = ({_LATEST_REPORT_RUN_SQL.strip()})
             LIMIT 1
           )""",
        {
            "content": body.get("narrative_content"),
            "sj": json.dumps(body.get("structured_json")) if body.get("structured_json") is not None else None,
            "status": body.get("verification_status"),
            "jid": job_id,
            "key": section_key,
        },
    )
    db.commit()
    row = fetchone(
        db,
        f"""SELECT * FROM report_sections
            WHERE job_id=:jid AND section_key=:key
              AND report_run_id = ({_LATEST_REPORT_RUN_SQL.strip()})""",
        {"jid": job_id, "key": section_key},
    )
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Section not found"}})
    return _section_api(dict(row))


@router.get("/reports/{job_id}/gate")
def report_gate(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    rows = fetchall(
        db,
        f"""SELECT section_key, status, approved FROM report_sections rs
           WHERE rs.job_id=:jid
             AND rs.report_run_id = (
               {_LATEST_REPORT_RUN_SQL.strip()}
             )""",
        {"jid": job_id},
    )
    run = fetchone(
        db,
        f"SELECT status FROM report_runs WHERE id = ({_LATEST_REPORT_RUN_SQL.strip()})",
        {"jid": job_id},
    )
    run_status = (run or {}).get("status") or ""
    pending = [r["section_key"] for r in rows if not r.get("approved")]
    needs = [r["section_key"] for r in rows if r.get("status") == "needs_review"]
    from app.services.report_renderer import section_order_for_job

    section_order = section_order_for_job(db, job_id)
    present = {r["section_key"] for r in rows}
    missing_sections = [k for k in section_order if k not in present]
    if run_status == "running":
        missing_required: list[str] = []
    elif not rows:
        missing_required = ["report_not_generated"]
    elif missing_sections:
        missing_required = missing_sections
    else:
        missing_required = []
    return {
        "cleared": len(rows) >= len(section_order) and len(pending) == 0 and not missing_sections,
        "pending": pending,
        "needs_review": needs,
        "missing_required": missing_required,
        "sections_completed": len(rows),
        "sections_total": len(section_order),
        "run_status": run_status,
    }


@router.post("/reports/{job_id}/approve")
def approve_report(
    job_id: str,
    body: dict | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    execute(
        db,
        """UPDATE report_sections SET approved=TRUE, status='approved', approved_at=NOW()
           WHERE job_id=:jid""",
        {"jid": job_id},
    )
    db.commit()
    rows = fetchall(
        db,
        "SELECT * FROM report_sections WHERE job_id=:jid ORDER BY sort_order",
        {"jid": job_id},
    )
    return [_section_api(dict(r)) for r in rows]


def _report_version_label(version_index: int | None) -> str | None:
    if version_index is None:
        return None
    return f"V1.{int(version_index)}"


def _iso_ts(value) -> str | None:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _report_catalog_api_row(row: dict, *, sections_total: int | None = None) -> dict:
    ver_idx = row.get("version_index")
    has_run = bool(row.get("report_run_id"))
    return {
        "job_id": str(row["job_id"]),
        "report_run_id": str(row["report_run_id"]) if has_run else None,
        "version": _report_version_label(int(ver_idx)) if has_run and ver_idx is not None else None,
        "created_by": str(row["created_by"]) if row.get("created_by") else None,
        "created_by_email": row.get("created_by_email"),
        "organization": row.get("organization"),
        "case_type": row.get("case_type"),
        "report_type": row.get("report_type"),
        "job_status": row.get("job_status"),
        "job_type": row.get("job_type"),
        "report_status": row.get("report_status") if has_run else "none",
        "sections_completed": int(row.get("sections_completed") or 0),
        "sections_total": sections_total,
        "export_count": int(row.get("export_count") or 0),
        "job_created_at": _iso_ts(row.get("job_created_at")),
        "report_created_at": _iso_ts(row.get("report_created_at")),
        "report_completed_at": _iso_ts(row.get("report_completed_at")),
        "duration_ms": row.get("duration_ms"),
        "report_error": row.get("report_error"),
    }


@router.get("/reports/list")
def list_report_catalog(
    job_id: str | None = Query(None),
    run_status: str | None = Query(None),
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """List all forensic jobs with report run versions, creator, and organization."""
    from app.services.report_renderer import section_order_for_job

    params: dict = {}
    where = ["1=1"]
    if job_id:
        where.append("c.job_id = CAST(:job_id AS uuid)")
        params["job_id"] = job_id
    if run_status:
        if run_status == "none":
            where.append("c.report_run_id IS NULL")
        else:
            where.append("c.report_status = :run_status")
            params["run_status"] = run_status
    if from_ts:
        where.append("c.sort_ts >= CAST(:from_ts AS timestamptz)")
        params["from_ts"] = from_ts
    if to_ts:
        where.append("c.sort_ts <= CAST(:to_ts AS timestamptz)")
        params["to_ts"] = to_ts
    where_sql = " AND ".join(where)

    count_row = fetchone(
        db,
        f"""WITH catalog AS (
              SELECT j.id AS job_id,
                     j.status AS job_status,
                     j.type AS job_type,
                     j.created_by,
                     j.created_at AS job_created_at,
                     j.updated_at AS job_updated_at,
                     u.email AS created_by_email,
                     ci.organization,
                     ci.case_type,
                     ci.report_type,
                     rr.id AS report_run_id,
                     rr.status AS report_status,
                     rr.created_at AS report_created_at,
                     rr.completed_at AS report_completed_at,
                     rr.duration_ms,
                     rr.error AS report_error,
                     (SELECT count(*) FROM report_sections rs WHERE rs.report_run_id = rr.id) AS sections_completed,
                     (SELECT count(*) FROM report_exports e WHERE e.report_run_id = rr.id AND e.format <> 'html') AS export_count,
                     CASE WHEN rr.id IS NOT NULL
                       THEN ROW_NUMBER() OVER (PARTITION BY j.id ORDER BY rr.created_at ASC) - 1
                       ELSE NULL
                     END AS version_index,
                     COALESCE(rr.created_at, j.created_at) AS sort_ts
              FROM jobs j
              LEFT JOIN users u ON u.id = j.created_by
              LEFT JOIN case_intake ci ON ci.job_id = j.id
              LEFT JOIN report_runs rr ON rr.job_id = j.id
            )
            SELECT count(*) c FROM catalog c WHERE {where_sql}""",
        params,
    )
    total = int(count_row["c"]) if count_row else 0
    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset
    rows = fetchall(
        db,
        f"""WITH catalog AS (
              SELECT j.id AS job_id,
                     j.status AS job_status,
                     j.type AS job_type,
                     j.created_by,
                     j.created_at AS job_created_at,
                     j.updated_at AS job_updated_at,
                     u.email AS created_by_email,
                     ci.organization,
                     ci.case_type,
                     ci.report_type,
                     rr.id AS report_run_id,
                     rr.status AS report_status,
                     rr.created_at AS report_created_at,
                     rr.completed_at AS report_completed_at,
                     rr.duration_ms,
                     rr.error AS report_error,
                     (SELECT count(*) FROM report_sections rs WHERE rs.report_run_id = rr.id) AS sections_completed,
                     (SELECT count(*) FROM report_exports e WHERE e.report_run_id = rr.id AND e.format <> 'html') AS export_count,
                     CASE WHEN rr.id IS NOT NULL
                       THEN ROW_NUMBER() OVER (PARTITION BY j.id ORDER BY rr.created_at ASC) - 1
                       ELSE NULL
                     END AS version_index,
                     COALESCE(rr.created_at, j.created_at) AS sort_ts
              FROM jobs j
              LEFT JOIN users u ON u.id = j.created_by
              LEFT JOIN case_intake ci ON ci.job_id = j.id
              LEFT JOIN report_runs rr ON rr.job_id = j.id
            )
            SELECT * FROM catalog c
            WHERE {where_sql}
            ORDER BY c.sort_ts DESC, c.job_id ASC, c.version_index ASC NULLS LAST
            LIMIT :limit OFFSET :offset""",
        params,
    )
    sections_cache: dict[str, int] = {}
    items = []
    for r in rows:
        row = dict(r)
        jid = str(row["job_id"])
        if jid not in sections_cache:
            sections_cache[jid] = len(section_order_for_job(db, jid))
        items.append(_report_catalog_api_row(row, sections_total=sections_cache[jid]))
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/reports/exports")
def list_all_report_exports(
    job_id: str | None = Query(None),
    format: str | None = Query(None, alias="format"),
    run_status: str | None = Query(None),
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """List report exports across jobs with optional filters."""
    params: dict = {}
    where = ["e.format <> 'html'"]
    if job_id:
        where.append("r.job_id = CAST(:job_id AS uuid)")
        params["job_id"] = job_id
    if format:
        where.append("e.format = :fmt")
        params["fmt"] = format.lower()
    if run_status:
        where.append("r.status = :run_status")
        params["run_status"] = run_status
    if from_ts:
        where.append("e.created_at >= CAST(:from_ts AS timestamptz)")
        params["from_ts"] = from_ts
    if to_ts:
        where.append("e.created_at <= CAST(:to_ts AS timestamptz)")
        params["to_ts"] = to_ts
    where_sql = " AND ".join(where)
    count_row = fetchone(
        db,
        f"""SELECT count(*) c FROM report_exports e
            JOIN report_runs r ON r.id = e.report_run_id
            WHERE {where_sql}""",
        params,
    )
    total = int(count_row["c"]) if count_row else 0
    offset = (page - 1) * page_size
    params["limit"] = page_size
    params["offset"] = offset
    rows = fetchall(
        db,
        f"""SELECT e.id, e.format, e.uri, e.sha256, e.manifest_uri, e.created_at,
                   r.id AS report_run_id, r.status AS run_status, r.started_at AS run_started_at,
                   r.job_id
            FROM report_exports e
            JOIN report_runs r ON r.id = e.report_run_id
            WHERE {where_sql}
            ORDER BY e.created_at DESC
            LIMIT :limit OFFSET :offset""",
        params,
    )
    return {
        "items": [_export_api_row(dict(r)) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/reports/{job_id}/exports")
def list_report_exports(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    rows = fetchall(
        db,
        """SELECT e.id, e.format, e.uri, e.sha256, e.manifest_uri, e.created_at,
                  r.id AS report_run_id, r.status AS run_status, r.started_at AS run_started_at
           FROM report_exports e
           JOIN report_runs r ON r.id = e.report_run_id
           WHERE r.job_id = CAST(:jid AS uuid) AND e.format <> 'html'
           ORDER BY e.created_at DESC""",
        {"jid": job_id},
    )
    return {"items": [_export_api_row(dict(r), job_id=job_id) for r in rows]}


@router.get("/reports/exports/{export_id}/download")
def download_report_export(
    export_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    row = fetchone(
        db,
        """SELECT e.id, e.format, e.uri, e.sha256, e.metadata, e.created_at, r.job_id
           FROM report_exports e
           JOIN report_runs r ON r.id = e.report_run_id
           WHERE e.id = CAST(:id AS uuid)""",
        {"id": export_id},
    )
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Export not found"}})
    data = get_bytes(row["uri"])
    if not data:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "file_missing", "message": "Export file is no longer available in storage"}},
        )
    filename, media_type = export_download_filename(dict(row))
    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/reports/{job_id}/export/preview-pdf")
async def upload_preview_pdf_api(
    job_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    run = fetchone(db, _LATEST_REPORT_RUN_SQL, {"jid": job_id})
    if not run:
        raise HTTPException(status_code=400, detail={"error": {"code": "no_report", "message": "Generate report first"}})
    pdf_bytes = await file.read()
    try:
        result = store_preview_pdf(db, job_id, str(run["id"]), pdf_bytes)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    created_row = fetchone(
        db,
        """SELECT e.id, e.format, e.sha256, e.manifest_uri, e.created_at, e.report_run_id,
                  r.status AS run_status, r.started_at AS run_started_at
           FROM report_exports e
           JOIN report_runs r ON r.id = e.report_run_id
           WHERE e.id = CAST(:id AS uuid)""",
        {"id": result["id"]},
    )
    if created_row:
        return _export_api_row(dict(created_row), job_id=job_id)
    return result


@router.post("/reports/{job_id}/export")
def export_report_api(
    job_id: str,
    body: dict | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    body = body or {}
    run = fetchone(db, _LATEST_REPORT_RUN_SQL, {"jid": job_id})
    if not run:
        raise HTTPException(status_code=400, detail={"error": {"code": "no_report", "message": "Generate report first"}})
    fmt = str(body.get("format") or "docx").strip().lower()
    if fmt not in {"pdf", "docx", "json", "package"}:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "unsupported_format", "message": "Report download format must be PDF or DOCX."}},
        )
    try:
        result = export_report(db, job_id, str(run["id"]), fmt=fmt)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "unsupported_format", "message": str(exc)}},
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "export_failed", "message": str(exc)}},
        ) from exc
    created_row = fetchone(
        db,
        """SELECT e.id, e.format, e.sha256, e.manifest_uri, e.created_at, e.report_run_id,
                  r.status AS run_status, r.started_at AS run_started_at
           FROM report_exports e
           JOIN report_runs r ON r.id = e.report_run_id
           WHERE e.id = CAST(:id AS uuid)""",
        {"id": result["id"]},
    )
    if created_row:
        return _export_api_row(dict(created_row), job_id=job_id)
    return {
        "id": result["id"],
        "job_id": job_id,
        "report_run_id": str(run["id"]),
        "format": result["format"],
        "manifest_uri": result.get("manifest_uri"),
        "sha256": result["sha256"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/reports/{job_id}/feedback")
def submit_feedback(
    job_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    sec = None
    if body.get("section_key"):
        sec = fetchone(
            db,
            "SELECT id FROM report_sections WHERE job_id=:jid AND section_key=:key",
            {"jid": job_id, "key": body["section_key"]},
        )
    row = fetchone(
        db,
        """INSERT INTO human_feedback (report_section_id, user_id, feedback, rating)
           VALUES (:sid, :uid, :fb, NULL) RETURNING id, created_at""",
        {
            "sid": sec["id"] if sec else None,
            "uid": current.user_id,
            "fb": body.get("content") or body.get("feedback_type"),
        },
    )
    db.commit()
    return {
        "id": str(row["id"]),
        "job_id": job_id,
        "section_key": body.get("section_key"),
        "feedback_type": body.get("feedback_type"),
        "content": body.get("content"),
        "created_at": row["created_at"].isoformat(),
    }
