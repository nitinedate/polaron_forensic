"""Extended VULN: ASV workflow, bounded pentest, endpoint inventory."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.vuln_asv import (
    ASV_DISCLAIMER,
    build_asv_submission_package,
    create_asv_provider,
    record_asv_attestation,
    row_asv_provider,
)
from app.services.vuln_edr_inventory import ingest_endpoint_inventory
from app.services.vuln_helpers import audit, is_uuid
from app.services.vuln_pentest import SAFE_PLAYBOOKS, create_pentest_job, run_pentest_job

router = APIRouter(tags=["vuln-extended"])


def _require_vuln_module() -> None:
    if not get_settings().vuln_module_enabled:
        raise HTTPException(status_code=404, detail={"error": {"code": "vuln_disabled", "message": "Vulnerability module is disabled"}})


class AsvProviderCreate(BaseModel):
    name: str
    accreditation_id: str | None = None
    contact_email: str | None = None


class AsvSubmissionCreate(BaseModel):
    provider_id: str | None = None
    target_scope: str


class AsvAttestationRecord(BaseModel):
    attestation_ref: str
    attestation_date: str | None = None
    result_status: str = "pass"
    attestation_document_ref: str | None = None
    notes: str | None = None


class PentestJobCreate(BaseModel):
    authorization_ref: str
    targets: list[str] = Field(default_factory=list)
    playbook: str = "safe_recon"


class EndpointInventoryIn(BaseModel):
    case_id: str
    hostname: str | None = None
    inventory: dict[str, Any] = Field(default_factory=dict)


# ---------- PCI ASV external workflow ----------


@router.get("/api/vuln/asv/providers")
def list_asv_providers(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    rows = fetchall(db, "SELECT * FROM vuln_asv_providers WHERE status = 'active' ORDER BY name")
    return [row_asv_provider(r) for r in rows]


@router.post("/api/vuln/asv/providers")
def register_asv_provider(
    body: AsvProviderCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    if not get_settings().asv_module_enabled:
        raise HTTPException(400, detail={"error": {"code": "asv_disabled", "message": "ASV module disabled"}})
    row = create_asv_provider(db, name=body.name, accreditation_id=body.accreditation_id, contact_email=body.contact_email)
    db.commit()
    return row


@router.post("/api/cases/{case_id}/asv/submission")
def create_asv_submission(
    case_id: str,
    body: AsvSubmissionCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("dashboard:export")),
):
    _require_vuln_module()
    result = build_asv_submission_package(
        db,
        case_id=case_id,
        provider_id=body.provider_id if is_uuid(body.provider_id) else None,
        target_scope=body.target_scope,
        created_by=current.user_id,
    )
    db.commit()
    return {**result, "classification": "Confidential — Internal Use Only"}


@router.post("/api/vuln/asv/submissions/{submission_id}/attestation")
def record_asv_attestation_endpoint(
    submission_id: str,
    body: AsvAttestationRecord,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    result = record_asv_attestation(
        db,
        submission_id=submission_id,
        attestation_ref=body.attestation_ref,
        attestation_date=body.attestation_date,
        result_status=body.result_status,
        document_ref=body.attestation_document_ref,
        notes=body.notes,
        recorded_by=current.user_id,
    )
    audit(db, actor_id=current.user_id, action="asv.attestation.record", resource_type="asv_submission", resource_id=submission_id)
    db.commit()
    return result


@router.get("/api/vuln/asv/disclaimer")
def asv_disclaimer():
    return {"disclaimer": ASV_DISCLAIMER, "requires_accredited_asv": True}


# ---------- Bounded pentest ----------


@router.get("/api/vuln/pentest/playbooks")
def list_pentest_playbooks():
    return {
        "playbooks": sorted(SAFE_PLAYBOOKS),
        "note": "Safe recon only — no destructive exploitation or automated full pentest",
    }


@router.post("/api/cases/{case_id}/pentest-jobs")
def start_pentest_job(
    case_id: str,
    body: PentestJobCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:validate")),
):
    _require_vuln_module()
    if not get_settings().pentest_module_enabled:
        raise HTTPException(400, detail={"error": {"code": "pentest_disabled", "message": "Pentest module disabled"}})
    if not body.authorization_ref:
        raise HTTPException(400, detail={"error": {"code": "authz_required", "message": "authorization_ref required"}})
    if not body.targets:
        raise HTTPException(400, detail={"error": {"code": "targets_required", "message": "At least one target required"}})
    try:
        created = create_pentest_job(
            db,
            case_id=case_id,
            authorization_ref=body.authorization_ref,
            targets=body.targets,
            playbook=body.playbook,
            created_by=current.user_id,
        )
    except ValueError as exc:
        raise HTTPException(400, detail={"error": {"code": "invalid_playbook", "message": str(exc)}}) from exc
    db.commit()
    try:
        from app.tasks import pentest_job_task

        if current.schema_name:
            pentest_job_task.delay(current.schema_name, created["id"])
    except Exception:
        run_pentest_job(db, job_id=created["id"])
        db.commit()
    return created


@router.get("/api/vuln/pentest-jobs/{job_id}")
def get_pentest_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_pentest_jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Pentest job not found"}})
    findings = fetchall(
        db,
        "SELECT * FROM vuln_pentest_findings WHERE pentest_job_id = CAST(:id AS uuid) ORDER BY created_at",
        {"id": job_id},
    )
    return {
        "id": str(row["id"]),
        "case_id": str(row["case_id"]),
        "playbook": row["playbook"],
        "status": row["status"],
        "findings_count": row.get("findings_count"),
        "findings": [
            {"id": str(f["id"]), "step_key": f["step_key"], "target": f["target"], "severity": f["severity"], "result": f.get("result_json")}
            for f in findings
        ],
    }


# ---------- Endpoint inventory (EDR-lite, collection only) ----------


@router.post("/api/vuln/agents/{agent_id}/inventory")
def submit_agent_inventory(
    agent_id: str,
    body: EndpointInventoryIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:manage")),
):
    _require_vuln_module()
    if not get_settings().edr_inventory_enabled:
        raise HTTPException(400, detail={"error": {"code": "edr_inventory_disabled", "message": "Endpoint inventory disabled"}})
    result = ingest_endpoint_inventory(
        db,
        agent_id=agent_id,
        case_id=body.case_id,
        hostname=body.hostname,
        inventory=body.inventory,
    )
    db.commit()
    return result


@router.get("/api/vuln/agents/{agent_id}/inventory")
def list_agent_inventory(
    agent_id: str,
    limit: int = 20,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT id, packages_count, processes_count, collected_at
           FROM vuln_endpoint_inventory
           WHERE agent_id = CAST(:aid AS uuid)
           ORDER BY collected_at DESC LIMIT :lim""",
        {"aid": agent_id, "lim": min(max(limit, 1), 100)},
    )
    return [
        {
            "id": str(r["id"]),
            "packages_count": r["packages_count"],
            "processes_count": r["processes_count"],
            "collected_at": r["collected_at"].isoformat() if r.get("collected_at") else None,
        }
        for r in rows
    ]
