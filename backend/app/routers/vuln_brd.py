"""BRD completion APIs — agents, credentials, snapshots, alerts, ownership.

Additive routes under /api/vuln/* so forensic /api/agents is untouched.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.vuln_brd import (
    AGENT_STATES,
    ALLOWED_AGENT_TRANSITIONS,
    create_dashboard_snapshot,
    mark_stale_agents,
    row_agent,
)
from app.services.vuln_helpers import audit, is_uuid

router = APIRouter(tags=["vuln-brd"])


def _require_vuln_module() -> None:
    if not get_settings().vuln_module_enabled:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "vuln_disabled", "message": "Vulnerability module is disabled"}},
        )


class AgentCreate(BaseModel):
    agent_uuid: str
    name: str | None = None
    hostname: str | None = None
    platform: str | None = None
    version: str | None = None
    asset_id: str | None = None
    scanner_id: str | None = None
    device_class: str | None = None
    policy_name: str | None = None
    lifecycle_state: str = "planned"


class AgentUpdate(BaseModel):
    name: str | None = None
    hostname: str | None = None
    platform: str | None = None
    version: str | None = None
    asset_id: str | None = None
    scanner_id: str | None = None
    device_class: str | None = None
    policy_name: str | None = None
    last_checkin_at: str | None = None
    last_scan_at: str | None = None
    error_text: str | None = None
    link_key_provenance: str | None = None


class AgentTransition(BaseModel):
    lifecycle_state: str
    evidence_note: str | None = None


class CredentialCreate(BaseModel):
    name: str
    vault_ref: str
    credential_type: str = "ssh"
    privilege_scope: str | None = None


class CredentialUpdate(BaseModel):
    name: str | None = None
    vault_ref: str | None = None
    credential_type: str | None = None
    privilege_scope: str | None = None
    lifecycle_state: str | None = None
    last_test_result: str | None = None
    rotation_due_at: str | None = None


class ThresholdCreate(BaseModel):
    metric_key: str
    operator: str = "gte"
    threshold_value: float
    enabled: bool = True


class AssetOwnerCreate(BaseModel):
    owner_role: str = Field(description="business | technical | risk")
    owner_user_id: str | None = None
    owner_email: str | None = None
    source: str = "manual"


# ---------- Agents (BRD §8.3) ----------


@router.get("/api/vuln/agents")
def list_agents(
    lifecycle_state: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:read")),
):
    _require_vuln_module()
    if lifecycle_state:
        rows = fetchall(
            db,
            "SELECT * FROM vuln_agents WHERE lifecycle_state = :st ORDER BY updated_at DESC",
            {"st": lifecycle_state},
        )
    else:
        rows = fetchall(db, "SELECT * FROM vuln_agents ORDER BY updated_at DESC")
    return [row_agent(r) for r in rows]


@router.post("/api/vuln/agents")
def create_agent(
    body: AgentCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:manage")),
):
    _require_vuln_module()
    state = body.lifecycle_state if body.lifecycle_state in AGENT_STATES else "planned"
    # AGENT-001: duplicate agent UUID detection
    existing = fetchone(db, "SELECT id FROM vuln_agents WHERE agent_uuid = :u", {"u": body.agent_uuid})
    if existing:
        raise HTTPException(
            409,
            detail={"error": {"code": "duplicate_agent", "message": "Agent UUID already registered"}},
        )
    row = fetchone(
        db,
        """INSERT INTO vuln_agents
           (agent_uuid, asset_id, scanner_id, name, hostname, platform, version,
            lifecycle_state, device_class, policy_name)
           VALUES (:uuid,
                   CASE WHEN :aid IS NULL THEN NULL ELSE CAST(:aid AS uuid) END,
                   CASE WHEN :sid IS NULL THEN NULL ELSE CAST(:sid AS uuid) END,
                   :name, :host, :plat, :ver, :state, :dclass, :policy)
           RETURNING *""",
        {
            "uuid": body.agent_uuid,
            "aid": body.asset_id if is_uuid(body.asset_id) else None,
            "sid": body.scanner_id if is_uuid(body.scanner_id) else None,
            "name": body.name,
            "host": body.hostname,
            "plat": body.platform,
            "ver": body.version,
            "state": state,
            "dclass": body.device_class,
            "policy": body.policy_name,
        },
    )
    audit(
        db,
        actor_id=current.user_id,
        action="agent.create",
        resource_type="vuln_agent",
        resource_id=str(row["id"]),
        details={"agent_uuid": body.agent_uuid, "state": state},
    )
    db.commit()
    return row_agent(row)


@router.get("/api/vuln/agents/{agent_id}")
def get_agent(
    agent_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Agent not found"}})
    return row_agent(row)


@router.patch("/api/vuln/agents/{agent_id}")
def update_agent(
    agent_id: str,
    body: AgentUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:manage")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Agent not found"}})
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        if k in ("asset_id", "scanner_id"):
            execute(
                db,
                f"UPDATE vuln_agents SET {k} = CASE WHEN :v IS NULL THEN NULL ELSE CAST(:v AS uuid) END, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v if is_uuid(str(v) if v else None) else None, "id": agent_id},
            )
        elif k in ("last_checkin_at", "last_scan_at"):
            execute(
                db,
                f"UPDATE vuln_agents SET {k} = CAST(:v AS timestamptz), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v, "id": agent_id},
            )
        else:
            execute(
                db,
                f"UPDATE vuln_agents SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v, "id": agent_id},
            )
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    return row_agent(row)


@router.post("/api/vuln/agents/{agent_id}/transition")
def transition_agent(
    agent_id: str,
    body: AgentTransition,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:manage")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Agent not found"}})
    current_state = row["lifecycle_state"]
    new_state = body.lifecycle_state
    if new_state not in AGENT_STATES:
        raise HTTPException(400, detail={"error": {"code": "invalid_state", "message": f"Unknown state {new_state}"}})
    allowed = ALLOWED_AGENT_TRANSITIONS.get(current_state, set())
    if new_state not in allowed:
        raise HTTPException(
            400,
            detail={
                "error": {
                    "code": "invalid_transition",
                    "message": f"Cannot transition {current_state} → {new_state}",
                    "allowed": sorted(allowed),
                }
            },
        )
    execute(
        db,
        "UPDATE vuln_agents SET lifecycle_state = :st, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
        {"st": new_state, "id": agent_id},
    )
    audit(
        db,
        actor_id=current.user_id,
        action="agent.transition",
        resource_type="vuln_agent",
        resource_id=agent_id,
        details={"from": current_state, "to": new_state, "evidence_note": body.evidence_note},
    )
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    return row_agent(row)


@router.post("/api/vuln/agents/mark-stale")
def agents_mark_stale(
    stale_hours: int = Query(default=72, ge=1, le=720),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:manage")),
):
    _require_vuln_module()
    n = mark_stale_agents(db, stale_hours=stale_hours)
    db.commit()
    return {"stale_count": n, "stale_hours": stale_hours}


# ---------- Credential vault refs (BRD §8) ----------


def _cred_row(r: dict) -> dict:
    return {
        "id": str(r["id"]),
        "name": r["name"],
        "vault_ref": r["vault_ref"],
        "credential_type": r["credential_type"],
        "privilege_scope": r.get("privilege_scope"),
        "lifecycle_state": r["lifecycle_state"],
        "last_tested_at": r["last_tested_at"].isoformat() if r.get("last_tested_at") else None,
        "last_test_result": r.get("last_test_result"),
        "rotation_due_at": r["rotation_due_at"].isoformat() if r.get("rotation_due_at") else None,
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
    }


@router.get("/api/vuln/credentials")
def list_credentials(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("credential:read")),
):
    _require_vuln_module()
    rows = fetchall(db, "SELECT * FROM vuln_credential_refs ORDER BY name")
    return [_cred_row(r) for r in rows]


@router.post("/api/vuln/credentials")
def create_credential(
    body: CredentialCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("credential:manage")),
):
    _require_vuln_module()
    # Never store plaintext secrets — vault_ref only
    row = fetchone(
        db,
        """INSERT INTO vuln_credential_refs
           (name, vault_ref, credential_type, privilege_scope, lifecycle_state, created_by)
           VALUES (:name, :ref, :ctype, :scope, 'requested', CAST(:uid AS uuid))
           RETURNING *""",
        {
            "name": body.name,
            "ref": body.vault_ref,
            "ctype": body.credential_type,
            "scope": body.privilege_scope,
            "uid": current.user_id,
        },
    )
    db.commit()
    return _cred_row(row)


@router.patch("/api/vuln/credentials/{cred_id}")
def update_credential(
    cred_id: str,
    body: CredentialUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("credential:manage")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_credential_refs WHERE id = CAST(:id AS uuid)", {"id": cred_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Credential not found"}})
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        if k == "rotation_due_at":
            execute(
                db,
                "UPDATE vuln_credential_refs SET rotation_due_at = CAST(:v AS timestamptz), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v, "id": cred_id},
            )
        elif k == "last_test_result":
            execute(
                db,
                """UPDATE vuln_credential_refs
                   SET last_test_result = :v, last_tested_at = NOW(), updated_at = NOW()
                   WHERE id = CAST(:id AS uuid)""",
                {"v": v, "id": cred_id},
            )
        else:
            execute(
                db,
                f"UPDATE vuln_credential_refs SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v, "id": cred_id},
            )
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_credential_refs WHERE id = CAST(:id AS uuid)", {"id": cred_id})
    return _cred_row(row)


# ---------- Scan results / risk history / snapshots ----------


@router.get("/api/vuln/scan-jobs/{job_id}/results")
def list_scan_results(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        "SELECT * FROM vuln_scan_results WHERE scan_job_id = CAST(:id AS uuid) ORDER BY created_at DESC",
        {"id": job_id},
    )
    return [
        {
            "id": str(r["id"]),
            "scan_job_id": str(r["scan_job_id"]),
            "hosts_attempted": r["hosts_attempted"],
            "hosts_assessed": r["hosts_assessed"],
            "credential_success_count": r["credential_success_count"],
            "credential_fail_count": r["credential_fail_count"],
            "plugin_error_count": r["plugin_error_count"],
            "integrity_hash": r.get("integrity_hash"),
            "completed_at": r["completed_at"].isoformat() if r.get("completed_at") else None,
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        }
        for r in rows
    ]


@router.get("/api/vuln/findings/{finding_id}/risk-history")
def finding_risk_history(
    finding_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT * FROM vuln_risk_scores
           WHERE finding_id = CAST(:id AS uuid)
           ORDER BY scored_at DESC LIMIT 100""",
        {"id": finding_id},
    )
    return [
        {
            "id": str(r["id"]),
            "finding_id": str(r["finding_id"]) if r.get("finding_id") else None,
            "model_version": r["model_version"],
            "enterprise_risk_score": float(r["enterprise_risk_score"]),
            "risk_band": r["risk_band"],
            "factors_json": r.get("factors_json"),
            "scored_at": r["scored_at"].isoformat() if r.get("scored_at") else None,
        }
        for r in rows
    ]


@router.post("/api/vuln/dashboards/{layer}/snapshot")
def snapshot_dashboard(
    layer: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    snap = create_dashboard_snapshot(db, layer=layer, filters={}, user_id=current.user_id)
    db.commit()
    return snap


@router.get("/api/vuln/dashboards/{layer}/snapshots")
def list_snapshots(
    layer: str,
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT id, layer, filter_hash, freshness_at, created_at
           FROM vuln_dashboard_snapshots
           WHERE layer = :layer
           ORDER BY created_at DESC LIMIT :lim""",
        {"layer": layer, "lim": limit},
    )
    return [
        {
            "id": str(r["id"]),
            "layer": r["layer"],
            "filter_hash": r.get("filter_hash"),
            "freshness_at": r["freshness_at"].isoformat() if r.get("freshness_at") else None,
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        }
        for r in rows
    ]


# ---------- Thresholds + notifications ----------


@router.get("/api/vuln/alert-thresholds")
def list_thresholds(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:admin")),
):
    _require_vuln_module()
    rows = fetchall(db, "SELECT * FROM vuln_alert_thresholds ORDER BY metric_key")
    return [
        {
            "id": str(r["id"]),
            "metric_key": r["metric_key"],
            "operator": r["operator"],
            "threshold_value": float(r["threshold_value"]),
            "enabled": bool(r["enabled"]),
            "last_triggered_at": r["last_triggered_at"].isoformat() if r.get("last_triggered_at") else None,
        }
        for r in rows
    ]


@router.post("/api/vuln/alert-thresholds")
def upsert_threshold(
    body: ThresholdCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:admin")),
):
    _require_vuln_module()
    row = fetchone(
        db,
        """INSERT INTO vuln_alert_thresholds (metric_key, operator, threshold_value, enabled, created_by)
           VALUES (:k, :op, :v, :en, CAST(:uid AS uuid))
           ON CONFLICT (metric_key) DO UPDATE
             SET operator = EXCLUDED.operator,
                 threshold_value = EXCLUDED.threshold_value,
                 enabled = EXCLUDED.enabled,
                 updated_at = NOW()
           RETURNING *""",
        {
            "k": body.metric_key,
            "op": body.operator,
            "v": body.threshold_value,
            "en": body.enabled,
            "uid": current.user_id,
        },
    )
    db.commit()
    return {"id": str(row["id"]), "metric_key": row["metric_key"]}


@router.get("/api/vuln/notifications")
def list_notifications(
    acknowledged: bool | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    if acknowledged is None:
        rows = fetchall(db, "SELECT * FROM vuln_notifications ORDER BY created_at DESC LIMIT 100")
    else:
        rows = fetchall(
            db,
            "SELECT * FROM vuln_notifications WHERE acknowledged = :a ORDER BY created_at DESC LIMIT 100",
            {"a": acknowledged},
        )
    return [
        {
            "id": str(r["id"]),
            "event_type": r["event_type"],
            "title": r["title"],
            "body": r.get("body"),
            "acknowledged": bool(r["acknowledged"]),
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        }
        for r in rows
    ]


@router.post("/api/vuln/notifications/{notif_id}/ack")
def ack_notification(
    notif_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    execute(
        db,
        "UPDATE vuln_notifications SET acknowledged = TRUE WHERE id = CAST(:id AS uuid)",
        {"id": notif_id},
    )
    db.commit()
    return {"ok": True}


# ---------- Asset ownership history (BRD §7.2) ----------


@router.get("/api/vuln/assets/{asset_id}/owners")
def list_asset_owners(
    asset_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("asset:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT * FROM vuln_asset_owners
           WHERE asset_id = CAST(:id AS uuid)
           ORDER BY effective_from DESC""",
        {"id": asset_id},
    )
    return [
        {
            "id": str(r["id"]),
            "asset_id": str(r["asset_id"]),
            "owner_role": r["owner_role"],
            "owner_user_id": str(r["owner_user_id"]) if r.get("owner_user_id") else None,
            "owner_email": r.get("owner_email"),
            "effective_from": r["effective_from"].isoformat() if r.get("effective_from") else None,
            "effective_to": r["effective_to"].isoformat() if r.get("effective_to") else None,
            "source": r.get("source"),
        }
        for r in rows
    ]


@router.post("/api/vuln/assets/{asset_id}/owners")
def add_asset_owner(
    asset_id: str,
    body: AssetOwnerCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("asset:write")),
):
    _require_vuln_module()
    # Close previous open record for same role
    execute(
        db,
        """UPDATE vuln_asset_owners SET effective_to = NOW()
           WHERE asset_id = CAST(:aid AS uuid) AND owner_role = :role AND effective_to IS NULL""",
        {"aid": asset_id, "role": body.owner_role},
    )
    row = fetchone(
        db,
        """INSERT INTO vuln_asset_owners (asset_id, owner_role, owner_user_id, owner_email, source)
           VALUES (CAST(:aid AS uuid), :role,
                   CASE WHEN :uid IS NULL THEN NULL ELSE CAST(:uid AS uuid) END,
                   :email, :src)
           RETURNING *""",
        {
            "aid": asset_id,
            "role": body.owner_role,
            "uid": body.owner_user_id if is_uuid(body.owner_user_id) else None,
            "email": body.owner_email,
            "src": body.source,
        },
    )
    db.commit()
    return {"id": str(row["id"]), "owner_role": row["owner_role"]}


# ---------- FR-15 Custom detection checks ----------


class CustomCheckCreate(BaseModel):
    name: str
    check_type: str = "nuclei"
    content_ref: str
    severity_hint: str | None = None
    cve_hint: str | None = None
    pci_requirement_tag: str | None = None
    lifecycle_state: str = "draft"


class CustomCheckUpdate(BaseModel):
    name: str | None = None
    content_ref: str | None = None
    severity_hint: str | None = None
    cve_hint: str | None = None
    pci_requirement_tag: str | None = None
    lifecycle_state: str | None = None


@router.get("/api/vuln/custom-checks")
def list_custom_checks(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    rows = fetchall(db, "SELECT * FROM vuln_custom_checks ORDER BY name")
    return [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "check_type": r["check_type"],
            "content_ref": r["content_ref"],
            "lifecycle_state": r["lifecycle_state"],
            "severity_hint": r.get("severity_hint"),
            "cve_hint": r.get("cve_hint"),
            "pci_requirement_tag": r.get("pci_requirement_tag"),
        }
        for r in rows
    ]


@router.post("/api/vuln/custom-checks")
def create_custom_check(
    body: CustomCheckCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    row = fetchone(
        db,
        """INSERT INTO vuln_custom_checks
           (name, check_type, content_ref, lifecycle_state, severity_hint, cve_hint, pci_requirement_tag, created_by)
           VALUES (:name, :ctype, :ref, :state, :sev, :cve, :pci, CAST(:uid AS uuid))
           RETURNING *""",
        {
            "name": body.name,
            "ctype": body.check_type,
            "ref": body.content_ref,
            "state": body.lifecycle_state,
            "sev": body.severity_hint,
            "cve": body.cve_hint,
            "pci": body.pci_requirement_tag,
            "uid": current.user_id,
        },
    )
    db.commit()
    audit(db, actor_id=current.user_id, action="custom_check.create", resource_type="custom_check", resource_id=str(row["id"]))
    db.commit()
    return {"id": str(row["id"]), "name": row["name"], "lifecycle_state": row["lifecycle_state"]}


@router.patch("/api/vuln/custom-checks/{check_id}")
def update_custom_check(
    check_id: str,
    body: CustomCheckUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        execute(db, f"UPDATE vuln_custom_checks SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)", {"v": v, "id": check_id})
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_custom_checks WHERE id = CAST(:id AS uuid)", {"id": check_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Custom check not found"}})
    return {"id": str(row["id"]), "name": row["name"], "lifecycle_state": row["lifecycle_state"]}


# ---------- FR-16 Safe exploit validation ----------


class ExploitValidateBody(BaseModel):
    authorization_ref: str


@router.post("/api/vuln/findings/{finding_id}/validate")
def validate_finding_exploit(
    finding_id: str,
    body: ExploitValidateBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:validate")),
):
    _require_vuln_module()
    from app.services.vuln_exploit_validation import ExploitValidationError, validate_finding_safe

    try:
        result = validate_finding_safe(
            db,
            finding_id=finding_id,
            authorization_ref=body.authorization_ref,
            validated_by=current.user_id,
        )
    except ExploitValidationError as exc:
        raise HTTPException(400, detail={"error": {"code": exc.code, "message": exc.message}}) from exc
    audit(db, actor_id=current.user_id, action="finding.validate", resource_type="finding", resource_id=finding_id, details=result)
    db.commit()
    return result


# ---------- FR-17 PCI readiness ----------


class PciReadinessBody(BaseModel):
    period_start: str | None = None
    period_end: str | None = None


@router.post("/api/cases/{case_id}/pci-readiness")
def create_pci_readiness_package(
    case_id: str,
    body: PciReadinessBody,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("dashboard:export")),
):
    _require_vuln_module()
    from app.services.vuln_pci import build_pci_readiness_package

    return build_pci_readiness_package(
        db,
        case_id=case_id,
        created_by=current.user_id,
        period_start=body.period_start,
        period_end=body.period_end,
    )


# ---------- FR-14 Agent finding ingest ----------


class AgentFindingIn(BaseModel):
    plugin_id: str | None = None
    cve: str | None = None
    cvss: float | None = None
    severity: str | None = None
    synopsis: str | None = None
    remediation: str | None = None


class AgentFindingsReport(BaseModel):
    case_id: str
    findings: list[AgentFindingIn] = Field(default_factory=list)


@router.post("/api/vuln/agents/{agent_id}/findings")
def ingest_agent_findings(
    agent_id: str,
    body: AgentFindingsReport,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("agent:manage")),
):
    _require_vuln_module()
    from app.services.vuln_finding_ingest import refresh_asset_risk, upsert_finding

    agent = fetchone(db, "SELECT * FROM vuln_agents WHERE id = CAST(:id AS uuid)", {"id": agent_id})
    if not agent:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Agent not found"}})
    if not agent.get("asset_id"):
        raise HTTPException(400, detail={"error": {"code": "asset_required", "message": "Agent must be linked to an asset"}})

    asset_id = str(agent["asset_id"])
    asset = fetchone(
        db,
        "SELECT case_id, criticality, external_exposure FROM vuln_assets WHERE id = CAST(:id AS uuid)",
        {"id": asset_id},
    )
    if not asset:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Asset not found"}})
    case_id = str(asset["case_id"])
    if case_id != body.case_id:
        raise HTTPException(400, detail={"error": {"code": "case_mismatch", "message": "case_id does not match agent asset"}})

    asset_meta = {
        "criticality": asset.get("criticality") or "tier2",
        "external_exposure": asset.get("external_exposure") or "internal",
    }
    ingested = 0
    for f in body.findings:
        fid = upsert_finding(
            db,
            case_id=case_id,
            scan_job_id=None,
            asset_id=asset_id,
            vuln=f.model_dump(),
            asset_meta=asset_meta,
            credentialed=True,
            source="agent",
        )
        if fid:
            ingested += 1
    execute(
        db,
        "UPDATE vuln_agents SET last_checkin_at = NOW(), last_scan_at = NOW(), lifecycle_state = 'healthy', updated_at = NOW() WHERE id = CAST(:id AS uuid)",
        {"id": agent_id},
    )
    refresh_asset_risk(db, asset_id)
    db.commit()
    return {"agent_id": agent_id, "ingested": ingested, "case_id": case_id}
