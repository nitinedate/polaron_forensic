"""Vulnerability / Nessus enterprise APIs — additive module; gated by VULN_MODULE_ENABLED."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.deps import CurrentUser, firm_db, get_current_user, get_db, require_firm_permission
from app.services.aetheris_severity import SEVERITY_ORDER, aetheris_severity_sql, classify_severity
from app.services.scan_orchestrator import scan_job_progress, scan_job_target_rows
from app.services.case_delete import DELETABLE_SCAN_JOB_STATUSES, delete_scan_job_cascade
from app.services.scanner_agent_jobs import RetryNotAllowed, retry_edge_job, retry_failed_edge_jobs_for_case
from app.services.scanner_adapter import get_scanner_client
from app.services.nessus_client import NessusClientError
from app.services.vuln_helpers import (
    audit,
    dashboard_layer,
    is_uuid,
    overview_kpis,
    row_scanner,
    timeline,
)

router = APIRouter(tags=["vuln"])


def _require_vuln_module() -> None:
    if not get_settings().vuln_module_enabled:
        raise HTTPException(status_code=404, detail={"error": {"code": "vuln_disabled", "message": "Vulnerability module is disabled"}})


def _vuln_list_db(
    db: Session = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
) -> Session:
    """Firm users see their scanners. Platform admin sees the only active firm (local lab)."""
    from sqlalchemy import select

    from app.db.session import apply_firm_search_path, bind_firm_schema
    from app.db.tenant import Scope, TenantContext, set_tenant_context
    from app.deps import enrich_firm_context
    from app.models.platform import Firm

    _require_vuln_module()
    if current.scope == Scope.FIRM:
        current.require_perm("scan:read")
        ctx = enrich_firm_context(db, TenantContext(slug=current.tenant, scope=Scope.FIRM))
        set_tenant_context(ctx)
        bind_firm_schema(db, ctx.schema_name)
        apply_firm_search_path(db, ctx.schema_name)
        return db
    if current.scope == Scope.PLATFORM:
        firms = db.execute(select(Firm).where(Firm.status == "active")).scalars().all()
        if len(firms) != 1:
            raise HTTPException(
                status_code=403,
                detail={"error": {"code": "forbidden", "message": "Firm access only"}},
            )
        bind_firm_schema(db, firms[0].schema_name)
        apply_firm_search_path(db, firms[0].schema_name)
        return db
    raise HTTPException(
        status_code=403,
        detail={"error": {"code": "forbidden", "message": "Firm access only"}},
    )


class ScannerCreate(BaseModel):
    name: str
    url: str = "agent://local"
    edition: str | None = None
    api_key_ref: str | None = None
    connection_mode: str | None = None  # gmp | edge_agent
    scanner_role: str | None = None  # persistent_edge | portable | remote_vpn | central


class ScannerUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    edition: str | None = None
    api_key_ref: str | None = None
    status: str | None = None
    connection_mode: str | None = None
    scanner_role: str | None = None


class BindClientTokenIn(BaseModel):
    token: str
    name: str | None = None
    scanner_role: str | None = None
    scanner_id: str | None = None


class PolicyCreate(BaseModel):
    name: str
    policy_type: str = "basic_network"
    case_id: str | None = None
    scanner_id: str | None = None
    settings_json: dict[str, Any] | None = None
    compliance_framework: str | None = None


class PolicyUpdate(BaseModel):
    name: str | None = None
    policy_type: str | None = None
    scanner_id: str | None = None
    settings_json: dict[str, Any] | None = None
    compliance_framework: str | None = None
    lifecycle_state: str | None = None


class ScanTargetIn(BaseModel):
    target: str
    target_type: str = "host"
    credential_ref: str | None = None
    excluded: bool = False


class ScanJobCreate(BaseModel):
    policy_id: str | None = None
    scheduled_at: str | None = None
    authorization_ref: str | None = None
    scan_window_start: str | None = None
    scan_window_end: str | None = None
    targets: list[ScanTargetIn] = Field(default_factory=list)
    scanner_id: str | None = None
    preflight_confirmed: bool = False
    orchestration_enabled: bool | None = None
    network_token_id: str | None = None


class NetworkTokenCreate(BaseModel):
    name: str = "Client network"
    cidr: str
    note: str | None = None
    authorization_ref: str | None = None


class NetworkTokenActivate(BaseModel):
    token: str


class ScanJobUpdate(BaseModel):
    status: str | None = None
    external_scan_id: str | None = None


class RemediationCreate(BaseModel):
    finding_id: str
    owner_id: str | None = None
    sla_due: str | None = None
    status: str = "open"


class RemediationUpdate(BaseModel):
    owner_id: str | None = None
    sla_due: str | None = None
    status: str | None = None
    resolution: str | None = None
    rescan_job_id: str | None = None
    accepted_risk_ref: str | None = None
    escalation_level: int | None = None


class ExceptionCreate(BaseModel):
    finding_id: str
    reason: str
    compensating_controls: str | None = None
    expires_at: str | None = None
    residual_risk: str | None = None


class ExceptionDecide(BaseModel):
    status: str  # approved | rejected
    residual_risk: str | None = None


class EvidenceCreate(BaseModel):
    case_id: str | None = None
    framework: str | None = None
    control_id: str | None = None
    title: str
    metadata_json: dict[str, Any] | None = None
    period_start: str | None = None
    period_end: str | None = None


def _policy_row(r: dict) -> dict:
    return {
        "id": str(r["id"]),
        "case_id": str(r["case_id"]) if r.get("case_id") else None,
        "name": r["name"],
        "policy_type": r["policy_type"],
        "scanner_id": str(r["scanner_id"]) if r.get("scanner_id") else None,
        "settings_json": r.get("settings_json"),
        "compliance_framework": r.get("compliance_framework"),
        "created_by": str(r["created_by"]) if r.get("created_by") else None,
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
    }


def _job_row(db: Session, r: dict) -> dict:
    targets = fetchall(
        db,
        "SELECT target, target_type, credential_ref, excluded FROM vuln_scan_targets WHERE scan_job_id = CAST(:id AS uuid)",
        {"id": str(r["id"])},
    )
    progress = scan_job_progress(db, r)
    return {
        "id": str(r["id"]),
        "case_id": str(r["case_id"]),
        "policy_id": str(r["policy_id"]) if r.get("policy_id") else None,
        "status": r["status"],
        "progress_pct": progress["progress_pct"],
        "progress_label": progress["progress_label"],
        "error": r.get("error"),
        "scheduled_at": r["scheduled_at"].isoformat() if r.get("scheduled_at") else None,
        "started_at": r["started_at"].isoformat() if r.get("started_at") else None,
        "completed_at": r["completed_at"].isoformat() if r.get("completed_at") else None,
        "source": r.get("source") or "platform",
        "authorization_ref": r.get("authorization_ref"),
        "scan_window_start": r["scan_window_start"].isoformat() if r.get("scan_window_start") else None,
        "scan_window_end": r["scan_window_end"].isoformat() if r.get("scan_window_end") else None,
        "external_scan_id": r.get("external_scan_id"),
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        "targets": [
            {
                "target": t["target"],
                "target_type": t.get("target_type") or "host",
                "credential_ref": t.get("credential_ref"),
                "excluded": bool(t.get("excluded")),
            }
            for t in targets
        ],
    }


def _finding_row(r: dict) -> dict:
    rf = r.get("risk_factors_json")
    if isinstance(rf, str):
        try:
            rf = json.loads(rf)
        except ValueError:
            rf = {}
    rf = rf if isinstance(rf, dict) else {}
    return {
        "id": str(r["id"]),
        "case_id": str(r["case_id"]),
        "scan_job_id": str(r["scan_job_id"]) if r.get("scan_job_id") else None,
        "asset_id": str(r["asset_id"]) if r.get("asset_id") else None,
        "plugin_id": r.get("plugin_id"),
        "plugin_family": r.get("plugin_family"),
        "cve": r.get("cve"),
        "cvss": float(r["cvss"]) if r.get("cvss") is not None else None,
        "score_available": rf.get("score_available", r.get("cvss") is not None) if isinstance(rf, dict) else r.get("cvss") is not None,
        "severity": classify_severity(
            cvss=float(r["cvss"]) if r.get("cvss") is not None else 0.0,
            synopsis=str(r.get("synopsis") or ""),
            raw_severity=r.get("severity"),
            basis=rf.get("severity_basis"),
        )[0],
        "port": r.get("port"),
        "protocol": r.get("protocol"),
        "service": r.get("service"),
        "synopsis": r.get("synopsis"),
        "remediation": r.get("remediation"),
        "status": r["status"],
        "is_kev": bool(r.get("is_kev")),
        "enterprise_risk_score": float(r["enterprise_risk_score"]) if r.get("enterprise_risk_score") is not None else None,
        "risk_band": r.get("risk_band"),
        "risk_factors_json": rf,
        "pci_requirement_tag": r.get("pci_requirement_tag"),
        "exploit_validation_status": r.get("exploit_validation_status"),
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
    }


def _asset_row(db: Session, r: dict) -> dict:
    ids = fetchall(
        db,
        "SELECT id, id_type, value, source FROM vuln_asset_identifiers WHERE asset_id = CAST(:id AS uuid)",
        {"id": str(r["id"])},
    )
    return {
        "id": str(r["id"]),
        "case_id": str(r["case_id"]),
        "hostname": r.get("hostname"),
        "primary_ip": r.get("primary_ip"),
        "mac": r.get("mac"),
        "os": r.get("os"),
        "asset_type": r.get("asset_type"),
        "risk_score": float(r["risk_score"]) if r.get("risk_score") is not None else None,
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        "identifiers": [
            {"id": str(i["id"]), "id_type": i["id_type"], "value": i["value"], "source": i.get("source")}
            for i in ids
        ],
    }


def _rem_row(r: dict) -> dict:
    return {
        "id": str(r["id"]),
        "finding_id": str(r["finding_id"]),
        "owner_id": str(r["owner_id"]) if r.get("owner_id") else None,
        "sla_due": r["sla_due"].isoformat() if r.get("sla_due") else None,
        "status": r["status"],
        "resolution": r.get("resolution"),
        "rescan_job_id": str(r["rescan_job_id"]) if r.get("rescan_job_id") else None,
        "accepted_risk_ref": r.get("accepted_risk_ref"),
        "escalation_level": int(r.get("escalation_level") or 0),
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
    }


# ---------- Overview / dashboards ----------


@router.get("/api/vuln/overview")
def get_overview(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    return overview_kpis(db)


@router.get("/api/vuln/dashboards/{layer}")
def get_dashboard(
    layer: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    return dashboard_layer(db, layer)


@router.get("/api/vuln/dashboards/{layer}/export")
def export_dashboard(
    layer: str,
    format: str = Query(default="json"),
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("dashboard:export")),
):
    _require_vuln_module()
    data = dashboard_layer(db, layer)
    data["export"] = {
        "format": format,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user": current.user_id,
        "classification": "Confidential - Internal Use Only",
    }
    return data


def _client_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if request.client and request.client.host:
        return request.client.host
    return ""


# ---------- Scanners ----------


@router.get("/api/scanners")
def list_scanners(
    db: Session = Depends(_vuln_list_db),
):
    _require_vuln_module()
    from app.services.scanner_credentials import ensure_scanner_role_column

    ensure_scanner_role_column(db)
    rows = fetchall(db, "SELECT * FROM vuln_scanners ORDER BY name")
    return [row_scanner(r) for r in rows]


@router.get("/api/scanners/network-tokens")
def list_network_tokens(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    from app.services.vuln_network_tokens import list_network_tokens as _list

    return _list(db)


@router.get("/api/scanners/network-tokens/session")
def get_network_token_session(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    from app.services.vuln_network_tokens import session_for_user

    return session_for_user(db, current.user_id)


@router.post("/api/scanners/network-tokens")
def create_network_token(
    body: NetworkTokenCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    from app.services.vuln_network_tokens import NetworkTokenError, mint_network_token

    try:
        row = mint_network_token(
            db,
            name=body.name,
            cidr=body.cidr,
            note=body.note,
            authorization_ref=body.authorization_ref,
            created_by=current.user_id,
        )
    except NetworkTokenError as exc:
        raise HTTPException(400, detail={"error": {"code": exc.code, "message": exc.message}}) from exc
    audit(
        db,
        actor_id=current.user_id,
        action="scanner.network_token.mint",
        resource_type="network_token",
        resource_id=str(row.get("id") or ""),
    )
    db.commit()
    return row


@router.post("/api/scanners/network-tokens/activate")
def activate_network_token(
    body: NetworkTokenActivate,
    request: Request,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    from app.services.vuln_network_tokens import NetworkTokenError, activate_network_token as _activate

    try:
        row = _activate(
            db,
            token=body.token,
            user_id=current.user_id,
            client_ip=_client_ip(request),
        )
    except NetworkTokenError as exc:
        raise HTTPException(401, detail={"error": {"code": exc.code, "message": exc.message}}) from exc
    audit(
        db,
        actor_id=current.user_id,
        action="scanner.network_token.activate",
        resource_type="network_token",
        resource_id=str(row.get("id") or ""),
    )
    db.commit()
    return row


@router.post("/api/scanners/network-tokens/{token_id}/revoke")
def revoke_network_token(
    token_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    from app.services.vuln_network_tokens import revoke_network_token as _revoke

    row = _revoke(db, token_id)
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Network token not found"}})
    audit(
        db,
        actor_id=current.user_id,
        action="scanner.network_token.revoke",
        resource_type="network_token",
        resource_id=token_id,
    )
    db.commit()
    return row


@router.post("/api/scanners/bind-client-token")
def bind_scanner_client_token(
    body: BindClientTokenIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    """Set the edge AGENT_TOKEN to the emailed client access token (same token as web login)."""
    _require_vuln_module()
    from app.services.client_access_token import parse_and_verify
    from app.services.scanner_agent_auth import (
        CONNECTION_MODE_EDGE,
        EDGE_AGENT_URL,
        ensure_edge_agent_recovery_columns,
        hash_agent_token,
        token_hint,
    )
    from app.services.scanner_credentials import (
        SCANNER_ROLE_PORTABLE,
        ensure_scanner_role_column,
        is_edge_agent_scanner,
    )

    try:
        _tenant, email = parse_and_verify(body.token, current.tenant)
    except ValueError as exc:
        raise HTTPException(
            401,
            detail={"error": {"code": "invalid_token", "message": str(exc)}},
        ) from exc
    if email != (current.email or "").strip().lower():
        raise HTTPException(
            401,
            detail={"error": {"code": "invalid_token", "message": "Access token does not match the signed-in user"}},
        )

    ensure_scanner_role_column(db)
    ensure_edge_agent_recovery_columns(db)
    token = (body.token or "").strip()
    token_hash = hash_agent_token(token)
    hint = token_hint(token)
    role = (body.scanner_role or "").strip().lower() or SCANNER_ROLE_PORTABLE
    name = (body.name or "").strip() or "Laptop"
    rows = fetchall(db, "SELECT * FROM vuln_scanners ORDER BY name")
    chosen = None
    want_id = (body.scanner_id or "").strip()
    if want_id:
        chosen = next((r for r in rows if str(r.get("id")) == want_id), None)
    if chosen is None:
        chosen = next((r for r in rows if str(r.get("name") or "") == name), None)
    if chosen is None:
        edge = [r for r in rows if is_edge_agent_scanner(r)]
        if len(edge) == 1:
            chosen = edge[0]
    if chosen is not None:
        execute(
            db,
            """UPDATE vuln_scanners
               SET connection_mode = :mode,
                   url = :url,
                   agent_token_hash = :th,
                   agent_token_hint = :hint,
                   updated_at = NOW()
               WHERE id = CAST(:id AS uuid)""",
            {
                "mode": CONNECTION_MODE_EDGE,
                "url": EDGE_AGENT_URL,
                "th": token_hash,
                "hint": hint,
                "id": str(chosen["id"]),
            },
        )
        db.commit()
        audit(
            db,
            actor_id=current.user_id,
            action="scanner.bind_client_token",
            resource_type="scanner",
            resource_id=str(chosen["id"]),
        )
        db.commit()
        out = row_scanner(
            fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": str(chosen["id"])})
            or chosen
        )
        out["agent_token"] = token
        out["agent_token_once"] = True
        return out

    row = fetchone(
        db,
        """INSERT INTO vuln_scanners
           (name, url, edition, api_key_ref, connection_mode, scanner_role, agent_token_hash, agent_token_hint)
           VALUES (:name, :url, 'openvas', NULL, :mode, :role, :th, :hint)
           RETURNING *""",
        {
            "name": name,
            "url": EDGE_AGENT_URL,
            "mode": CONNECTION_MODE_EDGE,
            "role": role,
            "th": token_hash,
            "hint": hint,
        },
    )
    db.commit()
    audit(
        db,
        actor_id=current.user_id,
        action="scanner.bind_client_token",
        resource_type="scanner",
        resource_id=str(row["id"]),
    )
    db.commit()
    out = row_scanner(row)
    out["agent_token"] = token
    out["agent_token_once"] = True
    return out


@router.post("/api/scanners")
def create_scanner(
    body: ScannerCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    from app.services.scanner_agent_auth import (
        CONNECTION_MODE_EDGE,
        CONNECTION_MODE_GMP,
        EDGE_AGENT_URL,
        hash_agent_token,
        mint_agent_token,
        token_hint,
    )
    from app.services.scanner_credentials import (
        SCANNER_ROLES,
        SCANNER_ROLE_CENTRAL,
        SCANNER_ROLE_PERSISTENT,
        SCANNER_ROLE_PORTABLE,
        SCANNER_ROLE_REMOTE_VPN,
        connection_mode_for_role,
        ensure_scanner_role_column,
        infer_scanner_role,
        is_edge_agent_scanner,
        is_remote_scanner_url,
    )

    ensure_scanner_role_column(db)
    requested_role = str(body.scanner_role or "").strip().lower() or None
    if requested_role and requested_role not in SCANNER_ROLES:
        raise HTTPException(
            400,
            detail={
                "error": {
                    "code": "invalid_role",
                    "message": "scanner_role must be persistent_edge, portable, remote_vpn, or central",
                }
            },
        )
    mode = (body.connection_mode or "").strip().lower()
    if requested_role:
        mode = connection_mode_for_role(requested_role)
    elif not mode:
        mode = CONNECTION_MODE_EDGE
    if mode not in {CONNECTION_MODE_GMP, CONNECTION_MODE_EDGE}:
        raise HTTPException(
            400,
            detail={"error": {"code": "invalid_mode", "message": "connection_mode must be gmp or edge_agent"}},
        )
    url = (body.url or "").strip() or (EDGE_AGENT_URL if mode == CONNECTION_MODE_EDGE else "tls://")
    if requested_role not in {SCANNER_ROLE_CENTRAL, SCANNER_ROLE_REMOTE_VPN} and is_edge_agent_scanner(
        None, url=url, connection_mode=mode
    ):
        mode = CONNECTION_MODE_EDGE
        url = EDGE_AGENT_URL
    role = requested_role or infer_scanner_role(
        None, url=url, connection_mode=mode, scanner_role=requested_role
    )
    if role == SCANNER_ROLE_REMOTE_VPN:
        mode = CONNECTION_MODE_GMP
        if not url or url.lower().startswith("agent://") or url.lower() in {"tls://", "tls://:9390"}:
            raise HTTPException(
                400,
                detail={
                    "error": {
                        "code": "gmp_url_required",
                        "message": "Managed Remote / VPN scanners need a reachable GMP URL such as tls://site-vpn-host:9390",
                    }
                },
            )
    if role == SCANNER_ROLE_CENTRAL:
        mode = CONNECTION_MODE_GMP
        if not url or url.lower().startswith("agent://") or url.lower() in {"tls://", "tls://:9390"}:
            url = "unix:///run/gvmd/gvmd.sock"
        if is_remote_scanner_url(url):
            raise HTTPException(
                400,
                detail={
                    "error": {
                        "code": "central_gmp_url_required",
                        "message": "Central GMP uses this server's OpenVAS (unix:///run/gvmd/gvmd.sock or gmp://gvmd:9390). Use Managed Remote / VPN for a site scanner.",
                    }
                },
            )
    if role in {SCANNER_ROLE_PERSISTENT, SCANNER_ROLE_PORTABLE}:
        mode = CONNECTION_MODE_EDGE
        url = EDGE_AGENT_URL

    agent_token = None
    token_hash = None
    hint = None
    if mode == CONNECTION_MODE_EDGE:
        from app.services.scanner_agent_auth import ensure_edge_agent_recovery_columns

        ensure_edge_agent_recovery_columns(db)
        agent_token = mint_agent_token()
        token_hash = hash_agent_token(agent_token)
        hint = token_hint(agent_token)

    try:
        row = fetchone(
            db,
            """INSERT INTO vuln_scanners
               (name, url, edition, api_key_ref, connection_mode, scanner_role, agent_token_hash, agent_token_hint,
                agent_recovery_token_hash)
               VALUES (:name, :url, :edition, :ref, :mode, :role, :th, :hint, NULL)
               RETURNING *""",
            {
                "name": body.name,
                "url": url,
                "edition": body.edition or "openvas",
                "ref": body.api_key_ref,
                "mode": mode,
                "role": role,
                "th": token_hash,
                "hint": hint,
            },
        )
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        # Columns may be missing until migration 028/030/031 is applied.
        if mode == CONNECTION_MODE_EDGE:
            try:
                row = fetchone(
                    db,
                    """INSERT INTO vuln_scanners
                       (name, url, edition, api_key_ref, connection_mode, scanner_role, agent_token_hash, agent_token_hint)
                       VALUES (:name, :url, :edition, :ref, :mode, :role, :th, :hint)
                       RETURNING *""",
                    {
                        "name": body.name,
                        "url": url,
                        "edition": body.edition or "openvas",
                        "ref": body.api_key_ref,
                        "mode": mode,
                        "role": role,
                        "th": token_hash,
                        "hint": hint,
                    },
                )
            except Exception as exc2:
                try:
                    db.rollback()
                except Exception:
                    pass
                try:
                    row = fetchone(
                        db,
                        """INSERT INTO vuln_scanners
                           (name, url, edition, api_key_ref, connection_mode, agent_token_hash, agent_token_hint)
                           VALUES (:name, :url, :edition, :ref, :mode, :th, :hint)
                           RETURNING *""",
                        {
                            "name": body.name,
                            "url": url,
                            "edition": body.edition or "openvas",
                            "ref": body.api_key_ref,
                            "mode": mode,
                            "th": token_hash,
                            "hint": hint,
                        },
                    )
                except Exception as exc3:
                    raise HTTPException(
                        500,
                        detail={
                            "error": {
                                "code": "migration_required",
                                "message": "Apply migration 028_firm_vuln_edge_agent.sql before creating edge agents",
                                "detail": str(exc3)[:300],
                            }
                        },
                    ) from exc3
                _ = exc2
        else:
            try:
                row = fetchone(
                    db,
                    """INSERT INTO vuln_scanners
                       (name, url, edition, api_key_ref, connection_mode, scanner_role)
                       VALUES (:name, :url, :edition, :ref, :mode, :role)
                       RETURNING *""",
                    {
                        "name": body.name,
                        "url": url,
                        "edition": body.edition or "openvas",
                        "ref": body.api_key_ref,
                        "mode": mode,
                        "role": role,
                    },
                )
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                row = fetchone(
                    db,
                    """INSERT INTO vuln_scanners (name, url, edition, api_key_ref)
                       VALUES (:name, :url, :edition, :ref)
                       RETURNING *""",
                    {"name": body.name, "url": url, "edition": body.edition, "ref": body.api_key_ref},
                )
            _ = exc
    db.commit()
    audit(db, actor_id=current.user_id, action="scanner.create", resource_type="scanner", resource_id=str(row["id"]))
    db.commit()
    out = row_scanner(row)
    if agent_token:
        out["agent_token"] = agent_token
        out["agent_token_once"] = True
    return out


@router.get("/api/scanners/{scanner_id}")
def get_scanner(
    scanner_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scanner not found"}})
    return row_scanner(row)


@router.post("/api/scanners/{scanner_id}/ensure-agent-recovery-token")
def ensure_scanner_agent_recovery_token(
    scanner_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    """Mint/replace AGENT_RECOVERY_TOKEN only — keeps the existing primary AGENT_TOKEN."""
    _require_vuln_module()
    from app.services.scanner_agent_auth import (
        ensure_edge_agent_recovery_columns,
        hash_agent_token,
        mint_agent_token,
    )
    from app.services.scanner_credentials import is_edge_agent_scanner

    ensure_edge_agent_recovery_columns(db)
    row = fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scanner not found"}})
    if not is_edge_agent_scanner(row):
        raise HTTPException(
            400,
            detail={"error": {"code": "not_edge_agent", "message": "Scanner is not connection_mode=edge_agent"}},
        )
    if not row.get("agent_token_hash"):
        raise HTTPException(
            400,
            detail={
                "error": {
                    "code": "no_primary_token",
                    "message": "Scanner has no primary agent token; create/rotate primary first",
                }
            },
        )
    recovery_token = mint_agent_token()
    execute(
        db,
        """UPDATE vuln_scanners
           SET agent_recovery_token_hash = :rh,
               updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {"rh": hash_agent_token(recovery_token), "id": scanner_id},
    )
    db.commit()
    audit(
        db,
        actor_id=current.user_id,
        action="scanner.ensure_agent_recovery_token",
        resource_type="scanner",
        resource_id=scanner_id,
    )
    db.commit()
    out = row_scanner(
        fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id}) or row
    )
    out["agent_recovery_token"] = recovery_token
    out["agent_recovery_token_once"] = True
    out["primary_token_unchanged"] = True
    return out


@router.post("/api/scanners/{scanner_id}/rotate-agent-token")
def rotate_scanner_agent_token(
    scanner_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    """Reissue the single edge-agent bearer token (shown once). Does not mint a recovery token."""
    _require_vuln_module()
    from datetime import datetime, timedelta, timezone

    from app.services.scanner_agent_auth import (
        CONNECTION_MODE_EDGE,
        PREVIOUS_TOKEN_GRACE_HOURS,
        ensure_edge_agent_recovery_columns,
        hash_agent_token,
        mint_agent_token,
        token_hint,
    )
    from app.services.scanner_credentials import is_edge_agent_scanner

    ensure_edge_agent_recovery_columns(db)
    row = fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scanner not found"}})
    if not is_edge_agent_scanner(row):
        raise HTTPException(
            400,
            detail={"error": {"code": "not_edge_agent", "message": "Scanner is not connection_mode=edge_agent"}},
        )
    token = mint_agent_token()
    previous_hash = row.get("agent_token_hash")
    grace_until = datetime.now(timezone.utc) + timedelta(hours=PREVIOUS_TOKEN_GRACE_HOURS)
    execute(
        db,
        """UPDATE vuln_scanners
           SET connection_mode = :mode,
               agent_previous_token_hash = COALESCE(:prev, agent_previous_token_hash),
               agent_previous_token_valid_until = CASE
                   WHEN :prev IS NULL THEN agent_previous_token_valid_until
                   ELSE CAST(:grace AS timestamptz)
               END,
               agent_token_hash = :th,
               agent_token_hint = :hint,
               agent_recovery_token_hash = NULL,
               updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {
            "mode": CONNECTION_MODE_EDGE,
            "prev": previous_hash,
            "grace": grace_until.isoformat(),
            "th": hash_agent_token(token),
            "hint": token_hint(token),
            "id": scanner_id,
        },
    )
    db.commit()
    audit(
        db,
        actor_id=current.user_id,
        action="scanner.rotate_agent_token",
        resource_type="scanner",
        resource_id=scanner_id,
    )
    db.commit()
    out = row_scanner(
        fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id}) or row
    )
    out["agent_token"] = token
    out["agent_token_once"] = True
    out["previous_token_grace_hours"] = PREVIOUS_TOKEN_GRACE_HOURS
    return out


@router.patch("/api/scanners/{scanner_id}")
def update_scanner(
    scanner_id: str,
    body: ScannerUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    from app.services.scanner_credentials import (
        SCANNER_ROLES,
        SCANNER_ROLE_CENTRAL,
        SCANNER_ROLE_PERSISTENT,
        SCANNER_ROLE_PORTABLE,
        SCANNER_ROLE_REMOTE_VPN,
        connection_mode_for_role,
        ensure_scanner_role_column,
        is_remote_scanner_url,
    )

    ensure_scanner_role_column(db)
    row = fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scanner not found"}})
    data = body.model_dump(exclude_unset=True)
    if "scanner_role" in data and data["scanner_role"]:
        role = str(data["scanner_role"]).strip().lower()
        if role not in SCANNER_ROLES:
            raise HTTPException(
                400,
                detail={
                    "error": {
                        "code": "invalid_role",
                        "message": "scanner_role must be persistent_edge, portable, remote_vpn, or central",
                    }
                },
            )
        data["scanner_role"] = role
        data["connection_mode"] = connection_mode_for_role(role)
        if role in {SCANNER_ROLE_PERSISTENT, SCANNER_ROLE_PORTABLE}:
            data["url"] = "agent://local"
        elif role == SCANNER_ROLE_REMOTE_VPN:
            url = str(data.get("url") or row.get("url") or "").strip()
            if not url or url.lower().startswith("agent://") or url.lower() in {"tls://", "tls://:9390"}:
                raise HTTPException(
                    400,
                    detail={
                        "error": {
                            "code": "gmp_url_required",
                            "message": "Managed Remote / VPN scanners need a reachable GMP URL such as tls://site-vpn-host:9390",
                        }
                    },
                )
            data["url"] = url
        elif role == SCANNER_ROLE_CENTRAL:
            url = str(data.get("url") or row.get("url") or "").strip()
            if not url or url.lower().startswith("agent://") or url.lower() in {"tls://", "tls://:9390"}:
                url = "unix:///run/gvmd/gvmd.sock"
            if is_remote_scanner_url(url):
                raise HTTPException(
                    400,
                    detail={
                        "error": {
                            "code": "central_gmp_url_required",
                            "message": "Central GMP uses this server's OpenVAS (unix:///run/gvmd/gvmd.sock or gmp://gvmd:9390). Use Managed Remote / VPN for a site scanner.",
                        }
                    },
                )
            data["url"] = url
    if "connection_mode" in data and data["connection_mode"]:
        mode = str(data["connection_mode"]).strip().lower()
        if mode not in {"gmp", "edge_agent"}:
            raise HTTPException(
                400,
                detail={"error": {"code": "invalid_mode", "message": "connection_mode must be gmp or edge_agent"}},
            )
        data["connection_mode"] = mode
        if mode == "edge_agent" and "url" not in data:
            data["url"] = "agent://local"
    for k, v in data.items():
        execute(db, f"UPDATE vuln_scanners SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)", {"v": v, "id": scanner_id})
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id})
    return row_scanner(row)


# ---------- Policies ----------


@router.get("/api/scan-policies")
def list_policies(
    case_id: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    if case_id:
        rows = fetchall(
            db,
            "SELECT * FROM vuln_scan_policies WHERE case_id = CAST(:cid AS uuid) OR case_id IS NULL ORDER BY name",
            {"cid": case_id},
        )
    else:
        rows = fetchall(db, "SELECT * FROM vuln_scan_policies ORDER BY name")
    return [_policy_row(r) for r in rows]


@router.post("/api/scan-policies")
def create_policy(
    body: PolicyCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    row = fetchone(
        db,
        """INSERT INTO vuln_scan_policies
           (case_id, name, policy_type, scanner_id, settings_json, compliance_framework, created_by)
           VALUES (CAST(:cid AS uuid), :name, :ptype, CAST(:sid AS uuid), CAST(:settings AS jsonb), :fw, CAST(:uid AS uuid))
           RETURNING *""",
        {
            "cid": body.case_id if is_uuid(body.case_id) else None,
            "name": body.name,
            "ptype": body.policy_type,
            "sid": body.scanner_id if is_uuid(body.scanner_id) else None,
            "settings": json.dumps(body.settings_json or {}),
            "fw": body.compliance_framework,
            "uid": current.user_id,
        },
    )
    db.commit()
    return _policy_row(row)


@router.get("/api/scan-policies/{policy_id}")
def get_policy(
    policy_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_scan_policies WHERE id = CAST(:id AS uuid)", {"id": policy_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Policy not found"}})
    return _policy_row(row)


@router.patch("/api/scan-policies/{policy_id}")
def update_policy(
    policy_id: str,
    body: PolicyUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:policy_manage")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_scan_policies WHERE id = CAST(:id AS uuid)", {"id": policy_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Policy not found"}})
    data = body.model_dump(exclude_unset=True)
    if "settings_json" in data and data["settings_json"] is not None:
        data["settings_json"] = json.dumps(data["settings_json"])
        execute(
            db,
            "UPDATE vuln_scan_policies SET settings_json = CAST(:v AS jsonb), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
            {"v": data.pop("settings_json"), "id": policy_id},
        )
    for k, v in data.items():
        if k == "scanner_id":
            execute(
                db,
                "UPDATE vuln_scan_policies SET scanner_id = CAST(:v AS uuid), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v if is_uuid(v) else None, "id": policy_id},
            )
        else:
            execute(db, f"UPDATE vuln_scan_policies SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)", {"v": v, "id": policy_id})
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_scan_policies WHERE id = CAST(:id AS uuid)", {"id": policy_id})
    return _policy_row(row)


# ---------- Scan jobs ----------


@router.get("/api/cases/{case_id}/scan-jobs")
def list_scan_jobs(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        "SELECT * FROM vuln_scan_jobs WHERE case_id = CAST(:cid AS uuid) ORDER BY created_at DESC",
        {"cid": case_id},
    )
    return [_job_row(db, r) for r in rows]


@router.post("/api/cases/{case_id}/scan-jobs")
def create_scan_job(
    case_id: str,
    body: ScanJobCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    _require_vuln_module()
    if not body.preflight_confirmed:
        raise HTTPException(
            400,
            detail={
                "error": {
                    "code": "preflight_required",
                    "message": "Confirm pre-scan controls (authorization, targets, scanner health, feed, credentials, window).",
                }
            },
        )
    if not body.authorization_ref:
        raise HTTPException(400, detail={"error": {"code": "authz_required", "message": "authorization_ref is required"}})
    active_targets = [t for t in body.targets if not t.excluded]
    if not active_targets:
        raise HTTPException(400, detail={"error": {"code": "targets_required", "message": "At least one target required"}})

    from app.services.vuln_network_tokens import (
        get_connected_token,
        pick_central_scanner_id,
        session_for_user,
        targets_outside_cidr,
    )

    network = None
    if body.network_token_id and is_uuid(body.network_token_id):
        network = get_connected_token(db, body.network_token_id)
        if not network:
            raise HTTPException(
                400,
                detail={
                    "error": {
                        "code": "network_token_required",
                        "message": "Connect the scanner token for this network before launching.",
                    }
                },
            )
    else:
        network = session_for_user(db, current.user_id)

    if network:
        outside = targets_outside_cidr([t.target for t in active_targets], str(network.get("cidr") or ""))
        if outside:
            preview = ", ".join(outside[:5])
            extra = f" (+{len(outside) - 5} more)" if len(outside) > 5 else ""
            raise HTTPException(
                400,
                detail={
                    "error": {
                        "code": "targets_not_in_network",
                        "message": f"Targets must be inside {network.get('cidr')}: {preview}{extra}",
                    }
                },
            )

    preflight = {
        "authorization": True,
        "targets_validated": True,
        "confirmed_at": datetime.now(timezone.utc).isoformat(),
        "confirmed_by": current.user_id,
    }
    if network:
        preflight["network_token_id"] = network.get("id")
        preflight["network_cidr"] = network.get("cidr")
        preflight["connected_public_ip"] = network.get("connected_public_ip")

    scanner_id = body.scanner_id if is_uuid(body.scanner_id) else None
    policy_settings = {}
    if is_uuid(body.policy_id):
        pol = fetchone(
            db,
            "SELECT scanner_id, settings_json FROM vuln_scan_policies WHERE id = CAST(:id AS uuid)",
            {"id": body.policy_id},
        )
        if not pol:
            raise HTTPException(400, detail={"error": {"code": "policy_not_found", "message": "Selected policy was not found"}})
        policy_settings = pol.get("settings_json") or {}
        if isinstance(policy_settings, str):
            try:
                policy_settings = json.loads(policy_settings)
            except ValueError:
                raise HTTPException(400, detail={"error": {"code": "invalid_scan_policy", "message": "Policy settings contain invalid JSON"}})
        if not scanner_id and pol.get("scanner_id"):
            scanner_id = str(pol["scanner_id"])

    remote_scanner = False
    edge_agent = False
    scanner_url = ""
    if scanner_id:
        from app.services.scanner_agent_auth import ensure_edge_agent_readiness_columns

        ensure_edge_agent_readiness_columns(db)
        sc = fetchone(
            db,
            "SELECT url, edition, status, connection_mode, openvas_ready, agent_status_detail FROM vuln_scanners WHERE id = CAST(:id AS uuid)",
            {"id": scanner_id},
        )
        if not sc:
            raise HTTPException(
                400,
                detail={"error": {"code": "scanner_not_found", "message": "Selected scanner was not found"}},
            )
        if (sc.get("status") or "").lower() == "disabled":
            raise HTTPException(
                400,
                detail={"error": {"code": "scanner_disabled", "message": "Selected scanner is disabled"}},
            )
        scanner_url = str(sc.get("url") or "")
        from app.services.scanner_credentials import is_edge_agent_scanner, is_remote_scanner_url

        edge_agent = is_edge_agent_scanner(sc)
        if edge_agent and sc.get("openvas_ready") is not True:
            raise HTTPException(409, detail={"error": {"code": "edge_scanner_not_ready",
                "message": str(sc.get("agent_status_detail") or "Laptop scanner is waiting for OpenVAS feed/configuration readiness")[:500]}})
        remote_scanner = is_remote_scanner_url(scanner_url) or edge_agent
        if network and (edge_agent or remote_scanner):
            raise HTTPException(
                400,
                detail={
                    "error": {
                        "code": "network_token_requires_central",
                        "message": "A connected client network must launch on the server Central GMP scanner.",
                    }
                },
            )

    if network and not scanner_id:
        scanner_id = pick_central_scanner_id(db)

    # Remote / edge OpenVAS must not run premise-local nmap/nuclei orchestration.
    orch_json = None
    initial_status = "pending"
    if edge_agent:
        from app.services.scanner_service_policy import validate_request

        try:
            policy_request = validate_request(policy_settings)
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, detail={"error": {"code": "invalid_scan_policy", "message": str(exc)}})
        orch_json = json.dumps(
            {
                "enabled": False,
                "edge_agent": True,
                "remote_openvas": True,
                "scanner_url": scanner_url[:200],
                "scan_policy_request": policy_request,
                "service_policy_version": "aetheris-services-2.1",
            }
        )
        initial_status = "queued"
    elif remote_scanner and body.orchestration_enabled is not True:
        orch_json = json.dumps({"enabled": False, "remote_openvas": True, "scanner_url": scanner_url[:200]})
    elif body.orchestration_enabled is True or (
        body.orchestration_enabled is None
        and get_settings().vuln_orchestration_enabled
        and not remote_scanner
    ):
        orch_json = json.dumps({"pipeline": None, "enabled": True})

    row = fetchone(
        db,
        """INSERT INTO vuln_scan_jobs
           (case_id, policy_id, scanner_id, status, scheduled_at, authorization_ref,
            scan_window_start, scan_window_end, preflight_json, orchestration_json)
           VALUES (CAST(:cid AS uuid), CAST(:pid AS uuid), CAST(:sid AS uuid), :status,
                   CAST(:sched AS timestamptz), :authz,
                   CAST(:ws AS timestamptz), CAST(:we AS timestamptz), CAST(:pf AS jsonb),
                   CAST(:orch AS jsonb))
           RETURNING *""",
        {
            "cid": case_id,
            "pid": body.policy_id if is_uuid(body.policy_id) else None,
            "sid": scanner_id,
            "status": initial_status,
            "sched": body.scheduled_at,
            "authz": body.authorization_ref,
            "ws": body.scan_window_start,
            "we": body.scan_window_end,
            "pf": json.dumps(preflight),
            "orch": orch_json,
        },
    )
    for t in body.targets:
        execute(
            db,
            """INSERT INTO vuln_scan_targets (scan_job_id, target, target_type, credential_ref, excluded)
               VALUES (CAST(:jid AS uuid), :target, :ttype, :cred, :excl)""",
            {
                "jid": str(row["id"]),
                "target": t.target,
                "ttype": t.target_type,
                "cred": t.credential_ref,
                "excl": t.excluded,
            },
        )
    timeline(
        db,
        case_id=case_id,
        source_type="scan_job",
        source_id=str(row["id"]),
        event_type="scan.created",
        actor=current.user_id,
        summary=f"Scan job created with {len(active_targets)} target(s)",
    )
    db.commit()

    # Edge-agent jobs wait for the laptop agent; do not start premise OpenVAS sync.
    if not edge_agent:
        try:
            from app.tasks import nessus_scan_sync_task

            schema = current.schema_name
            if schema:
                nessus_scan_sync_task.delay(schema, str(row["id"]))
        except Exception:
            pass

    row = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": str(row["id"])})
    return _job_row(db, row)


@router.get("/api/scan-jobs/{job_id}")
def get_scan_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scan job not found"}})
    return _job_row(db, row)


_SEVERITY_ORDER = SEVERITY_ORDER


def _host_set_from_values(values: list[Any] | None) -> set[str]:
    out: set[str] = set()
    for v in values or []:
        s = str(v or "").strip()
        if s:
            out.add(s)
    return out


@router.get("/api/scan-jobs/{job_id}/severity-summary")
def get_scan_job_severity_summary(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:read")),
):
    """Finding severity breakdown + distinct host IPs for a scan job (View Details)."""
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scan job not found"}})

    progress = scan_job_progress(db, row)

    # All IPs associated with the job: targets + assessed hosts from edge evidence.
    target_rows = fetchall(
        db,
        """SELECT target, excluded FROM vuln_scan_targets
           WHERE scan_job_id = CAST(:jid AS uuid)
           ORDER BY target""",
        {"jid": job_id},
    )
    all_hosts: set[str] = set()
    for t in target_rows:
        host = str(t.get("target") or "").strip()
        if host:
            all_hosts.add(host)

    orch = row.get("orchestration_json")
    if isinstance(orch, str):
        try:
            orch = json.loads(orch)
        except json.JSONDecodeError:
            orch = None
    if isinstance(orch, dict):
        all_hosts |= _host_set_from_values(orch.get("assessed_hosts") or [])
        for item in orch.get("skipped_hosts") or []:
            if isinstance(item, dict):
                h = str(item.get("host") or item.get("target") or "").strip()
            else:
                h = str(item or "").strip()
            if h:
                all_hosts.add(h)

    result_meta = fetchone(
        db,
        """SELECT result_json, hosts_assessed, hosts_attempted, plugin_error_count
           FROM vuln_scan_results
           WHERE scan_job_id = CAST(:jid AS uuid)
           ORDER BY created_at DESC LIMIT 1""",
        {"jid": job_id},
    )
    rj: dict[str, Any] = {}
    if result_meta and result_meta.get("result_json"):
        rj = result_meta["result_json"]
        if isinstance(rj, str):
            try:
                rj = json.loads(rj)
            except json.JSONDecodeError:
                rj = {}
        if isinstance(rj, dict):
            all_hosts |= _host_set_from_values(rj.get("assessed_hosts") or [])
            for item in rj.get("skipped_hosts") or []:
                if isinstance(item, dict):
                    h = str(item.get("host") or item.get("target") or "").strip()
                else:
                    h = str(item or "").strip()
                if h:
                    all_hosts.add(h)

    # Verification summary is exposed in Scan Details, not the client report.
    # Edge jobs still require durable laptop evidence. Central/orchestrated jobs
    # are verified from vuln_scan_results or inferred engine/finding coverage.
    from app.services.scan_assessment_evidence import infer_central_scan_result, _json_obj

    target_count = len(target_rows)
    if not result_meta:
        inferred = infer_central_scan_result(db, row)
        if inferred:
            result_meta = inferred
            rj = inferred.get("result_json") if isinstance(inferred.get("result_json"), dict) else {}
    hosts_assessed = int((result_meta or {}).get("hosts_assessed") or 0)
    plugin_error_count = int((result_meta or {}).get("plugin_error_count") or 0)
    skipped_raw = rj.get("skipped_hosts") or [] if isinstance(rj, dict) else []
    skipped_count = len(skipped_raw) if isinstance(skipped_raw, list) else 0
    explicit_complete = rj.get("assessment_complete") if isinstance(rj, dict) else None
    orch_obj = _json_obj(row.get("orchestration_json"))
    is_edge = bool(orch_obj.get("edge_agent"))
    accounted = min(target_count, hosts_assessed + skipped_count)
    coverage_ok = target_count > 0 and accounted >= target_count
    if is_edge:
        verified = bool(
            row.get("status") == "completed"
            and result_meta
            and explicit_complete is True
            and coverage_ok
        )
    else:
        verified = bool(row.get("status") == "completed" and result_meta and coverage_ok)
    clean_eligible = bool(verified and skipped_count == 0 and plugin_error_count == 0)
    if verified and skipped_count > 0:
        assessment_label = "VERIFIED WITH SCOPE EXCEPTION"
    elif verified and plugin_error_count > 0:
        assessment_label = "VERIFIED WITH WARNINGS"
    elif verified:
        assessment_label = "VERIFIED"
    else:
        assessment_label = "UNVERIFIED"

    agg_rows = fetchall(
        db,
        f"""
        SELECT {aetheris_severity_sql("f")} AS severity,
               COUNT(*)::int AS count,
               ARRAY_AGG(
                 DISTINCT COALESCE(
                   NULLIF(trim(a.primary_ip), ''),
                   NULLIF(trim(a.hostname), ''),
                   NULLIF(trim(f.risk_factors_json->>'host'), ''),
                   NULLIF(trim(f.risk_factors_json->>'hostname'), '')
                 )
               ) FILTER (
                 WHERE COALESCE(
                   NULLIF(trim(a.primary_ip), ''),
                   NULLIF(trim(a.hostname), ''),
                   NULLIF(trim(f.risk_factors_json->>'host'), ''),
                   NULLIF(trim(f.risk_factors_json->>'hostname'), '')
                 ) IS NOT NULL
               ) AS hosts
          FROM vuln_findings f
          LEFT JOIN vuln_assets a ON a.id = f.asset_id
         WHERE f.scan_job_id = CAST(:jid AS uuid)
         GROUP BY 1
        """,
        {"jid": job_id},
    )
    by_sev: dict[str, dict] = {}
    total = 0
    for r in agg_rows:
        sev = (r.get("severity") or "info").lower()
        if sev not in _SEVERITY_ORDER:
            sev = "info"
        count = int(r.get("count") or 0)
        hosts_raw = r.get("hosts") or []
        hosts = sorted({str(h).strip() for h in hosts_raw if h and str(h).strip()})
        all_hosts |= set(hosts)
        existing = by_sev.get(sev)
        if existing:
            existing["count"] += count
            existing["hosts"] = sorted(set(existing["hosts"]) | set(hosts))
        else:
            by_sev[sev] = {"severity": sev, "count": count, "hosts": hosts}
        total += count

    severities = []
    for sev in _SEVERITY_ORDER:
        item = by_sev.get(sev) or {"severity": sev, "count": 0, "hosts": []}
        pct = round((item["count"] / total) * 100, 1) if total else 0.0
        severities.append(
            {
                "severity": item["severity"],
                "count": item["count"],
                "pct": pct,
                "hosts": item["hosts"],
            }
        )

    from app.services.vuln_capacity import detect_scan_accel

    return {
        "job_id": job_id,
        "status": row["status"],
        "progress_pct": progress["progress_pct"],
        "progress_label": progress.get("progress_label"),
        "error": row.get("error"),
        "total": total,
        "all_hosts": sorted(all_hosts),
        "severities": severities,
        "targets": scan_job_target_rows(db, row),
        "service_coverage": (orch if isinstance(orch, dict) else {}).get("service_coverage") or (rj if isinstance(rj, dict) else {}).get("service_coverage") or {},
        "policy_snapshots": (orch if isinstance(orch, dict) else {}).get("policy_snapshots") or (rj if isinstance(rj, dict) else {}).get("policy_snapshots") or {},
        "accel": detect_scan_accel(),
        "assessment": {
            "assessed": hosts_assessed,
            "target_count": target_count,
            "skipped": skipped_count,
            "verified": verified,
            "label": assessment_label,
            "clean_eligible": clean_eligible,
            "plugin_error_count": plugin_error_count,
        },
    }


@router.patch("/api/scan-jobs/{job_id}")
def update_scan_job(
    job_id: str,
    body: ScanJobUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Scan job not found"}})
    data = body.model_dump(exclude_unset=True)

    # Edge-agent completion is authoritative only through
    # POST /api/scanner-agent/jobs/{id}/results, which persists a durable
    # vuln_scan_results evidence row before setting the terminal status.
    # Prevent UI/admin PATCH races from creating "completed but unverified"
    # jobs with no scan-result evidence.
    if str(data.get("status") or "").strip().lower() == "completed":
        from app.services.scanner_agent_jobs import job_is_edge_agent

        if job_is_edge_agent(row):
            evidence = fetchone(
                db,
                """SELECT result_json FROM vuln_scan_results
                   WHERE scan_job_id = CAST(:jid AS uuid)
                   ORDER BY created_at DESC LIMIT 1""",
                {"jid": job_id},
            )
            result_json = evidence.get("result_json") if evidence else None
            if isinstance(result_json, str):
                try:
                    result_json = json.loads(result_json)
                except Exception:
                    result_json = {}
            if not isinstance(result_json, dict) or result_json.get("assessment_complete") is not True:
                raise HTTPException(
                    409,
                    detail={
                        "error": {
                            "code": "edge_completion_requires_evidence",
                            "message": (
                                "Edge scan cannot be marked completed before durable OpenVAS "
                                "result evidence has been ingested by the scanner agent."
                            ),
                        }
                    },
                )

    for k, v in data.items():
        execute(db, f"UPDATE vuln_scan_jobs SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)", {"v": v, "id": job_id})
    if data.get("status") == "completed":
        execute(db, "UPDATE vuln_scan_jobs SET completed_at = NOW() WHERE id = CAST(:id AS uuid)", {"id": job_id})
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    return _job_row(db, row)


@router.delete("/api/scan-jobs/{job_id}")
def delete_queued_scan_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    """Stop server-side scan work for this job, then delete it."""
    _require_vuln_module()
    existing = fetchone(
        db,
        "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)",
        {"id": job_id},
    )
    if not existing:
        raise HTTPException(
            404,
            detail={"error": {"code": "not_found", "message": "Scan job not found"}},
        )
    status = str(existing.get("status") or "").strip().lower()
    if status not in DELETABLE_SCAN_JOB_STATUSES:
        raise HTTPException(
            409,
            detail={
                "error": {
                    "code": "job_not_deletable",
                    "message": (
                        f"Scan job is {status or 'unknown'}; "
                        "delete is available for queued, processing, and running jobs."
                    ),
                }
            },
        )

    from app.services.case_delete import terminate_scan_job_runtime

    stopped = terminate_scan_job_runtime(existing)
    delete_scan_job_cascade(db, job_id)
    timeline(
        db,
        case_id=str(existing["case_id"]),
        source_type="scan_job",
        source_id=job_id,
        event_type="scan.job_deleted",
        actor=current.user_id,
        summary=f"Scan job stopped and deleted while {status}",
    )
    db.commit()
    return {"ok": True, "id": job_id, "status": "deleted", "terminated": stopped}


@router.post("/api/scan-jobs/{job_id}/retry")
def retry_scan_job(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    """Requeue a failed edge job with its original targets and OpenVAS task ids."""
    _require_vuln_module()
    try:
        payload = retry_edge_job(db, job_id, actor=current.user_id)
    except RetryNotAllowed as exc:
        status = 404 if exc.code == "not_found" else 409
        raise HTTPException(
            status_code=status,
            detail={"error": {"code": exc.code, "message": str(exc)}},
        ) from exc
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    return _job_row(db, row) if row else payload


@router.post("/api/cases/{case_id}/scan-jobs/retry-failed")
def retry_failed_scan_jobs_for_case(
    case_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:launch")),
):
    """Requeue each failed edge job in this case independently. Targets are never merged."""
    _require_vuln_module()
    result = retry_failed_edge_jobs_for_case(db, case_id, actor=current.user_id)
    db.commit()
    return result


# ---------- Findings / assets ----------


@router.get("/api/cases/{case_id}/vulnerabilities")
def list_vulnerabilities(
    case_id: str,
    page: int = 1,
    page_size: int = 50,
    severity: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    offset = (page - 1) * page_size
    where = "case_id = CAST(:cid AS uuid)"
    params: dict[str, Any] = {"cid": case_id, "lim": page_size, "off": offset}
    if severity:
        where += f" AND ({aetheris_severity_sql('')}) = :sev"
        params["sev"] = severity
    total = fetchone(db, f"SELECT COUNT(*)::int AS n FROM vuln_findings WHERE {where}", params) or {"n": 0}
    rows = fetchall(
        db,
        f"SELECT * FROM vuln_findings WHERE {where} ORDER BY created_at DESC LIMIT :lim OFFSET :off",
        params,
    )
    return {"items": [_finding_row(r) for r in rows], "total": int(total["n"]), "page": page, "page_size": page_size}


@router.get("/api/assets")
def list_assets(
    case_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("asset:read")),
):
    _require_vuln_module()
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    offset = (page - 1) * page_size
    where = "TRUE"
    params: dict[str, Any] = {"lim": page_size, "off": offset}
    if case_id:
        where = "case_id = CAST(:cid AS uuid)"
        params["cid"] = case_id
    total = fetchone(db, f"SELECT COUNT(*)::int AS n FROM vuln_assets WHERE {where}", params) or {"n": 0}
    rows = fetchall(
        db,
        f"SELECT * FROM vuln_assets WHERE {where} ORDER BY created_at DESC LIMIT :lim OFFSET :off",
        params,
    )
    return {"items": [_asset_row(db, r) for r in rows], "total": int(total["n"]), "page": page, "page_size": page_size}


@router.get("/api/assets/{asset_id}")
def get_asset(
    asset_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("asset:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_assets WHERE id = CAST(:id AS uuid)", {"id": asset_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Asset not found"}})
    return _asset_row(db, row)


@router.get("/api/assets/{asset_id}/risk")
def get_asset_risk(
    asset_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("asset:read")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_assets WHERE id = CAST(:id AS uuid)", {"id": asset_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Asset not found"}})
    agg = fetchone(
        db,
        f"""SELECT COUNT(*)::int AS finding_count,
                  COUNT(*) FILTER (WHERE {aetheris_severity_sql('')} = 'critical')::int AS critical_count,
                  COUNT(*) FILTER (WHERE {aetheris_severity_sql('')} = 'high')::int AS high_count,
                  COUNT(*) FILTER (WHERE {aetheris_severity_sql('')} = 'medium')::int AS medium_count,
                  COUNT(*) FILTER (WHERE {aetheris_severity_sql('')} = 'low')::int AS low_count
           FROM vuln_findings WHERE asset_id = CAST(:id AS uuid) AND status = 'open'""",
        {"id": asset_id},
    ) or {}
    cves = fetchall(
        db,
        """SELECT DISTINCT cve FROM vuln_findings
           WHERE asset_id = CAST(:id AS uuid) AND cve IS NOT NULL AND status = 'open'
           ORDER BY cve LIMIT 10""",
        {"id": asset_id},
    )
    return {
        "asset_id": asset_id,
        "risk_score": float(row["risk_score"]) if row.get("risk_score") is not None else None,
        "finding_count": int(agg.get("finding_count") or 0),
        "critical_count": int(agg.get("critical_count") or 0),
        "high_count": int(agg.get("high_count") or 0),
        "medium_count": int(agg.get("medium_count") or 0),
        "low_count": int(agg.get("low_count") or 0),
        "top_cves": [c["cve"] for c in cves],
    }


# ---------- Remediation ----------


@router.get("/api/remediation-tasks")
def list_remediation(
    page: int = 1,
    page_size: int = 50,
    status: str | None = None,
    finding_id: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    page = max(page, 1)
    page_size = min(max(page_size, 1), 200)
    offset = (page - 1) * page_size
    where = "TRUE"
    params: dict[str, Any] = {"lim": page_size, "off": offset}
    if status:
        where += " AND status = :st"
        params["st"] = status
    if finding_id:
        where += " AND finding_id = CAST(:fid AS uuid)"
        params["fid"] = finding_id
    total = fetchone(db, f"SELECT COUNT(*)::int AS n FROM vuln_remediation_tasks WHERE {where}", params) or {"n": 0}
    rows = fetchall(
        db,
        f"SELECT * FROM vuln_remediation_tasks WHERE {where} ORDER BY created_at DESC LIMIT :lim OFFSET :off",
        params,
    )
    return {"items": [_rem_row(r) for r in rows], "total": int(total["n"]), "page": page, "page_size": page_size}


@router.post("/api/remediation-tasks")
def create_remediation(
    body: RemediationCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:remediate")),
):
    _require_vuln_module()
    row = fetchone(
        db,
        """INSERT INTO vuln_remediation_tasks (finding_id, owner_id, sla_due, status)
           VALUES (CAST(:fid AS uuid), CAST(:oid AS uuid), CAST(:sla AS timestamptz), :st)
           RETURNING *""",
        {
            "fid": body.finding_id,
            "oid": body.owner_id if is_uuid(body.owner_id) else None,
            "sla": body.sla_due,
            "st": body.status,
        },
    )
    finding = fetchone(db, "SELECT case_id FROM vuln_findings WHERE id = CAST(:id AS uuid)", {"id": body.finding_id})
    if finding:
        timeline(
            db,
            case_id=str(finding["case_id"]),
            source_type="remediation",
            source_id=str(row["id"]),
            event_type="remediation.created",
            actor=current.user_id,
            summary="Remediation task created",
        )
    db.commit()
    return _rem_row(row)


@router.patch("/api/remediation-tasks/{task_id}")
def update_remediation(
    task_id: str,
    body: RemediationUpdate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:remediate")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_remediation_tasks WHERE id = CAST(:id AS uuid)", {"id": task_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Task not found"}})
    data = body.model_dump(exclude_unset=True)

    for k, v in data.items():
        if k in ("owner_id", "rescan_job_id") and v is not None:
            execute(
                db,
                f"UPDATE vuln_remediation_tasks SET {k} = CAST(:v AS uuid), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v if is_uuid(str(v)) else None, "id": task_id},
            )
        elif k == "sla_due":
            execute(
                db,
                "UPDATE vuln_remediation_tasks SET sla_due = CAST(:v AS timestamptz), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
                {"v": v, "id": task_id},
            )
        else:
            execute(db, f"UPDATE vuln_remediation_tasks SET {k} = :v, updated_at = NOW() WHERE id = CAST(:id AS uuid)", {"v": v, "id": task_id})
    db.commit()
    row = fetchone(db, "SELECT * FROM vuln_remediation_tasks WHERE id = CAST(:id AS uuid)", {"id": task_id})
    return _rem_row(row)


@router.delete("/api/remediation-tasks/{task_id}")
def delete_remediation(
    task_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:remediate")),
):
    _require_vuln_module()
    execute(db, "DELETE FROM vuln_remediation_tasks WHERE id = CAST(:id AS uuid)", {"id": task_id})
    db.commit()
    return {"ok": True}


@router.post("/api/findings/{finding_id}/remediation")
def create_finding_remediation(
    finding_id: str,
    body: dict,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:remediate")),
):
    _require_vuln_module()
    payload = RemediationCreate(
        finding_id=finding_id,
        owner_id=body.get("owner_id"),
        sla_due=body.get("sla_due"),
        status="open",
    )
    row = fetchone(
        db,
        """INSERT INTO vuln_remediation_tasks (finding_id, owner_id, sla_due, status)
           VALUES (CAST(:fid AS uuid), CAST(:oid AS uuid), CAST(:sla AS timestamptz), :st)
           RETURNING *""",
        {
            "fid": payload.finding_id,
            "oid": payload.owner_id if is_uuid(payload.owner_id) else None,
            "sla": payload.sla_due,
            "st": payload.status,
        },
    )
    finding = fetchone(db, "SELECT case_id FROM vuln_findings WHERE id = CAST(:id AS uuid)", {"id": finding_id})
    if finding:
        timeline(
            db,
            case_id=str(finding["case_id"]),
            source_type="remediation",
            source_id=str(row["id"]),
            event_type="remediation.created",
            actor=current.user_id,
            summary=body.get("notes") or "Remediation task created from finding",
        )
    db.commit()
    return _rem_row(row)


# ---------- Exceptions (SoD) ----------


@router.get("/api/vuln/exceptions")
def list_exceptions(
    status: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    if status:
        rows = fetchall(db, "SELECT * FROM vuln_exceptions WHERE status = :st ORDER BY created_at DESC", {"st": status})
    else:
        rows = fetchall(db, "SELECT * FROM vuln_exceptions ORDER BY created_at DESC")
    return [
        {
            "id": str(r["id"]),
            "finding_id": str(r["finding_id"]),
            "requested_by": str(r["requested_by"]),
            "approved_by": str(r["approved_by"]) if r.get("approved_by") else None,
            "status": r["status"],
            "reason": r.get("reason"),
            "compensating_controls": r.get("compensating_controls"),
            "expires_at": r["expires_at"].isoformat() if r.get("expires_at") else None,
            "residual_risk": r.get("residual_risk"),
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        }
        for r in rows
    ]


@router.post("/api/vuln/exceptions")
def create_exception(
    body: ExceptionCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:write")),
):
    _require_vuln_module()
    row = fetchone(
        db,
        """INSERT INTO vuln_exceptions
           (finding_id, requested_by, reason, compensating_controls, expires_at, residual_risk)
           VALUES (CAST(:fid AS uuid), CAST(:uid AS uuid), :reason, :cc, CAST(:exp AS timestamptz), :rr)
           RETURNING *""",
        {
            "fid": body.finding_id,
            "uid": current.user_id,
            "reason": body.reason,
            "cc": body.compensating_controls,
            "exp": body.expires_at,
            "rr": body.residual_risk,
        },
    )
    db.commit()
    return {"id": str(row["id"]), "status": row["status"]}


@router.post("/api/vuln/exceptions/{exception_id}/decide")
def decide_exception(
    exception_id: str,
    body: ExceptionDecide,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("exception:approve")),
):
    _require_vuln_module()
    row = fetchone(db, "SELECT * FROM vuln_exceptions WHERE id = CAST(:id AS uuid)", {"id": exception_id})
    if not row:
        raise HTTPException(404, detail={"error": {"code": "not_found", "message": "Exception not found"}})
    if str(row["requested_by"]) == str(current.user_id):
        raise HTTPException(
            403,
            detail={"error": {"code": "sod_violation", "message": "Requester cannot approve their own exception"}},
        )
    if body.status not in ("approved", "rejected"):
        raise HTTPException(400, detail={"error": {"code": "invalid_status", "message": "status must be approved or rejected"}})
    execute(
        db,
        """UPDATE vuln_exceptions
           SET status = :st, approved_by = CAST(:uid AS uuid), residual_risk = COALESCE(:rr, residual_risk), updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {"st": body.status, "uid": current.user_id, "rr": body.residual_risk, "id": exception_id},
    )
    if body.status == "approved":
        execute(
            db,
            "UPDATE vuln_findings SET status = 'exception', updated_at = NOW() WHERE id = CAST(:fid AS uuid)",
            {"fid": str(row["finding_id"])},
        )
    db.commit()
    return {"id": exception_id, "status": body.status}


# ---------- Evidence ----------


@router.get("/api/vuln/evidence")
def list_evidence(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("evidence:read")),
):
    _require_vuln_module()
    rows = fetchall(db, "SELECT * FROM vuln_evidence_packages ORDER BY created_at DESC")
    return [
        {
            "id": str(r["id"]),
            "case_id": str(r["case_id"]) if r.get("case_id") else None,
            "framework": r.get("framework"),
            "control_id": r.get("control_id"),
            "title": r["title"],
            "integrity_hash": r.get("integrity_hash"),
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        }
        for r in rows
    ]


@router.post("/api/vuln/evidence")
def create_evidence(
    body: EvidenceCreate,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("evidence:read")),
):
    _require_vuln_module()
    meta = body.metadata_json or {}
    raw = json.dumps({"title": body.title, "framework": body.framework, "control_id": body.control_id, "meta": meta}, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    row = fetchone(
        db,
        """INSERT INTO vuln_evidence_packages
           (case_id, framework, control_id, title, metadata_json, integrity_hash, period_start, period_end, created_by)
           VALUES (CAST(:cid AS uuid), :fw, :ctrl, :title, CAST(:meta AS jsonb), :hash,
                   CAST(:ps AS timestamptz), CAST(:pe AS timestamptz), CAST(:uid AS uuid))
           RETURNING *""",
        {
            "cid": body.case_id if is_uuid(body.case_id) else None,
            "fw": body.framework,
            "ctrl": body.control_id,
            "title": body.title,
            "meta": json.dumps(meta),
            "hash": digest,
            "ps": body.period_start,
            "pe": body.period_end,
            "uid": current.user_id,
        },
    )
    db.commit()
    return {"id": str(row["id"]), "integrity_hash": digest}


# ---------- Timeline ----------


@router.get("/api/timeline")
def get_timeline(
    case_id: str,
    limit: int = 100,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("vuln:read")),
):
    _require_vuln_module()
    rows = fetchall(
        db,
        """SELECT * FROM vuln_timeline_events
           WHERE case_id = CAST(:cid AS uuid)
           ORDER BY timestamp_utc DESC LIMIT :lim""",
        {"cid": case_id, "lim": min(max(limit, 1), 500)},
    )
    events = [
        {
            "id": str(r["id"]),
            "case_id": str(r["case_id"]),
            "source_type": r["source_type"],
            "source_id": str(r["source_id"]) if r.get("source_id") else None,
            "timestamp_utc": r["timestamp_utc"].isoformat() if r.get("timestamp_utc") else None,
            "event_type": r["event_type"],
            "actor": r.get("actor"),
            "asset_id": str(r["asset_id"]) if r.get("asset_id") else None,
            "summary": r.get("summary"),
        }
        for r in rows
    ]
    return {"case_id": case_id, "events": events, "total": len(events)}


# ---------- Health / Nessus probe ----------


@router.get("/api/vuln/scanner/status")
def scanner_status(
    scanner_id: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:admin")),
):
    _require_vuln_module()
    url = get_settings().nessus_default_url
    edition = "nessus"
    sc = None
    if scanner_id:
        sc = fetchone(db, "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)", {"id": scanner_id})
        if sc:
            url = sc["url"]
            edition = sc.get("edition") or edition
    from app.services.scanner_credentials import infer_scanner_role, is_edge_agent_scanner, scanner_heartbeat_online

    if sc and is_edge_agent_scanner(sc):
        online = scanner_heartbeat_online(sc)
        return {
            "ok": bool(online),
            "edition": edition or "openvas",
            "scanner_role": infer_scanner_role(sc),
            "configured": True,
            "status": {
                "status": "ok" if online else "offline",
                "transport": "edge_agent",
                "last_heartbeat_at": sc["last_heartbeat_at"].isoformat() if sc.get("last_heartbeat_at") else None,
                "message": "Edge agent heartbeat current" if online else "No recent laptop/appliance heartbeat",
            },
        }
    client = get_scanner_client(edition=edition, base_url=url or "", api_key_ref=(sc or {}).get("api_key_ref"))
    try:
        status = client.server_status()
        return {
            "ok": str(status.get("status") or "").lower() in {"ok", "ready"},
            "edition": edition,
            "scanner_role": infer_scanner_role(sc) if sc else None,
            "configured": client.configured,
            "status": status,
        }
    except NessusClientError as exc:
        return {"ok": False, "edition": edition, "error": str(exc), "configured": client.configured}


@router.get("/api/vuln/nessus/status")
def nessus_status(
    scanner_id: str | None = None,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("scan:admin")),
):
    """Legacy alias — prefer /api/vuln/scanner/status."""
    return scanner_status(scanner_id=scanner_id, db=db, current=current)
