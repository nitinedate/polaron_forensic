"""Authenticate on-site scanner agents via bearer token + X-Tenant."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, apply_firm_search_path, bind_firm_schema
from app.db.sql_helpers import fetchone
from app.models.platform import Firm

bearer = HTTPBearer(auto_error=False)

EDGE_AGENT_URL = "agent://local"
CONNECTION_MODE_EDGE = "edge_agent"
CONNECTION_MODE_GMP = "gmp"


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_agent_token() -> str:
    return secrets.token_urlsafe(32)


def token_hint(token: str) -> str:
    return token[-4:] if len(token) >= 4 else token


def is_edge_agent_scanner(row: dict[str, Any] | None) -> bool:
    if not row:
        return False
    mode = str(row.get("connection_mode") or CONNECTION_MODE_GMP).strip().lower()
    if mode == CONNECTION_MODE_EDGE:
        return True
    url = str(row.get("url") or "").strip().lower()
    return url.startswith("agent://")


@dataclass
class EdgeAgentContext:
    firm_slug: str
    schema_name: str
    scanner_id: str
    scanner_name: str
    scanner: dict[str, Any]


def resolve_firm_schema(db: Session, tenant_slug: str) -> tuple[str, str]:
    slug = (tenant_slug or "").strip().lower()
    if not slug:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "tenant_required", "message": "X-Tenant header is required"}},
        )
    firm = db.execute(select(Firm).where(Firm.slug == slug)).scalar_one_or_none()
    if not firm:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "tenant_not_found", "message": "Organization not found"}},
        )
    if firm.status != "active":
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "tenant_suspended", "message": "Organization is suspended"}},
        )
    return slug, firm.schema_name


def get_edge_agent(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    x_tenant: str | None = Header(default=None, alias="X-Tenant"),
) -> EdgeAgentContext:
    if not creds or not creds.credentials:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "unauthorized", "message": "Agent bearer token required"}},
        )
    db = SessionLocal()
    try:
        db.execute(text("SET search_path TO public"))
        firm_slug, schema_name = resolve_firm_schema(db, x_tenant or "")
        bind_firm_schema(db, schema_name)
        apply_firm_search_path(db, schema_name)
        token_hash = hash_agent_token(creds.credentials)
        row = fetchone(
            db,
            """SELECT * FROM vuln_scanners
               WHERE agent_token_hash = :th
                 AND lower(coalesce(connection_mode, 'gmp')) = :mode
                 AND lower(status) = 'active'
               LIMIT 1""",
            {"th": token_hash, "mode": CONNECTION_MODE_EDGE},
        )
        if not row:
            raise HTTPException(
                status_code=401,
                detail={"error": {"code": "unauthorized", "message": "Invalid agent token"}},
            )
        return EdgeAgentContext(
            firm_slug=firm_slug,
            schema_name=schema_name,
            scanner_id=str(row["id"]),
            scanner_name=str(row.get("name") or ""),
            scanner=dict(row),
        )
    finally:
        db.close()
