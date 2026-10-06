"""Network-scoped browser scanner tokens (no laptop agent)."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.scanner_agent_auth import hash_agent_token, mint_agent_token, token_hint

TOKEN_TTL_DAYS = 7


class NetworkTokenError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def parse_cidr(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise NetworkTokenError("cidr_required", "Network CIDR is required")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise NetworkTokenError("invalid_cidr", "Enter a valid IPv4 or IPv6 CIDR (for example 203.0.113.0/24)") from exc


def target_in_cidr(target: str, cidr: str) -> bool:
    value = (target or "").strip()
    if not value or not cidr:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    try:
        return ipaddress.ip_address(value) in net
    except ValueError:
        pass
    try:
        other = ipaddress.ip_network(value, strict=False)
        return other.subnet_of(net)
    except ValueError:
        return False


def targets_outside_cidr(targets: list[str], cidr: str) -> list[str]:
    return [t for t in targets if t and not target_in_cidr(t, cidr)]


def ensure_network_tokens_table(db: Session) -> None:
    execute(
        db,
        """
        CREATE TABLE IF NOT EXISTS vuln_network_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            cidr TEXT NOT NULL,
            note TEXT,
            authorization_ref TEXT,
            token_hash TEXT NOT NULL UNIQUE,
            token_hint TEXT,
            status TEXT NOT NULL DEFAULT 'issued',
            connected_public_ip TEXT,
            connected_at TIMESTAMPTZ,
            connected_by UUID,
            created_by UUID,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
    )
    execute(db, "CREATE INDEX IF NOT EXISTS vuln_network_tokens_status_idx ON vuln_network_tokens (status)")
    execute(
        db,
        "CREATE INDEX IF NOT EXISTS vuln_network_tokens_connected_by_idx ON vuln_network_tokens (connected_by)",
    )
    db.flush()


def row_network_token(row: dict[str, Any] | None, *, token: str | None = None) -> dict[str, Any] | None:
    if not row:
        return None
    out = {
        "id": str(row["id"]),
        "name": row.get("name"),
        "cidr": row.get("cidr"),
        "note": row.get("note"),
        "authorization_ref": row.get("authorization_ref"),
        "token_hint": row.get("token_hint"),
        "status": row.get("status") or "issued",
        "connected_public_ip": row.get("connected_public_ip"),
        "connected_at": row["connected_at"].isoformat() if row.get("connected_at") else None,
        "connected_by": str(row["connected_by"]) if row.get("connected_by") else None,
        "created_by": str(row["created_by"]) if row.get("created_by") else None,
        "expires_at": row["expires_at"].isoformat() if row.get("expires_at") else None,
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
    }
    if token:
        out["token"] = token
        out["token_once"] = True
    return out


def _not_expired(row: dict[str, Any]) -> bool:
    expires = row.get("expires_at")
    if not expires:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > datetime.now(timezone.utc)


def list_network_tokens(db: Session) -> list[dict[str, Any]]:
    ensure_network_tokens_table(db)
    rows = fetchall(db, "SELECT * FROM vuln_network_tokens ORDER BY created_at DESC")
    return [row_network_token(r) for r in rows if r]


def mint_network_token(
    db: Session,
    *,
    name: str,
    cidr: str,
    note: str | None,
    authorization_ref: str | None,
    created_by: str | None,
) -> dict[str, Any]:
    ensure_network_tokens_table(db)
    label = (name or "").strip() or "Client network"
    network = parse_cidr(cidr)
    token = mint_agent_token()
    expires = datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS)
    row = fetchone(
        db,
        """INSERT INTO vuln_network_tokens
           (name, cidr, note, authorization_ref, token_hash, token_hint, status, created_by, expires_at)
           VALUES (:name, :cidr, :note, :authz, :th, :hint, 'issued', CAST(:uid AS uuid), :exp)
           RETURNING *""",
        {
            "name": label,
            "cidr": network,
            "note": (note or "").strip() or None,
            "authz": (authorization_ref or "").strip() or None,
            "th": hash_agent_token(token),
            "hint": token_hint(token),
            "uid": created_by if created_by else None,
            "exp": expires,
        },
    )
    db.commit()
    return row_network_token(row, token=token) or {}


def activate_network_token(
    db: Session,
    *,
    token: str,
    user_id: str | None,
    client_ip: str,
) -> dict[str, Any]:
    ensure_network_tokens_table(db)
    raw = (token or "").strip()
    if not raw:
        raise NetworkTokenError("token_required", "Scanner token is required")
    row = fetchone(
        db,
        "SELECT * FROM vuln_network_tokens WHERE token_hash = :th",
        {"th": hash_agent_token(raw)},
    )
    if not row:
        raise NetworkTokenError("invalid_token", "Scanner token is invalid")
    if (row.get("status") or "") == "revoked":
        raise NetworkTokenError("token_revoked", "This scanner token was revoked")
    if not _not_expired(row):
        raise NetworkTokenError("token_expired", "This scanner token has expired — request a new one")
    ip = (client_ip or "").strip() or None
    if ip and not target_in_cidr(ip, str(row.get("cidr") or "")):
        # Still connect: public egress may sit outside a declared site CIDR.
        # Launch still enforces target IPs against the CIDR.
        pass
    updated = fetchone(
        db,
        """UPDATE vuln_network_tokens
           SET status = 'connected',
               connected_public_ip = :ip,
               connected_at = NOW(),
               connected_by = CAST(:uid AS uuid),
               updated_at = NOW()
           WHERE id = CAST(:id AS uuid)
           RETURNING *""",
        {"ip": ip, "uid": user_id if user_id else None, "id": str(row["id"])},
    )
    db.commit()
    return row_network_token(updated) or {}


def session_for_user(db: Session, user_id: str | None) -> dict[str, Any] | None:
    ensure_network_tokens_table(db)
    if not user_id:
        return None
    row = fetchone(
        db,
        """SELECT * FROM vuln_network_tokens
           WHERE status = 'connected'
             AND connected_by = CAST(:uid AS uuid)
             AND (expires_at IS NULL OR expires_at > NOW())
           ORDER BY connected_at DESC NULLS LAST
           LIMIT 1""",
        {"uid": user_id},
    )
    return row_network_token(row)


def get_connected_token(db: Session, token_id: str) -> dict[str, Any] | None:
    ensure_network_tokens_table(db)
    row = fetchone(
        db,
        """SELECT * FROM vuln_network_tokens
           WHERE id = CAST(:id AS uuid)
             AND status = 'connected'
             AND (expires_at IS NULL OR expires_at > NOW())""",
        {"id": token_id},
    )
    return row_network_token(row)


def revoke_network_token(db: Session, token_id: str) -> dict[str, Any] | None:
    ensure_network_tokens_table(db)
    row = fetchone(
        db,
        """UPDATE vuln_network_tokens
           SET status = 'revoked', updated_at = NOW()
           WHERE id = CAST(:id AS uuid)
           RETURNING *""",
        {"id": token_id},
    )
    if not row:
        return None
    db.commit()
    return row_network_token(row)


def pick_central_scanner_id(db: Session) -> str | None:
    row = fetchone(
        db,
        """SELECT id FROM vuln_scanners
           WHERE lower(COALESCE(status, 'active')) = 'active'
             AND (
               lower(COALESCE(scanner_role, '')) = 'central'
               OR (
                 lower(COALESCE(connection_mode, 'gmp')) = 'gmp'
                 AND (
                   url IS NULL
                   OR url ILIKE 'unix://%'
                   OR url ILIKE '%gvmd%'
                 )
               )
             )
           ORDER BY name
           LIMIT 1""",
    )
    return str(row["id"]) if row and row.get("id") else None
