"""Parse per-scanner credential refs for remote OpenVAS / Nessus."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.services.greenbone_gmp import is_local_gvmd_tcp_url, parse_socket_path

SCANNER_ROLE_PERSISTENT = "persistent_edge"
SCANNER_ROLE_PORTABLE = "portable"
SCANNER_ROLE_REMOTE_VPN = "remote_vpn"
SCANNER_ROLE_CENTRAL = "central"

SCANNER_ROLES = {
    SCANNER_ROLE_PERSISTENT,
    SCANNER_ROLE_PORTABLE,
    SCANNER_ROLE_REMOTE_VPN,
    SCANNER_ROLE_CENTRAL,
}
CUSTOMER_SCANNER_ROLES = {
    SCANNER_ROLE_PERSISTENT,
    SCANNER_ROLE_PORTABLE,
    SCANNER_ROLE_REMOTE_VPN,
}
EDGE_SCANNER_ROLES = {SCANNER_ROLE_PERSISTENT, SCANNER_ROLE_PORTABLE}
HEARTBEAT_STALE_SEC = 180


def is_edge_agent_scanner(row: dict[str, Any] | None = None, *, url: str | None = None, connection_mode: str | None = None) -> bool:
    """True when the scanner is an on-site agent (HTTPS poll), not GMP-driven from premise."""
    mode = ""
    raw_url = url
    if row:
        mode = str(row.get("connection_mode") or "").strip().lower()
        raw_url = raw_url if raw_url is not None else row.get("url")
    if connection_mode:
        mode = str(connection_mode).strip().lower()
    if mode == "edge_agent":
        return True
    return str(raw_url or "").strip().lower().startswith("agent://")


def is_remote_scanner_url(url: str | None) -> bool:
    """True when the scanner is not the local Compose gvmd socket/TCP alias."""
    raw = (url or "").strip()
    if not raw:
        return False
    if raw.lower().startswith("agent://"):
        return True
    if parse_socket_path(raw):
        return False
    if is_local_gvmd_tcp_url(raw):
        return False
    return True


def parse_gmp_credentials(api_key_ref: str | None) -> tuple[str | None, str | None]:
    """Return (username, password) from scanner.api_key_ref.

    Accepted formats:
    - ``username:password``
    - JSON ``{"username":"...","password":"..."}`` or ``{"user":"...","pass":"..."}``
    """
    raw = (api_key_ref or "").strip()
    if not raw:
        return None, None
    if raw.startswith("{"):
        try:
            data: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            return None, None
        user = data.get("username") or data.get("user") or data.get("gmp_username")
        password = data.get("password") or data.get("pass") or data.get("gmp_password")
        return (str(user) if user else None), (str(password) if password else None)
    if ":" in raw:
        user, password = raw.split(":", 1)
        user, password = user.strip(), password.strip()
        if user and password:
            return user, password
    return None, None


def normalize_scanner_url(url: str | None) -> str:
    """Ensure remote OpenVAS URLs have an explicit scheme for GMP TLS."""
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        # bare host:port → TLS GMP (Greenbone default 9390)
        return f"tls://{raw}"
    parsed = urlparse(raw if "://" in raw else f"tls://{raw}")
    scheme = (parsed.scheme or "").lower()
    if scheme in {"gmp", "http"}:
        host = parsed.hostname or "localhost"
        port = parsed.port or 9390
        return f"tls://{host}:{port}"
    return raw


def ensure_scanner_role_column(db) -> None:
    """Best-effort ADD COLUMN so existing firms work before migration 031."""
    try:
        from app.db.sql_helpers import execute

        execute(db, "ALTER TABLE vuln_scanners ADD COLUMN IF NOT EXISTS scanner_role TEXT")
        try:
            db.flush()
        except Exception:
            pass
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def connection_mode_for_role(role: str | None) -> str:
    if str(role or "").strip().lower() in EDGE_SCANNER_ROLES:
        return "edge_agent"
    return "gmp"


def infer_scanner_role(
    row: dict[str, Any] | None = None,
    *,
    url: str | None = None,
    connection_mode: str | None = None,
    scanner_role: str | None = None,
) -> str:
    """Resolve deployment class. Explicit column wins; otherwise infer."""
    explicit = str(scanner_role or (row or {}).get("scanner_role") or "").strip().lower()
    if explicit in SCANNER_ROLES:
        return explicit
    if is_edge_agent_scanner(row, url=url, connection_mode=connection_mode):
        return SCANNER_ROLE_PORTABLE
    raw_url = url if url is not None else (row or {}).get("url")
    if is_remote_scanner_url(raw_url) and not str(raw_url or "").strip().lower().startswith("agent://"):
        return SCANNER_ROLE_REMOTE_VPN
    return SCANNER_ROLE_CENTRAL


def scanner_heartbeat_online(row: dict[str, Any] | None, *, stale_sec: int = HEARTBEAT_STALE_SEC) -> bool | None:
    """True/False for edge roles; None when the scanner is GMP-driven (no laptop heartbeat)."""
    if not row:
        return None
    role = infer_scanner_role(row)
    if role not in EDGE_SCANNER_ROLES:
        return None
    hb = row.get("last_heartbeat_at")
    if not hb:
        return False
    if isinstance(hb, str):
        try:
            hb = datetime.fromisoformat(hb.replace("Z", "+00:00"))
        except ValueError:
            return False
    if getattr(hb, "tzinfo", None) is None:
        hb = hb.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - hb).total_seconds()
    return age <= max(30, int(stale_sec))
