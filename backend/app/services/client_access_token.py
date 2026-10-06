"""Reusable HMAC access token emailed to the user. Same string on all 3 products."""

from __future__ import annotations

import hashlib
import hmac
import re

from app.config import Settings, get_settings

TOKEN_PREFIX = "ath1"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def normalize_tenant(tenant: str) -> str:
    return (tenant or "").strip().lower()


def resolved_client_token_secret(settings: Settings | None = None) -> str:
    cfg = settings or get_settings()
    raw = (cfg.client_token_secret or cfg.jwt_secret or "").strip()
    return raw or "dev-secret-change-in-production"


def _mac(tenant: str, email: str, settings: Settings | None = None) -> str:
    msg = f"{normalize_tenant(tenant)}\n{normalize_email(email)}".encode("utf-8")
    return hmac.new(resolved_client_token_secret(settings).encode("utf-8"), msg, hashlib.sha256).hexdigest()


def mint_client_access_token(tenant: str, email: str, settings: Settings | None = None) -> str:
    tenant_n = normalize_tenant(tenant)
    email_n = normalize_email(email)
    if not tenant_n:
        raise ValueError("tenant is required")
    if not EMAIL_RE.match(email_n):
        raise ValueError("email is required")
    return f"{TOKEN_PREFIX}.{tenant_n}.{email_n}.{_mac(tenant_n, email_n, settings)}"


def parse_and_verify(token: str, expected_tenant: str, settings: Settings | None = None) -> tuple[str, str]:
    """Return (tenant, email) if the token is valid for expected_tenant."""
    raw = (token or "").strip()
    parts = raw.split(".")
    if len(parts) < 4 or parts[0] != TOKEN_PREFIX:
        raise ValueError("Invalid access token")
    tenant = normalize_tenant(parts[1])
    digest = parts[-1].lower()
    email = normalize_email(".".join(parts[2:-1]))
    want_tenant = normalize_tenant(expected_tenant)
    if not tenant or tenant != want_tenant:
        raise ValueError("Invalid access token")
    if not EMAIL_RE.match(email) or len(digest) != 64:
        raise ValueError("Invalid access token")
    expected = _mac(tenant, email, settings)
    if not hmac.compare_digest(digest, expected):
        raise ValueError("Invalid access token")
    return tenant, email


def token_request_allowed(tenant: str, email: str, cooldown_sec: int = 60) -> bool:
    """True when this address may receive another email. Fail-open if Redis is down."""
    key = f"client-access-token:{normalize_tenant(tenant)}:{normalize_email(email)}"
    try:
        from app.services.job_locks import _redis_client

        client = _redis_client()
        if client.get(key):
            return False
        client.set(key, "1", ex=max(1, cooldown_sec), nx=True)
        return True
    except Exception:
        return True
