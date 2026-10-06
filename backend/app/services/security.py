import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import Settings, get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$"
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str | None) -> bool:
    if not hashed:
        return False
    return pwd_context.verify(plain, hashed)


def validate_password(password: str) -> None:
    if not PASSWORD_PATTERN.match(password):
        raise ValueError(
            "Password must be at least 12 characters with upper, lower, digit, and symbol."
        )


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def normalize_totp_code(code: str) -> str:
    """Strip spaces/dashes so '747 345' and '747345' both verify."""
    return re.sub(r"\D+", "", (code or "").strip())


def create_access_token(
    *,
    subject: str,
    email: str,
    roles: list[str],
    perms: list[str],
    tenant: str,
    scope: str,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_ttl_minutes)
    payload = {
        "sub": subject,
        "email": email,
        "roles": roles,
        "perms": perms,
        "tenant": tenant,
        "scope": scope,
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def create_mfa_token(*, subject: str, tenant: str, scope: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {
        "sub": subject,
        "tenant": tenant,
        "scope": scope,
        "exp": expire,
        "type": "mfa",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str, expected_type: str | None = None) -> dict:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError as exc:
        raise ValueError("Invalid token") from exc
    if expected_type and payload.get("type") != expected_type:
        raise ValueError("Invalid token type")
    return payload


def refresh_expires_at(settings: Settings | None = None) -> datetime:
    """Return refresh-token expiry.

    JWT_REFRESH_TTL_DAYS=0 means no application-configured idle/session expiry.
    PostgreSQL still requires a concrete timestamp, so use Python's safe far-future
    value. Explicit logout/revocation remains authoritative.
    """
    settings = settings or get_settings()
    days = int(settings.jwt_refresh_ttl_days or 0)
    if days <= 0:
        return datetime.max.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) + timedelta(days=days)


def reset_expires_at(hours: int = 24) -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=hours)


def invite_expires_at(days: int = 7) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def create_invite_token(*, user_id: str, tenant: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    payload = {
        "sub": user_id,
        "tenant": tenant,
        "type": "invite",
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_invite_token(token: str) -> dict:
    payload = decode_token(token, expected_type="invite")
    return payload
