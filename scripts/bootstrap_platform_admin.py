"""Create or reset the platform Superadmin login (idempotent upsert)."""

from __future__ import annotations

import uuid
from pathlib import Path
import sys

backend_root = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_root))

from sqlalchemy import select

from app.config import get_settings
from app.db.session import SessionLocal
from app.models.platform import (
    PlatformPermission,
    PlatformRole,
    PlatformRolePermission,
    PlatformUser,
    PlatformUserRole,
)
from app.services.permissions_catalog import PLATFORM_PERMISSIONS
from app.services.security import hash_password, validate_password

SUPERADMIN_USER_ID = uuid.UUID("a0000000-0000-4000-8000-000000000001")
SUPERADMIN_ROLE_ID = uuid.UUID("a0000000-0000-4000-8000-000000000010")
LEGACY_ADMIN_EMAILS = ("admin@platform.test",)
# Documented installer password (README / 036 seed). Policy requires uppercase for
# user-chosen passwords; this seed is accepted so boot does not warn every start.
DOCUMENTED_PLATFORM_PASSWORD = "admin@123456789"


def seed_platform_rbac(db) -> PlatformRole:
    perm_by_code: dict[str, PlatformPermission] = {}
    for code, resource, action, description in PLATFORM_PERMISSIONS:
        existing = db.execute(select(PlatformPermission).where(PlatformPermission.code == code)).scalar_one_or_none()
        if existing:
            perm_by_code[code] = existing
            continue
        perm = PlatformPermission(code=code, resource=resource, action=action, description=description)
        db.add(perm)
        db.flush()
        perm_by_code[code] = perm

    role = db.execute(select(PlatformRole).where(PlatformRole.name == "superadmin")).scalar_one_or_none()
    if not role:
        legacy = db.execute(select(PlatformRole).where(PlatformRole.name == "tenant_admin")).scalar_one_or_none()
        if legacy:
            legacy.name = "superadmin"
            legacy.description = "Platform super administrator — provisions firms and firm admins"
            db.flush()
            role = legacy
        else:
            role = PlatformRole(
                id=SUPERADMIN_ROLE_ID,
                name="superadmin",
                description="Platform super administrator — provisions firms and firm admins",
                is_system=True,
            )
            db.add(role)
            db.flush()
    for code, *_ in PLATFORM_PERMISSIONS:
        perm = perm_by_code[code]
        link = db.execute(
            select(PlatformRolePermission).where(
                PlatformRolePermission.role_id == role.id,
                PlatformRolePermission.permission_id == perm.id,
            )
        ).scalar_one_or_none()
        if not link:
            db.add(PlatformRolePermission(role_id=role.id, permission_id=perm.id))
    return role


def _find_user(db, email: str) -> PlatformUser | None:
    user = db.execute(select(PlatformUser).where(PlatformUser.email == email)).scalar_one_or_none()
    if user:
        return user
    user = db.get(PlatformUser, SUPERADMIN_USER_ID)
    if user:
        return user
    for legacy in LEGACY_ADMIN_EMAILS:
        if legacy == email:
            continue
        user = db.execute(select(PlatformUser).where(PlatformUser.email == legacy)).scalar_one_or_none()
        if user:
            return user
    return None


def main() -> None:
    settings = get_settings()
    email = (settings.platform_admin_email or "").strip().lower()
    password = settings.platform_admin_password or ""

    db = SessionLocal()
    try:
        role = seed_platform_rbac(db)
        user = _find_user(db, email)
        created = user is None
        password_ok = True
        try:
            if password != DOCUMENTED_PLATFORM_PASSWORD:
                validate_password(password)
        except ValueError as exc:
            password_ok = False
            if user:
                print(f"warn: {exc} Keeping the existing SQL-seeded Superadmin password.")
            else:
                raise SystemExit(str(exc)) from exc

        if user:
            if password_ok:
                user.email = email or user.email
                user.password_hash = hash_password(password)
            user.status = "active"
            user.is_email_verified = True
            user.mfa_enabled = False
            if not user.profile:
                user.profile = {
                    "first_name": "Platform",
                    "last_name": "Superadmin",
                    "locale": "en",
                    "timezone": "UTC",
                }
        else:
            user = PlatformUser(
                id=SUPERADMIN_USER_ID,
                email=email,
                password_hash=hash_password(password),
                status="active",
                is_email_verified=True,
                mfa_enabled=False,
                profile={"first_name": "Platform", "last_name": "Superadmin", "locale": "en", "timezone": "UTC"},
            )
            db.add(user)
            db.flush()

        assigned = db.execute(
            select(PlatformUserRole).where(
                PlatformUserRole.user_id == user.id,
                PlatformUserRole.role_id == role.id,
            )
        ).scalar_one_or_none()
        if not assigned:
            db.add(PlatformUserRole(user_id=user.id, role_id=role.id))

        db.commit()
        action = "Created" if created else "Updated"
        print(f"{action} platform superadmin: {email}")
        print(f"Login organization slug: {settings.platform_tenant_slug}")
    except Exception as exc:
        db.rollback()
        raise SystemExit(str(exc)) from exc
    finally:
        db.close()


if __name__ == "__main__":
    main()
