"""Keep firm permission catalog and admin role grants in sync with permissions_catalog.py."""

from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.firm import FirmPermission, FirmRole, FirmRolePermission
from app.models.platform import Firm
from app.services.permissions_catalog import FIRM_PERMISSIONS

ADMIN_ROLE_NAME = "admin"
USER_ROLE_NAME = "user"


def grant_all_permissions_to_admin(db: Session, admin_role: FirmRole) -> None:
    """Grant every permission in the firm schema to the admin role (including custom permissions)."""
    existing = {
        rp.permission_id
        for rp in db.execute(
            select(FirmRolePermission).where(FirmRolePermission.role_id == admin_role.id)
        ).scalars()
    }
    for perm in db.execute(select(FirmPermission)).scalars():
        if perm.id not in existing:
            db.add(FirmRolePermission(role_id=admin_role.id, permission_id=perm.id))


def grant_permission_to_admin(db: Session, permission_id) -> None:
    admin_role = db.execute(
        select(FirmRole).where(FirmRole.name == ADMIN_ROLE_NAME)
    ).scalar_one_or_none()
    if not admin_role:
        return
    exists = db.execute(
        select(FirmRolePermission).where(
            FirmRolePermission.role_id == admin_role.id,
            FirmRolePermission.permission_id == permission_id,
        )
    ).scalar_one_or_none()
    if exists:
        return
    db.add(FirmRolePermission(role_id=admin_role.id, permission_id=permission_id))


def sync_firm_rbac(db: Session, schema_name: str) -> dict[str, FirmRole]:
    """Upsert firm permissions and grant every permission to the admin role."""
    db.execute(text(f'SET search_path TO "{schema_name}", public'))

    perm_by_code: dict[str, FirmPermission] = {}
    for code, resource, action, description in FIRM_PERMISSIONS:
        perm = db.execute(select(FirmPermission).where(FirmPermission.code == code)).scalar_one_or_none()
        if not perm:
            perm = FirmPermission(code=code, resource=resource, action=action, description=description)
            db.add(perm)
            db.flush()
        elif perm.description != description:
            perm.description = description
        perm_by_code[code] = perm

    roles: dict[str, FirmRole] = {}
    for name, desc, is_system in (
        (ADMIN_ROLE_NAME, "Firm administrator — full organization access", True),
        (USER_ROLE_NAME, "Standard firm user — profile and security settings only", True),
    ):
        role = db.execute(select(FirmRole).where(FirmRole.name == name)).scalar_one_or_none()
        if not role:
            role = FirmRole(name=name, description=desc, is_system=is_system)
            db.add(role)
            db.flush()
        elif role.description != desc:
            role.description = desc
        roles[name] = role

    grant_all_permissions_to_admin(db, roles[ADMIN_ROLE_NAME])

    user_role = roles[USER_ROLE_NAME]
    db.execute(
        FirmRolePermission.__table__.delete().where(FirmRolePermission.role_id == user_role.id)
    )

    db.flush()
    return roles


def sync_all_firm_rbac(db: Session) -> int:
    firms = db.execute(select(Firm).order_by(Firm.slug)).scalars().all()
    for firm in firms:
        sync_firm_rbac(db, firm.schema_name)
    db.flush()
    return len(firms)
