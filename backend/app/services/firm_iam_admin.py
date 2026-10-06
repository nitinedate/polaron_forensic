"""Platform superadmin operations on roles and permissions inside a firm schema."""

from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.firm import FirmPermission, FirmRole, FirmRolePermission
from app.models.platform import Firm
from app.services.firm_rbac_sync import grant_permission_to_admin
from app.services.rbac_service import role_to_dict

RESERVED_ROLE_NAMES = frozenset({"admin", "user", "superadmin", "tenant_admin", "super_admin"})


def _set_schema(db: Session, schema_name: str) -> None:
    db.execute(text(f'SET search_path TO "{schema_name}", public'))


def list_firm_roles(db: Session, firm: Firm) -> list[dict]:
    _set_schema(db, firm.schema_name)
    roles = db.execute(select(FirmRole).order_by(FirmRole.name)).scalars().all()
    return [role_to_dict(db, r) for r in roles]


def create_firm_role(
    db: Session,
    firm: Firm,
    *,
    name: str,
    description: str | None,
    permission_codes: list[str],
) -> FirmRole:
    if name in RESERVED_ROLE_NAMES:
        raise ValueError("Reserved role name")
    _set_schema(db, firm.schema_name)
    existing = db.execute(select(FirmRole).where(FirmRole.name == name)).scalar_one_or_none()
    if existing:
        raise ValueError("Role already exists")
    role = FirmRole(name=name, description=description, is_system=False)
    db.add(role)
    db.flush()
    perms = db.execute(select(FirmPermission).where(FirmPermission.code.in_(permission_codes))).scalars().all()
    for perm in perms:
        db.add(FirmRolePermission(role_id=role.id, permission_id=perm.id))
    db.flush()
    return role


def update_firm_role(
    db: Session,
    firm: Firm,
    role_id: str,
    *,
    description: str | None = None,
    permission_codes: list[str] | None = None,
) -> FirmRole:
    _set_schema(db, firm.schema_name)
    role = db.get(FirmRole, role_id)
    if not role:
        raise ValueError("Role not found")
    if description is not None:
        role.description = description
    if permission_codes is not None and not role.is_system:
        db.execute(FirmRolePermission.__table__.delete().where(FirmRolePermission.role_id == role.id))
        perms = db.execute(select(FirmPermission).where(FirmPermission.code.in_(permission_codes))).scalars().all()
        for perm in perms:
            db.add(FirmRolePermission(role_id=role.id, permission_id=perm.id))
    db.flush()
    return role


def delete_firm_role(db: Session, firm: Firm, role_id: str) -> None:
    _set_schema(db, firm.schema_name)
    role = db.get(FirmRole, role_id)
    if not role:
        raise ValueError("Role not found")
    if role.is_system:
        raise ValueError("Cannot delete system role")
    db.delete(role)
    db.flush()


def list_firm_permissions(db: Session, firm: Firm) -> list[FirmPermission]:
    _set_schema(db, firm.schema_name)
    return db.execute(
        select(FirmPermission).order_by(FirmPermission.resource, FirmPermission.action)
    ).scalars().all()


def create_firm_permission(
    db: Session,
    firm: Firm,
    *,
    code: str,
    resource: str,
    action: str,
    description: str | None,
) -> FirmPermission:
    _set_schema(db, firm.schema_name)
    existing = db.execute(select(FirmPermission).where(FirmPermission.code == code)).scalar_one_or_none()
    if existing:
        raise ValueError("Permission already exists")
    perm = FirmPermission(code=code, resource=resource, action=action, description=description)
    db.add(perm)
    db.flush()
    grant_permission_to_admin(db, perm.id)
    db.flush()
    return perm
