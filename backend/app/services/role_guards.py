"""Firm role assignment guards shared by invite and authz flows."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.firm import FirmRole

RESERVED_FIRM_ROLE_NAMES = frozenset({"superadmin", "tenant_admin", "super_admin"})


def load_assignable_roles(db: Session, role_ids: list[str]) -> list[FirmRole]:
    if not role_ids:
        raise ValueError("At least one role is required")
    roles = db.execute(select(FirmRole).where(FirmRole.id.in_(role_ids))).scalars().all()
    if len(roles) != len(set(role_ids)):
        raise ValueError("One or more roles are invalid")
    blocked = [r.name for r in roles if r.name in RESERVED_FIRM_ROLE_NAMES]
    if blocked:
        raise ValueError("Cannot assign platform-level roles")
    return roles
