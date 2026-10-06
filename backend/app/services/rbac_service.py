from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.firm import FirmPermission, FirmRole, FirmRolePermission, FirmUser, FirmUserRole
from app.models.platform import PlatformPermission, PlatformRole, PlatformRolePermission, PlatformUser, PlatformUserRole


def get_platform_user_permissions(db: Session, user: PlatformUser) -> tuple[list[str], list[str]]:
    db.refresh(user, ["roles"])
    role_names: list[str] = []
    perm_codes: set[str] = set()
    for ur in user.roles:
        db.refresh(ur, ["role"])
        role = ur.role
        role_names.append(role.name)
        for rp in db.execute(
            select(PlatformRolePermission).where(PlatformRolePermission.role_id == role.id)
        ).scalars():
            perm = db.get(PlatformPermission, rp.permission_id)
            if perm:
                perm_codes.add(perm.code)
    return role_names, sorted(perm_codes)


def get_firm_user_permissions(db: Session, user: FirmUser) -> tuple[list[str], list[str]]:
    role_names: list[str] = []
    perm_codes: set[str] = set()
    for ur in db.execute(select(FirmUserRole).where(FirmUserRole.user_id == user.id)).scalars():
        role = db.get(FirmRole, ur.role_id)
        if not role:
            continue
        role_names.append(role.name)
        if role.name == "admin" and role.is_system:
            continue
        for rp in db.execute(
            select(FirmRolePermission).where(FirmRolePermission.role_id == role.id)
        ).scalars():
            perm = db.get(FirmPermission, rp.permission_id)
            if perm:
                perm_codes.add(perm.code)
    if "admin" in role_names:
        return role_names, ["*"]
    return role_names, sorted(perm_codes)


def user_has_permission(perms: list[str], required: str) -> bool:
    return "*" in perms or required in perms


def load_platform_user(db: Session, user_id) -> PlatformUser | None:
    return db.execute(
        select(PlatformUser)
        .where(PlatformUser.id == user_id)
        .options(selectinload(PlatformUser.roles).selectinload(PlatformUserRole.role))
    ).scalar_one_or_none()


def load_firm_user(db: Session, user_id) -> FirmUser | None:
    return db.get(FirmUser, user_id)


def role_to_dict(db: Session, role: FirmRole) -> dict:
    if role.is_system and role.name == "admin":
        return {
            "id": str(role.id),
            "name": role.name,
            "description": role.description,
            "is_system": role.is_system,
            "permissions": ["*"],
        }
    perm_codes: list[str] = []
    for rp in db.execute(select(FirmRolePermission).where(FirmRolePermission.role_id == role.id)).scalars():
        perm = db.get(FirmPermission, rp.permission_id)
        if perm:
            perm_codes.append(perm.code)
    return {
        "id": str(role.id),
        "name": role.name,
        "description": role.description,
        "is_system": role.is_system,
        "permissions": perm_codes,
    }
