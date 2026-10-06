from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm
from app.models.firm import FirmPermission, FirmRole, FirmRolePermission
from app.models.platform import AuditLog
from app.schemas.iam import CreateRoleIn, RoleOut, UpdateRoleIn
from app.services.rbac_service import role_to_dict

router = APIRouter(prefix="/api/roles", tags=["roles"])


@router.get("", response_model=list[RoleOut])
def list_roles(db: Session = Depends(firm_db), current: CurrentUser = Depends(require_firm)):
    current.require_perm("role:read")
    roles = db.execute(select(FirmRole).order_by(FirmRole.name)).scalars().all()
    return [RoleOut(**role_to_dict(db, r)) for r in roles]


@router.post("", response_model=RoleOut)
def create_role(
    body: CreateRoleIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("role:manage")
    if body.name in ("admin", "user", "superadmin", "tenant_admin", "super_admin"):
        raise HTTPException(status_code=400, detail={"error": {"code": "validation", "message": "Reserved role name"}})
    existing = db.execute(select(FirmRole).where(FirmRole.name == body.name)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail={"error": {"code": "duplicate", "message": "Role already exists"}})
    role = FirmRole(name=body.name, description=body.description, is_system=False)
    db.add(role)
    db.flush()
    perms = db.execute(select(FirmPermission).where(FirmPermission.code.in_(body.permission_codes))).scalars().all()
    for p in perms:
        db.add(FirmRolePermission(role_id=role.id, permission_id=p.id))
    db.add(
        AuditLog(
            scope="firm",
            tenant_slug=current.tenant,
            actor_id=current.user_id,
            action="role.created",
            resource_type="role",
            resource_id=str(role.id),
        )
    )
    db.commit()
    return RoleOut(**role_to_dict(db, role))


@router.patch("/{role_id}", response_model=RoleOut)
def update_role(
    role_id: str,
    body: UpdateRoleIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("role:manage")
    role = db.get(FirmRole, role_id)
    if not role:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Role not found"}})
    if body.description is not None:
        role.description = body.description
    if body.permission_codes is not None and not role.is_system:
        db.execute(
            FirmRolePermission.__table__.delete().where(FirmRolePermission.role_id == role.id)
        )
        perms = db.execute(select(FirmPermission).where(FirmPermission.code.in_(body.permission_codes))).scalars().all()
        for p in perms:
            db.add(FirmRolePermission(role_id=role.id, permission_id=p.id))
    db.commit()
    return RoleOut(**role_to_dict(db, role))


@router.delete("/{role_id}")
def delete_role(
    role_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("role:manage")
    role = db.get(FirmRole, role_id)
    if not role:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Role not found"}})
    if role.is_system:
        raise HTTPException(status_code=400, detail={"error": {"code": "forbidden", "message": "Cannot delete system role"}})
    db.delete(role)
    db.commit()
    return {"ok": True}
