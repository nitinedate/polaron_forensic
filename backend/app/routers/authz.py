from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm
from app.models.firm import FirmRole, FirmUser, FirmUserRole
from app.schemas.iam import AssignRoleIn, RoleOut
from app.services.rbac_service import role_to_dict
from app.services.role_guards import RESERVED_FIRM_ROLE_NAMES

router = APIRouter(prefix="/api/authz", tags=["authz"])


@router.get("/users/{user_id}/roles", response_model=list[RoleOut])
def list_user_roles(
    user_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:update")
    user = db.get(FirmUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
    rows = db.execute(select(FirmUserRole).where(FirmUserRole.user_id == user.id)).scalars().all()
    roles = [db.get(FirmRole, r.role_id) for r in rows]
    return [RoleOut(**role_to_dict(db, r)) for r in roles if r]


@router.post("/users/{user_id}/roles")
def assign_role(
    user_id: str,
    body: AssignRoleIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:update")
    user = db.get(FirmUser, user_id)
    role = db.get(FirmRole, body.role_id)
    if not user or not role:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User or role not found"}})
    if role.name in RESERVED_FIRM_ROLE_NAMES:
        raise HTTPException(status_code=400, detail={"error": {"code": "forbidden", "message": "Invalid role"}})
    existing = db.execute(
        select(FirmUserRole).where(FirmUserRole.user_id == user.id, FirmUserRole.role_id == role.id)
    ).scalar_one_or_none()
    if existing:
        return {"ok": True}
    db.add(FirmUserRole(user_id=user.id, role_id=role.id))
    db.commit()
    return {"ok": True}


@router.delete("/users/{user_id}/roles/{role_id}")
def remove_role(
    user_id: str,
    role_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:update")
    row = db.execute(
        select(FirmUserRole).where(FirmUserRole.user_id == user_id, FirmUserRole.role_id == role_id)
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Assignment not found"}})
    role = db.get(FirmRole, role_id)
    if role and role.name == "admin":
        admin_count = db.execute(
            select(FirmUserRole)
            .join(FirmRole, FirmRole.id == FirmUserRole.role_id)
            .where(FirmRole.name == "admin")
        ).scalars().all()
        if len(admin_count) <= 1:
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "forbidden", "message": "Cannot remove the last firm administrator"}},
            )
    db.delete(row)
    db.commit()
    return {"ok": True}
