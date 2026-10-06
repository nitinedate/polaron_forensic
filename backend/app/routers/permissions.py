from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm
from app.models.firm import FirmPermission
from app.schemas.iam import CreatePermissionIn, PermissionOut

router = APIRouter(prefix="/api/permissions", tags=["permissions"])


@router.get("", response_model=list[PermissionOut])
def list_permissions(db: Session = Depends(firm_db), current: CurrentUser = Depends(require_firm)):
    current.require_perm("permission:read")
    perms = db.execute(select(FirmPermission).order_by(FirmPermission.resource, FirmPermission.action)).scalars().all()
    return [
        PermissionOut(
            id=str(p.id),
            code=p.code,
            resource=p.resource,
            action=p.action,
            description=p.description,
        )
        for p in perms
    ]


@router.post("", response_model=PermissionOut)
def create_permission(
    body: CreatePermissionIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("role:manage")
    existing = db.execute(select(FirmPermission).where(FirmPermission.code == body.code)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail={"error": {"code": "duplicate", "message": "Permission already exists"}})
    perm = FirmPermission(
        code=body.code,
        resource=body.resource,
        action=body.action,
        description=body.description,
    )
    db.add(perm)
    db.flush()
    from app.services.firm_rbac_sync import grant_permission_to_admin

    grant_permission_to_admin(db, perm.id)
    db.commit()
    return PermissionOut(
        id=str(perm.id),
        code=perm.code,
        resource=perm.resource,
        action=perm.action,
        description=perm.description,
    )
