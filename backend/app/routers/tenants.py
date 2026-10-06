from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.deps import CurrentUser, platform_db, require_platform
from app.models.platform import AuditLog, Firm
from app.schemas.iam import (
    CreatePermissionIn,
    CreateRoleIn,
    CreateTenantIn,
    CreateTenantUserIn,
    PermissionOut,
    RoleOut,
    TenantDetailOut,
    TenantOut,
    TenantUserOut,
    UpdateRoleIn,
    UpdateTenantIn,
    UpdateTenantUserIn,
    Profile,
)
from app.services.email_service import EmailService
from app.services.firm_iam_admin import (
    create_firm_permission,
    create_firm_role,
    delete_firm_role,
    list_firm_permissions,
    list_firm_roles,
    update_firm_role,
)
from app.services.firm_user_admin import (
    deactivate_firm_user,
    get_firm_or_raise,
    invite_firm_admin,
    list_firm_users,
    resend_firm_user_invite,
    update_firm_user,
)
from app.services.tenant_provisioner import destroy_firm, provision_firm
from app.models.firm import FirmUser
from app.services.invite_service import resend_firm_invite

router = APIRouter(prefix="/api/tenants", tags=["tenants"])
email_service = EmailService()


def firm_to_out(f: Firm) -> TenantOut:
    return TenantOut(
        id=str(f.id),
        name=f.name,
        slug=f.slug,
        schema_name=f.schema_name,
        status=f.status,
        plan=f.plan,
        primary_host=f.primary_host,
        created_at=f.created_at,
    )


def get_firm_admin(db: Session, schema_name: str) -> tuple[str | None, str | None]:
    row = db.execute(
        text(
            f"""
            SELECT u.email, u.status
            FROM "{schema_name}".users u
            JOIN "{schema_name}".user_roles ur ON ur.user_id = u.id
            JOIN "{schema_name}".roles r ON r.id = ur.role_id
            WHERE r.name = 'admin'
            ORDER BY u.created_at ASC
            LIMIT 1
            """
        )
    ).first()
    if not row:
        return None, None
    return row.email, row.status


def firm_to_detail(db: Session, f: Firm) -> TenantDetailOut:
    admin_email, admin_status = get_firm_admin(db, f.schema_name)
    base = firm_to_out(f)
    return TenantDetailOut(**base.model_dump(), admin_email=admin_email, admin_status=admin_status)

@router.get("", response_model=list[TenantOut])
def list_tenants(
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firms = db.execute(select(Firm).order_by(Firm.created_at.desc())).scalars().all()
    return [firm_to_out(f) for f in firms]


@router.get("/{firm_id}", response_model=TenantDetailOut)
def get_tenant(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})
    return firm_to_detail(db, firm)


@router.patch("/{firm_id}", response_model=TenantDetailOut)
def update_tenant(
    firm_id: str,
    body: UpdateTenantIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})

    changes: dict[str, str | None] = {}
    if body.name is not None and body.name.strip() and body.name.strip() != firm.name:
        firm.name = body.name.strip()
        changes["name"] = firm.name
    if body.plan is not None and body.plan.strip() and body.plan.strip() != firm.plan:
        firm.plan = body.plan.strip()
        changes["plan"] = firm.plan
    if body.primary_host is not None and body.primary_host != firm.primary_host:
        firm.primary_host = body.primary_host.strip() or None
        changes["primary_host"] = firm.primary_host

    if changes:
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.updated",
                resource_type="firm",
                resource_id=str(firm.id),
                details=changes,
            )
        )
    db.commit()
    db.refresh(firm)
    return firm_to_detail(db, firm)


@router.post("", response_model=TenantOut)
def create_tenant(
    body: CreateTenantIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    if not body.admin_email:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "validation", "message": "admin_email is required to invite the firm administrator"}},
        )
    try:
        firm = provision_firm(
            db,
            name=body.name,
            slug=body.slug,
            plan=body.plan,
            primary_host=body.primary_host,
            admin_email=str(body.admin_email),
            email_service=email_service,
            actor_id=current.user_id,
            send_invite=body.send_invite,
        )
        db.commit()
        return firm_to_out(firm)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "provision_failed", "message": str(exc)}})


@router.post("/{firm_id}/suspend", response_model=TenantOut)
def suspend_tenant(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})
    firm.status = "suspended"
    db.add(
        AuditLog(
            scope="platform",
            tenant_slug=firm.slug,
            actor_id=current.user_id,
            action="firm.suspended",
            resource_type="firm",
            resource_id=str(firm.id),
        )
    )
    db.commit()
    return firm_to_out(firm)


@router.post("/{firm_id}/activate", response_model=TenantOut)
def activate_tenant(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})
    firm.status = "active"
    db.add(
        AuditLog(
            scope="platform",
            tenant_slug=firm.slug,
            actor_id=current.user_id,
            action="firm.activated",
            resource_type="firm",
            resource_id=str(firm.id),
        )
    )
    db.commit()
    return firm_to_out(firm)


@router.delete("/{firm_id}")
def delete_tenant(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})

    snapshot = {
        "name": firm.name,
        "slug": firm.slug,
        "schema_name": firm.schema_name,
    }
    destroy_firm(db, firm)
    db.add(
        AuditLog(
            scope="platform",
            tenant_slug=snapshot["slug"],
            actor_id=current.user_id,
            action="firm.deleted",
            resource_type="firm",
            resource_id=firm_id,
            details=snapshot,
        )
    )
    db.commit()
    return {"ok": True}


@router.post("/{firm_id}/resend-admin-invite")
def resend_admin_invite(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})

    admin_email, admin_status = get_firm_admin(db, firm.schema_name)
    if not admin_email:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "not_found", "message": "No firm administrator found"}},
        )
    if admin_status != "pending":
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "validation", "message": "Firm administrator has already activated their account"}},
        )

    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.execute(select(FirmUser).where(FirmUser.email == admin_email)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "not_found", "message": "Firm administrator user not found"}},
        )

    try:
        resend_firm_invite(
            db,
            user,
            invited_by=current.user_id,
            email_service=email_service,
            firm_slug=firm.slug,
            is_admin=True,
        )
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.admin_invite_resent",
                resource_type="firm",
                resource_id=str(firm.id),
                details={"admin_email": admin_email},
            )
        )
        db.commit()
        return {"ok": True}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "invite_failed", "message": str(exc)}})


def _tenant_user_out(row: dict) -> TenantUserOut:
    profile = row.get("profile") or {}
    return TenantUserOut(
        id=row["id"],
        email=row["email"],
        status=row["status"],
        mfa_enabled=row["mfa_enabled"],
        is_email_verified=row["is_email_verified"],
        created_at=row["created_at"],
        roles=row.get("roles") or [],
        profile=Profile(
            first_name=profile.get("first_name"),
            last_name=profile.get("last_name"),
            phone=profile.get("phone"),
            avatar_url=profile.get("avatar_url"),
            locale=profile.get("locale", "en"),
            timezone=profile.get("timezone", "UTC"),
        ),
    )


@router.get("/{firm_id}/users", response_model=list[TenantUserOut])
def list_tenant_users(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})
    rows = list_firm_users(db, firm)
    return [_tenant_user_out(r) for r in rows]


@router.post("/{firm_id}/users", response_model=TenantUserOut)
def create_tenant_admin_user(
    firm_id: str,
    body: CreateTenantUserIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    """Superadmin: invite a firm administrator (admin role only, MFA on by default)."""
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        profile = body.profile.model_dump() if body.profile else None
        user = invite_firm_admin(
            db,
            firm,
            email=str(body.email),
            invited_by=current.user_id,
            email_service=email_service,
            profile=profile,
            mfa_enabled=body.mfa_enabled,
        )
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.admin_invited",
                resource_type="user",
                resource_id=str(user.id),
                details={"email": user.email},
            )
        )
        db.commit()
        rows = list_firm_users(db, firm)
        match = next((r for r in rows if r["id"] == str(user.id)), None)
        if match:
            return _tenant_user_out(match)
        return TenantUserOut(
            id=str(user.id),
            email=user.email,
            status=user.status,
            mfa_enabled=user.mfa_enabled,
            is_email_verified=user.is_email_verified,
            created_at=user.created_at,
            roles=["admin"],
            profile=body.profile,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "create_failed", "message": str(exc)}})


@router.patch("/{firm_id}/users/{user_id}", response_model=TenantUserOut)
def update_tenant_user(
    firm_id: str,
    user_id: str,
    body: UpdateTenantUserIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        profile = body.profile.model_dump(exclude_none=True) if body.profile else None
        update_firm_user(
            db,
            firm,
            user_id,
            status=body.status,
            mfa_enabled=body.mfa_enabled,
            profile=profile,
        )
        db.commit()
        rows = list_firm_users(db, firm)
        match = next((r for r in rows if r["id"] == user_id), None)
        if not match:
            raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
        return _tenant_user_out(match)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "update_failed", "message": str(exc)}})


@router.delete("/{firm_id}/users/{user_id}")
def deactivate_tenant_user(
    firm_id: str,
    user_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        deactivate_firm_user(db, firm, user_id)
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.user_deactivated",
                resource_type="user",
                resource_id=user_id,
            )
        )
        db.commit()
        return {"ok": True}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "deactivate_failed", "message": str(exc)}})


@router.post("/{firm_id}/users/{user_id}/invite")
def resend_tenant_user_invite(
    firm_id: str,
    user_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        resend_firm_user_invite(
            db,
            firm,
            user_id,
            invited_by=current.user_id,
            email_service=email_service,
        )
        db.commit()
        return {"ok": True}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "invite_failed", "message": str(exc)}})


@router.get("/{firm_id}/roles", response_model=list[RoleOut])
def list_tenant_roles(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})
    return [RoleOut(**r) for r in list_firm_roles(db, firm)]


@router.post("/{firm_id}/roles", response_model=RoleOut)
def create_tenant_role(
    firm_id: str,
    body: CreateRoleIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        role = create_firm_role(
            db,
            firm,
            name=body.name,
            description=body.description,
            permission_codes=body.permission_codes,
        )
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.role_created",
                resource_type="role",
                resource_id=str(role.id),
                details={"name": role.name},
            )
        )
        db.commit()
        rows = list_firm_roles(db, firm)
        match = next((r for r in rows if r["id"] == str(role.id)), None)
        if not match:
            raise HTTPException(status_code=500, detail={"error": {"code": "internal", "message": "Role created but not found"}})
        return RoleOut(**match)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "create_failed", "message": str(exc)}})


@router.patch("/{firm_id}/roles/{role_id}", response_model=RoleOut)
def update_tenant_role(
    firm_id: str,
    role_id: str,
    body: UpdateRoleIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        update_firm_role(
            db,
            firm,
            role_id,
            description=body.description,
            permission_codes=body.permission_codes,
        )
        db.commit()
        rows = list_firm_roles(db, firm)
        match = next((r for r in rows if r["id"] == role_id), None)
        if not match:
            raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Role not found"}})
        return RoleOut(**match)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "update_failed", "message": str(exc)}})


@router.delete("/{firm_id}/roles/{role_id}")
def delete_tenant_role(
    firm_id: str,
    role_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        delete_firm_role(db, firm, role_id)
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.role_deleted",
                resource_type="role",
                resource_id=role_id,
            )
        )
        db.commit()
        return {"ok": True}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "delete_failed", "message": str(exc)}})


@router.get("/{firm_id}/permissions", response_model=list[PermissionOut])
def list_tenant_permissions(
    firm_id: str,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    firm = db.get(Firm, firm_id)
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Firm not found"}})
    perms = list_firm_permissions(db, firm)
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


@router.post("/{firm_id}/permissions", response_model=PermissionOut)
def create_tenant_permission(
    firm_id: str,
    body: CreatePermissionIn,
    db: Session = Depends(platform_db),
    current: CurrentUser = Depends(require_platform),
):
    current.require_perm("tenant:manage")
    try:
        firm = get_firm_or_raise(db, firm_id)
        perm = create_firm_permission(
            db,
            firm,
            code=body.code,
            resource=body.resource,
            action=body.action,
            description=body.description,
        )
        db.add(
            AuditLog(
                scope="platform",
                tenant_slug=firm.slug,
                actor_id=current.user_id,
                action="firm.permission_created",
                resource_type="permission",
                resource_id=str(perm.id),
                details={"code": perm.code},
            )
        )
        db.commit()
        return PermissionOut(
            id=str(perm.id),
            code=perm.code,
            resource=perm.resource,
            action=perm.action,
            description=perm.description,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "create_failed", "message": str(exc)}})
