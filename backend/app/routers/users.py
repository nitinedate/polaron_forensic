from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.db.tenant import Scope
from app.deps import CurrentUser, firm_db, get_current_user, get_db, require_firm
from app.models.firm import FirmUser
from app.models.platform import AuditLog, Firm, PlatformUser
from app.schemas.iam import (
    ChangePasswordIn,
    CreateUserIn,
    Profile,
    UpdateMeIn,
    UpdateUserIn,
    UserListOut,
    UserOut,
)
from app.services.email_service import EmailService
from app.services.auth_service import AuthService
from app.services.invite_service import invite_firm_user, resend_firm_invite
from app.services.role_guards import load_assignable_roles
from app.services.security import hash_password, validate_password, verify_password

router = APIRouter(prefix="/api/users", tags=["users"])
email_service = EmailService()
auth_service = AuthService()


def user_to_out(u: FirmUser) -> UserOut:
    profile = u.profile or {}
    return UserOut(
        id=str(u.id),
        email=u.email,
        username=u.username,
        status=u.status,
        is_email_verified=u.is_email_verified,
        mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at,
        created_at=u.created_at,
        profile=Profile(
            first_name=profile.get("first_name"),
            last_name=profile.get("last_name"),
            phone=profile.get("phone"),
            avatar_url=profile.get("avatar_url"),
            locale=profile.get("locale", "en"),
            timezone=profile.get("timezone", "UTC"),
        ),
    )


def platform_user_to_out(u: PlatformUser) -> UserOut:
    profile = u.profile or {}
    return UserOut(
        id=str(u.id),
        email=u.email,
        username=None,
        status=u.status,
        is_email_verified=u.is_email_verified,
        mfa_enabled=u.mfa_enabled,
        last_login_at=u.last_login_at,
        created_at=u.created_at,
        profile=Profile(
            first_name=profile.get("first_name"),
            last_name=profile.get("last_name"),
            phone=profile.get("phone"),
            avatar_url=profile.get("avatar_url"),
            locale=profile.get("locale", "en"),
            timezone=profile.get("timezone", "UTC"),
        ),
    )


@router.get("/me", response_model=UserOut)
def get_me(current: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.scope == Scope.PLATFORM:
        db.execute(text("SET search_path TO public"))
        user = db.get(PlatformUser, current.user_id)
        if not user:
            raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
        return platform_user_to_out(user)
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Organization not found"}})
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.get(FirmUser, current.user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
    return user_to_out(user)


@router.patch("/me", response_model=UserOut)
def update_me(
    body: UpdateMeIn,
    current: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current.scope == Scope.PLATFORM:
        db.execute(text("SET search_path TO public"))
        user = db.get(PlatformUser, current.user_id)
        profile = dict(user.profile or {})
        if body.first_name is not None:
            profile["first_name"] = body.first_name
        if body.last_name is not None:
            profile["last_name"] = body.last_name
        if body.phone is not None:
            profile["phone"] = body.phone
        user.profile = profile
        db.commit()
        return platform_user_to_out(user)
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.get(FirmUser, current.user_id)
    profile = dict(user.profile or {})
    if body.first_name is not None:
        profile["first_name"] = body.first_name
    if body.last_name is not None:
        profile["last_name"] = body.last_name
    if body.phone is not None:
        profile["phone"] = body.phone
    user.profile = profile
    db.commit()
    return user_to_out(user)


@router.post("/me/change-password")
def change_password_me(
    body: ChangePasswordIn,
    current: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current.scope == Scope.PLATFORM:
        db.execute(text("SET search_path TO public"))
        user = db.get(PlatformUser, current.user_id)
        if not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail={"error": {"code": "invalid_password", "message": "Current password is incorrect"}})
        try:
            validate_password(body.new_password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": {"code": "validation", "message": str(exc)}})
        user.password_hash = hash_password(body.new_password)
        db.commit()
        return {"ok": True}
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.get(FirmUser, current.user_id)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail={"error": {"code": "invalid_password", "message": "Current password is incorrect"}})
    try:
        validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": {"code": "validation", "message": str(exc)}})
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}


@router.get("", response_model=UserListOut)
def list_users(
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    search: str = Query(""),
):
    current.require_perm("user:read")
    q = select(FirmUser)
    if search.strip():
        like = f"%{search.strip()}%"
        q = q.where(or_(FirmUser.email.ilike(like), FirmUser.username.ilike(like)))
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    items = (
        db.execute(q.order_by(FirmUser.created_at.desc()).offset((page - 1) * page_size).limit(page_size))
        .scalars()
        .all()
    )
    return UserListOut(
        items=[user_to_out(u) for u in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=UserOut)
def create_user(
    body: CreateUserIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:create")
    profile = body.profile.model_dump() if body.profile else None
    try:
        load_assignable_roles(db, body.role_ids)
        user = invite_firm_user(
            db,
            email=str(body.email),
            role_ids=body.role_ids,
            invited_by=current.user_id,
            email_service=email_service,
            firm_slug=current.tenant,
            profile=profile,
            mfa_enabled=body.mfa_enabled,
        )
        db.add(
            AuditLog(
                scope="firm",
                tenant_slug=current.tenant,
                actor_id=current.user_id,
                action="user.invited",
                resource_type="user",
                resource_id=str(user.id),
            )
        )
        db.commit()
        return user_to_out(user)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "create_failed", "message": str(exc)}})


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UpdateUserIn,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:update")
    user = db.get(FirmUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
    if body.status is not None:
        user.status = body.status
    if body.profile is not None:
        profile = dict(user.profile or {})
        profile.update(body.profile.model_dump(exclude_none=True))
        user.profile = profile
    if body.mfa_enabled is not None:
        auth_service.set_user_mfa_enabled(db, user, body.mfa_enabled)
    db.commit()
    return user_to_out(user)


@router.delete("/{user_id}")
def deactivate_user(
    user_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:update")
    user = db.get(FirmUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
    user.status = "disabled"
    db.add(
        AuditLog(
            scope="firm",
            tenant_slug=current.tenant,
            actor_id=current.user_id,
            action="user.deactivated",
            resource_type="user",
            resource_id=str(user.id),
        )
    )
    db.commit()
    return {"ok": True}


@router.post("/{user_id}/invite")
def resend_invite(
    user_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm),
):
    current.require_perm("user:create")
    user = db.get(FirmUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
    try:
        resend_firm_invite(
            db,
            user,
            invited_by=current.user_id,
            email_service=email_service,
            firm_slug=current.tenant,
        )
        db.commit()
        return {"ok": True}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "invite_failed", "message": str(exc)}})
