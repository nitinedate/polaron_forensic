from fastapi import APIRouter, Depends, HTTPException
import re
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.tenant import Scope
from app.deps import CurrentUser, enrich_firm_context, get_current_user, get_db, resolve_tenant
from app.models.platform import Firm
from app.models.firm import FirmUser
from app.models.platform import PlatformUser
from app.schemas.iam import (
    ChangePasswordIn,
    ActivateAccountIn,
    ForgotPasswordIn,
    InviteStatusOut,
    LoginIn,
    RequestAccessTokenIn,
    TokenLoginIn,
    MfaRequired,
    MfaSetupConfirmIn,
    MfaVerifyIn,
    RefreshIn,
    ResetPasswordIn,
    TokenPair,
    TotpConfirmIn,
    TotpConfirmOut,
    TotpEnrollOut,
)
from app.services.auth_service import AuthService
from app.services.invite_service import (
    activate_firm_account,
    create_password_reset,
    get_invite_status,
    reset_password_with_token,
)
from app.services.email_service import EmailService
from app.services.client_access_token import mint_client_access_token, parse_and_verify, token_request_allowed
from app.services.security import validate_password, verify_password, hash_password

router = APIRouter(prefix="/api/auth", tags=["auth"])
auth_service = AuthService()
email_service = EmailService()


def _resolve_login_context(db: Session, tenant_slug: str):
    settings = get_settings()
    slug = tenant_slug.strip().lower()
    if slug in (settings.platform_tenant_slug, "platform"):
        db.execute(text("SET search_path TO public"))
        return Scope.PLATFORM, None
    firm = db.execute(select(Firm).where(Firm.slug == slug)).scalar_one_or_none()
    if not firm:
        raise HTTPException(status_code=401, detail={"error": {"code": "invalid_credentials", "message": "Invalid credentials"}})
    if firm.status != "active":
        raise HTTPException(status_code=403, detail={"error": {"code": "tenant_suspended", "message": "Organization is suspended"}})
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    return Scope.FIRM, firm.schema_name


@router.post("/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context

    tctx = get_tenant_context()
    tenant_slug = tctx.slug if tctx else get_settings().platform_tenant_slug
    try:
        scope, schema_name = _resolve_login_context(db, tenant_slug)
        result = auth_service.login(
            db,
            email=body.email,
            password=body.password,
            tenant_slug=tenant_slug if scope == Scope.PLATFORM else tenant_slug,
            scope=scope,
            schema_name=schema_name,
        )
        db.commit()
        if result.get("mfa_enrollment_required") or result.get("mfa_required"):
            return result
        return TokenPair(**result)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail={"error": {"code": "invalid_credentials", "message": str(exc)}})


@router.post("/request-access-token")
def request_access_token(body: RequestAccessTokenIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context

    tctx = get_tenant_context()
    tenant_slug = tctx.slug if tctx else get_settings().platform_tenant_slug
    email = (body.email or "").strip().lower()
    try:
        scope, schema_name = _resolve_login_context(db, tenant_slug)
        user = auth_service.find_active_user_for_access_token(
            db, email=email, scope=scope, schema_name=schema_name
        )
        if user and token_request_allowed(tenant_slug, email):
            token = mint_client_access_token(tenant_slug, email)
            email_service.send_access_token(email, token, tenant_slug)
    except HTTPException:
        pass
    except Exception:
        import logging

        logging.getLogger(__name__).exception(
            "request-access-token failed for tenant=%s email=%s",
            tenant_slug,
            email,
        )
        db.rollback()
    return {"ok": True}


@router.post("/token-login", response_model=TokenPair)
def token_login(body: TokenLoginIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context

    tctx = get_tenant_context()
    tenant_slug = tctx.slug if tctx else get_settings().platform_tenant_slug
    try:
        _tenant, email = parse_and_verify(body.token, tenant_slug)
        scope, schema_name = _resolve_login_context(db, tenant_slug)
        result = auth_service.login_with_client_token(
            db,
            email=email,
            tenant_slug=tenant_slug,
            scope=scope,
            schema_name=schema_name,
        )
        db.commit()
        return TokenPair(**result)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail={"error": {"code": "invalid_token", "message": str(exc)}})
    except HTTPException:
        db.rollback()
        raise


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context, Scope

    ctx = get_tenant_context()
    tenant_slug = ctx.slug if ctx else get_settings().platform_tenant_slug
    try:
        if ctx and ctx.scope == Scope.PLATFORM:
            db.execute(text("SET search_path TO public"))
            result = auth_service.refresh(db, refresh_token=body.refresh_token, tenant_slug=tenant_slug, scope=Scope.PLATFORM, schema_name=None)
        else:
            firm = db.execute(select(Firm).where(Firm.slug == tenant_slug)).scalar_one_or_none()
            if not firm:
                raise ValueError("Invalid refresh token")
            result = auth_service.refresh(
                db,
                refresh_token=body.refresh_token,
                tenant_slug=tenant_slug,
                scope=Scope.FIRM,
                schema_name=firm.schema_name,
            )
        db.commit()
        return TokenPair(**result)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail={"error": {"code": "invalid_token", "message": str(exc)}})


@router.post("/logout")
def logout(body: RefreshIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context

    ctx = get_tenant_context()
    tenant_slug = ctx.slug if ctx else get_settings().platform_tenant_slug
    try:
        if ctx and ctx.scope == Scope.PLATFORM:
            auth_service.logout(db, refresh_token=body.refresh_token, scope=Scope.PLATFORM, schema_name=None)
        else:
            firm = db.execute(select(Firm).where(Firm.slug == tenant_slug)).scalar_one_or_none()
            schema = firm.schema_name if firm else None
            auth_service.logout(db, refresh_token=body.refresh_token, scope=Scope.FIRM, schema_name=schema)
        db.commit()
    except Exception:
        db.rollback()
    return {"ok": True}


@router.post("/forgot-password")
def forgot_password(body: ForgotPasswordIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context

    ctx = get_tenant_context()
    tenant_slug = ctx.slug if ctx else get_settings().platform_tenant_slug
    scope = ctx.scope.value if ctx else Scope.PLATFORM.value
    try:
        if ctx and ctx.scope == Scope.PLATFORM:
            db.execute(text("SET search_path TO public"))
        else:
            firm = db.execute(select(Firm).where(Firm.slug == tenant_slug)).scalar_one_or_none()
            if firm:
                db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
                scope = Scope.FIRM.value
        create_password_reset(
            db,
            email=body.email,
            scope=scope,
            email_service=email_service,
            tenant_slug=tenant_slug,
        )
        db.commit()
    except Exception:
        db.rollback()
    return {"ok": True}


def _resolve_firm_reset_context(db: Session, tenant_slug: str):
    slug = tenant_slug.strip().lower()
    firm = db.execute(select(Firm).where(Firm.slug == slug)).scalar_one_or_none()
    if not firm:
        raise ValueError(f"Organization not found for slug: {slug}")
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    return firm, slug


@router.get("/invite/status", response_model=InviteStatusOut)
def invite_status(
    token: str,
    tenant: str,
    db: Session = Depends(get_db),
):
    db.execute(text("SET search_path TO public"))
    return InviteStatusOut(**get_invite_status(db, token=token, tenant_slug=tenant))


@router.post("/activate")
def activate_account(body: ActivateAccountIn, db: Session = Depends(get_db)):
    try:
        db.execute(text("SET search_path TO public"))
        result = activate_firm_account(
            db,
            token=body.token,
            new_password=body.new_password,
            tenant_slug=body.tenant,
            email_service=email_service,
        )
        db.commit()
        return {
            "ok": True,
            "email": result.email,
            "tenant": result.tenant_slug,
            "activated": True,
        }
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "activation_failed", "message": str(exc)}})


@router.post("/reset-password")
def reset_password(body: ResetPasswordIn, db: Session = Depends(get_db)):
    from app.db.tenant import get_tenant_context, Scope

    ctx = get_tenant_context()
    settings = get_settings()
    token = re.sub(r"\s+", "", body.token.strip())
    tenant_slug = (
        (body.tenant or "").strip().lower()
        or (ctx.slug if ctx else settings.platform_tenant_slug)
    )

    try:
        if tenant_slug in (settings.platform_tenant_slug, "platform"):
            db.execute(text("SET search_path TO public"))
            scope = Scope.PLATFORM.value
            tenant_slug = settings.platform_tenant_slug
        else:
            _resolve_firm_reset_context(db, tenant_slug)
            scope = Scope.FIRM.value

        reset_password_with_token(
            db,
            token=token,
            new_password=body.new_password,
            scope=scope,
            tenant_slug=tenant_slug,
            email_service=email_service,
        )
        db.commit()
        return {"ok": True}
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"error": {"code": "reset_failed", "message": str(exc)}})


@router.post("/mfa/verify", response_model=TokenPair)
def mfa_verify(body: MfaVerifyIn, db: Session = Depends(get_db)):
    try:
        result = auth_service.verify_mfa(db, mfa_token=body.mfa_token, code=body.code)
        db.commit()
        return TokenPair(**result)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail={"error": {"code": "mfa_failed", "message": str(exc)}})


@router.post("/mfa/totp/setup/confirm", response_model=TokenPair)
def mfa_setup_confirm(body: MfaSetupConfirmIn, db: Session = Depends(get_db)):
    """Confirm first-time TOTP enrollment during login and complete sign-in."""
    try:
        result = auth_service.confirm_totp_enrollment_login(
            db, mfa_token=body.mfa_token, code=body.code
        )
        db.commit()
        return TokenPair(**result)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=401, detail={"error": {"code": "mfa_setup_failed", "message": str(exc)}})


@router.post("/mfa/totp/enroll", response_model=TotpEnrollOut)
def mfa_enroll(current: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.scope == Scope.PLATFORM or current.is_tenant_admin():
        raise HTTPException(
            status_code=403,
            detail={"error": {"code": "mfa_not_allowed", "message": "MFA is not available for tenant administrators"}},
        )
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "Organization not found"}})
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.get(FirmUser, current.user_id)
    if not user:
        raise HTTPException(status_code=404, detail={"error": {"code": "not_found", "message": "User not found"}})
    result = auth_service.enroll_totp(db, user, current.email)
    db.commit()
    return TotpEnrollOut(**result)


@router.post("/mfa/totp/confirm", response_model=TotpConfirmOut)
def mfa_confirm(body: TotpConfirmIn, current: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.scope == Scope.PLATFORM:
        raise HTTPException(status_code=403, detail={"error": {"code": "forbidden", "message": "Not allowed"}})
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.get(FirmUser, current.user_id)
    codes = auth_service.confirm_totp(db, user, body.code)
    db.commit()
    return TotpConfirmOut(recovery_codes=codes)


@router.post("/mfa/disable")
def mfa_disable(current: CurrentUser = Depends(get_current_user), db: Session = Depends(get_db)):
    if current.scope == Scope.PLATFORM:
        raise HTTPException(status_code=403, detail={"error": {"code": "forbidden", "message": "Not allowed"}})
    firm = db.execute(select(Firm).where(Firm.slug == current.tenant)).scalar_one_or_none()
    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    user = db.get(FirmUser, current.user_id)
    auth_service.disable_mfa(db, user)
    db.commit()
    return {"ok": True}
