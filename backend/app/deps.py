from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import get_db
from app.db.tenant import Scope, TenantContext, get_tenant_context, set_tenant_context
from app.models.platform import Firm
from app.models.firm import FirmUser
from app.models.platform import PlatformUser
from app.services.rbac_service import user_has_permission
from app.services.security import decode_token

bearer = HTTPBearer(auto_error=False)


def resolve_tenant(slug: str | None) -> TenantContext:
    settings = get_settings()
    slug = (slug or settings.platform_tenant_slug).strip().lower()
    if slug == settings.platform_tenant_slug or slug == "platform":
        return TenantContext(slug=settings.platform_tenant_slug, scope=Scope.PLATFORM)
    return TenantContext(slug=slug, scope=Scope.FIRM)


async def tenant_middleware(request: Request, call_next):
    slug = request.headers.get("X-Tenant") or get_settings().platform_tenant_slug
    ctx = resolve_tenant(slug)
    set_tenant_context(ctx)
    try:
        response = await call_next(request)
        return response
    finally:
        set_tenant_context(None)


def enrich_firm_context(db: Session, ctx: TenantContext) -> TenantContext:
    if ctx.scope != Scope.FIRM:
        return ctx
    firm = db.execute(select(Firm).where(Firm.slug == ctx.slug)).scalar_one_or_none()
    if not firm:
        raise HTTPException(status_code=404, detail={"error": {"code": "tenant_not_found", "message": "Organization not found"}})
    if firm.status != "active":
        raise HTTPException(status_code=403, detail={"error": {"code": "tenant_suspended", "message": "Organization is suspended"}})
    ctx.schema_name = firm.schema_name
    ctx.firm_id = str(firm.id)
    ctx.firm_status = firm.status
    return ctx


class CurrentUser:
    def __init__(
        self,
        user_id: str,
        email: str,
        roles: list[str],
        perms: list[str],
        scope: Scope,
        tenant: str,
        schema_name: str | None = None,
    ):
        self.user_id = user_id
        self.email = email
        self.roles = roles
        self.perms = perms
        self.scope = scope
        self.tenant = tenant
        self.schema_name = schema_name

    def require_perm(self, perm: str) -> None:
        if not user_has_permission(self.perms, perm):
            raise HTTPException(
                status_code=403,
                detail={"error": {"code": "forbidden", "message": f"Missing permission: {perm}"}},
            )

    def is_tenant_admin(self) -> bool:
        return any(r in self.roles for r in ("superadmin", "tenant_admin", "super_admin"))

    def is_firm_admin(self) -> bool:
        return self.scope == Scope.FIRM and "admin" in self.roles

    def is_platform(self) -> bool:
        return self.scope == Scope.PLATFORM


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    x_tenant: Annotated[str | None, Header(alias="X-Tenant")] = None,
) -> CurrentUser:
    if not creds:
        raise HTTPException(status_code=401, detail={"error": {"code": "unauthorized", "message": "Authentication required"}})
    try:
        payload = decode_token(creds.credentials, expected_type="access")
    except ValueError:
        raise HTTPException(status_code=401, detail={"error": {"code": "unauthorized", "message": "Invalid token"}})

    settings = get_settings()
    tenant_header = (x_tenant or settings.platform_tenant_slug).strip().lower()
    token_tenant = payload.get("tenant", settings.platform_tenant_slug)
    if token_tenant != tenant_header and not (
        tenant_header in (settings.platform_tenant_slug, "platform") and payload.get("scope") == Scope.PLATFORM.value
    ):
        raise HTTPException(status_code=403, detail={"error": {"code": "tenant_mismatch", "message": "Tenant mismatch"}})

    scope = Scope(payload.get("scope", Scope.FIRM.value))
    return CurrentUser(
        user_id=payload["sub"],
        email=payload.get("email", ""),
        roles=payload.get("roles", []),
        perms=payload.get("perms", []),
        scope=scope,
        tenant=token_tenant,
    )


def require_platform(current: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
    if current.scope != Scope.PLATFORM:
        raise HTTPException(status_code=403, detail={"error": {"code": "forbidden", "message": "Platform access only"}})
    return current


def optional_platform_db(
    db: Annotated[Session, Depends(get_db)],
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> Session:
    if current.scope == Scope.PLATFORM:
        db.execute(text("SET search_path TO public"))
    return db


def require_firm(current: Annotated[CurrentUser, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]) -> CurrentUser:
    if current.scope != Scope.FIRM:
        raise HTTPException(status_code=403, detail={"error": {"code": "forbidden", "message": "Firm access only"}})
    ctx = enrich_firm_context(db, TenantContext(slug=current.tenant, scope=Scope.FIRM))
    set_tenant_context(ctx)
    from app.db.session import bind_firm_schema

    bind_firm_schema(db, ctx.schema_name)
    current.schema_name = ctx.schema_name
    return current


def firm_db(db: Annotated[Session, Depends(get_db)], current: Annotated[CurrentUser, Depends(require_firm)]) -> Session:
    # require_firm already set search_path; re-assert in case of pooled connection reuse.
    if current.schema_name:
        from app.db.session import apply_firm_search_path

        apply_firm_search_path(db, current.schema_name)
    return db


def require_firm_permission(perm: str):
    def _dep(current: Annotated[CurrentUser, Depends(require_firm)]) -> CurrentUser:
        current.require_perm(perm)
        return current

    return _dep


def require_firm_permission_released(perm: str):
    """Auth + permission check, then release the DB connection before the route runs.

    Use on long I/O routes (evidence upload) so a 4GB file does not hold a pool slot.
    """

    def _dep(current: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if current.scope != Scope.FIRM:
            raise HTTPException(status_code=403, detail={"error": {"code": "forbidden", "message": "Firm access only"}})
        current.require_perm(perm)
        db = SessionLocal_for_brief()
        try:
            ctx = enrich_firm_context(db, TenantContext(slug=current.tenant, scope=Scope.FIRM))
            set_tenant_context(ctx)
            current.schema_name = ctx.schema_name
        finally:
            db.close()
        return current

    return _dep


def SessionLocal_for_brief():
    from app.db.session import SessionLocal

    return SessionLocal()


def platform_db(db: Annotated[Session, Depends(get_db)], current: Annotated[CurrentUser, Depends(require_platform)]) -> Session:
    db.execute(text("SET search_path TO public"))
    return db
