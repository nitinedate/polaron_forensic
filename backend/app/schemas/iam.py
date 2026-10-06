from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


class Profile(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    avatar_url: str | None = None
    locale: str = "en"
    timezone: str = "UTC"


class UserOut(BaseModel):
    id: str
    email: str
    username: str | None = None
    status: str
    is_email_verified: bool
    mfa_enabled: bool
    last_login_at: datetime | None = None
    created_at: datetime
    profile: Profile | None = None


class UserListOut(BaseModel):
    items: list[UserOut]
    total: int
    page: int
    page_size: int


class PermissionOut(BaseModel):
    id: str
    code: str
    resource: str
    action: str
    description: str | None = None


class RoleOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    is_system: bool
    permissions: list[str]


class TenantOut(BaseModel):
    id: str
    name: str
    slug: str
    schema_name: str
    status: str
    plan: str
    primary_host: str | None = None
    created_at: datetime


class TenantDetailOut(TenantOut):
    admin_email: str | None = None
    admin_status: str | None = None


class UpdateTenantIn(BaseModel):
    name: str | None = None
    plan: str | None = None
    primary_host: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaRequired(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    methods: list[str]


class MfaEnrollmentRequired(BaseModel):
    mfa_enrollment_required: bool = True
    mfa_token: str
    secret: str
    otpauth_uri: str
    qr_png_base64: str


class MfaSetupConfirmIn(BaseModel):
    mfa_token: str
    code: str


class LoginIn(BaseModel):
    email: str
    password: str


class RequestAccessTokenIn(BaseModel):
    email: str


class TokenLoginIn(BaseModel):
    token: str


class RefreshIn(BaseModel):
    refresh_token: str


class MfaVerifyIn(BaseModel):
    mfa_token: str
    code: str


class ForgotPasswordIn(BaseModel):
    email: str


class ResetPasswordIn(BaseModel):
    token: str
    new_password: str
    tenant: str | None = None


class ActivateAccountIn(BaseModel):
    token: str
    new_password: str
    tenant: str


class InviteStatusOut(BaseModel):
    valid: bool
    email: str | None = None
    tenant_slug: str | None = None
    tenant_name: str | None = None
    role: str | None = None
    is_admin: bool = False
    expires_at: datetime | None = None
    message: str | None = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class CreateTenantIn(BaseModel):
    name: str
    slug: str
    plan: str = "standard"
    primary_host: str | None = None
    admin_email: str | None = None
    admin_password: str | None = None  # ignored; invite flow only
    send_invite: bool = True


class CreateUserIn(BaseModel):
    email: str
    password: str | None = None  # ignored; invite flow
    status: str | None = "pending"
    profile: Profile | None = None
    role_ids: list[str] = Field(default_factory=list)
    mfa_enabled: bool = True


class UpdateUserIn(BaseModel):
    status: str | None = None
    profile: Profile | None = None
    mfa_enabled: bool | None = None


class TenantUserOut(BaseModel):
    id: str
    email: str
    status: str
    mfa_enabled: bool
    is_email_verified: bool
    created_at: datetime
    roles: list[str] = Field(default_factory=list)
    profile: Profile | None = None


class CreateTenantUserIn(BaseModel):
    email: str
    profile: Profile | None = None
    mfa_enabled: bool = True


class UpdateTenantUserIn(BaseModel):
    status: str | None = None
    mfa_enabled: bool | None = None
    profile: Profile | None = None


class UpdateMeIn(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None


class CreateRoleIn(BaseModel):
    name: str
    description: str | None = None
    permission_codes: list[str] = Field(default_factory=list)


class UpdateRoleIn(BaseModel):
    description: str | None = None
    permission_codes: list[str] | None = None


class CreatePermissionIn(BaseModel):
    code: str
    resource: str
    action: str
    description: str | None = None


class AssignRoleIn(BaseModel):
    role_id: str


class TotpEnrollOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_png_base64: str


class TotpConfirmIn(BaseModel):
    code: str


class TotpConfirmOut(BaseModel):
    recovery_codes: list[str]
