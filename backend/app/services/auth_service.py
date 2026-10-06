import base64
import io
import secrets
import uuid
from datetime import datetime, timezone

import pyotp
import qrcode
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.tenant import Scope
from app.models.firm import (
    FirmMfaRecoveryCode,
    FirmMfaTotp,
    FirmRefreshToken,
    FirmUser,
)
from app.models.platform import PlatformRefreshToken, PlatformUser
from app.services.rbac_service import get_firm_user_permissions, get_platform_user_permissions
from app.services.security import (
    create_access_token,
    create_mfa_token,
    decode_token,
    generate_token,
    hash_password,
    hash_token,
    normalize_totp_code,
    refresh_expires_at,
    verify_password,
)


class AuthService:
    def login(
        self,
        db: Session,
        *,
        email: str,
        password: str,
        tenant_slug: str,
        scope: Scope,
        schema_name: str | None = None,
    ) -> dict:
        email = email.lower()
        if scope == Scope.PLATFORM:
            user = db.execute(select(PlatformUser).where(PlatformUser.email == email)).scalar_one_or_none()
            if not user or user.status == "disabled":
                raise ValueError("Invalid credentials")
            if not verify_password(password, user.password_hash):
                raise ValueError("Invalid credentials")
            roles, perms = get_platform_user_permissions(db, user)
            if user.mfa_enabled:
                mfa_token = create_mfa_token(subject=str(user.id), tenant=tenant_slug, scope=scope.value)
                return {"mfa_required": True, "mfa_token": mfa_token, "methods": ["totp"]}
            return self._issue_platform_tokens(db, user, roles, perms, tenant_slug)

        if not schema_name:
            raise ValueError("Invalid tenant")
        db.execute(text(f'SET search_path TO "{schema_name}", public'))
        user = db.execute(select(FirmUser).where(FirmUser.email == email)).scalar_one_or_none()
        if not user or user.status in ("disabled", "locked"):
            raise ValueError("Invalid credentials")
        if user.status == "pending":
            raise ValueError("Account pending activation. Check your invite email.")
        if not verify_password(password, user.password_hash):
            raise ValueError("Invalid credentials")
        roles, perms = get_firm_user_permissions(db, user)
        if user.mfa_enabled:
            mfa_token = create_mfa_token(subject=str(user.id), tenant=tenant_slug, scope=scope.value)
            totp_row = db.get(FirmMfaTotp, user.id)
            if not totp_row or not totp_row.confirmed:
                enroll = self.enroll_totp(db, user, user.email)
                return {
                    "mfa_enrollment_required": True,
                    "mfa_token": mfa_token,
                    **enroll,
                }
            return {"mfa_required": True, "mfa_token": mfa_token, "methods": ["totp"]}
        user.last_login_at = datetime.now(timezone.utc)
        db.flush()
        return self._issue_firm_tokens(db, user, roles, perms, tenant_slug, schema_name)

    def login_with_client_token(
        self,
        db: Session,
        *,
        email: str,
        tenant_slug: str,
        scope: Scope,
        schema_name: str | None = None,
    ) -> dict:
        """Issue a session from the emailed HMAC token. MFA is skipped (email is the second factor)."""
        email = email.lower()
        if scope == Scope.PLATFORM:
            user = db.execute(select(PlatformUser).where(PlatformUser.email == email)).scalar_one_or_none()
            if not user or user.status in ("disabled", "pending"):
                raise ValueError("Invalid credentials")
            roles, perms = get_platform_user_permissions(db, user)
            return self._issue_platform_tokens(db, user, roles, perms, tenant_slug)

        if not schema_name:
            raise ValueError("Invalid tenant")
        db.execute(text(f'SET search_path TO "{schema_name}", public'))
        user = db.execute(select(FirmUser).where(FirmUser.email == email)).scalar_one_or_none()
        if not user or user.status in ("disabled", "locked"):
            raise ValueError("Invalid credentials")
        if user.status == "pending":
            raise ValueError("Account pending activation. Check your invite email.")
        roles, perms = get_firm_user_permissions(db, user)
        user.last_login_at = datetime.now(timezone.utc)
        db.flush()
        return self._issue_firm_tokens(db, user, roles, perms, tenant_slug, schema_name)

    def find_active_user_for_access_token(
        self,
        db: Session,
        *,
        email: str,
        scope: Scope,
        schema_name: str | None = None,
    ):
        email = email.lower()
        if scope == Scope.PLATFORM:
            user = db.execute(select(PlatformUser).where(PlatformUser.email == email)).scalar_one_or_none()
            if not user or user.status in ("disabled", "pending"):
                return None
            return user
        if not schema_name:
            return None
        db.execute(text(f'SET search_path TO "{schema_name}", public'))
        user = db.execute(select(FirmUser).where(FirmUser.email == email)).scalar_one_or_none()
        if not user or user.status != "active":
            return None
        return user

    def verify_mfa(self, db: Session, *, mfa_token: str, code: str) -> dict:
        payload = decode_token(mfa_token, expected_type="mfa")
        scope = payload.get("scope")
        tenant = payload.get("tenant")
        user_id = payload.get("sub")
        normalized = normalize_totp_code(code)
        if not normalized:
            raise ValueError("Invalid verification code")

        if scope == Scope.PLATFORM.value:
            user = db.get(PlatformUser, user_id)
            if not user:
                raise ValueError("Invalid MFA session")
            raise ValueError("MFA is not available for platform administrators")

        from app.models.platform import Firm

        firm = db.execute(select(Firm).where(Firm.slug == tenant)).scalar_one_or_none()
        if not firm:
            raise ValueError("Invalid MFA session")
        db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
        try:
            uid = uuid.UUID(str(user_id))
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid MFA session") from exc
        user = db.get(FirmUser, uid)
        if not user:
            raise ValueError("Invalid MFA session")
        totp_row = db.get(FirmMfaTotp, uid)
        if not totp_row or not totp_row.confirmed:
            raise ValueError("MFA not configured")
        totp = pyotp.TOTP(totp_row.secret)
        if not totp.verify(normalized, valid_window=2):
            raise ValueError("Invalid verification code")
        roles, perms = get_firm_user_permissions(db, user)
        user.last_login_at = datetime.now(timezone.utc)
        db.flush()
        return self._issue_firm_tokens(db, user, roles, perms, tenant, firm.schema_name)

    def refresh(self, db: Session, *, refresh_token: str, tenant_slug: str, scope: Scope, schema_name: str | None) -> dict:
        token_hash = hash_token(refresh_token)
        now = datetime.now(timezone.utc)

        if scope == Scope.PLATFORM:
            row = db.execute(
                select(PlatformRefreshToken).where(
                    PlatformRefreshToken.token_hash == token_hash,
                    PlatformRefreshToken.revoked_at.is_(None),
                )
            ).scalar_one_or_none()
            if not row or row.expires_at < now:
                raise ValueError("Invalid refresh token")
            user = db.get(PlatformUser, row.user_id)
            if not user:
                raise ValueError("Invalid refresh token")
            row.revoked_at = now
            roles, perms = get_platform_user_permissions(db, user)
            return self._issue_platform_tokens(db, user, roles, perms, tenant_slug)

        if not schema_name:
            raise ValueError("Invalid tenant")
        db.execute(text(f'SET search_path TO "{schema_name}", public'))
        row = db.execute(
            select(FirmRefreshToken).where(
                FirmRefreshToken.token_hash == token_hash,
                FirmRefreshToken.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        if not row or row.expires_at < now:
            raise ValueError("Invalid refresh token")
        user = db.get(FirmUser, row.user_id)
        if not user:
            raise ValueError("Invalid refresh token")
        row.revoked_at = now
        roles, perms = get_firm_user_permissions(db, user)
        return self._issue_firm_tokens(db, user, roles, perms, tenant_slug, schema_name)

    def logout(self, db: Session, *, refresh_token: str, scope: Scope, schema_name: str | None) -> None:
        token_hash = hash_token(refresh_token)
        now = datetime.now(timezone.utc)
        if scope == Scope.PLATFORM:
            row = db.execute(
                select(PlatformRefreshToken).where(PlatformRefreshToken.token_hash == token_hash)
            ).scalar_one_or_none()
            if row:
                row.revoked_at = now
            return
        if schema_name:
            db.execute(text(f'SET search_path TO "{schema_name}", public'))
        row = db.execute(
            select(FirmRefreshToken).where(FirmRefreshToken.token_hash == token_hash)
        ).scalar_one_or_none()
        if row:
            row.revoked_at = now

    def enroll_totp(self, db: Session, user: FirmUser, email: str) -> dict:
        existing = db.get(FirmMfaTotp, user.id)
        if existing and not existing.confirmed:
            secret = existing.secret
        else:
            secret = pyotp.random_base32()
            if existing:
                existing.secret = secret
                existing.confirmed = False
            else:
                db.add(FirmMfaTotp(user_id=user.id, secret=secret, confirmed=False))
            db.flush()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=email, issuer_name="Forensic Automation")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return {
            "secret": secret,
            "otpauth_uri": uri,
            "qr_png_base64": base64.b64encode(buf.getvalue()).decode(),
        }

    def confirm_totp(self, db: Session, user: FirmUser, code: str) -> list[str]:
        row = db.get(FirmMfaTotp, user.id)
        if not row:
            raise ValueError("Enrollment not started")
        normalized = normalize_totp_code(code)
        if not normalized:
            raise ValueError("Invalid verification code")
        totp = pyotp.TOTP(row.secret)
        if not totp.verify(normalized, valid_window=2):
            raise ValueError("Invalid verification code")
        row.confirmed = True
        user.mfa_enabled = True
        db.execute(
            text("DELETE FROM mfa_recovery_codes WHERE user_id = :uid"),
            {"uid": str(user.id)},
        )
        codes = [secrets.token_hex(4) for _ in range(8)]
        for c in codes:
            db.add(FirmMfaRecoveryCode(user_id=user.id, code_hash=hash_token(c)))
        db.flush()
        return codes

    def confirm_totp_enrollment_login(
        self, db: Session, *, mfa_token: str, code: str
    ) -> dict:
        """Complete first-time MFA setup during login and issue session tokens."""
        payload = decode_token(mfa_token, expected_type="mfa")
        if payload.get("scope") != Scope.FIRM.value:
            raise ValueError("Invalid MFA session")
        tenant = payload.get("tenant")
        user_id = payload.get("sub")
        from app.models.platform import Firm

        firm = db.execute(select(Firm).where(Firm.slug == tenant)).scalar_one_or_none()
        if not firm:
            raise ValueError("Invalid MFA session")
        db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
        user = db.get(FirmUser, user_id)
        if not user:
            raise ValueError("Invalid MFA session")
        self.confirm_totp(db, user, code)
        roles, perms = get_firm_user_permissions(db, user)
        user.last_login_at = datetime.now(timezone.utc)
        db.flush()
        return self._issue_firm_tokens(db, user, roles, perms, tenant, firm.schema_name)

    def disable_mfa(self, db: Session, user: FirmUser) -> None:
        self.set_user_mfa_enabled(db, user, False)

    def set_user_mfa_enabled(self, db: Session, user: FirmUser, enabled: bool) -> None:
        user.mfa_enabled = enabled
        if not enabled:
            row = db.get(FirmMfaTotp, user.id)
            if row:
                db.delete(row)
            db.execute(text("DELETE FROM mfa_recovery_codes WHERE user_id = :uid"), {"uid": str(user.id)})
        db.flush()

    def _issue_platform_tokens(
        self, db: Session, user: PlatformUser, roles: list[str], perms: list[str], tenant: str
    ) -> dict:
        settings = get_settings()
        access = create_access_token(
            subject=str(user.id),
            email=user.email,
            roles=roles,
            perms=perms,
            tenant=tenant,
            scope=Scope.PLATFORM.value,
        )
        refresh = generate_token()
        db.add(
            PlatformRefreshToken(
                user_id=user.id,
                token_hash=hash_token(refresh),
                expires_at=refresh_expires_at(),
            )
        )
        user.last_login_at = datetime.now(timezone.utc)
        db.flush()
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_ttl_minutes * 60,
        }

    def _issue_firm_tokens(
        self,
        db: Session,
        user: FirmUser,
        roles: list[str],
        perms: list[str],
        tenant: str,
        schema_name: str,
    ) -> dict:
        settings = get_settings()
        access = create_access_token(
            subject=str(user.id),
            email=user.email,
            roles=roles,
            perms=perms,
            tenant=tenant,
            scope=Scope.FIRM.value,
        )
        refresh = generate_token()
        db.add(
            FirmRefreshToken(
                user_id=user.id,
                token_hash=hash_token(refresh),
                expires_at=refresh_expires_at(),
            )
        )
        db.flush()
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_ttl_minutes * 60,
        }
