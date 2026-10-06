import re
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.firm import FirmInvitation, FirmPasswordResetToken, FirmUser, FirmUserRole
from app.models.platform import Firm, PlatformPasswordResetToken, PlatformUser
from app.services.email_service import EmailService
from app.services.role_guards import load_assignable_roles
from app.services.security import (
    generate_token,
    hash_password,
    hash_token,
    invite_expires_at,
    reset_expires_at,
    validate_password,
)


@dataclass
class PasswordResetResult:
    email: str
    tenant_slug: str
    activated: bool


def get_invite_status(db: Session, *, token: str, tenant_slug: str) -> dict:
    tenant_slug = tenant_slug.strip().lower()
    token = re.sub(r"\s+", "", token.strip())
    if not token:
        return {"valid": False, "message": "Missing invitation token"}

    firm = db.execute(select(Firm).where(Firm.slug == tenant_slug)).scalar_one_or_none()
    if not firm:
        return {"valid": False, "message": "Organization not found"}

    if firm.status != "active":
        return {
            "valid": False,
            "message": "Organization is suspended",
            "tenant_slug": tenant_slug,
            "tenant_name": firm.name,
        }

    schema = firm.schema_name
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    row = db.execute(
        text(
            f"""
            SELECT u.email, u.status, i.expires_at,
                   COALESCE(string_agg(DISTINCT r.name, ', '), '') AS roles
            FROM "{schema}".invitations i
            JOIN "{schema}".users u ON u.id = i.user_id
            LEFT JOIN "{schema}".user_roles ur ON ur.user_id = u.id
            LEFT JOIN "{schema}".roles r ON r.id = ur.role_id
            WHERE (i.token_plain = :token OR i.token_hash = :token_hash)
              AND i.accepted_at IS NULL
            GROUP BY u.email, u.status, i.expires_at, i.created_at
            ORDER BY i.created_at DESC
            LIMIT 1
            """
        ),
        {"token": token, "token_hash": token_hash},
    ).first()

    base = {"tenant_slug": tenant_slug, "tenant_name": firm.name}

    if not row:
        return {
            **base,
            "valid": False,
            "message": "Invalid or already used invitation. Ask your administrator to resend the invite.",
        }

    if row.expires_at < now:
        return {
            **base,
            "valid": False,
            "message": "Invitation expired. Ask your administrator to resend the invite.",
            "email": row.email,
            "expires_at": row.expires_at,
        }

    if row.status == "active":
        return {
            **base,
            "valid": False,
            "message": "Account already activated. You can sign in.",
            "email": row.email,
        }

    roles = row.roles or ""
    return {
        **base,
        "valid": True,
        "email": row.email,
        "role": roles or None,
        "is_admin": "admin" in roles.split(", "),
        "expires_at": row.expires_at,
        "message": None,
    }


def invite_firm_user(
    db: Session,
    *,
    email: str,
    role_ids: list[str],
    invited_by,
    email_service: EmailService,
    firm_slug: str,
    profile: dict | None = None,
    mfa_enabled: bool = True,
) -> FirmUser:
    email = email.lower()
    existing = db.execute(select(FirmUser).where(FirmUser.email == email)).scalar_one_or_none()
    if existing:
        raise ValueError("A user with this email already exists")

    roles = load_assignable_roles(db, role_ids)

    user = FirmUser(
        email=email,
        status="pending",
        is_email_verified=False,
        mfa_enabled=mfa_enabled,
        profile=profile
        or {"first_name": None, "last_name": None, "phone": None, "locale": "en", "timezone": "UTC"},
    )
    db.add(user)
    db.flush()

    for role in roles:
        db.add(FirmUserRole(user_id=user.id, role_id=role.id))

    token = generate_token()
    db.add(
        FirmInvitation(
            user_id=user.id,
            email=email,
            token_hash=hash_token(token),
            token_plain=token,
            expires_at=invite_expires_at(),
            invited_by=invited_by,
        )
    )
    db.flush()
    email_service.send_invite(email, token, firm_slug, is_admin=False)
    return user


def resend_firm_invite(
    db: Session,
    user: FirmUser,
    *,
    invited_by,
    email_service: EmailService,
    firm_slug: str,
    is_admin: bool = False,
) -> None:
    if user.status != "pending":
        raise ValueError("User is not pending invitation")
    token = generate_token()
    db.add(
        FirmInvitation(
            user_id=user.id,
            email=user.email,
            token_hash=hash_token(token),
            token_plain=token,
            expires_at=invite_expires_at(),
            invited_by=invited_by,
        )
    )
    db.flush()
    email_service.send_invite(user.email, token, firm_slug, is_admin=is_admin)


def create_password_reset(
    db: Session,
    *,
    email: str,
    scope: str,
    email_service: EmailService,
    tenant_slug: str,
) -> None:
    email = email.lower()
    if scope == "platform":
        user = db.execute(select(PlatformUser).where(PlatformUser.email == email)).scalar_one_or_none()
        if not user:
            return
        token = generate_token()
        db.add(
            PlatformPasswordResetToken(
                user_id=user.id,
                token_hash=hash_token(token),
                expires_at=reset_expires_at(),
            )
        )
        db.flush()
        email_service.send_password_reset(email, token, tenant_slug)
    else:
        user = db.execute(select(FirmUser).where(FirmUser.email == email)).scalar_one_or_none()
        if not user:
            return
        token = generate_token()
        db.add(
            FirmPasswordResetToken(
                user_id=user.id,
                token_hash=hash_token(token),
                expires_at=reset_expires_at(),
            )
        )
        db.flush()
        email_service.send_password_reset(email, token, tenant_slug)


def reset_password_with_token(
    db: Session,
    *,
    token: str,
    new_password: str,
    scope: str,
    tenant_slug: str,
    email_service: EmailService | None = None,
) -> PasswordResetResult | None:
    validate_password(new_password)
    token = re.sub(r"\s+", "", token.strip())
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    if scope == "platform":
        row = db.execute(
            select(PlatformPasswordResetToken).where(
                PlatformPasswordResetToken.token_hash == token_hash,
                PlatformPasswordResetToken.used_at.is_(None),
            )
        ).scalar_one_or_none()
        if not row or row.expires_at < now:
            raise ValueError("Invalid or expired reset token")
        user = db.get(PlatformUser, row.user_id)
        if not user:
            raise ValueError("Invalid or expired reset token")
        user.password_hash = hash_password(new_password)
        user.status = "active"
        user.is_email_verified = True
        row.used_at = now
        db.flush()
        result = PasswordResetResult(email=user.email, tenant_slug=tenant_slug, activated=False)
        if email_service:
            email_service.send_password_reset_confirmation(user.email, tenant_slug, activated=False)
        return result

    invite_row = db.execute(
        text(
            """
            SELECT user_id, expires_at
            FROM invitations
            WHERE (token_plain = :token OR token_hash = :token_hash)
              AND accepted_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
            """
        ),
        {"token": token, "token_hash": token_hash},
    ).first()
    if invite_row and invite_row.expires_at >= now:
        user = db.get(FirmUser, invite_row.user_id)
        if not user:
            raise ValueError("Invalid or expired reset token")
        db.execute(
            text(
                """
                UPDATE users
                SET password_hash = :password_hash,
                    status = 'active',
                    is_email_verified = true,
                    updated_at = :now
                WHERE id = :user_id
                """
            ),
            {"password_hash": hash_password(new_password), "user_id": invite_row.user_id, "now": now},
        )
        db.execute(
            text("UPDATE invitations SET accepted_at = :now WHERE user_id = :user_id AND accepted_at IS NULL"),
            {"now": now, "user_id": invite_row.user_id},
        )
        db.flush()
        result = PasswordResetResult(email=user.email, tenant_slug=tenant_slug, activated=True)
        if email_service:
            email_service.send_password_reset_confirmation(user.email, tenant_slug, activated=True)
        return result

    reset_row = db.execute(
        text(
            """
            SELECT user_id, expires_at
            FROM password_reset_tokens
            WHERE token_hash = :token_hash AND used_at IS NULL
            """
        ),
        {"token_hash": token_hash},
    ).first()
    if not reset_row or reset_row.expires_at < now:
        raise ValueError("Invalid or expired reset token")
    user = db.get(FirmUser, reset_row.user_id)
    if not user:
        raise ValueError("Invalid or expired reset token")
    db.execute(
        text(
            """
            UPDATE users
            SET password_hash = :password_hash, status = 'active', updated_at = :now
            WHERE id = :user_id
            """
        ),
        {"password_hash": hash_password(new_password), "user_id": reset_row.user_id, "now": now},
    )
    db.execute(
        text("UPDATE password_reset_tokens SET used_at = :now WHERE token_hash = :token_hash"),
        {"now": now, "token_hash": token_hash},
    )
    db.flush()
    result = PasswordResetResult(email=user.email, tenant_slug=tenant_slug, activated=False)
    if email_service:
        email_service.send_password_reset_confirmation(user.email, tenant_slug, activated=False)
    return result


def activate_firm_account(
    db: Session,
    *,
    token: str,
    new_password: str,
    tenant_slug: str,
    email_service: EmailService,
) -> PasswordResetResult:
    tenant_slug = tenant_slug.strip().lower()
    firm = db.execute(select(Firm).where(Firm.slug == tenant_slug)).scalar_one_or_none()
    if not firm:
        raise ValueError("Organization not found")
    if firm.status != "active":
        raise ValueError("Organization is suspended")

    db.execute(text(f'SET search_path TO "{firm.schema_name}", public'))
    result = reset_password_with_token(
        db,
        token=token,
        new_password=new_password,
        scope="firm",
        tenant_slug=tenant_slug,
        email_service=email_service,
    )
    if not result or not result.activated:
        raise ValueError("Invalid or expired invitation token")
    return result
