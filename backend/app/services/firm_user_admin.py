"""Platform superadmin operations on users inside a firm schema."""

from __future__ import annotations

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.firm import FirmRole, FirmUser, FirmUserRole
from app.models.platform import Firm
from app.services.auth_service import AuthService
from app.services.email_service import EmailService
from app.services.invite_service import invite_firm_user, resend_firm_invite


def _set_schema(db: Session, schema_name: str) -> None:
    db.execute(text(f'SET search_path TO "{schema_name}", public'))


def get_firm_or_raise(db: Session, firm_id: str) -> Firm:
    firm = db.get(Firm, firm_id)
    if not firm:
        raise ValueError("Firm not found")
    return firm


def list_firm_users(db: Session, firm: Firm) -> list[dict]:
    rows = db.execute(
        text(
            f"""
            SELECT u.id, u.email, u.status, u.mfa_enabled, u.is_email_verified, u.created_at, u.profile,
                   COALESCE(string_agg(DISTINCT r.name, ', ' ORDER BY r.name), '') AS roles
            FROM "{firm.schema_name}".users u
            LEFT JOIN "{firm.schema_name}".user_roles ur ON ur.user_id = u.id
            LEFT JOIN "{firm.schema_name}".roles r ON r.id = ur.role_id
            GROUP BY u.id, u.email, u.status, u.mfa_enabled, u.is_email_verified, u.created_at, u.profile
            ORDER BY u.created_at ASC
            """
        )
    ).mappings().all()
    items = []
    for row in rows:
        items.append(
            {
                "id": str(row["id"]),
                "email": row["email"],
                "status": row["status"],
                "mfa_enabled": bool(row["mfa_enabled"]),
                "is_email_verified": bool(row["is_email_verified"]),
                "created_at": row["created_at"],
                "roles": [r.strip() for r in (row["roles"] or "").split(",") if r.strip()],
                "profile": row["profile"],
            }
        )
    return items


def invite_firm_admin(
    db: Session,
    firm: Firm,
    *,
    email: str,
    invited_by,
    email_service: EmailService,
    profile: dict | None = None,
    mfa_enabled: bool = True,
) -> FirmUser:
    """Superadmin: invite a firm administrator (admin role only)."""
    _set_schema(db, firm.schema_name)
    admin_role = db.execute(select(FirmRole).where(FirmRole.name == "admin")).scalar_one_or_none()
    if not admin_role:
        raise ValueError("Firm admin role is not provisioned — run RBAC sync")
    return invite_firm_user(
        db,
        email=email,
        role_ids=[str(admin_role.id)],
        invited_by=invited_by,
        email_service=email_service,
        firm_slug=firm.slug,
        profile=profile,
        mfa_enabled=mfa_enabled,
    )


def update_firm_user(
    db: Session,
    firm: Firm,
    user_id: str,
    *,
    status: str | None = None,
    mfa_enabled: bool | None = None,
    profile: dict | None = None,
) -> FirmUser:
    _set_schema(db, firm.schema_name)
    user = db.get(FirmUser, user_id)
    if not user:
        raise ValueError("User not found")
    if status is not None:
        user.status = status
    if profile is not None:
        merged = dict(user.profile or {})
        merged.update(profile)
        user.profile = merged
    if mfa_enabled is not None:
        AuthService().set_user_mfa_enabled(db, user, mfa_enabled)
    db.flush()
    return user


def deactivate_firm_user(db: Session, firm: Firm, user_id: str) -> None:
    _set_schema(db, firm.schema_name)
    user = db.get(FirmUser, user_id)
    if not user:
        raise ValueError("User not found")
    is_admin = db.execute(
        select(FirmUserRole)
        .join(FirmRole, FirmRole.id == FirmUserRole.role_id)
        .where(FirmUserRole.user_id == user.id, FirmRole.name == "admin")
    ).first()
    if is_admin:
        total_admins = db.execute(
            text(
                f"""
                SELECT COUNT(DISTINCT ur.user_id) AS c
                FROM "{firm.schema_name}".user_roles ur
                JOIN "{firm.schema_name}".roles r ON r.id = ur.role_id
                WHERE r.name = 'admin' AND EXISTS (
                    SELECT 1 FROM "{firm.schema_name}".users u
                    WHERE u.id = ur.user_id AND u.status <> 'disabled'
                )
                """
            )
        ).scalar_one()
        if total_admins <= 1 and user.status != "disabled":
            raise ValueError("Cannot deactivate the last active firm administrator")
    user.status = "disabled"
    db.flush()


def resend_firm_user_invite(
    db: Session,
    firm: Firm,
    user_id: str,
    *,
    invited_by,
    email_service: EmailService,
) -> None:
    _set_schema(db, firm.schema_name)
    user = db.get(FirmUser, user_id)
    if not user:
        raise ValueError("User not found")
    is_admin = db.execute(
        select(FirmUserRole)
        .join(FirmRole, FirmRole.id == FirmUserRole.role_id)
        .where(FirmUserRole.user_id == user.id, FirmRole.name == "admin")
    ).first()
    resend_firm_invite(
        db,
        user,
        invited_by=invited_by,
        email_service=email_service,
        firm_slug=firm.slug,
        is_admin=bool(is_admin),
    )
