from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.platform import AuditLog, Firm
from app.models.firm import FirmInvitation, FirmRole, FirmUser, FirmUserRole
from app.services.email_service import EmailService
from app.services.firm_rbac_sync import sync_firm_rbac
from app.services.firm_schema_apply import provision_organization_schema
from app.services.security import generate_token, hash_token, invite_expires_at


def schema_name_for_slug(slug: str) -> str:
    safe = slug.lower().replace("-", "_")
    return f"firm_{safe}"


def provision_firm_schema(db: Session, schema_name: str) -> None:
    """Create all org tables required for forensic + user management."""
    provision_organization_schema(db, schema_name)


def seed_firm_rbac(db: Session, schema_name: str) -> dict[str, FirmRole]:
    return sync_firm_rbac(db, schema_name)


def create_firm_admin_invite(
    db: Session,
    *,
    email: str,
    schema_name: str,
    email_service: EmailService,
    firm_slug: str,
    send_invite: bool = True,
) -> FirmUser:
    db.execute(text(f'SET search_path TO "{schema_name}", public'))
    admin_role = db.execute(select(FirmRole).where(FirmRole.name == "admin")).scalar_one()
    user = FirmUser(
        email=email.lower(),
        status="pending",
        is_email_verified=False,
        mfa_enabled=True,
        profile={"first_name": None, "last_name": None, "phone": None, "locale": "en", "timezone": "UTC"},
    )
    db.add(user)
    db.flush()
    db.add(FirmUserRole(user_id=user.id, role_id=admin_role.id))

    token = generate_token()
    db.add(
        FirmInvitation(
            user_id=user.id,
            email=email.lower(),
            token_hash=hash_token(token),
            token_plain=token,
            expires_at=invite_expires_at(),
            invited_by=None,
        )
    )
    db.flush()
    if send_invite:
        email_service.send_invite(email, token, firm_slug, is_admin=True)
    return user


def _ensure_default_case(db: Session, schema_name: str) -> None:
    """Create a default workspace case when cases table exists (idempotent)."""
    try:
        db.execute(
            text(
                f"""INSERT INTO "{schema_name}".cases (title, status, timezone)
                    SELECT 'Default workspace', 'open', 'UTC'
                    WHERE NOT EXISTS (
                      SELECT 1 FROM "{schema_name}".cases WHERE title = 'Default workspace'
                    )"""
            )
        )
    except Exception:
        # cases table may not exist if apply_firm_cases failed — non-fatal
        pass


def provision_firm(
    db: Session,
    *,
    name: str,
    slug: str,
    plan: str,
    primary_host: str | None,
    admin_email: str,
    email_service: EmailService,
    actor_id: str | None = None,
    send_invite: bool = True,
) -> Firm:
    """Superadmin provisions a tenant: org schema + RBAC + firm-admin invite.

    Order:
      1. Register firm in public.firms
      2. Create schema + all forensic/IAM tables (automatic)
      3. Seed admin/user roles and permissions
      4. Invite firm admin (pending until they set password)
    """
    slug = slug.strip().lower()
    schema = schema_name_for_slug(slug)

    existing = db.execute(select(Firm).where((Firm.slug == slug) | (Firm.schema_name == schema))).scalar_one_or_none()
    if existing:
        raise ValueError("A firm with this slug already exists")

    firm = Firm(
        name=name,
        slug=slug,
        schema_name=schema,
        plan=plan,
        primary_host=primary_host,
        status="active",
    )
    db.add(firm)
    db.flush()

    # Organization tables are created here — before the admin accepts the invite.
    provision_firm_schema(db, schema)

    db.execute(text(f'SET search_path TO "{schema}", public'))
    seed_firm_rbac(db, schema)
    _ensure_default_case(db, schema)
    create_firm_admin_invite(
        db,
        email=admin_email,
        schema_name=schema,
        email_service=email_service,
        firm_slug=slug,
        send_invite=send_invite,
    )

    db.add(
        AuditLog(
            scope="platform",
            tenant_slug=slug,
            actor_id=actor_id,
            action="firm.provisioned",
            resource_type="firm",
            resource_id=str(firm.id),
            details={"admin_email": admin_email, "schema_name": schema},
        )
    )
    db.flush()
    return firm


def destroy_firm(db: Session, firm: Firm) -> None:
    db.execute(text(f'DROP SCHEMA IF EXISTS "{firm.schema_name}" CASCADE'))
    db.delete(firm)
    db.flush()
