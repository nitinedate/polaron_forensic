"""Provision default firm_a if missing (used after DB reset)."""

from __future__ import annotations

import sys
from pathlib import Path

backend_root = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_root))

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.email_service import EmailService
from app.services.tenant_provisioner import provision_firm


def main() -> None:
    db = SessionLocal()
    try:
        existing = db.execute(
            text("SELECT id, schema_name FROM public.firms WHERE slug='a' OR schema_name='firm_a'")
        ).fetchone()
        if existing:
            print(f"firm_a already exists id={existing[0]} schema={existing[1]}")
            return
        firm = provision_firm(
            db,
            name="Firm A",
            slug="a",
            plan="standard",
            primary_host=None,
            admin_email="admin@firm-a.test",
            email_service=EmailService(),
        )
        db.commit()
        print(f"provisioned firm_a id={firm.id} schema={firm.schema_name}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
