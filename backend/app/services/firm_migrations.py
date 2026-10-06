"""Apply idempotent firm-scoped migrations for existing organizations."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.platform import Firm
from app.services.firm_schema_apply import apply_firm_extension_functions

log = logging.getLogger("firm_migrations")


def apply_firm_migrations(db: Session, schema_name: str) -> None:
    """Re-apply all firm extension functions (safe / IF NOT EXISTS)."""
    apply_firm_extension_functions(db, schema_name, strict=False)
    try:
        from app.services.pipeline_heal import ensure_pipeline_heal_table

        ensure_pipeline_heal_table(db, schema_name)
    except Exception as exc:
        log.warning("pipeline_heal ensure failed for %s: %s", schema_name, exc)


def apply_all_firm_migrations(db: Session) -> int:
    firms = db.execute(select(Firm).where(Firm.status == "active")).scalars().all()
    for firm in firms:
        if not firm.schema_name:
            continue
        try:
            apply_firm_migrations(db, firm.schema_name)
        except Exception as exc:
            log.warning("firm migration skipped for %s: %s", firm.schema_name, exc)
    db.commit()
    return len(firms)
