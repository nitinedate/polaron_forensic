"""Purge legacy RPT-* objectives and migrate case intake IDs to AXIOM O-* ids."""
from __future__ import annotations

import json

from sqlalchemy import text

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall
from app.services.report_template_service import (
    canonical_objective_ids,
    purge_legacy_report_objectives,
    seed_report_template_catalog,
)


def _migrate_table_objective_ids(db, table: str) -> int:
    rows = db.execute(
        text(f"SELECT job_id, objective_ids FROM {table} WHERE objective_ids IS NOT NULL")
    ).fetchall()
    updated = 0
    for job_id, raw in rows:
        ids = raw if isinstance(raw, list) else json.loads(raw or "[]")
        if not ids:
            continue
        canonical = canonical_objective_ids(db, [str(x) for x in ids])
        if canonical == ids:
            continue
        db.execute(
            text(f"UPDATE {table} SET objective_ids = CAST(:ids AS jsonb) WHERE job_id = :jid"),
            {"ids": json.dumps(canonical), "jid": job_id},
        )
        updated += 1
    return updated


def migrate_intake_objective_ids(db) -> int:
    return _migrate_table_objective_ids(db, "case_intake")


def migrate_objective_procedure_scope_ids(db) -> int:
    rows = db.execute(
        text(
            "SELECT job_id, enabled_objective_ids FROM objective_procedure_scope "
            "WHERE enabled_objective_ids IS NOT NULL"
        )
    ).fetchall()
    updated = 0
    for job_id, raw in rows:
        ids = raw if isinstance(raw, list) else json.loads(raw or "[]")
        if not ids:
            continue
        canonical = canonical_objective_ids(db, [str(x) for x in ids])
        if canonical == ids:
            continue
        db.execute(
            text(
                "UPDATE objective_procedure_scope "
                "SET enabled_objective_ids = CAST(:ids AS jsonb) WHERE job_id = :jid"
            ),
            {"ids": json.dumps(canonical), "jid": job_id},
        )
        updated += 1
    return updated


def migrate_firm_objective_ids(db) -> dict[str, int]:
    totals = {"intake": 0, "scope": 0, "schemas": 0}
    firm_rows = fetchall(
        db,
        "SELECT schema_name FROM public.firms WHERE status = 'active' AND schema_name IS NOT NULL",
        {},
    )
    for firm in firm_rows:
        schema = firm["schema_name"]
        try:
            apply_firm_search_path(db, schema)
            totals["intake"] += migrate_intake_objective_ids(db)
            totals["scope"] += migrate_objective_procedure_scope_ids(db)
            totals["schemas"] += 1
        except Exception:
            db.rollback()
            continue
    return totals


def main() -> None:
    db = SessionLocal()
    try:
        purged = purge_legacy_report_objectives(db)
        print(f"Purged legacy rows: {purged}")
        seed_report_template_catalog(db)
        firm_totals = migrate_firm_objective_ids(db)
        print(
            "Migrated firm schemas:",
            firm_totals["schemas"],
            "intake rows:",
            firm_totals["intake"],
            "scope rows:",
            firm_totals["scope"],
        )
        db.commit()
        total = db.execute(text("SELECT COUNT(*) FROM public.reports_objective")).scalar()
        rpt = db.execute(
            text(
                "SELECT COUNT(*) FROM public.reports_objective "
                "WHERE objective_id LIKE 'RPT-%' OR objective_id LIKE 'RPT-TPL-%'"
            )
        ).scalar()
        print(f"Total objectives: {total}, legacy remaining: {rpt}")
        rows = db.execute(
            text(
                "SELECT objective_id, LEFT(title, 60) "
                "FROM public.reports_objective "
                "WHERE title ILIKE '%File Access%' ORDER BY objective_id"
            )
        ).fetchall()
        print("File Access rows:", rows)
    except Exception as exc:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
