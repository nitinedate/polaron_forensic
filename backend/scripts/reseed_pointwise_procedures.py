"""Reseed reports_objective with point-wise procedures."""

from __future__ import annotations

from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone
from app.services.report_template_service import purge_legacy_report_objectives, seed_report_template_catalog


def main() -> None:
    db = SessionLocal()
    try:
        result = seed_report_template_catalog(db)
        purged = purge_legacy_report_objectives(db)
        db.commit()
        rows = fetchall(
            db,
            """SELECT title, length(procedure_text) AS n,
                      left(procedure_text, 80) AS preview
               FROM public.reports_objective
               WHERE objective_id LIKE 'RPT-O%'
               ORDER BY title
               LIMIT 5""",
        )
        sample = fetchone(
            db,
            """SELECT length(procedure_text) AS n,
                      (procedure_text LIKE '1.%') AS numbered,
                      (procedure_text ILIKE '%OCR%') AS has_ocr
               FROM public.reports_objective
               WHERE title = 'File Access and Handling'
               ORDER BY updated_at DESC NULLS LAST
               LIMIT 1""",
        )
        print({"seed": result, "purged_legacy": purged, "sample": dict(sample or {}), "rows": [dict(r) for r in rows]})
    finally:
        db.close()


if __name__ == "__main__":
    main()
