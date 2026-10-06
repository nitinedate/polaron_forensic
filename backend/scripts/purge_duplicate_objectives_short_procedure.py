"""Delete duplicate-title rows from public.reports_objective.

For each report type + title, keeps the row whose procedure_text starts with '1.'
and removes legacy short duplicates (e.g. RPT-O901 vs O016). Applies to all objectives.
"""

from __future__ import annotations

import json
import sys

from app.db.session import SessionLocal
from app.services.report_template_service import purge_duplicate_objectives_without_numbered_procedure


def main() -> int:
    db = SessionLocal()
    try:
        result = purge_duplicate_objectives_without_numbered_procedure(db)
        db.commit()
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        db.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
