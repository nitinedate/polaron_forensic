"""Truncate public.reports_objective and reseed from AXIOM only (same titles as before)."""

from __future__ import annotations

import json
import sys

from app.db.session import SessionLocal
from app.services.report_template_service import reseed_reports_objective_axiom_only


def main() -> int:
    db = SessionLocal()
    try:
        result = reseed_reports_objective_axiom_only(db)
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
