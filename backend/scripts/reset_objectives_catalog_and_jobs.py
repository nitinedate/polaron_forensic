"""Reseed reports_objective from AXIOM, purge duplicate titles, clear all job objective storage."""

from __future__ import annotations

import json
import sys

from app.db.session import SessionLocal
from app.services.report_template_service import reset_objectives_catalog_and_jobs


def main() -> int:
    db = SessionLocal()
    try:
        result = reset_objectives_catalog_and_jobs(db)
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
