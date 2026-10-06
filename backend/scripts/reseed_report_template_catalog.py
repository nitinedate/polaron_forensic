"""Truncate reports_artifacts / reports_objective and re-seed from AXIOM mappings."""

from __future__ import annotations

import argparse
import json
import sys

from app.db.session import SessionLocal
from app.services.report_template_service import get_report_artifact_mapping, reset_report_template_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset and re-seed report template catalog")
    parser.add_argument("--platform", default="Windows")
    parser.add_argument("--keep-job-selections", action="store_true")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = reset_report_template_catalog(
            db,
            platform=args.platform,
            clear_job_selections=not args.keep_job_selections,
        )
        db.commit()
        mapping = get_report_artifact_mapping(db, platform=args.platform)
        summary = {
            **result,
            "report_types_seeded": len(mapping.get("report_types") or []),
            "report_type_ids": [r["report_type_id"] for r in mapping.get("report_types") or []],
        }
        print(json.dumps(summary, indent=2, default=str))
        return 0
    except Exception as exc:
        db.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
