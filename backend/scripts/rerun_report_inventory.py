#!/usr/bin/env python3
"""Re-persist section B report-template artifact counts for a job."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: rerun_report_inventory.py <job_id> [schema]")
        return 1

    job_id = sys.argv[1].strip()
    schema = (sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris").strip()

    from app.db.session import firm_session
    from app.services.axiom_artifact_runner import persist_collector_counts

    with firm_session(schema) as db:
        counts = persist_collector_counts(db, job_id, report_only=True)
        db.commit()
        print(f"report inventory persisted: {len(counts)} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
