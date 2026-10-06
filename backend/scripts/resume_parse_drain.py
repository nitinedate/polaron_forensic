"""Repair pipeline phase and re-queue background parse drain for a job."""
from __future__ import annotations

import sys

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import execute, fetchone
from app.services.pipeline_orchestrator import merge_orchestration_into_progress

JOB = sys.argv[1] if len(sys.argv) > 1 else ""
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"


def main() -> None:
    if not JOB:
        print("usage: resume_parse_drain.py <job_id> [schema]")
        raise SystemExit(1)
    db = SessionLocal()
    apply_firm_search_path(db, SCHEMA)
    pending_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND parse_status='pending'",
        {"j": JOB},
    )
    parsed_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND parse_status='parsed'",
        {"j": JOB},
    )
    pending = int(pending_row["c"]) if pending_row else 0
    parsed = int(parsed_row["c"]) if parsed_row else 0
    total = max(parsed + pending, 1)
    print(f"pending={pending:,} parsed={parsed:,}")
    execute(
        db,
        """UPDATE jobs SET status='indexing',
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {
            "id": JOB,
            "pp": __import__("json").dumps({
                "phase": "parse",
                "completed": parsed,
                "total": total,
                "label": f"Background parse — {parsed:,} / {total:,} forensic files",
            }),
        },
    )
    db.commit()
    merge_orchestration_into_progress(db, JOB)
    db.commit()
    from app.tasks import parse_drain_task

    parse_drain_task.delay(SCHEMA, JOB)
    print("parse_drain_task queued")


if __name__ == "__main__":
    main()
