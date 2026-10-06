#!/usr/bin/env python3
"""Re-queue a stalled extraction job from checkpoint (run inside api container)."""
from __future__ import annotations

import sys

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.job_control import extraction_is_stale, load_extraction_checkpoint


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: resume_stalled_job.py <job_id> [schema_name]")
        return 1
    job_id = sys.argv[1]
    schema = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"

    from app.routers.jobs import _queue_disk_build

    with firm_session(schema) as db:
        row = fetchone(
            db,
            "SELECT id, status, updated_at, files_extracted, files_total FROM jobs WHERE id=:id",
            {"id": job_id},
        )
        if not row:
            print("Job not found")
            return 1
        print("before", dict(row), "stale", extraction_is_stale(row))
        cp = load_extraction_checkpoint(db, job_id)
        shards = (cp or {}).get("completed_shards") or []
        print("checkpoint shards", len(shards), "workers", (cp or {}).get("worker_count"))
        execute(
            db,
            "UPDATE jobs SET status='processing', stop_requested=FALSE, error=NULL, updated_at=NOW() WHERE id=:id",
            {"id": job_id},
        )
        db.commit()
        _queue_disk_build(db, schema, job_id, force=True)
        row2 = fetchone(
            db,
            "SELECT status, celery_task_id, updated_at FROM jobs WHERE id=:id",
            {"id": job_id},
        )
        print("after", dict(row2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
