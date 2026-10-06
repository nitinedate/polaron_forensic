#!/usr/bin/env python3
"""Recover a stalled forensic job without deleting evidence or resetting progress."""
from __future__ import annotations

import argparse
import json

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.job_locks import force_release_job_lock


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    ap.add_argument("--job-id", required=True)
    args = ap.parse_args()

    with firm_session(args.schema) as db:
        job = fetchone(
            db,
            "SELECT id,status,progress_pct,error,updated_at FROM jobs WHERE id=:id",
            {"id": args.job_id},
        )
        if not job:
            raise SystemExit(f"Job {args.job_id} does not exist in schema {args.schema}")
        statuses = fetchall(
            db,
            """SELECT parse_status, count(*)::bigint AS c
               FROM job_artifacts WHERE job_id=:jid GROUP BY parse_status ORDER BY parse_status""",
            {"jid": args.job_id},
        )
        pending = fetchone(
            db,
            "SELECT count(*)::bigint AS c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'",
            {"jid": args.job_id},
        )
        pending_n = int(pending["c"]) if pending else 0
        summary = {str(r["parse_status"]): int(r["c"]) for r in statuses}
        print(json.dumps({"job": dict(job), "parse_status": summary}, default=str, indent=2))

        execute(
            db,
            """UPDATE jobs SET status='indexing', error=NULL, stop_requested=FALSE, updated_at=NOW()
               WHERE id=:id""",
            {"id": args.job_id},
        )
        write_disk_log(
            db,
            args.job_id,
            f"Reliability recovery requested — {pending_n:,} parse artifacts pending; preserving existing progress",
            stage="parse",
            level="warning",
        )
        db.commit()

    # Deployment recreates worker-disk before invoking this script; any surviving
    # parse lock therefore belongs to the dead worker and is safe to clear.
    released = force_release_job_lock("parse", args.job_id)
    print(f"stale_parse_lock_released={released}")

    if pending_n > 0:
        from app.tasks import parse_drain_task

        result = parse_drain_task.apply_async(args=(args.schema, args.job_id), countdown=2)
        print(f"queued=parse_drain task_id={result.id}")
        return 0

    # Parse is already drained. In stage-aware mode OCR owns the GPU before text
    # RAG, then RAG finishes before inventory/graph work.
    with firm_session(args.schema) as db:
        from app.services.dual_rag_index import _count_indexable_without_chunks
        try:
            from app.services.ocr_gpu import count_pending_ocr
            ocr_left = int(count_pending_ocr(db, args.job_id) or 0)
        except Exception:
            ocr_left = 0
        rag_left = int(_count_indexable_without_chunks(db, args.job_id) or 0)

    if ocr_left > 0:
        from app.tasks import ocr_drain_task

        result = ocr_drain_task.apply_async(args=(args.schema, args.job_id), countdown=2)
        print(f"queued=ocr_drain pending={ocr_left} task_id={result.id}")
        return 0

    if rag_left > 0:
        from app.tasks import rag_append_task

        result = rag_append_task.apply_async(args=(args.schema, args.job_id), countdown=2)
        print(f"queued=rag_append pending={rag_left} task_id={result.id}")
        return 0

    from app.tasks import axiom_artifact_inventory_task

    result = axiom_artifact_inventory_task.apply_async(args=(args.schema, args.job_id), countdown=2)
    print(f"queued=artifact_inventory task_id={result.id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
