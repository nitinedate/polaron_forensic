#!/usr/bin/env python3
"""Diagnose artifact inventory stall for recent jobs."""

from __future__ import annotations

import json
import sys

from app.db.session import firm_session
from app.db.sql_helpers import fetchall
from app.services.axiom_artifact_runner import (
    axiom_inventory_progress,
    inventory_task_in_flight,
    parse_pending_count,
)


def main() -> int:
    schema = sys.argv[1] if len(sys.argv) > 1 else "firm_aetheris"
    with firm_session(schema) as db:
        jobs = fetchall(
            db,
            """SELECT id, status, progress_pct, pipeline_progress, updated_at, error
               FROM jobs ORDER BY updated_at DESC LIMIT 5""",
        )
        for j in jobs:
            jid = j["id"]
            inv = axiom_inventory_progress(db, jid)
            inflight = inventory_task_in_flight(db, jid)
            pending = parse_pending_count(db, jid)
            pp = j.get("pipeline_progress")
            if isinstance(pp, str):
                pp = json.loads(pp)
            print(f"=== {jid}")
            print(f"  status={j['status']} pct={j['progress_pct']} pending_parse={pending}")
            print(f"  inv={inv} inflight={inflight}")
            print(f"  pp={pp}")
            print(f"  updated={j.get('updated_at')} error={j.get('error')}")
            logs = fetchall(
                db,
                """SELECT timestamp, stage, message FROM disk_build_logs
                   WHERE job_id=:jid ORDER BY timestamp DESC LIMIT 10""",
                {"jid": jid},
            )
            for lg in reversed(logs):
                print(f"  {lg['timestamp']} [{lg['stage']}] {(lg['message'] or '')[:120]}")
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
