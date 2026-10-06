#!/usr/bin/env python3
"""Re-queue artifact inventory for a job stuck at ~85% with zero persisted counts."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: resume_axiom_inventory.py <job_id> [schema]")
        return 1

    job_id = sys.argv[1].strip()
    schema = (sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris").strip()

    from app.db.session import firm_session
    from app.services.axiom_artifact_runner import (
        PIPELINE_PROGRESS_CAP,
        axiom_inventory_progress,
        queue_axiom_artifact_inventory,
    )
    from app.db.sql_helpers import execute
    import json

    with firm_session(schema) as db:
        inv = axiom_inventory_progress(db, job_id)
        print(f"before: completed={inv.get('completed')} total={inv.get('total')} done={inv.get('done')}")
        if inv.get("done"):
            print("inventory already complete")
            return 0

        execute(
            db,
            """UPDATE jobs SET status='indexing', progress_pct=:pct,
               pipeline_progress=CAST(:pp AS jsonb), error=NULL, updated_at=NOW()
               WHERE id=:id""",
            {
                "id": job_id,
                "pct": PIPELINE_PROGRESS_CAP,
                "pp": json.dumps({
                    "phase": "artifact_inventory",
                    "completed": int(inv.get("completed") or 0),
                    "total": int(inv.get("total") or 0),
                    "label": f"Artifact inventory — {int(inv.get('completed') or 0):,} / {int(inv.get('total') or 0):,}",
                }),
            },
        )
        db.commit()

        result = queue_axiom_artifact_inventory(db, job_id, schema_name=schema)
        print(f"queue result: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
