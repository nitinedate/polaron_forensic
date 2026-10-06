"""AXIOM export vs Python inventory reconciliation stub (DOCX §8)."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall


def refresh_reconciliation_stub(db: Session, job_id: str) -> int:
    """Seed reconciliation rows from current inventory (delta=0 until AXIOM export import)."""
    try:
        from app.services.catalog_artifact_runner import ensure_job_axiom_results_schema

        ensure_job_axiom_results_schema(db)
    except Exception:
        pass
    rows = fetchall(
        db,
        """SELECT artifact_id, COALESCE(occurrence_count, artifact_count, 0) AS cnt,
                  query_snapshot
           FROM job_axiom_artifact_results
           WHERE job_id = :jid AND status = 'done'""",
        {"jid": job_id},
    )
    written = 0
    for row in rows:
        aid = str(row.get("artifact_id") or "")
        if not aid:
            continue
        py_count = int(row.get("cnt") or 0)
        qs = row.get("query_snapshot")
        execute(
            db,
            """INSERT INTO job_count_reconciliation
               (job_id, artifact_id, axiom_export_count, python_inventory_count, delta,
                delta_reason, query_snapshot, updated_at)
               VALUES (:jid, :aid, NULL, :py, 0, 'pending_axiom_export', CAST(:qs AS jsonb), NOW())
               ON CONFLICT (job_id, artifact_id) DO UPDATE SET
                 python_inventory_count = EXCLUDED.python_inventory_count,
                 delta = EXCLUDED.delta,
                 delta_reason = EXCLUDED.delta_reason,
                 query_snapshot = EXCLUDED.query_snapshot,
                 updated_at = NOW()""",
            {
                "jid": job_id,
                "aid": aid,
                "py": py_count,
                "qs": json.dumps(qs if isinstance(qs, dict) else {}),
            },
        )
        written += 1
    db.flush()
    return written
