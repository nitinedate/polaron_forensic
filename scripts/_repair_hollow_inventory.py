"""Clear premature near-zero inventory and re-queue for the latest aetheris job."""
from __future__ import annotations

from sqlalchemy import text
from app.db.session import firm_session

schema = "firm_aetheris"
with firm_session(schema) as db:
    from app.services.axiom_artifact_runner import (
        clear_artifact_inventory_results,
        clear_inventory_runtime_cache,
        inventory_results_look_premature,
        materialized_artifact_count,
        queue_axiom_artifact_inventory,
    )

    job = db.execute(
        text("SELECT id, status FROM jobs ORDER BY created_at DESC LIMIT 1")
    ).mappings().first()
    if not job:
        print("No jobs")
        raise SystemExit(0)
    jid = str(job["id"])
    art_n = materialized_artifact_count(db, jid)
    premature = inventory_results_look_premature(db, jid)
    print(f"job={jid} status={job['status']} artifacts={art_n} premature={premature}")
    clear_artifact_inventory_results(db, jid)
    clear_inventory_runtime_cache(jid)
    db.commit()
    print("cleared results + caches")
    result = queue_axiom_artifact_inventory(db, jid, schema_name=schema)
    print("queue:", result)
