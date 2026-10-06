from app.db.session import firm_session
from app.db.sql_helpers import fetchone
from app.services.pipeline_supervisor import (
    _observe_stalled_inventory,
    _should_redispatch,
    _sequential_gate,
    analyze_job_pipeline,
)
from app.services.pipeline_orchestrator import sync_orchestration_from_job, prior_supervisor_keys_done

J = "7f6f7fdd-726e-4f18-ac11-8e211c871c99"

with firm_session("firm_aetheris") as db:
    row = fetchone(
        db,
        """SELECT id, status, error, updated_at, stop_requested, disk_source, extracted_disk_uri,
                  pipeline_progress, celery_task_id, extraction_checkpoint
           FROM jobs WHERE id=:id""",
        {"id": J},
    )
    print("status", row["status"], "stop", row["stop_requested"])
    print("obs", _observe_stalled_inventory(db, J, row, stale_sec=180))
    print(
        "should",
        _should_redispatch(
            db, J, "inventory_agent", row, stale_threshold=180, within_sec=90
        ),
    )
    orch = sync_orchestration_from_job(db, J)
    print("prior_done", prior_supervisor_keys_done(orch["agents"], "inventory_agent"))
    for k, v in orch["agents"].items():
        if v.get("state") != "done":
            print(" not done", k, v.get("state"), v.get("label"))
    print(
        "gate",
        _sequential_gate(
            db,
            J,
            {
                "agent_id": "inventory_agent",
                "action": "artifact_inventory",
                "reason": "test",
            },
        ),
    )
    print("analyze", analyze_job_pipeline(db, J))
