"""Diagnose artifact inventory progress for a job."""
import sys

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall, fetchone
from app.services.axiom_artifact_runner import axiom_inventory_progress, inventory_task_in_flight

JOB = sys.argv[1] if len(sys.argv) > 1 else "4316aaf4-4eb7-4704-a692-905e0d3e6246"
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"

db = SessionLocal()
apply_firm_search_path(db, SCHEMA)
inv = axiom_inventory_progress(db, JOB)
print("inventory:", inv)
print("in_flight:", inventory_task_in_flight(db, JOB))
row = fetchone(db, "SELECT status, progress_pct, pipeline_progress FROM jobs WHERE id=:id", {"id": JOB})
print("job:", row)
cnt = fetchone(db, "SELECT count(*) c FROM job_axiom_artifact_results WHERE job_id=:j", {"j": JOB})
print("results:", cnt)
logs = fetchall(
    db,
    """SELECT message, timestamp FROM disk_build_logs
       WHERE job_id=:j AND stage='artifact_inventory'
       ORDER BY timestamp DESC LIMIT 10""",
    {"j": JOB},
)
print("recent logs:")
for line in logs:
    print(" ", line)
db.close()
