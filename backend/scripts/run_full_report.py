"""Run full report generation synchronously (for testing)."""
import json
import sys
import time

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall, fetchone
from app.services.report_generator import generate_report

JOB = sys.argv[1] if len(sys.argv) > 1 else "4316aaf4-4eb7-4704-a692-905e0d3e6246"
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"

db = SessionLocal()
apply_firm_search_path(db, SCHEMA)
print(f"Starting report for job={JOB} schema={SCHEMA}")
t0 = time.time()
result = generate_report(db, JOB, schema_name=SCHEMA, report_run_id=None)
elapsed = round(time.time() - t0, 1)
print("result", json.dumps(result, default=str))
run = fetchone(
    db,
    "SELECT id, status, error FROM report_runs WHERE job_id=:jid ORDER BY created_at DESC LIMIT 1",
    {"jid": JOB},
)
if run:
    rid = str(run["id"])
    rows = fetchall(
        db,
        """SELECT section_key, confidence_grade, length(content_md) len
           FROM report_sections WHERE report_run_id=:rid ORDER BY sort_order""",
        {"rid": rid},
    )
    print(f"run_id={rid} status={run.get('status')} sections={len(rows)} elapsed={elapsed}s")
    for r in rows:
        print(f"  {r['section_key']}: grade={r.get('confidence_grade')} len={r.get('len')}")
db.close()
