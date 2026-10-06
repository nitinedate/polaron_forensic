"""Refresh B. ARTIFACTS section on the latest report run."""
from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import execute, fetchone
from app.services.artifact_report_service import gather_artifact_summary
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
SCHEMA = "firm_aetheris"

db = SessionLocal()
apply_firm_search_path(db, SCHEMA)
run = fetchone(
    db,
    "SELECT id FROM report_runs WHERE job_id=:jid ORDER BY created_at DESC LIMIT 1",
    {"jid": JOB},
)
if not run:
    print("no run")
    raise SystemExit(1)
rid = str(run["id"])
md, structured = gather_artifact_summary(db, JOB, schema_name=SCHEMA)
execute(
    db,
    """UPDATE report_sections SET content_md=:content, structured_json=CAST(:sj AS jsonb),
       confidence_grade='A', review_notes=CAST(:rn AS jsonb), updated_at=NOW()
       WHERE report_run_id=:rid AND section_key='artifact_summary'""",
    {
        "content": md,
        "sj": json.dumps(structured),
        "rn": '{"source": "selected_artifact_prompts"}',
        "rid": rid,
    },
)
db.commit()
print("categories", len(structured.get("categories") or []))
for cat in (structured.get("categories") or [])[:3]:
    print(cat.get("title"), len(cat.get("items") or []))
db.close()
