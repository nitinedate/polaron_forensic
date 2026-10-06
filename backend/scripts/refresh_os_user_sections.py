"""Regenerate OS + user profile sections on the latest report run."""
from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import execute, fetchone
from app.config import get_settings
from app.services.report_profile_sections import build_os_report_markdown, build_user_report_markdown
from app.services.report_renderer import section_title

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
SCHEMA = "firm_aetheris"
settings = get_settings()

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
primary = settings.llm_primary_model

for key, builder in (
    ("os_information", build_os_report_markdown),
    ("user_profile_information", build_user_report_markdown),
):
    md = builder(db, JOB, schema_name=SCHEMA, primary_model=primary)
    execute(
        db,
        """UPDATE report_sections SET content_md=:content, confidence_grade='A',
           review_notes=CAST(:rn AS jsonb), updated_at=NOW()
           WHERE report_run_id=:rid AND section_key=:key""",
        {
            "content": md,
            "rn": '{"source": "profile_facts_and_prompts"}',
            "rid": rid,
            "key": key,
        },
    )
    print("updated", key, "len", len(md))
db.commit()
db.close()
