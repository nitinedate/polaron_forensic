from sqlalchemy import text
from app.db.session import firm_session
from app.services.report_generator import _intake_ready
from app.config import get_settings
import urllib.request

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
SCHEMA = "firm_aetheris"

print("OLLAMA_BASE_URL", get_settings().ollama_base_url)
try:
    print("ollama_http", urllib.request.urlopen(get_settings().ollama_base_url.rstrip("/") + "/api/tags", timeout=5).status)
except Exception as exc:
    print("ollama_http_err", exc)

with firm_session(SCHEMA) as db:
    print("search_path", db.execute(text("SHOW search_path")).scalar())
    print("postgres_inet", db.execute(text("SELECT inet_server_addr()")).scalar())
    ready, missing = _intake_ready(db, JOB)
    print("intake_ready", ready, missing)
    job = db.execute(text("SELECT id, status FROM jobs WHERE id=:j"), {"j": JOB}).mappings().first()
    print("job", dict(job) if job else None)
    intake = db.execute(text("SELECT job_id, case_type, report_type, subjects, objective_ids FROM case_intake WHERE job_id=:j"), {"j": JOB}).mappings().first()
    print("intake", dict(intake) if intake else None)
    run = db.execute(
        text(
            "SELECT id, status, duration_ms FROM report_runs WHERE job_id=:j "
            "ORDER BY created_at DESC LIMIT 1"
        ),
        {"j": JOB},
    ).mappings().first()
    print("latest_run", dict(run) if run else None)
    if run:
        print(
            "sections",
            db.execute(
                text("SELECT count(*) FROM report_sections WHERE report_run_id=:r"),
                {"r": str(run["id"])},
            ).scalar(),
        )
