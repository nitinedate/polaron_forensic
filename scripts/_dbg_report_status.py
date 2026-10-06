"""Inspect latest report_runs for the mobile job."""
from sqlalchemy import text
from app.db.session import SessionLocal

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
db = SessionLocal()
try:
    db.execute(text("SET search_path TO firm_aetheris, public"))
    job = db.execute(
        text("SELECT id, status, updated_at FROM jobs WHERE id=:j"),
        {"j": JOB},
    ).mappings().first()
    print("job", dict(job) if job else None)
    runs = db.execute(
        text(
            """
            SELECT id, status, error, created_at, started_at, completed_at,
                   left(coalesce(progress::text,''), 400) AS progress
            FROM report_runs
            WHERE job_id=:j
            ORDER BY created_at DESC
            LIMIT 5
            """
        ),
        {"j": JOB},
    ).mappings().all()
    print("runs", len(runs))
    for r in runs:
        print(dict(r))
    secs = db.execute(
        text(
            """
            SELECT count(*) AS n,
                   count(*) FILTER (WHERE status='ready' OR draft_markdown IS NOT NULL) AS with_body
            FROM report_sections rs
            JOIN report_runs rr ON rr.id = rs.report_run_id
            WHERE rr.job_id=:j
              AND rr.id = (SELECT id FROM report_runs WHERE job_id=:j ORDER BY created_at DESC LIMIT 1)
            """
        ),
        {"j": JOB},
    ).mappings().first()
    print("sections", dict(secs) if secs else None)
finally:
    db.close()
