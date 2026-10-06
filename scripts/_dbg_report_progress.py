from sqlalchemy import text
from app.db.session import SessionLocal

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
db = SessionLocal()
try:
    db.execute(text("SET search_path TO firm_aetheris, public"))
    run = db.execute(
        text(
            """
            SELECT id, status, error,
                   left(coalesce(progress::text, ''), 400) AS progress
            FROM report_runs
            WHERE job_id=:j
            ORDER BY created_at DESC
            LIMIT 1
            """
        ),
        {"j": JOB},
    ).mappings().first()
    print("run", dict(run) if run else None)
    if run:
        n = db.execute(
            text("SELECT count(*) FROM report_sections WHERE report_run_id=:r"),
            {"r": str(run["id"])},
        ).scalar()
        print("sections", n)
    print(
        "job",
        db.execute(text("SELECT status FROM jobs WHERE id=:j"), {"j": JOB}).scalar(),
    )
finally:
    db.close()
