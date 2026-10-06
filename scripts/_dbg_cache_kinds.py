"""Inspect WA deleted browse caches under firm_aetheris."""
from sqlalchemy import text
from app.db.session import SessionLocal

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"

db = SessionLocal()
try:
    db.execute(text("SET search_path TO firm_aetheris, public"))
    rows = db.execute(
        text(
            """
            SELECT cache_kind,
                   length(payload::text) AS nbytes,
                   jsonb_typeof(payload) AS t,
                   CASE WHEN jsonb_typeof(payload)='array'
                        THEN jsonb_array_length(payload) ELSE NULL END AS n
            FROM job_evidence_browse_cache
            WHERE job_id=:j
            ORDER BY cache_kind
            """
        ),
        {"j": JOB},
    ).mappings().all()
    print("caches:")
    for r in rows:
        print(" ", dict(r))
    if not rows:
        print("  (none)")
    arts = db.execute(
        text("SELECT count(*) FROM job_artifacts WHERE job_id=:j"),
        {"j": JOB},
    ).scalar()
    print("job_artifacts", arts)
finally:
    db.close()
