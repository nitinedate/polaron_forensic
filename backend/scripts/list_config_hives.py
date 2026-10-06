from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
rows = fetchall(
    db,
    """SELECT file_path, parse_status FROM job_artifacts
       WHERE job_id=:jid AND file_path ILIKE 'Windows/System32/config/%'
       ORDER BY file_path LIMIT 30""",
    {"jid": JOB},
)
for r in rows:
    print(r["file_path"], r["parse_status"])
db.close()
