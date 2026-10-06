from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
row = fetchone(
    db,
    """SELECT count(*) c FROM job_artifacts
       WHERE job_id=:jid AND file_path = 'Windows/System32/config/SOFTWARE'""",
    {"jid": JOB},
)
print("SOFTWARE exact", row)
row2 = fetchone(
    db,
    """SELECT count(*) c FROM job_artifacts
       WHERE job_id=:jid AND file_path ILIKE '%System32/config/SOFTWARE'""",
    {"jid": JOB},
)
print("SOFTWARE ilike", row2)
db.close()
