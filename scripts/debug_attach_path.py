from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
rows = fetchall(
    db,
    "SELECT file_path FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%Attachments%'",
    {"j": j},
)
print(len(rows))
for r in rows:
    print(r["file_path"])
db.close()
