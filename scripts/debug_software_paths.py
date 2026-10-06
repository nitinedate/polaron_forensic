from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts
       WHERE job_id=:j AND (
         file_path ILIKE '%SOFTWARE%'
         OR file_path ILIKE '%RegBack%'
         OR file_path ILIKE '%config/%'
       )
       AND size_bytes > 100000
       ORDER BY size_bytes DESC LIMIT 30""",
    {"j": job},
)
for r in rows:
    print(r["size_bytes"], r["file_path"])
db.close()
