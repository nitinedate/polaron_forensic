from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

rows = fetchall(
    db,
    """SELECT file_path, extension, size_bytes FROM job_artifacts
       WHERE job_id=:j AND (
         lower(file_path) LIKE '%.eml'
         OR lower(file_path) LIKE '%.emlx'
         OR lower(coalesce(extension,'')) IN ('.eml','.emlx')
       )
       ORDER BY file_path LIMIT 100""",
    {"j": j},
)
print("eml files", len(rows))
for r in rows:
    print(r)

# eml in path substring
rows2 = fetchall(
    db,
    """SELECT file_path FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%eml%'
       AND file_path NOT ILIKE '%Program Files%'
       AND file_path NOT ILIKE '%.dll%'
       ORDER BY file_path LIMIT 30""",
    {"j": j},
)
print("eml substring", len(rows2))
for r in rows2:
    print(r["file_path"])

db.close()
