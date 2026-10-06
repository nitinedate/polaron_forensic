from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

r = fetchone(
    db,
    """SELECT count(*) c FROM artifact_parse_results apr
       JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
       WHERE ja.job_id=:j AND (
         apr.normalized::text ILIKE '%email%'
         OR apr.normalized::text ILIKE '%outlook%'
         OR apr.normalized::text ILIKE '%message%'
       )""",
    {"j": j},
)
print("parse email-like", r)

rows = fetchall(
    db,
    """SELECT ja.file_path, left(apr.normalized::text, 200) n
       FROM artifact_parse_results apr
       JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
       WHERE ja.job_id=:j AND (
         apr.normalized::text ILIKE '%email%'
         OR ja.file_path ILIKE '%.msg'
       ) LIMIT 10""",
    {"j": j},
)
for r in rows:
    print(r)

db.close()
