from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
rows = fetchall(
    db,
    """SELECT ja.file_path, apr.normalized::text n
       FROM job_artifacts ja
       JOIN artifact_parse_results apr ON apr.job_artifact_id=ja.id
       WHERE ja.job_id=:jid AND (
         apr.normalized::text ILIKE '%profile_list%'
         OR ja.file_path ILIKE '%ProfileList%'
         OR ja.file_path ILIKE '%SOFTWARE%'
       )
       LIMIT 10""",
    {"jid": JOB},
)
print("rows", len(rows))
for r in rows:
    print(r["file_path"], (r["n"] or "")[:150])
db.close()
