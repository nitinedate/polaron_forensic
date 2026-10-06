from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
rows = fetchall(
    db,
    """SELECT file_path, parse_status FROM job_artifacts
       WHERE job_id=:jid AND (
         file_path ILIKE 'Windows/System32/config/SAM'
         OR file_path ILIKE 'Windows/System32/config/SOFTWARE'
         OR file_path ILIKE 'Windows/System32/config/SECURITY'
         OR file_path ILIKE '%ProfileList%'
       )""",
    {"jid": JOB},
)
print("artifacts", rows)
row = fetchall(
    db,
    """SELECT apr.normalized FROM job_artifacts ja
       JOIN artifact_parse_results apr ON apr.job_artifact_id=ja.id
       WHERE ja.job_id=:jid AND ja.file_path ILIKE 'Windows/System32/config/SAM'""",
    {"jid": JOB},
)
if row:
    norm = row[0]["normalized"]
    if isinstance(norm, str):
        norm = json.loads(norm)
    sam_users = [r for r in norm if isinstance(r, dict) and r.get("record_type") == "sam_user"]
    print("sam_user count", len(sam_users))
    for u in sam_users[:12]:
        print(u)
db.close()
