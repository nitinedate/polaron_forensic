from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
row = fetchone(
    db,
    """SELECT apr.normalized FROM job_artifacts ja
       JOIN artifact_parse_results apr ON apr.job_artifact_id=ja.id
       WHERE ja.job_id=:jid AND ja.file_path ILIKE '%/SYSTEM' LIMIT 1""",
    {"jid": JOB},
)
norm = row.get("normalized") if row else None
if isinstance(norm, str):
    norm = json.loads(norm)
text = json.dumps(norm or [])
for needle in ("product", "windows", "build", "22631", "version", "11"):
    if needle.lower() in text.lower():
        print("found", needle)
print("sample records:", text[:3000])
db.close()
