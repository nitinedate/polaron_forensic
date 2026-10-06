from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchall

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
rows = fetchall(
    db,
    """SELECT ja.file_path, left(apr.normalized::text, 300) n
       FROM job_artifacts ja
       JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
       WHERE ja.job_id=:jid AND (
         apr.normalized::text ILIKE '%product_name%'
         OR apr.normalized::text ILIKE '%ProductName%'
         OR apr.normalized::text ILIKE '%windows_os%'
         OR ja.file_path ILIKE '%/SAM'
       )
       LIMIT 15""",
    {"jid": JOB},
)
for r in rows:
    print(r["file_path"])
    print(r["n"][:200])
    print("---")
db.close()
