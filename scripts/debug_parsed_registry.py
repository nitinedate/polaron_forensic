from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

# SOFTWARE hive presence
r = fetchone(
    db,
    """SELECT count(*) c FROM job_artifacts
       WHERE job_id=:j AND (
         file_path ILIKE '%/config/SOFTWARE'
         OR lower(file_name)='software'
       )""",
    {"j": job},
)
print("SOFTWARE hive count", r)

# Parsed registry records
for rt in ("installed_program", "feature_usage", "usb_device"):
    r = fetchone(
        db,
        """SELECT count(*) c FROM artifact_parse_results apr
           JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
           WHERE ja.job_id=:j AND apr.normalized::text ILIKE :pat""",
        {"j": job, "pat": f"%{rt}%"},
    )
    print("parsed", rt, r)

# Sample feature usage parse
rows = fetchall(
    db,
    """SELECT ja.file_path, apr.normalized
       FROM artifact_parse_results apr
       JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
       WHERE ja.job_id=:j AND apr.normalized::text ILIKE '%feature_usage%'
       LIMIT 5""",
    {"j": job},
)
print("feature samples", len(rows))
for row in rows:
    print(row["file_path"], str(row["normalized"])[:200])

db.close()
