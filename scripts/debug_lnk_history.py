from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

queries = [
    ("ext_lnk", "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND lower(coalesce(extension,''))='.lnk'"),
    ("path_lnk", "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%.lnk'"),
    ("ency_lnk", "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND encyclopedia_artifact_id='WFS-SHL-0001'"),
    ("history_files", """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND size_bytes>512 AND (
      lower(file_name) IN ('history','places.sqlite') OR file_path ILIKE '%/History' OR file_path ILIKE '%/places.sqlite'
    )"""),
    ("history_total_size", """SELECT count(*) c, sum(size_bytes) s FROM job_artifacts WHERE job_id=:j AND size_bytes>512 AND (
      lower(file_name) IN ('history','places.sqlite') OR file_path ILIKE '%/History' OR file_path ILIKE '%/places.sqlite'
      OR file_path ILIKE '%/Web Data' OR file_path ILIKE '%/History.db'
    )"""),
]
for name, q in queries:
    r = fetchone(db, q, {"j": job})
    print(name, r)

rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND size_bytes>512 AND (
      lower(file_name) IN ('history','places.sqlite') OR file_path ILIKE '%/History' OR file_path ILIKE '%/places.sqlite'
      OR file_path ILIKE '%/Web Data' OR file_path ILIKE '%/History.db'
    ) ORDER BY size_bytes DESC LIMIT 15""",
    {"j": job},
)
print("top history files:")
for r in rows:
    print(r["size_bytes"], r["file_path"])
db.close()
