from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
queries = {
    "all_lnk": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%.lnk'",
    "recent_lnk": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%Recent%.lnk'",
    "webcache": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%WebCache%'",
    "webcachev01": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_name ILIKE '%WebCacheV01.dat%'",
    "firefox_history": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%places.sqlite%'",
}
for name, q in queries.items():
    print(name, fetchone(db, q, {"j": j}))
db.close()
