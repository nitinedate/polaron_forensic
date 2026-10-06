from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import count_browser_url_hits, _read_job_files, _count_chrome_sqlite, _count_firefox_sqlite
import re

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

pats = [
    re.compile(
        r"facebook\.com|instagram\.com|twitter\.com|x\.com|linkedin\.com|"
        r"tiktok\.com|reddit\.com|pinterest\.com|youtube\.com",
        re.I,
    ),
]

rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts
       WHERE job_id=:j AND size_bytes > 512 AND (
         lower(file_name) IN ('history', 'places.sqlite')
         OR file_path ILIKE '%/History'
         OR file_path ILIKE '%/places.sqlite'
         OR file_path ILIKE '%/Web Data'
         OR file_path ILIKE '%/History.db'
       )
       ORDER BY size_bytes DESC""",
    {"j": job},
)
print("history candidates", len(rows))
contents = _read_job_files(db, job, rows)
total_visits = 0
total_urls = 0
for row in rows:
    path = (row.get("file_path") or "").replace("\\", "/")
    data = contents.get(path)
    if not data or len(data) < 512:
        continue
    low = path.lower()
    if "firefox" in low or "mozilla" in low:
        v = _count_chrome_sqlite(data, pats, count_visits=True)
        u = _count_chrome_sqlite(data, pats, count_visits=False)
    else:
        v = _count_chrome_sqlite(data, pats, count_visits=True)
        u = _count_chrome_sqlite(data, pats, count_visits=False)
    if v or u:
        print(path[-60:], "visits", v, "urls", u)
    total_visits += v
    total_urls += u
print("TOTAL visits", total_visits, "TOTAL urls", total_urls)
db.close()
