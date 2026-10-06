import re
import sqlite3
import tempfile
import os
from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchone
from app.services.artifact_live_counts import _read_job_files

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
row = fetchone(
    db,
    "SELECT file_path FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%Chrome/User Data/Default/History' LIMIT 1",
    {"j": job},
)
data = _read_job_files(db, job, [row])[row["file_path"].replace("\\", "/")]

patterns = [
    re.compile(
        r"facebook\.com|instagram\.com|twitter\.com|x\.com|linkedin\.com|"
        r"tiktok\.com|reddit\.com|pinterest\.com|youtube\.com|youtu\.be|"
        r"fb\.com|snapchat\.com|tumblr\.com|whatsapp\.com",
        re.I,
    ),
]

with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
    tmp.write(data)
    tmp_path = tmp.name

conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
cur = conn.cursor()

# visit_count sum
cur.execute("SELECT url, visit_count FROM urls WHERE url IS NOT NULL")
vc = 0
for url, visit_count in cur.fetchall():
    if patterns[0].search(str(url)):
        vc += max(int(visit_count or 0), 1)
print("visit_count method", vc)

# visits table rows
cur.execute(
    """SELECT u.url, COUNT(v.rowid) FROM urls u
       JOIN visits v ON v.url = u.id
       WHERE u.url IS NOT NULL GROUP BY u.url"""
)
vr = 0
for url, visits in cur.fetchall():
    if patterns[0].search(str(url)):
        vr += int(visits or 0)
print("visits table rows", vr)

# unique url rows
cur.execute("SELECT url FROM urls WHERE url IS NOT NULL")
uc = sum(1 for (url,) in cur.fetchall() if patterns[0].search(str(url)))
print("unique urls", uc)

conn.close()
os.unlink(tmp_path)
db.close()
