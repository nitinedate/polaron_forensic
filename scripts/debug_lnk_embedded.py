from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files
from app.parsers.jumplist import parse_jump_list

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
rows = fetchall(
    db,
    """SELECT file_path FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%.automaticDestinations-ms'""",
    {"j": job},
)
contents = _read_job_files(db, job, rows)
entry_total = embedded_total = stream_total = 0
for row in rows:
    path = row["file_path"].replace("\\", "/")
    data = contents.get(path)
    if not data:
        continue
    for rec in parse_jump_list(data, path):
        if rec.get("record_type") != "jump_list_file":
            continue
        entry_total += int(rec.get("entry_count") or 0)
        embedded_total += int(rec.get("embedded_lnk_count") or 0)
print("files", len(rows), "entries", entry_total, "embedded", embedded_total)
print("fs_lnk 625 + embedded =", 625 + embedded_total)
print("fs_lnk 625 + entries =", 625 + entry_total)
db.close()
