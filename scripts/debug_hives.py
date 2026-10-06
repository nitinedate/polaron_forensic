from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.parsers.registry import parse_registry_hive
from app.services.artifact_live_counts import _read_job_files

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

for label, q in [
    ("software_name", "SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND lower(file_name)='software' LIMIT 5"),
    ("software_path", "SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%/SOFTWARE' LIMIT 5"),
    ("software_like", "SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%software%' AND size_bytes>4096 ORDER BY size_bytes DESC LIMIT 10"),
]:
    rows = fetchall(db, q, {"j": job})
    print(f"--- {label} ({len(rows)})")
    for r in rows:
        print(r)

rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts
       WHERE job_id=:j AND size_bytes > 4096 AND (
         lower(file_name) IN ('software', 'system', 'ntuser.dat', 'usrclass.dat')
         OR file_path ILIKE '%/SOFTWARE'
         OR file_path ILIKE '%/SYSTEM'
         OR file_path ILIKE '%/NTUSER.DAT'
       )
       ORDER BY size_bytes DESC LIMIT 20""",
    {"j": job},
)
print("--- combined", len(rows))
for r in rows:
    print(r)

contents = _read_job_files(db, job, rows)
for path, data in contents.items():
    if not data:
        print("NO DATA", path)
        continue
    recs = parse_registry_hive(data, path)
    kinds = {}
    for rec in recs:
        rt = rec.get("record_type") or "other"
        kinds[rt] = kinds.get(rt, 0) + 1
    print(path, "records", len(recs), kinds)

db.close()
