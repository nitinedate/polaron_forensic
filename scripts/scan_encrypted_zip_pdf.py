import zipfile, io
from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j
       AND (lower(coalesce(extension,''))='.zip' OR file_path ILIKE '%.zip')
       AND size_bytes > 100""",
    {"j": j},
)
print("zip files", len(rows))
enc_files = 0
enc_entries = 0
for i in range(0, len(rows), 20):
    contents = _read_job_files(db, j, rows[i : i + 20])
    for row in rows:
        data = contents.get(row["file_path"].replace("\\", "/"))
        if not data:
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                flags = [i.flag_bits & 1 for i in zf.infolist()]
                if any(flags):
                    enc_files += 1
                    enc_entries += sum(flags)
        except Exception:
            pass
print("encrypted zip containers", enc_files, "encrypted entries inside", enc_entries)

# PDF deeper scan - 512KB
rows = fetchall(
    db,
    """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
      lower(coalesce(extension,''))='.pdf' OR file_path ILIKE '%.pdf'
    ) AND size_bytes>100 AND file_path NOT ILIKE '%Program Files%'""",
    {"j": j},
)
enc_pdf = 0
for i in range(0, len(rows), 50):
    contents = _read_job_files(db, j, rows[i : i + 50])
    for row in rows[i : i + 50]:
        data = contents.get(row["file_path"].replace("\\", "/"))
        if not data:
            continue
        sample = data[: min(len(data), 524288)]
        if b"/Encrypt" in sample or b"/Filter/Standard" in sample:
            enc_pdf += 1
print("encrypted pdfs (512k scan)", enc_pdf, "of", len(rows))
db.close()
