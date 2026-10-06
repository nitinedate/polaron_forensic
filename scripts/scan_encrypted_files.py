import time
from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files
from app.services.encryption_detect import is_encrypted_file

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts
       WHERE job_id=:j AND size_bytes > 64 AND (
         lower(coalesce(extension,'')) IN (
           '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
           '.zip','.7z','.rar','.aes','.enc','.gpg','.pgp','.kdbx'
         )
         OR file_path ILIKE '%.pdf'
         OR file_path ILIKE '%.doc'
         OR file_path ILIKE '%.docx'
         OR file_path ILIKE '%.xls'
         OR file_path ILIKE '%.xlsx'
         OR file_path ILIKE '%.ppt'
         OR file_path ILIKE '%.pptx'
       )
       AND file_path NOT ILIKE '%Program Files%'
       AND file_path NOT ILIKE '%WindowsApps%'
       ORDER BY size_bytes DESC""",
    {"j": j},
)
print("candidates", len(rows))
t0 = time.time()
found = []
for i in range(0, len(rows), 200):
    batch = rows[i : i + 200]
    contents = _read_job_files(db, j, batch)
    for row in batch:
        path = row["file_path"].replace("\\", "/")
        data = contents.get(path)
        if not data:
            continue
        if is_encrypted_file(data, path):
            found.append(path)
    print("scanned", min(i + 200, len(rows)), "found", len(found))

print("total encrypted", len(found), "seconds", round(time.time() - t0, 1))
for p in found[:15]:
    print(p)
db.close()
