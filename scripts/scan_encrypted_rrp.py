import time
from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

rows = fetchall(
    db,
    """SELECT file_path, size_bytes FROM job_artifacts
       WHERE job_id=:j AND size_bytes > 100
       AND file_path ILIKE '%RRP%'
       AND (
         lower(coalesce(extension,'')) IN ('.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.zip','.7z')
         OR file_path ILIKE '%.pdf' OR file_path ILIKE '%.xlsx'
       )
       ORDER BY size_bytes DESC""",
    {"j": j},
)
print("rrp docs", len(rows))
enc = 0
for i in range(0, len(rows), 50):
    contents = _read_job_files(db, j, rows[i : i + 50])
    for row in rows[i : i + 50]:
        path = row["file_path"].replace("\\", "/")
        data = contents.get(path)
        if not data:
            continue
        s = data[:65536]
        if (
            b"/Encrypt" in s
            or b"EncryptedPackage" in s
            or b"EncryptionInfo" in s
            or (data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and b"EncryptedPackage" in s)
        ):
            enc += 1
            print("ENC", path)
print("rrp encrypted", enc)

# OLE-header xlsx/docx (password protected office)
rows2 = fetchall(
    db,
    """SELECT file_path FROM job_artifacts WHERE job_id=:j AND size_bytes>100
       AND lower(coalesce(extension,'')) IN ('.xlsx','.docx','.pptx','.xls','.doc','.ppt')
       AND file_path NOT ILIKE '%Program Files%' LIMIT 500""",
    {"j": j},
)
ole_enc = 0
for i in range(0, len(rows2), 100):
    contents = _read_job_files(db, j, rows2[i : i + 100])
    for row in rows2[i : i + 100]:
        data = contents.get(row["file_path"].replace("\\", "/"))
        if data and data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            if b"EncryptedPackage" in data[:131072]:
                ole_enc += 1
print("ole office encrypted", ole_enc, "of", len(rows2))
db.close()
