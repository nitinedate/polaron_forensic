import time
from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_live_counts import _read_job_files

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

for label, sql in [
    ("pdf", """SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND (
      lower(coalesce(extension,''))='.pdf' OR file_path ILIKE '%.pdf'
    ) AND size_bytes>100 AND file_path NOT ILIKE '%Program Files%'"""),
    ("office", """SELECT file_path, size_bytes FROM job_artifacts WHERE job_id=:j AND (
      lower(coalesce(extension,'')) IN ('.doc','.docx','.xls','.xlsx','.ppt','.pptx')
    ) AND size_bytes>100 AND file_path NOT ILIKE '%Program Files%'"""),
]:
    rows = fetchall(db, sql, {"j": j})
    print(label, "candidates", len(rows))
    enc = 0
    t0 = time.time()
    for i in range(0, len(rows), 100):
        batch = rows[i : i + 100]
        contents = _read_job_files(db, j, batch)
        for row in batch:
            path = row["file_path"].replace("\\", "/")
            data = contents.get(path)
            if not data:
                continue
            sample = data[:65536]
            hit = False
            if label == "pdf":
                hit = b"/Encrypt" in sample or b"/Filter/Standard" in sample
            else:
                hit = (
                    b"EncryptedPackage" in sample
                    or b"EncryptionInfo" in sample
                    or b"RightsManagement" in sample
                    or b"DRMContent" in sample
                    or b"StandardPassword" in sample
                )
            if hit:
                enc += 1
        if i % 500 == 0:
            print(f"  scanned {min(i+100,len(rows))} enc={enc}")
    print(label, "encrypted", enc, "sec", round(time.time()-t0,1))

db.close()
