from sqlalchemy import text
from app.db.session import SessionLocal
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = db.execute(text("SELECT disk_source, status FROM jobs WHERE id=:j"), {"j": JOB}).mappings().first()
print("job", job)
ev = db.execute(text("SELECT original_name, sha1, size_bytes, host_path FROM evidence_files WHERE job_id=:j"), {"j": JOB}).fetchall()
print("evidence", ev)
db.close()
