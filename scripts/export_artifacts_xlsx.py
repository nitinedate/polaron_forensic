from pathlib import Path
from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_export import build_catalog_export_for_job

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
xlsx = build_catalog_export_for_job(db, job, job_label=job[:8])
out = Path("/tmp/artifacts_4316aaf4_new.xlsx")
out.write_bytes(xlsx)
print("wrote", out, "bytes", len(xlsx))
db.close()
