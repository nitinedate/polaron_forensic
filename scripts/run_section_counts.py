from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_sections import build_job_artifact_sections

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
inv = build_job_artifact_sections(db, job, schema_name="firm_aetheris")
for sec in inv["sections"]:
    if sec["title"] in (
        "Connected Devices",
        "Application Usages",
        "Communication",
        "Documents",
        "Media",
        "Operating System",
    ):
        print("==", sec["title"], "total", sec["count"])
        for it in sec["items"]:
            print(f"  {it['title']}: {it['count']}")
db.close()
