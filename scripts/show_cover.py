from sqlalchemy import text
from app.db.session import SessionLocal

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
row = db.execute(
    text("SELECT content_md FROM report_sections WHERE section_key='cover_page' AND job_id=:j ORDER BY updated_at DESC LIMIT 1"),
    {"j": JOB},
).scalar()
print("=== COVER ===")
print(row[:2500] if row else "none")
intake = db.execute(text("SELECT * FROM case_intake WHERE job_id=:j"), {"j": JOB}).mappings().first()
print("\n=== INTAKE ===")
for k in ["case_type", "report_type", "organization", "case_number", "examiner_name", "requesting_agency", "lab_location", "subjects", "background", "incident_summary"]:
    print(k, ":", intake.get(k) if intake else None)
db.close()
