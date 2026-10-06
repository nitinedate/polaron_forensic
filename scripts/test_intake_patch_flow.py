import json
from app.db.session import SessionLocal, reset_search_path, apply_firm_search_path
from app.db.sql_helpers import fetchone, execute

job_id = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
schema = "firm_aetheris"

db = SessionLocal()
reset_search_path(db)
apply_firm_search_path(db, schema)

existing = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": job_id})
fields = {
    "case_type": "Data Leakage",
    "organization": "RRP",
    "background": "test background",
    "incident_summary": None,
    "report_type": "general",
    "objective_ids": json.dumps(["user_activity"]),
    "custom_objectives": json.dumps([]),
    "subjects": json.dumps([{"name": "nitin edate", "email": "ndate1976@gmail.com", "role": "Test"}]),
    "scan_scope_json": json.dumps({}),
    "requesting_agency": None,
    "case_number": None,
    "examiner_name": None,
    "lab_location": None,
    "evidence_received_date": None,
    "chain_of_custody_ref": None,
    "vol18_form_json": json.dumps({}),
}
execute(
    db,
    """UPDATE case_intake SET case_type=:case_type, organization=:organization, background=:background,
       incident_summary=:incident_summary, report_type=:report_type, objective_ids=CAST(:objective_ids AS jsonb),
       custom_objectives=CAST(:custom_objectives AS jsonb), subjects=CAST(:subjects AS jsonb),
       scan_scope_json=CAST(:scan_scope_json AS jsonb),
       requesting_agency=:requesting_agency, case_number=:case_number, examiner_name=:examiner_name,
       lab_location=:lab_location, evidence_received_date=:evidence_received_date,
       chain_of_custody_ref=:chain_of_custody_ref,
       vol18_form_json=CAST(:vol18_form_json AS jsonb), updated_at=NOW()
       WHERE job_id=:jid""",
    {**fields, "jid": job_id},
)
db.commit()
apply_firm_search_path(db, schema)
row = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})
print("saved ok", row is not None, row.get("case_type") if row else None)
db.close()
