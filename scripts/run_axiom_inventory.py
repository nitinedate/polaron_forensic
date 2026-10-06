from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.axiom_artifact_runner import run_axiom_artifact_inventory

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
result = run_axiom_artifact_inventory(db, job, schema_name="firm_aetheris")
print(result)
db.close()
