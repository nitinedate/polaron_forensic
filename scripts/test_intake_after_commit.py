from sqlalchemy import text
from app.db.session import SessionLocal, apply_firm_search_path, reset_search_path
from app.db.sql_helpers import fetchone, execute

job_id = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
schema = "firm_aetheris"

db = SessionLocal()
reset_search_path(db)
apply_firm_search_path(db, schema)

existing = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": job_id})
print("step1 existing", existing)

execute(
    db,
    """UPDATE case_intake SET case_type=:case_type, updated_at=NOW() WHERE job_id=:jid""",
    {"case_type": "Test", "jid": job_id},
)
db.commit()
print("step2 search_path after commit", db.execute(text("SHOW search_path")).scalar())

try:
    row = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    print("step3 row without reapply", row is not None)
except Exception as exc:
    print("step3 failed", exc)

apply_firm_search_path(db, schema)
row2 = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})
print("step4 row after reapply", row2 is not None)
db.rollback()
db.close()
