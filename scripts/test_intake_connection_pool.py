from sqlalchemy import text
from app.db.session import SessionLocal, apply_firm_search_path, reset_search_path
from app.db.sql_helpers import fetchone, execute

job_id = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
schema = "firm_aetheris"

db = SessionLocal()
reset_search_path(db)
apply_firm_search_path(db, schema)

execute(
    db,
    "UPDATE case_intake SET case_type=:case_type, updated_at=NOW() WHERE job_id=:jid",
    {"case_type": "Test2", "jid": job_id},
)
db.commit()

conn1 = db.connection().connection
print("conn before close", id(conn1), db.execute(text("SHOW search_path")).scalar())

# Force connection return to pool (SQLAlchemy may do this on commit in some configs)
db.connection().close()

try:
    conn2 = db.connection().connection
    print("conn after re-checkout", id(conn2), db.execute(text("SHOW search_path")).scalar())
    row = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    print("row", row)
except Exception as exc:
    print("failed", type(exc).__name__, exc)

db.rollback()
db.close()
