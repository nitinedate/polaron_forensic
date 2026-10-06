from sqlalchemy import text
from app.db.session import SessionLocal, apply_firm_search_path, reset_search_path
from app.db.sql_helpers import fetchone, execute

job_id = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
schema = "firm_aetheris"

db = SessionLocal()
reset_search_path(db)
apply_firm_search_path(db, schema)

def conn_id():
    return id(db.connection().connection)

def show_sp(label):
    print(label, "conn", conn_id(), "search_path", db.execute(text("SHOW search_path")).scalar())

show_sp("start")
execute(db, "UPDATE case_intake SET case_type=:c, updated_at=NOW() WHERE job_id=:j", {"c": "T", "j": job_id})
show_sp("before commit")
db.commit()
show_sp("after commit")
try:
    row = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    show_sp("after select")
    print("row ok", row)
except Exception as exc:
    show_sp("after failed select")
    print("error", exc)
db.close()
