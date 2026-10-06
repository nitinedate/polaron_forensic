from sqlalchemy import text
from app.db.session import SessionLocal

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
print("report_runs table", db.execute(text("SELECT to_regclass('report_runs')")).scalar())
rows = db.execute(
    text("SELECT id, status, error, started_at FROM report_runs WHERE job_id=:j ORDER BY created_at DESC LIMIT 3"),
    {"j": "4316aaf4-4eb7-4704-a692-905e0d3e6246"},
).fetchall()
print("runs", rows)
sec = db.execute(
    text("SELECT count(*) FROM report_sections rs JOIN report_runs rr ON rr.id=rs.report_run_id WHERE rr.job_id=:j"),
    {"j": "4316aaf4-4eb7-4704-a692-905e0d3e6246"},
).scalar()
print("sections", sec)
db.close()
