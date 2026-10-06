from sqlalchemy import text
from app.db.session import SessionLocal

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
cover = db.execute(
    text(
        """SELECT content_md FROM report_sections rs
           JOIN report_runs rr ON rr.id=rs.report_run_id
           WHERE rs.job_id=:j AND rs.section_key='cover_page'
           ORDER BY rr.created_at DESC LIMIT 1"""
    ),
    {"j": JOB},
).scalar()
intro = db.execute(
    text(
        """SELECT content_md FROM report_sections rs
           JOIN report_runs rr ON rr.id=rs.report_run_id
           WHERE rs.job_id=:j AND rs.section_key='introduction'
           ORDER BY rr.created_at DESC LIMIT 1"""
    ),
    {"j": JOB},
).scalar()
n = db.execute(
    text(
        """SELECT count(*) FROM report_sections rs
           JOIN report_runs rr ON rr.id=rs.report_run_id
           WHERE rs.job_id=:j AND rr.id=(
             SELECT id FROM report_runs WHERE job_id=:j ORDER BY created_at DESC LIMIT 1
           )"""
    ),
    {"j": JOB},
).scalar()
print("sections", n)
print("=== COVER ===")
print(cover)
print("=== INTRO (first 600) ===")
print((intro or "")[:600])
db.close()
