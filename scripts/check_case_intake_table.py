from sqlalchemy import text
from app.db.session import SessionLocal

db = SessionLocal()
fn = db.execute(text("SELECT proname FROM pg_proc WHERE proname='apply_firm_phase3'")).fetchall()
print("apply_firm_phase3", fn)
db.execute(text("SET search_path TO firm_aetheris"))
t = db.execute(text("SELECT to_regclass('case_intake')")).scalar()
print("case_intake table", t)
rows = db.execute(
    text("SELECT tablename FROM pg_tables WHERE schemaname='firm_aetheris' ORDER BY tablename")
).fetchall()
print("tables count", len(rows))
print("has case_intake", any(r[0] == "case_intake" for r in rows))
db.close()
