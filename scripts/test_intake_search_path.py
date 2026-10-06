from sqlalchemy import text
from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone

db = SessionLocal()
db.execute(text("SET search_path TO public"))
firm = db.execute(text("SELECT slug, schema_name FROM firms WHERE slug='aetheris'")).mappings().first()
print("firm", dict(firm) if firm else None)
if firm:
    schema = firm["schema_name"]
    apply_firm_search_path(db, schema)
    t = db.execute(text("SELECT to_regclass('case_intake')")).scalar()
    print("case_intake in schema", schema, "->", t)
    # simulate patch_intake first query
    row = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": "4316aaf4-4eb7-4704-a692-905e0d3e6246"})
    print("existing intake", row)
    db.commit()
    # after commit - search path may be lost
    sp = db.execute(text("SHOW search_path")).scalar()
    print("search_path after commit", sp)
    apply_firm_search_path(db, schema)
    row2 = fetchone(db, "SELECT id FROM case_intake WHERE job_id=:jid", {"jid": "4316aaf4-4eb7-4704-a692-905e0d3e6246"})
    print("after reapply", row2)
db.close()
