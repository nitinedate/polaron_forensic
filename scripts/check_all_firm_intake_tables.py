from sqlalchemy import text
from app.db.session import SessionLocal

db = SessionLocal()
firms = db.execute(text("SELECT slug, schema_name FROM firms ORDER BY slug")).mappings().all()
for firm in firms:
    schema = firm["schema_name"]
    t = db.execute(
        text("SELECT to_regclass(:name)"),
        {"name": f"{schema}.case_intake"},
    ).scalar()
    print(firm["slug"], schema, "case_intake", t)
db.close()
