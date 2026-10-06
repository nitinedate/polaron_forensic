from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

queries = [
    ("attachments", "%Attachments%"),
    ("olk_blob", "%Olk%indexeddb.blob%"),
    ("hxstore", "%HxStore.hxd%"),
    ("store_vol", "%store.vol%"),
    ("user_msg", "%.msg"),
]
for name, p in queries:
    r = fetchone(
        db,
        f"""SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE :p
            AND file_path NOT ILIKE '%Program Files%'""",
        {"j": j, "p": p},
    )
    print(name, r["c"])

db.close()
