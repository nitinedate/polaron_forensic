from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.storage import get_bytes
from app.services.artifact_live_counts import _HISTORY_SQL, _HIVE_SQL, _JUMPLIST_SQL

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

for label, sql in [("history", _HISTORY_SQL), ("hive", _HIVE_SQL), ("jump", _JUMPLIST_SQL)]:
    rows = fetchall(db, sql, {"j": job})
    print(label, "rows", len(rows))
    if rows:
        r = rows[0]
        data = get_bytes(r.get("minio_uri") or "")
        print("  sample", r.get("file_path"), "bytes", len(data) if data else None, "uri", (r.get("minio_uri") or "")[:80])
db.close()
