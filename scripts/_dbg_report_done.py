from sqlalchemy import text
from app.db.session import SessionLocal

db = SessionLocal()
try:
    print("db", db.execute(text("SELECT current_database(), inet_server_addr(), inet_server_port()")).first())
    schemas = [
        r[0]
        for r in db.execute(
            text(
                "SELECT nspname FROM pg_namespace "
                "WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema'"
            )
        ).all()
    ]
    print("schemas", schemas)
    for sch in schemas:
        try:
            rows = db.execute(
                text(f"SELECT id::text, status FROM {sch}.jobs ORDER BY updated_at DESC LIMIT 10")
            ).all()
        except Exception as exc:
            continue
        if rows:
            print(sch, "jobs", rows)
        try:
            runs = db.execute(
                text(
                    f"SELECT id::text, job_id::text, status FROM {sch}.report_runs "
                    "ORDER BY created_at DESC LIMIT 5"
                )
            ).all()
        except Exception:
            runs = []
        if runs:
            print(sch, "runs", runs)
finally:
    db.close()
