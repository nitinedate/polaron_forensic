from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone
from app.services.artifact_preview import resolve_artifact_bytes
from app.services.mobile_forensic.sqlite_counts import analyze_sms_db

JOB = "02bcb441-d1de-45b0-8a79-9c9139f08875"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
try:
    row = fetchone(
        db,
        """SELECT id, file_path, file_name, size_bytes, minio_uri, extension
           FROM job_artifacts
           WHERE job_id=:j AND lower(file_name)='sms.db'
           ORDER BY size_bytes DESC NULLS LAST LIMIT 1""",
        {"j": JOB},
    )
    print("sms.db", row["file_path"] if row else None)
    if row:
        data = resolve_artifact_bytes(db, JOB, dict(row), persist=False, max_bytes=200 * 1024 * 1024)
        print("bytes", len(data) if data else 0)
        print(analyze_sms_db(data or b"", row["file_path"]))
finally:
    db.close()
