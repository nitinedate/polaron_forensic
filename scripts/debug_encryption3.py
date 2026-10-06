from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

rows = fetchall(
    db,
    """SELECT file_path, metadata FROM job_artifacts
       WHERE job_id=:j AND metadata IS NOT NULL AND metadata::text ILIKE '%encrypt%'
       LIMIT 10""",
    {"j": j},
)
print("metadata encrypt samples", len(rows))
for r in rows:
    print(r)

# Credential store files
cred_queries = [
    ("credentials_dir", "file_path ILIKE '%Microsoft/Credentials%'"),
    ("vault", "file_path ILIKE '%Vault%' AND file_path ILIKE '%AppData%'"),
    ("vpol", "file_name ILIKE 'Policy.vpol'"),
    ("credman", "file_path ILIKE '%CredentialManager%'"),
    ("webcred", "file_path ILIKE '%Web Credentials%'"),
    ("dpapi_master", "file_path ILIKE '%Microsoft/Protect/%'"),
]
for name, w in cred_queries:
    c = fetchone(db, f"SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND ({w})", {"j": j})
    print(name, c["c"])

db.close()
