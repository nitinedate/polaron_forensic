from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

# columns on job_artifacts
row = fetchone(db, "SELECT * FROM job_artifacts WHERE job_id=:j LIMIT 1", {"j": j})
print("columns", [k for k in row.keys() if 'encrypt' in k.lower() or 'efs' in k.lower() or 'meta' in k.lower()])

queries = [
    ("office_ext", """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND lower(coalesce(extension,'')) IN ('.doc','.docx','.xls','.xlsx','.ppt','.pptx','.pdf')"""),
    ("zip_7z", """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND lower(coalesce(extension,'')) IN ('.zip','.7z','.rar','.aes','.enc','.gpg','.pgp')"""),
    ("efs_stream", """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%:$EFS%'"""),
    ("encrypted_name", """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_name ILIKE '%encrypt%'"""),
    ("metadata_encrypt", """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND metadata::text ILIKE '%encrypt%'"""),
    ("parse_encrypt", """SELECT count(*) c FROM artifact_parse_results apr JOIN job_artifacts ja ON ja.id=apr.job_artifact_id WHERE ja.job_id=:j AND apr.normalized::text ILIKE '%encrypt%'"""),
]
for name, q in queries:
    print(name, fetchone(db, q, {"j": j})["c"])

# sample encrypted parse
rows = fetchall(
    db,
    """SELECT ja.file_path, left(apr.normalized::text, 180) n
       FROM artifact_parse_results apr JOIN job_artifacts ja ON ja.id=apr.job_artifact_id
       WHERE ja.job_id=:j AND apr.normalized::text ILIKE '%encrypt%' LIMIT 8""",
    {"j": j},
)
for r in rows:
    print(r)

# Windows credentials paths
for p in ["%Credentials%", "%Vault%", "%Policy.vpol%", "%LSA%Secrets%", "%DPAPI%"]:
    c = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE :p", {"j": j, "p": p})
    print("cred path", p, c["c"])

db.close()
