from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

# Axiom catalog
rows = fetchall(
    db,
    """SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts
       WHERE platform='Windows' AND category ILIKE '%encrypt%' OR category ILIKE '%credential%'
       ORDER BY artifact_name""",
)
print("catalog", len(rows))
for r in rows:
    print(r)

# File patterns
patterns = [
    ("bitlocker", "%bitlocker%"),
    ("efsv", "%.efs%"),
    ("encrypted_ext", "%encrypted%"),
    ("vc", "%.vc%"),
    ("cred", "%Credentials%"),
    ("vault", "%Vault%"),
    ("dpapi", "%DPAPI%"),
]
for name, p in patterns:
    c = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND file_path ILIKE :p", {"j": j, "p": p})
    print(name, c["c"])

db.close()
