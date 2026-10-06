from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall, fetchone

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

queries = {
    "eml": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND (lower(coalesce(extension,''))='.eml' OR file_path ILIKE '%.eml')",
    "msg": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND (lower(coalesce(extension,''))='.msg' OR file_path ILIKE '%.msg')",
    "pst": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND (lower(coalesce(extension,''))='.pst' OR file_path ILIKE '%.pst')",
    "ost": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND (lower(coalesce(extension,''))='.ost' OR file_path ILIKE '%.ost')",
    "eml_enc": "SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND encyclopedia_artifact_id LIKE 'EML-%'",
}
for name, q in queries.items():
    print(name, fetchone(db, q, {"j": j}))

rows = fetchall(
    db,
    """SELECT file_path, extension, size_bytes, encyclopedia_artifact_id
       FROM job_artifacts WHERE job_id=:j AND (
         lower(coalesce(extension,'')) IN ('.eml','.msg','.pst','.ost')
         OR file_path ILIKE '%Outlook%'
         OR file_path ILIKE '%Windows Mail%'
         OR file_path ILIKE '%/Mail/%'
         OR encyclopedia_artifact_id LIKE 'EML-%'
       )
       ORDER BY size_bytes DESC NULLS LAST LIMIT 25""",
    {"j": j},
)
print("samples", len(rows))
for r in rows:
    print(r)

# Axiom email catalog names
ax = fetchall(
    db,
    """SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts
       WHERE platform='Windows' AND category ILIKE '%email%' ORDER BY artifact_name LIMIT 40""",
)
print("axiom email catalog", len(ax))
for r in ax:
    print(r)

db.close()
