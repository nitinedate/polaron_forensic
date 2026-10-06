from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.axiom_catalog_ingest import compute_axiom_artifact_counts

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
counts = compute_axiom_artifact_counts(db, job, "Windows")

rows = db.execute(
    text("""SELECT artifact_name, artifact_count FROM job_axiom_artifact_results jar
            JOIN public.axiom_artifacts aa ON aa.artifact_id = jar.artifact_id
            WHERE jar.job_id=:j AND aa.category ILIKE '%email%'
            ORDER BY artifact_count DESC, artifact_name LIMIT 25"""),
    {"j": job},
).mappings().all()

print("from compute (top email):")
for r in rows:
    if int(r["artifact_count"] or 0) > 0:
        print(f"  {r['artifact_count']:>6}  {r['artifact_name']}")

# Update DB
from app.db.sql_helpers import execute
for aid, cnt in counts.items():
    if cnt <= 0:
        continue
    execute(
        db,
        """UPDATE job_axiom_artifact_results SET artifact_count=:c, status='done', updated_at=NOW()
           WHERE job_id=:j AND artifact_id=:aid""",
        {"j": job, "c": cnt, "aid": aid},
    )
db.commit()
print("updated nonzero", sum(1 for v in counts.values() if v > 0))
db.close()
