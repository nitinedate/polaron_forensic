from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
j = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
rows = fetchall(
    db,
    """SELECT aa.artifact_name, jar.artifact_count
       FROM job_axiom_artifact_results jar
       JOIN public.axiom_artifacts aa ON aa.artifact_id = jar.artifact_id
       WHERE jar.job_id=:j AND aa.category ILIKE '%email%'
       ORDER BY jar.artifact_count DESC, aa.artifact_name""",
    {"j": j},
)
nonzero = [r for r in rows if int(r["artifact_count"] or 0) > 0]
print(f"email artifacts nonzero: {len(nonzero)} / {len(rows)}")
for r in nonzero:
    print(f"  {int(r['artifact_count']):>6}  {r['artifact_name']}")
db.close()
