import time
from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.email_inventory import compute_all_email_counts
from app.db.sql_helpers import execute, fetchall

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

t0 = time.time()
email_counts = compute_all_email_counts(db, job)
print("email scan seconds", round(time.time() - t0, 1))
for k, v in sorted(email_counts.items(), key=lambda x: -x[1])[:15]:
    if v > 0:
        print(v, k)

rows = fetchall(
    db,
    """SELECT artifact_id, artifact_name FROM public.axiom_artifacts
       WHERE platform='Windows' AND category ILIKE '%email%'""",
)
updated = 0
for row in rows:
    aid = row["artifact_id"]
    aname = (row["artifact_name"] or "").strip().lower()
    aname = __import__("re").sub(r"\s+", " ", aname)
    cnt = int(email_counts.get(aname, 0))
    if cnt <= 0:
        continue
    execute(
        db,
        """UPDATE job_axiom_artifact_results
           SET artifact_count=:c, status='done', updated_at=NOW()
           WHERE job_id=:j AND artifact_id=:aid""",
        {"j": job, "c": cnt, "aid": aid},
    )
    updated += 1
db.commit()
print("updated", updated, "email artifacts")
db.close()
