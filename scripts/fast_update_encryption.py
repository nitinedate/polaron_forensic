import re
import time
from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.encryption_inventory import clear_encryption_count_cache, compute_all_encryption_counts
from app.db.sql_helpers import execute, fetchall

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

clear_encryption_count_cache(job)
t0 = time.time()
encryption_counts = compute_all_encryption_counts(db, job)
print("encryption scan seconds", round(time.time() - t0, 1))
for k, v in encryption_counts.items():
    print(v, k)

rows = fetchall(
    db,
    """SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts
       WHERE platform='Windows' AND (
         category ILIKE '%encryption%' OR category ILIKE '%credential%'
         OR artifact_name ILIKE '%encrypted files%'
         OR artifact_name ILIKE '%stored credentials%'
         OR artifact_name ILIKE '%anti-forensics%'
       )""",
)
updated = 0
for row in rows:
    aid = row["artifact_id"]
    aname = re.sub(r"\s+", " ", (row["artifact_name"] or "").strip().lower())
    cnt = int(encryption_counts.get(aname, 0))
    execute(
        db,
        """INSERT INTO job_axiom_artifact_results
           (job_id, artifact_id, artifact_count, status, answer, error, updated_at)
           VALUES (:j, :aid, :c, 'done', NULL, NULL, NOW())
           ON CONFLICT (job_id, artifact_id) DO UPDATE SET
             artifact_count=EXCLUDED.artifact_count,
             status='done',
             updated_at=NOW()""",
        {"j": job, "c": cnt, "aid": aid},
    )
    if cnt > 0:
        updated += 1
        print("saved", cnt, row["artifact_name"], aid)
db.commit()
print("updated", updated, "encryption artifacts")
db.close()
