from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

JOB = "5f01f8fd-cde5-4064-b125-7a48e44b1646"
db = sessionmaker(bind=create_engine("postgresql+psycopg2://forensic:forensic@postgres:5432/forensic"))()
db.execute(text("SET search_path TO firm_aetheris, public"))

run = db.execute(
    text("SELECT id, status FROM report_runs WHERE job_id=:j ORDER BY created_at DESC LIMIT 1"),
    {"j": JOB},
).mappings().first()
print("run", dict(run) if run else None)

secs = db.execute(
    text(
        """
        SELECT section_key, status, length(coalesce(content_md,'')) AS n,
               left(coalesce(content_md,''), 500) AS preview
        FROM report_sections WHERE report_run_id=:r ORDER BY created_at
        """
    ),
    {"r": run["id"]},
).mappings().all()
for s in secs:
    print("---", s["section_key"], s["status"], "len=", s["n"])
    print(s["preview"])
    print()

ax = db.execute(
    text(
        """
        SELECT count(*) AS c,
               count(*) FILTER (WHERE coalesce(artifact_count,0) > 0) AS nz
        FROM job_axiom_artifact_results WHERE job_id=:j
        """
    ),
    {"j": JOB},
).mappings().first()
print("axiom totals", dict(ax))

top = db.execute(
    text(
        """
        SELECT jar.artifact_id, jar.artifact_count, aa.artifact_name, aa.category
        FROM job_axiom_artifact_results jar
        LEFT JOIN public.axiom_artifacts aa ON aa.artifact_id = jar.artifact_id
        WHERE jar.job_id=:j AND coalesce(jar.artifact_count,0) > 0
        ORDER BY jar.artifact_count DESC
        LIMIT 20
        """
    ),
    {"j": JOB},
).mappings().all()
print("top axiom hits:")
for t in top:
    print(dict(t))

# mobile board
ds = db.execute(text("SELECT disk_source->'mobile_forensic_inventory' AS inv FROM jobs WHERE id=:j"), {"j": JOB}).mappings().first()
print("mobile inv", ds["inv"] if ds else None)

db.close()
