from sqlalchemy import text
from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

names = [
    "USB Devices", "Feature Usage", "Installed Microsoft Programs",
    "Installed Programs (Non-Microsoft)", "Web Chat URLs", "Social Media URLs",
    "Jump List", "LNK Files", "Logfile Analysis", "Picture",
]
rows = fetchall(
    db,
    """SELECT aa.artifact_name, jar.artifact_count
       FROM job_axiom_artifact_results jar
       JOIN public.axiom_artifacts aa ON aa.artifact_id = jar.artifact_id
       WHERE jar.job_id=:j AND aa.artifact_name = ANY(:names)""",
    {"j": job, "names": names},
)
for r in sorted(rows, key=lambda x: x["artifact_name"]):
    print(f"{r['artifact_count']:>8}  {r['artifact_name']}")

nonzero = fetchall(
    db,
    """SELECT count(*) c FROM job_axiom_artifact_results WHERE job_id=:j AND artifact_count > 0""",
    {"j": job},
)
print("nonzero total", nonzero[0]["c"])
db.close()
