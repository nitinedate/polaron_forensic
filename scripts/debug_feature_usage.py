from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_live_counts import _read_job_files
from app.db.sql_helpers import fetchall
import io
from Registry import Registry

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"

rows = fetchall(
    db,
    "SELECT file_path FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%NTUSER.DAT' ORDER BY size_bytes DESC LIMIT 5",
    {"j": job},
)
contents = _read_job_files(db, job, rows)
for path, data in contents.items():
    if not data:
        continue
    print("===", path, len(data))
    reg = Registry.Registry(io.BytesIO(data))
    for key_path in (
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage",
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch",
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
        "Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage",
    ):
        try:
            key = reg.open(key_path)
            subs = list(key.subkeys())
            vals = list(key.values())
            print(key_path, "subkeys", len(subs), "values", len(vals))
        except Exception as exc:
            print(key_path, "ERR", exc)

db.close()
