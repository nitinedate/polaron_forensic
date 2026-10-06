from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.artifact_live_counts import _read_job_files
from app.db.sql_helpers import fetchone
import io
from Registry import Registry

db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris"))
job = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
row = fetchone(db, "SELECT file_path FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%LENOVO/NTUSER.DAT' LIMIT 1", {"j": job})
contents = _read_job_files(db, job, [row])
data = contents[row["file_path"].replace("\\", "/")]
reg = Registry.Registry(io.BytesIO(data))
root = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage")
print("parent subkeys", [k.name() for k in root.subkeys()])
print("parent values", [v.name() for v in root.values()])
total = 0
for sk in root.subkeys():
    vals = list(sk.values())
    subs = list(sk.subkeys())
    print(" ", sk.name(), "values", len(vals), "subkeys", len(subs))
    total += len(vals)
print("total values in subkeys", total)
print("total with parent values", total + len(list(root.values())))
db.close()
