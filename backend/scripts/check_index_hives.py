from app.db.session import SessionLocal, apply_firm_search_path
from app.services.disk_manifest import build_index_map
from app.db.sql_helpers import fetchone
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": JOB})
manifest = row["disk_source"]
if isinstance(manifest, str):
    manifest = json.loads(manifest)
index = build_index_map(manifest or {})
for key in ("Windows/System32/config/SOFTWARE", "Windows/System32/config/SAM", "Windows/System32/config/SECURITY"):
    print(key, "in index", key in index or key.lower() in {k.lower() for k in index})
# search software in index keys
matches = [k for k in index if "config/software" in k.lower().replace("\\", "/")]
print("software matches", matches[:5])
db.close()
