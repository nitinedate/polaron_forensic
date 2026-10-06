"""Repair critical hives + RAG for an existing job (SOFTWARE/SYSTEM/SAM)."""
import json
import sys

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone
from app.services.critical_forensic_pipeline import ensure_critical_forensic_pipeline
from app.services.critical_forensic_paths import CRITICAL_FORENSIC_CATALOG
from app.services.identity_evidence_prompts import merge_os_facts

JOB = sys.argv[1] if len(sys.argv) > 1 else "4316aaf4-4eb7-4704-a692-905e0d3e6246"
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"

print("=== Critical forensic path catalog ===")
for row in CRITICAL_FORENSIC_CATALOG:
    print(f"- {row['path']}: {row['purpose']}")

db = SessionLocal()
apply_firm_search_path(db, SCHEMA)
print("\n=== Before ===")
for hive in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY"):
    row = fetchone(
        db,
        f"SELECT file_path, parse_status FROM job_artifacts WHERE job_id=:j AND file_path ILIKE '%/config/{hive}' LIMIT 1",
        {"j": JOB},
    )
    print(hive, row)
facts_before = merge_os_facts(db, JOB)
print("OS facts before:", {k: facts_before.get(k) for k in (
    "product_name", "version_number", "display_version", "install_time", "product_key", "product_id", "build_number",
)})

result = ensure_critical_forensic_pipeline(db, JOB, schema_name=SCHEMA, refresh_hives=True)
db.commit()
print("\n=== Pipeline result ===")
print(json.dumps(result, indent=2, default=str))

facts_after = merge_os_facts(db, JOB)
print("\n=== OS facts after ===")
print({k: facts_after.get(k) for k in (
    "product_name", "version_number", "display_version", "install_time", "product_key", "product_id", "build_number",
)})
db.close()
