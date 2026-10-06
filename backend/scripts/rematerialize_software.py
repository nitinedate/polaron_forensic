from app.db.session import SessionLocal, apply_firm_search_path
from app.services.artifact_materialize import rematerialize_critical_account_paths
from app.services.artifact_parse import parse_job_artifacts_for_paths
from app.services.disk_manifest import build_index_map
from app.services.forensic_profile_index import collect_os_facts, ensure_os_fact_chunks
from app.db.sql_helpers import fetchone
import json

JOB = "4316aaf4-4eb7-4704-a692-905e0d3e6246"
db = SessionLocal()
apply_firm_search_path(db, "firm_aetheris")
print("remat", rematerialize_critical_account_paths(db, JOB))
db.commit()
sw = fetchone(
    db,
    "SELECT id, file_path, parse_status FROM job_artifacts WHERE job_id=:jid AND file_path ILIKE 'Windows/System32/config/SOFTWARE'",
    {"jid": JOB},
)
print("SOFTWARE after remat", sw)
if sw and sw.get("parse_status") != "parsed":
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": JOB})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    index_map = build_index_map(manifest or {})
    pr = parse_job_artifacts_for_paths(
        db, JOB, paths=[sw["file_path"]], index_map=index_map, update_status=True,
    )
    print("parse result", pr)
    db.commit()
print("facts", collect_os_facts(db, JOB))
ensure_os_fact_chunks(db, JOB, refresh_hives=False)
db.commit()
db.close()
