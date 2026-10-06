from sqlalchemy import text
from app.db.session import SessionLocal
from app.services.axiom_artifact_runner import (
    inventory_scope_rows, resolve_job_axiom_platform,
    _stored_enabled_keys, _artifact_rows_for_platform, axiom_inventory_progress,
)
db = SessionLocal()
db.execute(text("SET search_path TO firm_aetheris, public"))
jid = "0d5081da-567f-4b8f-ab7d-86f369ed2c03"
plat = resolve_job_axiom_platform(db, jid)
all_rows = _artifact_rows_for_platform(db, plat)
enabled = _stored_enabled_keys(db, jid)
scope = inventory_scope_rows(db, jid, platform=plat)
print("platform", plat, "all", len(all_rows), "enabled", len(enabled or []), "scope", len(scope))
print("progress", axiom_inventory_progress(db, jid))
done = db.execute(
    text("SELECT artifact_id FROM job_axiom_artifact_results WHERE job_id=:j AND status='done'"),
    {"j": jid},
).fetchall()
done_ids = {str(r[0]) for r in done}
scope_ids = {str(r["artifact_id"]) for r in scope}
print("done", len(done_ids))
print("extra_done", sorted(done_ids - scope_ids))
print("missing", sorted(scope_ids - done_ids))
print("004/005 in scope", "RPT-ART-004" in scope_ids, "RPT-ART-005" in scope_ids)
print("004/005 in all", any(r["artifact_id"]=="RPT-ART-004" for r in all_rows), any(r["artifact_id"]=="RPT-ART-005" for r in all_rows))
