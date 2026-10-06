from sqlalchemy import text
from app.db.session import firm_session
from app.services.job_locks import force_release_job_lock
from app.services.axiom_artifact_runner import (
    clear_artifact_inventory_results,
    clear_inventory_runtime_cache,
    queue_axiom_artifact_inventory,
)

schema = "firm_aetheris"
jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
with firm_session(schema) as db:
    force_release_job_lock("inventory", jid)
    clear_artifact_inventory_results(db, jid)
    clear_inventory_runtime_cache(jid)
    db.commit()
    print("lock released, results cleared")
    print(queue_axiom_artifact_inventory(db, jid, schema_name=schema))
