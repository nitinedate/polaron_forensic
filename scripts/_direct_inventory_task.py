from app.services.job_locks import force_release_job_lock
from app.db.session import firm_session
from app.services.axiom_artifact_runner import (
    clear_artifact_inventory_results,
    clear_inventory_runtime_cache,
)
from app.tasks import axiom_artifact_inventory_task

schema = "firm_aetheris"
jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
force_release_job_lock("inventory", jid)
with firm_session(schema) as db:
    clear_artifact_inventory_results(db, jid)
    clear_inventory_runtime_cache(jid)
    db.commit()
async_result = axiom_artifact_inventory_task.delay(schema, jid)
print("dispatched", async_result.id)
