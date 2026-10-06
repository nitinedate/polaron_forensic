from sqlalchemy import text
from app.db.session import firm_session_readonly
import json

jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
with firm_session_readonly("firm_aetheris") as db:
    for name in [
        "Prefetch Files - Windows 8/10/11",
        "Windows Viber Chat Messages",
        "USB Devices",
        "Jump Lists",
    ]:
        r = db.execute(
            text(
                """
          SELECT r.artifact_count, r.count_domain, r.query_snapshot, r.updated_at
          FROM job_axiom_artifact_results r
          JOIN public.axiom_artifacts a ON a.artifact_id=r.artifact_id
          WHERE r.job_id=:j AND a.artifact_name=:n
        """
            ),
            {"j": jid, "n": name},
        ).mappings().first()
        qs = r["query_snapshot"] if r else None
        if isinstance(qs, str):
            qs = json.loads(qs)
        print("====", name)
        print("count", r["artifact_count"] if r else None, "updated", r["updated_at"] if r else None)
        print("snapshot", qs)
