from app.db.session import firm_session
from sqlalchemy import text
import json

jid = "a78a2cb7-a60d-4f94-85df-4a4b5b7e8b04"
with firm_session("firm_polaron") as db:
    row = db.execute(
        text("SELECT status, progress_pct, pipeline_progress, error FROM jobs WHERE id=CAST(:id AS uuid)"),
        {"id": jid},
    ).mappings().first()
    print("status", row["status"], "pct", row["progress_pct"])
    print("error", row["error"])
    pp = row["pipeline_progress"]
    if isinstance(pp, str):
        pp = json.loads(pp)
    agents = ((pp or {}).get("orchestration") or {}).get("agents") or {}
    for k in sorted(agents):
        if any(x in k for x in ("entity", "annot", "onto", "neo4j", "embed", "chunk")):
            print(k, agents[k])
    print("current", ((pp or {}).get("orchestration") or {}).get("current_agent_id"))
    print("phase", (pp or {}).get("phase"))
