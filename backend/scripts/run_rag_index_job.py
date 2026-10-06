from app.db.session import firm_session
from app.services.dual_rag_index import build_dual_rag_index
from app.services.neo4j_sync import sync_job_graph
from app.db.sql_helpers import execute, fetchone
import json

jid = "58b507de-03fd-44ba-b79e-6c334f229a1a"
schema = "firm_aetheris"

with firm_session(schema) as db:
    execute(
        db,
        "UPDATE job_artifacts SET ocr_status='skipped' WHERE job_id=:jid AND ocr_status='pending'",
        {"jid": jid},
    )
    execute(
        db,
        "UPDATE jobs SET status='indexing', error=NULL, updated_at=NOW() WHERE id=:id",
        {"id": jid},
    )
    db.commit()
    print("Starting RAG index...")
    rag = build_dual_rag_index(db, jid, schema_name=schema)
    print("RAG result", rag)
    sync_job_graph(db, jid, schema_name=schema)
    chunks = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid", {"jid": jid})
    total = int(chunks["c"]) if chunks else 0
    execute(
        db,
        """UPDATE jobs SET status='indexed', progress_pct=100,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {
            "pp": json.dumps(
                {
                    "phase": "rag",
                    "completed": total,
                    "total": max(total, 1),
                    "label": "chunks embedded",
                }
            ),
            "id": jid,
        },
    )
    db.commit()
    print("evidence_chunks", total)
