"""Re-queue a stale queued Neo4j sync so entity/annotation/ontology can start."""

from __future__ import annotations

from sqlalchemy import text

from app.db.session import SessionLocal
from app.tasks import graph_sync_task


def main() -> None:
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))
    row = db.execute(text("SELECT id FROM jobs ORDER BY created_at DESC LIMIT 1")).mappings().first()
    if not row:
        print("no job")
        return
    jid = str(row["id"])
    db.execute(
        text(
            """INSERT INTO graph_sync_state (job_id, status, error)
               VALUES (CAST(:j AS uuid), 'queued', NULL)
               ON CONFLICT (job_id) DO UPDATE SET status='queued', error=NULL"""
        ),
        {"j": jid},
    )
    db.commit()
    async_result = graph_sync_task.delay("firm_aetheris", jid)
    print("queued graph_sync", jid, async_result.id)


if __name__ == "__main__":
    main()
