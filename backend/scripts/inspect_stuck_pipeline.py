"""Print live job + huddle + graph/OCR/celery state."""

from __future__ import annotations

import json

from sqlalchemy import text

from app.db.session import SessionLocal


def main() -> None:
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))
    row = db.execute(
        text(
            """
            SELECT id, status, updated_at,
                   pipeline_progress->'orchestration'->>'current_agent_id' AS current
            FROM jobs ORDER BY created_at DESC LIMIT 1
            """
        )
    ).mappings().first()
    print("job", dict(row) if row else None)
    jid = str(row["id"])
    gs = db.execute(
        text("SELECT * FROM graph_sync_state WHERE job_id=:j"),
        {"j": jid},
    ).mappings().first()
    print("graph_sync_state", dict(gs) if gs else None)
    ocr = db.execute(
        text(
            """
            SELECT ocr_status, count(*) c
            FROM job_artifacts WHERE job_id=:j
            GROUP BY ocr_status ORDER BY c DESC
            """
        ),
        {"j": jid},
    ).mappings().all()
    print("ocr_status", [dict(x) for x in ocr])
    chunks = db.execute(
        text("SELECT count(*) c FROM rag_chunks WHERE job_id=:j"),
        {"j": jid},
    ).scalar()
    print("chunks", chunks)
    try:
        from app.celery_app import celery

        insp = celery.control.inspect(timeout=3.0)
        active = insp.active() or {}
        reserved = insp.reserved() or {}
        print("celery_active_keys", list(active.keys()))
        for host, tasks in active.items():
            print("active", host, [(t.get("name"), t.get("id")[:8], (t.get("args") or [])[:2]) for t in tasks[:12]])
        for host, tasks in reserved.items():
            print("reserved", host, [(t.get("name"), (t.get("args") or [])[:2]) for t in (tasks or [])[:8]])
    except Exception as exc:
        print("celery_inspect", exc)


if __name__ == "__main__":
    main()
