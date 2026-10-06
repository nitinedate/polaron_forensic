"""Persist Observe / Repair / Performance self-healing events."""

from __future__ import annotations

import json
import logging
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("pipeline_heal")


def ensure_pipeline_heal_table(db, schema_name: str) -> None:
    from sqlalchemy import text

    try:
        db.execute(text("SELECT public.apply_firm_pipeline_heal(:schema)"), {"schema": schema_name})
        return
    except Exception:
        pass
    # Fallback DDL when public function not yet loaded.
    db.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS "{schema_name}".pipeline_heal_events (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              job_id UUID NOT NULL REFERENCES "{schema_name}".jobs(id) ON DELETE CASCADE,
              agent VARCHAR(32) NOT NULL,
              issue_code VARCHAR(64) NOT NULL,
              issue_detail TEXT,
              stage VARCHAR(64),
              remedy_code VARCHAR(64),
              remedy_detail TEXT,
              status VARCHAR(32) NOT NULL DEFAULT 'detected',
              metadata JSONB NOT NULL DEFAULT '{{}}'::jsonb,
              created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
              resolved_at TIMESTAMPTZ
            )
            """
        )
    )
    db.execute(
        text(
            f'CREATE INDEX IF NOT EXISTS ix_pipeline_heal_job '
            f'ON "{schema_name}".pipeline_heal_events(job_id, created_at DESC)'
        )
    )


def record_heal_event(
    db,
    job_id: str,
    *,
    agent: str,
    issue_code: str,
    issue_detail: str | None = None,
    stage: str | None = None,
    remedy_code: str | None = None,
    remedy_detail: str | None = None,
    status: str = "detected",
    metadata: dict[str, Any] | None = None,
) -> str | None:
    """Insert a heal event; returns event id or None on failure."""
    try:
        row = fetchone(
            db,
            """INSERT INTO pipeline_heal_events
               (job_id, agent, issue_code, issue_detail, stage, remedy_code, remedy_detail, status, metadata)
               VALUES
               (:jid, :agent, :icode, :idetail, :stage, :rcode, :rdetail, :status, CAST(:meta AS jsonb))
               RETURNING id""",
            {
                "jid": job_id,
                "agent": agent,
                "icode": issue_code[:64],
                "idetail": (issue_detail or "")[:4000] or None,
                "stage": (stage or "")[:64] or None,
                "rcode": (remedy_code or "")[:64] or None,
                "rdetail": (remedy_detail or "")[:4000] or None,
                "status": status[:32],
                "meta": json.dumps(metadata or {}),
            },
        )
        return str(row["id"]) if row else None
    except Exception as exc:
        log.warning("record_heal_event failed job=%s: %s", job_id, exc)
        return None


def update_heal_event(
    db,
    event_id: str,
    *,
    status: str | None = None,
    remedy_code: str | None = None,
    remedy_detail: str | None = None,
    metadata: dict[str, Any] | None = None,
    resolve: bool = False,
) -> None:
    if not event_id:
        return
    sets = ["status = COALESCE(:status, status)"]
    params: dict[str, Any] = {"id": event_id, "status": status}
    if remedy_code is not None:
        sets.append("remedy_code = :rcode")
        params["rcode"] = remedy_code[:64]
    if remedy_detail is not None:
        sets.append("remedy_detail = :rdetail")
        params["rdetail"] = remedy_detail[:4000]
    if metadata is not None:
        sets.append("metadata = COALESCE(metadata, '{}'::jsonb) || CAST(:meta AS jsonb)")
        params["meta"] = json.dumps(metadata)
    if resolve or status in ("resolved", "failed"):
        sets.append("resolved_at = COALESCE(resolved_at, NOW())")
    try:
        execute(
            db,
            f"UPDATE pipeline_heal_events SET {', '.join(sets)} WHERE id=:id",
            params,
        )
    except Exception as exc:
        log.warning("update_heal_event failed id=%s: %s", event_id, exc)


def list_heal_events(db, job_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    try:
        rows = fetchall(
            db,
            """SELECT id, job_id, agent, issue_code, issue_detail, stage,
                      remedy_code, remedy_detail, status, metadata, created_at, resolved_at
               FROM pipeline_heal_events
               WHERE job_id=:jid
               ORDER BY created_at DESC
               LIMIT :lim""",
            {"jid": job_id, "lim": limit},
        )
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for r in rows or []:
        meta = r.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        out.append(
            {
                "id": str(r["id"]),
                "job_id": str(r["job_id"]),
                "agent": r.get("agent"),
                "issue_code": r.get("issue_code"),
                "issue_detail": r.get("issue_detail"),
                "stage": r.get("stage"),
                "remedy_code": r.get("remedy_code"),
                "remedy_detail": r.get("remedy_detail"),
                "status": r.get("status"),
                "metadata": meta,
                "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
                "resolved_at": r["resolved_at"].isoformat() if r.get("resolved_at") else None,
            }
        )
    return out


def open_issue_for_code(db, job_id: str, issue_code: str) -> dict | None:
    try:
        return fetchone(
            db,
            """SELECT id, status FROM pipeline_heal_events
               WHERE job_id=:jid AND issue_code=:code
                 AND status IN ('detected', 'repairing')
               ORDER BY created_at DESC LIMIT 1""",
            {"jid": job_id, "code": issue_code},
        )
    except Exception:
        return None
