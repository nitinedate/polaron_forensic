"""Pipeline logging for disk build jobs."""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.sql_helpers import execute
from app.services.retired_agents import is_retired_huddle_message


def write_disk_log(
    db: Session,
    job_id: str,
    message: str,
    *,
    stage: str = "build",
    level: str = "info",
    metadata: dict[str, Any] | None = None,
) -> None:
    if is_retired_huddle_message(message):
        return
    execute(
        db,
        """INSERT INTO disk_build_logs(job_id, stage, level, message, metadata)
           VALUES (:job_id, :stage, :level, :message, CAST(:metadata AS jsonb))""",
        {
            "job_id": job_id,
            "stage": stage,
            "level": level,
            "message": message,
            "metadata": json.dumps(metadata) if metadata else None,
        },
    )
    db.flush()


def write_disk_logs_batch(
    db: Session,
    job_id: str,
    rows: list[dict[str, Any]],
    *,
    stage: str = "folder_list",
    flush: bool = False,
) -> None:
    """Insert many listing lines in one round-trip."""
    if not rows:
        return
    payload = [
        {
            "job_id": job_id,
            "stage": stage,
            "level": str(row.get("level") or "info"),
            "message": str(row.get("message") or ""),
            "metadata": json.dumps(row["metadata"]) if row.get("metadata") else None,
        }
        for row in rows
        if str(row.get("message") or "").strip() and not is_retired_huddle_message(str(row.get("message") or ""))
    ]
    if not payload:
        return
    db.execute(
        text(
            """INSERT INTO disk_build_logs(job_id, stage, level, message, metadata)
               VALUES (:job_id, :stage, :level, :message, CAST(:metadata AS jsonb))"""
        ),
        payload,
    )
    if flush:
        db.flush()


def write_disk_log_committed(
    schema_name: str,
    job_id: str,
    message: str,
    *,
    stage: str = "build",
    level: str = "info",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Write a log line on a fresh session and commit so the UI can poll it immediately."""
    from app.db.session import firm_session

    with firm_session(schema_name) as db:
        write_disk_log(db, job_id, message, stage=stage, level=level, metadata=metadata)


@contextmanager
def disk_log_heartbeat(
    schema_name: str,
    job_id: str,
    message: str,
    *,
    stage: str = "virtual_disk",
    interval_sec: float = 15.0,
) -> Iterator[None]:
    """Emit periodic 'still working' logs while a long blocking step runs.

    Uses a separate DB session so it is safe alongside the caller's Session.
    """
    stop = threading.Event()
    started = time.monotonic()
    interval = max(float(interval_sec), 5.0)

    def _run() -> None:
        tick = 0
        while not stop.wait(interval):
            tick += 1
            elapsed = int(time.monotonic() - started)
            try:
                from app.db.session import firm_session
                from app.db.sql_helpers import execute

                with firm_session(schema_name) as db:
                    write_disk_log(
                        db,
                        job_id,
                        f"{message} — still in progress ({elapsed}s elapsed)",
                        stage=stage,
                        metadata={
                            "heartbeat": True,
                            "elapsed_sec": elapsed,
                            "tick": tick,
                        },
                    )
                    # Keep jobs.updated_at fresh so UI/API do not false-flag "stalled"
                    # during long E01 walks / filters with no file-count progress yet.
                    execute(
                        db,
                        "UPDATE jobs SET updated_at=NOW() WHERE id=:id",
                        {"id": job_id},
                    )
                    db.commit()
                if stage in ("extract", "virtual_disk"):
                    try:
                        from app.services.job_locks import DEFAULT_EXTRACT_LOCK_TTL_SEC, refresh_job_lock

                        refresh_job_lock("extract", job_id, ttl_sec=DEFAULT_EXTRACT_LOCK_TTL_SEC)
                    except Exception:
                        pass
            except Exception:
                # Never fail the parent job because a heartbeat log failed.
                pass

    thread = threading.Thread(
        target=_run,
        name=f"disk-log-hb-{job_id[:8]}-{stage}",
        daemon=True,
    )
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2.0)


def make_session_progress(
    db: Session,
    job_id: str,
    *,
    stage: str,
    commit: bool = True,
    schema_name: str | None = None,
) -> Callable[[str, dict[str, Any] | None], None]:
    """Return an on_progress(message, metadata) callback.

    Prefer a dedicated committed session (schema_name) so progress ticks cannot
    abort the caller's long-running transaction.
    """

    def _progress(message: str, metadata: dict[str, Any] | None = None) -> None:
        try:
            if schema_name:
                write_disk_log_committed(
                    schema_name,
                    job_id,
                    message,
                    stage=stage,
                    metadata=metadata,
                )
                return
            write_disk_log(db, job_id, message, stage=stage, metadata=metadata)
            if commit:
                db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    return _progress
