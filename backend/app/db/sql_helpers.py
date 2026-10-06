"""Lightweight SQLAlchemy helpers for forensic services."""

from __future__ import annotations

import random
import time
from typing import Any, Callable, TypeVar

from sqlalchemy import text
from sqlalchemy.orm import Session

T = TypeVar("T")


def is_retryable_db_error(exc: BaseException) -> bool:
    """True for deadlocks and dropped Postgres connections that a retry can recover."""
    text_l = str(exc).lower()
    return any(
        token in text_l
        for token in (
            "deadlock detected",
            "could not serialize",
            "server closed the connection",
            "connection unexpectedly",
            "connection already closed",
            "ssl syscall error",
            "terminating connection",
            "admin_shutdown",
            "crash shutdown",
        )
    )


def rollback_aborted_transaction(db: Session) -> bool:
    """Clear a Postgres aborted transaction so later statements can run.

    After a deadlock or other SQL error, psycopg2 leaves the session in
    InFailedSqlTransaction until rollback. Callers that catch and continue
    must recover here or every later query fails.
    """
    in_error = False
    try:
        conn = db.connection()
        dbapi = getattr(conn, "dbapi_connection", None) or getattr(conn, "connection", None)
        status_fn = getattr(dbapi, "get_transaction_status", None)
        if status_fn is not None:
            try:
                from psycopg2.extensions import TRANSACTION_STATUS_INERROR

                in_error = status_fn() == TRANSACTION_STATUS_INERROR
            except Exception:
                in_error = True
        else:
            # If we cannot inspect status, only roll back when a probe fails.
            db.execute(text("SELECT 1"))
            return False
    except Exception:
        in_error = True
    if not in_error:
        return False
    try:
        db.rollback()
        return True
    except Exception:
        return False


def fetchone(db: Session, sql: str, params: tuple | dict | None = None) -> dict[str, Any] | None:
    row = db.execute(text(sql), params or {}).mappings().first()
    return dict(row) if row else None


def fetchall(db: Session, sql: str, params: tuple | dict | None = None) -> list[dict[str, Any]]:
    return [dict(r) for r in db.execute(text(sql), params or {}).mappings().all()]


def execute(db: Session, sql: str, params: tuple | dict | None = None) -> None:
    db.execute(text(sql), params or {})


def retry_on_deadlock(db: Session, fn: Callable[[], T], *, attempts: int = 5) -> T:
    """Run fn, rolling back and retrying on deadlock / dropped connections.

    Two parse workers used to UPDATE job_artifacts in opposite row order (and
    mix those locks with an UPDATE on jobs). Postgres then raised DeadlockDetected
    and left the session aborted. Callers must keep artifact-row writes ordered
    by id and commit them before touching the jobs row; this retry absorbs the
    remaining races instead of pausing the drain.
    """
    last: BaseException | None = None
    tries = max(1, int(attempts))
    for attempt in range(tries):
        try:
            return fn()
        except Exception as exc:
            last = exc
            retryable = is_retryable_db_error(exc)
            if retryable:
                # The error itself proves that this transaction/connection
                # cannot be reused. Clear it even if a wrapped driver cannot
                # expose a reliable get_transaction_status() value.
                try:
                    db.rollback()
                except Exception:
                    rollback_aborted_transaction(db)
            else:
                rollback_aborted_transaction(db)
            if not retryable or attempt >= tries - 1:
                raise
            time.sleep(0.05 * (2 ** attempt) + random.uniform(0, 0.05))
    assert last is not None
    raise last
