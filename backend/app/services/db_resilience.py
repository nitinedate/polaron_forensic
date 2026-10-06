"""Retry and classify short-lived PostgreSQL outages (recovery, restart, pool drop)."""

from __future__ import annotations

import logging
import time
from typing import Callable, TypeVar

log = logging.getLogger("db_resilience")

T = TypeVar("T")

TRANSIENT_DB_MARKERS = (
    "the database system is starting up",
    "the database system is not yet accepting connections",
    "consistent recovery state has not been yet reached",
    "the database system is in recovery mode",
    "the database system is shutting down",
    "connection refused",
    "connection reset",
    "server closed the connection",
    "could not connect to server",
    "connection timed out",
    "timeout expired",
    "too many connections",
    "remaining connection slots",
    "sorry, too many clients already",
    "terminating connection due to administrator command",
    "ssl syscall error",
    "broken pipe",
    "admin_shutdown",
    "crash shutdown",
    "cannot connect now",
)


class TransientDatabaseError(RuntimeError):
    """Raised when a job should wait and retry after Postgres recovers."""


def is_transient_db_error(exc: BaseException | None) -> bool:
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen:
        seen.append(cur)
        name = type(cur).__name__.lower()
        text = str(cur).lower()
        if any(marker in text for marker in TRANSIENT_DB_MARKERS):
            return True
        if "pendingrollback" in name:
            return True
        cur = cur.__cause__ or getattr(cur, "__context__", None)
    return False


def _connect_kwargs() -> dict:
    from sqlalchemy.engine import make_url

    from app.config import get_settings

    url = make_url(get_settings().database_url)
    return {
        "host": url.host,
        "port": int(url.port or 5432),
        "user": url.username,
        "password": url.password or "",
        "dbname": url.database,
        "connect_timeout": 8,
    }


def connect_psycopg2_with_retry(*, attempts: int = 40, delay_sec: float = 1.0):
    """Open a raw psycopg2 connection, waiting through Postgres recovery."""
    import psycopg2

    kwargs = _connect_kwargs()
    last: BaseException | None = None
    delay = max(delay_sec, 0.4)
    for attempt in range(max(attempts, 1)):
        conn = None
        try:
            conn = psycopg2.connect(**kwargs)
            return conn
        except Exception as exc:
            last = exc
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            if not is_transient_db_error(exc) and "operationalerror" not in type(exc).__name__.lower():
                raise
            log.warning("postgres not ready (attempt %s/%s): %s", attempt + 1, attempts, exc)
            time.sleep(delay)
            delay = min(delay * 1.35, 8.0)
    raise TransientDatabaseError(str(last)[:500] if last else "postgres unavailable") from last


def wait_for_database(*, timeout_sec: float = 180.0, interval_sec: float = 2.0) -> bool:
    """Block until a simple SELECT 1 succeeds, or return False on timeout."""
    attempts = max(int(timeout_sec / max(interval_sec, 0.5)), 3)
    try:
        conn = connect_psycopg2_with_retry(attempts=attempts, delay_sec=interval_sec)
        conn.close()
        return True
    except Exception as exc:
        log.warning("database still unavailable after %.0fs: %s", timeout_sec, exc)
        return False


def call_with_db_retry(fn: Callable[[], T], *, attempts: int = 8, delay_sec: float = 2.0) -> T:
    last: BaseException | None = None
    for attempt in range(max(attempts, 1)):
        try:
            return fn()
        except Exception as exc:
            last = exc
            if not is_transient_db_error(exc):
                raise
            wait = min(delay_sec * (1.4**attempt), 12.0)
            log.warning("transient database error (attempt %s/%s): %s", attempt + 1, attempts, exc)
            wait_for_database(timeout_sec=wait, interval_sec=min(wait, 2.0))
    assert last is not None
    raise TransientDatabaseError(str(last)[:500]) from last
