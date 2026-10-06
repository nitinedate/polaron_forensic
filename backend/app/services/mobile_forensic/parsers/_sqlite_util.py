"""Read-only SQLite helpers for mobile parsers (never write to evidence)."""

from __future__ import annotations

import logging
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger("mobile_forensic.sqlite_util")


class SqliteEvidenceBytes(bytes):
    """Working-copy database bytes together with their acquired SQLite sidecars."""

    def __new__(cls, data: bytes, companions: dict[str, bytes]):
        obj = super().__new__(cls, data)
        obj.companions = companions
        return obj


@contextmanager
def open_sqlite_bytes(data: bytes | None) -> Iterator[sqlite3.Connection | None]:
    """Open SQLite from bytes via temp file (read-only analysis)."""
    if not data or not data[:16].startswith(b"SQLite format"):
        yield None
        return
    tmpdir = tempfile.TemporaryDirectory(prefix="mobile-sqlite-")
    path = Path(tmpdir.name) / "evidence.db"
    conn = None
    try:
        path.write_bytes(data)
        for suffix, companion in getattr(data, "companions", {}).items():
            if suffix in ("-wal", "-journal"):
                Path(str(path) + suffix).write_bytes(companion)
        # SQLite rebuilds SHM in this disposable working directory. Evidence bytes
        # and acquired WAL/journal files are never modified.
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except Exception as exc:
        log.debug("sqlite bytes open failed: %s", exc)
    try:
        yield conn
    finally:
        if conn is not None:
            conn.close()
        tmpdir.cleanup()


@contextmanager
def open_sqlite_readonly(path: Path) -> Iterator[sqlite3.Connection | None]:
    if not path.is_file():
        yield None
        return
    try:
        data = path.read_bytes()
    except OSError as exc:
        log.debug("sqlite read failed %s: %s", path, exc)
        yield None
        return
    with open_sqlite_bytes(data) as conn:
        yield conn


def table_names(conn: sqlite3.Connection) -> set[str]:
    return set(table_name_map(conn))


def table_name_map(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {str(r[0]).lower(): str(r[0]) for r in rows}


def resolve_table(conn: sqlite3.Connection, *candidates: str) -> str | None:
    mapping = table_name_map(conn)
    for cand in candidates:
        real = mapping.get(cand.lower())
        if real:
            return real
    return None


def column_name_map(conn: sqlite3.Connection, table: str) -> dict[str, str]:
    """Map lower(column) -> exact column name."""
    try:
        rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    except Exception:
        return {}
    return {str(r[1]).lower(): str(r[1]) for r in rows if len(r) > 1}


def iter_query(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple = (),
    *,
    batch_size: int = 1000,
    max_rows: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream query rows without an implicit forensic completeness cap."""
    try:
        cur = conn.execute(sql, params)
        cols = [d[0] for d in cur.description or []]
        yielded = 0
        while True:
            rows = cur.fetchmany(max(1, int(batch_size)))
            if not rows:
                break
            for row in rows:
                if max_rows is not None and yielded >= max_rows:
                    return
                yielded += 1
                yield {cols[j]: row[j] for j in range(len(cols))}
    except Exception as exc:
        log.debug("query failed: %s (%s)", sql[:120], exc)
        return


def safe_query(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple = (),
    *,
    limit: int | None = 5000,
) -> list[dict[str, Any]]:
    """Compatibility helper for small metadata queries.

    For evidentiary tables use :func:`iter_query`, which has no default row cap.
    """
    return list(iter_query(conn, sql, params, max_rows=limit))


def epoch_to_iso(value: Any) -> str | None:
    """Best-effort convert common mobile epoch formats to ISO-8601 UTC."""
    if value is None:
        return None
    try:
        # Some iOS timestamps are REAL values.
        n_float = float(value)
    except (TypeError, ValueError):
        s = str(value).strip()
        return s or None

    # Preserve fractional seconds while normalizing units.
    n = n_float
    if n > 10_000_000_000_000_000:  # ns-ish
        n /= 1_000_000_000
    elif n > 10_000_000_000_000:  # us
        n /= 1_000_000
    elif n > 10_000_000_000:  # ms
        n /= 1000

    # Apple Cocoa absolute time seconds since 2001-01-01.
    if 0 < n < 1_000_000_000:
        n += 978307200

    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None
