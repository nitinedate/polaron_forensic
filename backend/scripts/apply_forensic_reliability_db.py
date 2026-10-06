#!/usr/bin/env python3
"""Aetheris forensic reliability DB maintenance v1.2.

This revision is designed for a short maintenance window while API + worker-disk
are stopped. It intentionally uses ordinary CREATE INDEX rather than CREATE INDEX
CONCURRENTLY. The previous concurrent build could wait for unrelated long-lived
PostgreSQL snapshots and hit lock_timeout even after the disk worker was stopped.

Safety properties:
- no table/data deletion;
- missing columns are added only when absent;
- invalid indexes left by a failed concurrent build are removed and rebuilt;
- index lock waits are bounded and retried;
- index creation failure is non-fatal so the application/job can be recovered;
- schema-changing column DDL remains fatal because the code may depend on it.
"""
from __future__ import annotations

import re
import time
from typing import Iterable

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.db.session import engine

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def log(message: str) -> None:
    print(message, flush=True)


def qident(value: str) -> str:
    if not _IDENT.fullmatch(value or ""):
        raise ValueError(f"unsafe SQL identifier: {value!r}")
    return f'"{value}"'


def is_lock_timeout(exc: BaseException) -> bool:
    text_value = str(exc).lower()
    return "lock timeout" in text_value or "locknotavailable" in text_value


def show_activity(schema: str | None = None, table: str = "job_artifacts") -> None:
    """Print active transactions and relation lock holders using a fresh connection."""
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as diag:
            log("PostgreSQL activity relevant to maintenance:")
            rows = diag.execute(
                text(
                    """
                    SELECT
                        pid,
                        usename,
                        application_name,
                        client_addr::text AS client_addr,
                        state,
                        wait_event_type,
                        wait_event,
                        now() - xact_start AS xact_age,
                        now() - query_start AS query_age,
                        backend_xmin::text AS backend_xmin,
                        left(regexp_replace(query, E'[\\n\\r\\t]+', ' ', 'g'), 220) AS query
                    FROM pg_stat_activity
                    WHERE datname=current_database()
                      AND pid <> pg_backend_pid()
                      AND (state <> 'idle' OR xact_start IS NOT NULL)
                    ORDER BY xact_start NULLS LAST, query_start
                    """
                )
            ).mappings().all()
            if not rows:
                log("  no active/transactional sessions")
            for row in rows:
                log(
                    "  pid={pid} user={usename} app={application_name} client={client_addr} "
                    "state={state} wait={wait_event_type}/{wait_event} xact_age={xact_age} "
                    "query_age={query_age} xmin={backend_xmin} query={query}".format(**row)
                )

            if schema:
                holders = diag.execute(
                    text(
                        """
                        SELECT
                            a.pid,
                            a.usename,
                            a.application_name,
                            a.state,
                            l.mode,
                            l.granted,
                            now() - a.xact_start AS xact_age,
                            left(regexp_replace(a.query, E'[\\n\\r\\t]+', ' ', 'g'), 220) AS query
                        FROM pg_locks l
                        JOIN pg_stat_activity a ON a.pid=l.pid
                        WHERE l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
                          AND l.relation=to_regclass(:relation)
                          AND a.pid <> pg_backend_pid()
                        ORDER BY l.granted DESC, a.xact_start NULLS LAST
                        """
                    ),
                    {"relation": f"{schema}.{table}"},
                ).mappings().all()
                if holders:
                    log(f"Lock holders on {schema}.{table}:")
                    for row in holders:
                        log(
                            "  pid={pid} user={usename} app={application_name} state={state} "
                            "mode={mode} granted={granted} xact_age={xact_age} query={query}".format(**row)
                        )
    except Exception as exc:  # diagnostic must never hide original error
        log(f"Could not read PostgreSQL blocker diagnostics: {exc}")


def existing_columns(conn, schema: str, table: str) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            text(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema=:schema AND table_name=:table
                """
            ),
            {"schema": schema, "table": table},
        ).all()
    }


def index_state(conn, schema: str, name: str):
    row = conn.execute(
        text(
            """
            SELECT i.indisvalid, i.indisready
            FROM pg_class c
            JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_index i ON i.indexrelid=c.oid
            WHERE n.nspname=:schema AND c.relname=:name
            """
        ),
        {"schema": schema, "name": name},
    ).first()
    if not row:
        return None
    return bool(row[0]), bool(row[1])


def run_required_ddl(conn, schema: str, label: str, sql: str) -> None:
    log(label)
    try:
        conn.execute(text(sql))
    except (OperationalError, DBAPIError):
        log(f"Required DDL failed: {label}")
        show_activity(schema)
        raise


def build_index(conn, schema: str, name: str, cols_sql: str) -> bool:
    """Build one performance index with bounded lock waits.

    Indexes improve performance but are not required to preserve evidence/job state,
    therefore exhausting retries is a warning rather than a deployment-fatal error.
    """
    qs = qident(schema)
    qn = qident(name)

    state = index_state(conn, schema, name)
    if state and state[0] and state[1]:
        log(f"[{schema}] index {name} already valid; skipping")
        return True

    if state:
        log(f"[{schema}] index {name} exists but is invalid/not-ready; dropping stale index")
        try:
            conn.execute(text(f"DROP INDEX IF EXISTS {qs}.{qn}"))
        except (OperationalError, DBAPIError) as exc:
            log(f"[{schema}] could not drop invalid index {name}: {exc}")
            show_activity(schema)
            return False

    # In this script API + disk worker are paused. Ordinary CREATE INDEX avoids the
    # extra old-snapshot waits of CREATE INDEX CONCURRENTLY and still allows SELECTs.
    for attempt in range(1, 4):
        log(
            f"[{schema}] creating maintenance index {name} "
            f"(attempt {attempt}/3; large tables can take several minutes after lock acquisition)"
        )
        try:
            conn.execute(text(f"CREATE INDEX {qn} ON {qs}.job_artifacts {cols_sql}"))
            log(f"[{schema}] index {name} created")
            return True
        except (OperationalError, DBAPIError) as exc:
            if not is_lock_timeout(exc):
                log(f"[{schema}] index {name} failed: {exc}")
                show_activity(schema)
                return False
            log(f"[{schema}] index {name} could not acquire its maintenance lock within timeout")
            show_activity(schema)
            if attempt < 3:
                log(f"[{schema}] waiting 5 seconds before retrying {name}")
                time.sleep(5)

    log(
        f"[{schema}] WARNING: index {name} remains deferred after 3 lock-timeout attempts. "
        "Application recovery will continue; rerun maintenance later when other forensic work is idle."
    )
    return False


def main() -> int:
    deferred_indexes: list[str] = []

    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        # The wrapper pauses the principal forensic writer. Never hang forever while
        # waiting for a lock, but allow actual index scanning to run without a statement timeout.
        conn.execute(text("SET lock_timeout = '30s'"))
        conn.execute(text("SET statement_timeout = '0'"))
        conn.execute(text("SET maintenance_work_mem = '256MB'"))

        platform_rt = conn.execute(text("SELECT to_regclass('public.platform_refresh_tokens')")).scalar()
        if platform_rt:
            log("[public] extending active platform refresh sessions")
            conn.execute(
                text(
                    "UPDATE public.platform_refresh_tokens "
                    "SET expires_at=TIMESTAMPTZ '9999-12-31 23:59:59+00' "
                    "WHERE revoked_at IS NULL AND expires_at < TIMESTAMPTZ '9999-12-31 23:59:59+00'"
                )
            )

        schemas = [
            str(r[0])
            for r in conn.execute(
                text(
                    "SELECT schema_name FROM public.firms "
                    "WHERE lower(coalesce(status,''))='active' ORDER BY schema_name"
                )
            ).all()
        ]
        if not schemas:
            log("No active firm schemas found; nothing to repair.")
            return 0

        for schema in schemas:
            qs = qident(schema)
            log(f"[{schema}] checking forensic schema")

            refresh_exists = conn.execute(
                text("SELECT to_regclass(:tbl) IS NOT NULL"),
                {"tbl": f"{schema}.refresh_tokens"},
            ).scalar()
            if refresh_exists:
                log(f"[{schema}] extending active refresh sessions")
                conn.execute(
                    text(
                        f"UPDATE {qs}.refresh_tokens "
                        "SET expires_at=TIMESTAMPTZ '9999-12-31 23:59:59+00' "
                        "WHERE revoked_at IS NULL AND expires_at < TIMESTAMPTZ '9999-12-31 23:59:59+00'"
                    )
                )

            exists = conn.execute(
                text("SELECT to_regclass(:tbl) IS NOT NULL"),
                {"tbl": f"{schema}.job_artifacts"},
            ).scalar()
            if not exists:
                log(f"[{schema}] job_artifacts not present; skipping")
                continue

            cols = existing_columns(conn, schema, "job_artifacts")
            missing = {
                "parse_status": "TEXT DEFAULT 'pending'",
                "ocr_status": "TEXT DEFAULT 'pending'",
                "updated_at": "TIMESTAMPTZ DEFAULT NOW()",
                "metadata": "JSONB DEFAULT '{}'::jsonb",
            }
            for col, definition in missing.items():
                if col in cols:
                    log(f"[{schema}] column {col} already present; no ALTER needed")
                    continue
                run_required_ddl(
                    conn,
                    schema,
                    f"[{schema}] adding required missing column {col}",
                    f"ALTER TABLE {qs}.job_artifacts ADD COLUMN {qident(col)} {definition}",
                )

            indexes: Iterable[tuple[str, str]] = (
                ("ix_job_artifacts_job_parse_status", "(job_id, parse_status)"),
                ("ix_job_artifacts_job_ocr_status", "(job_id, ocr_status)"),
                ("ix_job_artifacts_job_updated", "(job_id, updated_at)"),
            )
            for name, cols_sql in indexes:
                if not build_index(conn, schema, name, cols_sql):
                    deferred_indexes.append(f"{schema}.{name}")

            log(f"[{schema}] ANALYZE job_artifacts")
            try:
                conn.execute(text(f"ANALYZE {qs}.job_artifacts"))
            except Exception as exc:
                log(f"[{schema}] WARNING: ANALYZE failed: {exc}")
            log(f"[{schema}] schema maintenance complete")

    if deferred_indexes:
        log("WARNING: the following optional performance indexes are still deferred:")
        for value in deferred_indexes:
            log(f"  {value}")
        log("Job recovery will continue because evidence/schema integrity is not dependent on these indexes.")
    else:
        log("All forensic reliability indexes are valid.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("Database maintenance cancelled by operator; current statement was aborted.")
        raise SystemExit(130)
