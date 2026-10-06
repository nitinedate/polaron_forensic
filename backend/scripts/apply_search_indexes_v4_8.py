#!/usr/bin/env python3
"""Build the v4.8 search-performance indexes on a live database.

Runs the same index set as migrations/037_search_performance_indexes.sql, but:

* CREATE INDEX CONCURRENTLY by default (no write lock on job_artifacts / rag_chunks
  while parse/RAG workers keep running); --no-concurrent for a maintenance window.
* idempotent and resumable: existing valid indexes are skipped, INVALID leftovers
  from an interrupted concurrent build are dropped and rebuilt.
* HNSW on rag_chunks.embedding_v2 is opt-in (--with-vector): it is the slowest build
  on a large corpus, and pgvector uses maintenance_work_mem (raise it first).
* ANALYZE at the end so the planner starts using the new indexes immediately.

    cd backend
    python scripts/apply_search_indexes_v4_8.py                 # all active firms
    python scripts/apply_search_indexes_v4_8.py --schema firm_x --with-vector
    python scripts/apply_search_indexes_v4_8.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import time

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.db.session import engine

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def log(msg: str) -> None:
    print(msg, flush=True)


def qident(v: str) -> str:
    if not _IDENT.fullmatch(v or ""):
        raise ValueError(f"unsafe identifier: {v!r}")
    return f'"{v}"'


# (index name, table, definition body) — {schema} substituted.
INDEXES: tuple[tuple[str, str, str], ...] = (
    ("ix_job_artifacts_path_trgm", "job_artifacts",
     'ON {schema}.job_artifacts USING gin (file_path gin_trgm_ops)'),
    ("ix_job_artifacts_name_trgm", "job_artifacts",
     'ON {schema}.job_artifacts USING gin (file_name gin_trgm_ops)'),
    ("ix_job_artifacts_job_ext", "job_artifacts",
     "ON {schema}.job_artifacts (job_id, lower(coalesce(extension, '')))"),
    ("ix_job_artifacts_job_enc", "job_artifacts",
     "ON {schema}.job_artifacts (job_id, encyclopedia_artifact_id) WHERE encyclopedia_artifact_id IS NOT NULL"),
    ("ix_job_artifacts_job_size", "job_artifacts",
     "ON {schema}.job_artifacts (job_id, size_bytes DESC NULLS LAST)"),
    ("ix_job_artifacts_job_deleted", "job_artifacts",
     "ON {schema}.job_artifacts (job_id) WHERE coalesce(metadata->>'is_deleted','') IN ('true','1')"),
    ("ix_job_artifacts_job_parse_pending", "job_artifacts",
     "ON {schema}.job_artifacts (job_id) WHERE parse_status = 'pending'"),
    ("ix_job_artifacts_job_ocr_pending", "job_artifacts",
     "ON {schema}.job_artifacts (job_id) WHERE ocr_status = 'pending'"),
    ("ix_rag_chunks_content_fts", "rag_chunks",
     "ON {schema}.rag_chunks USING gin (to_tsvector('english', coalesce(content, '')))"),
    ("ix_rag_chunks_job_artifact", "rag_chunks",
     "ON {schema}.rag_chunks (job_id, artifact_id) WHERE artifact_id IS NOT NULL"),
    ("ix_artifact_parse_results_artifact_created", "artifact_parse_results",
     "ON {schema}.artifact_parse_results (job_artifact_id, created_at DESC)"),
    ("ix_artifact_parse_results_parser", "artifact_parse_results",
     "ON {schema}.artifact_parse_results (parser_name)"),
    ("ix_artifact_parse_results_record_type", "artifact_parse_results",
     "ON {schema}.artifact_parse_results ((normalized->>'record_type'))"),
    ("ix_job_axiom_results_job_status", "job_axiom_artifact_results",
     "ON {schema}.job_axiom_artifact_results (job_id, status)"),
    ("ix_disk_build_logs_job_stage", "disk_build_logs",
     "ON {schema}.disk_build_logs (job_id, stage, timestamp DESC)"),
)

VECTOR_INDEX = (
    "ix_rag_chunks_embedding_v2_hnsw", "rag_chunks",
    "ON {schema}.rag_chunks USING hnsw (embedding_v2 vector_cosine_ops) "
    "WITH (m = 16, ef_construction = 64) WHERE embedding_v2 IS NOT NULL",
)

PUBLIC_INDEXES: tuple[tuple[str, str], ...] = (
    ("ix_axiom_artifacts_platform_sort", "ON public.axiom_artifacts (platform, sort_order)"),
    ("ix_axiom_artifacts_name_lower", "ON public.axiom_artifacts (lower(artifact_name))"),
)


def active_schemas(conn) -> list[str]:
    rows = conn.execute(
        text("SELECT schema_name FROM public.firms WHERE lower(coalesce(status,''))='active' ORDER BY 1")
    ).all()
    return [str(r[0]) for r in rows]


def table_exists(conn, schema: str, table: str) -> bool:
    return conn.execute(text("SELECT to_regclass(:r) IS NOT NULL"), {"r": f"{schema}.{table}"}).scalar() is True


def column_exists(conn, schema: str, table: str, column: str) -> bool:
    return bool(
        conn.execute(
            text(
                "SELECT 1 FROM information_schema.columns WHERE table_schema=:s AND table_name=:t AND column_name=:c"
            ),
            {"s": schema, "t": table, "c": column},
        ).first()
    )


def index_state(conn, schema: str, name: str):
    row = conn.execute(
        text(
            """SELECT i.indisvalid FROM pg_class c
               JOIN pg_namespace n ON n.oid=c.relnamespace
               JOIN pg_index i ON i.indexrelid=c.oid
               WHERE n.nspname=:s AND c.relname=:n"""
        ),
        {"s": schema, "n": name},
    ).first()
    if row is None:
        return None
    return bool(row[0])


def build_one(conn, schema: str, name: str, body: str, *, concurrent: bool, dry_run: bool, retries: int = 3) -> str:
    state = index_state(conn, schema, name)
    if state is True:
        return "exists"
    if state is False:
        log(f"  {name}: INVALID leftover found -> dropping")
        if not dry_run:
            conn.execute(text(f"DROP INDEX {'CONCURRENTLY ' if concurrent else ''}IF EXISTS {qident(schema)}.{qident(name)}"))
    sql = f"CREATE INDEX {'CONCURRENTLY ' if concurrent else ''}IF NOT EXISTS {qident(name)} " + body.format(schema=qident(schema))
    if dry_run:
        log(f"  DRY: {sql}")
        return "dry"
    for attempt in range(1, retries + 1):
        started = time.monotonic()
        try:
            conn.execute(text(sql))
            log(f"  {name}: built in {time.monotonic() - started:.1f}s")
            return "built"
        except (OperationalError, DBAPIError) as exc:
            msg = str(exc).lower()
            if "lock" in msg and attempt < retries:
                log(f"  {name}: lock wait (attempt {attempt}) -> retry in 10s")
                time.sleep(10)
                continue
            log(f"  {name}: FAILED ({str(exc).splitlines()[0][:200]})")
            return "failed"
    return "failed"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", help="single firm schema (default: all active firms)")
    ap.add_argument("--with-vector", action="store_true", help="also build HNSW on rag_chunks.embedding_v2")
    ap.add_argument("--no-concurrent", action="store_true", help="plain CREATE INDEX (maintenance window)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--maintenance-work-mem", default="1GB", help="session setting for index builds")
    args = ap.parse_args()
    concurrent = not args.no_concurrent

    # CONCURRENTLY cannot run inside a transaction: use AUTOCOMMIT connections.
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        conn.execute(text("SET lock_timeout = '60s'"))
        conn.execute(text("SET statement_timeout = 0"))
        try:
            conn.execute(text(f"SET maintenance_work_mem = '{args.maintenance_work_mem}'"))
        except Exception as exc:
            log(f"maintenance_work_mem not applied: {exc}")
        for ext in ("pg_trgm", "vector"):
            try:
                if not args.dry_run:
                    conn.execute(text(f"CREATE EXTENSION IF NOT EXISTS {ext}"))
            except Exception as exc:
                log(f"extension {ext}: {exc}")

        log("public catalog indexes:")
        for name, body in PUBLIC_INDEXES:
            build_one(conn, "public", name, body, concurrent=concurrent, dry_run=args.dry_run)

        schemas = [args.schema] if args.schema else active_schemas(conn)
        summary: dict[str, dict[str, int]] = {}
        for schema in schemas:
            if not _IDENT.fullmatch(schema):
                log(f"skip unsafe schema {schema!r}")
                continue
            log(f"schema {schema}:")
            counts = {"built": 0, "exists": 0, "failed": 0, "skipped": 0, "dry": 0}
            plan = list(INDEXES)
            if args.with_vector:
                plan.append(VECTOR_INDEX)
            touched: set[str] = set()
            for name, table, body in plan:
                if not table_exists(conn, schema, table):
                    counts["skipped"] += 1
                    continue
                if name == VECTOR_INDEX[0] and not column_exists(conn, schema, "rag_chunks", "embedding_v2"):
                    log(f"  {name}: embedding_v2 column absent -> skipped")
                    counts["skipped"] += 1
                    continue
                res = build_one(conn, schema, name, body, concurrent=concurrent, dry_run=args.dry_run)
                counts[res] = counts.get(res, 0) + 1
                if res == "built":
                    touched.add(table)
            for table in sorted(touched):
                try:
                    conn.execute(text(f"ANALYZE {qident(schema)}.{qident(table)}"))
                    log(f"  ANALYZE {table} done")
                except Exception as exc:
                    log(f"  ANALYZE {table} skipped: {exc}")
            summary[schema] = counts
        log("SUMMARY: " + "; ".join(f"{s}: {c}" for s, c in summary.items()))
        failed = sum(c.get("failed", 0) for c in summary.values())
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
