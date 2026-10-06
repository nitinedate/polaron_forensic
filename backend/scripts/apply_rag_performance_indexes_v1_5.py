#!/usr/bin/env python3
"""Create targeted indexes used by the streaming forensic RAG hot path.

The script is intentionally idempotent.  It uses normal CREATE INDEX while the
v1.5 deployment has paused the forensic workers, avoiding the long old-snapshot
waits previously observed with CREATE INDEX CONCURRENTLY.
"""
from __future__ import annotations

import argparse
import re
import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.db.session import engine


INDEXES = (
    (
        "ix_job_artifacts_job_id_id",
        'CREATE INDEX IF NOT EXISTS "ix_job_artifacts_job_id_id" '
        'ON "{schema}".job_artifacts (job_id, id)',
    ),
    (
        "ix_artifact_parse_results_artifact_created",
        'CREATE INDEX IF NOT EXISTS "ix_artifact_parse_results_artifact_created" '
        'ON "{schema}".artifact_parse_results (job_artifact_id, created_at DESC)',
    ),
    (
        "ix_ocr_results_artifact_created",
        'CREATE INDEX IF NOT EXISTS "ix_ocr_results_artifact_created" '
        'ON "{schema}".ocr_results (job_artifact_id, created_at DESC)',
    ),
    (
        "ix_rag_chunks_job_path_evidence",
        'CREATE INDEX IF NOT EXISTS "ix_rag_chunks_job_path_evidence" '
        'ON "{schema}".rag_chunks (job_id, file_path) '
        "WHERE chunk_type IN ('evidence','evidence_skip')",
    ),
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    args = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.schema):
        raise SystemExit(f"unsafe schema name: {args.schema}")

    deferred: list[str] = []
    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("SET lock_timeout='30s'"))
        conn.execute(text("SET statement_timeout='15min'"))
        for name, template in INDEXES:
            sql = template.format(schema=args.schema)
            started = time.monotonic()
            print(f"[{args.schema}] creating/checking {name} ...", flush=True)
            try:
                conn.execute(text(sql))
                print(f"[{args.schema}] {name} ready in {time.monotonic()-started:.1f}s", flush=True)
            except OperationalError as exc:
                msg = str(exc).lower()
                if "lock timeout" in msg or "locknotavailable" in msg:
                    print(f"[{args.schema}] WARNING: {name} deferred due to lock timeout", flush=True)
                    deferred.append(name)
                    continue
                raise
        for table in ("job_artifacts", "artifact_parse_results", "ocr_results", "rag_chunks"):
            try:
                conn.execute(text(f'ANALYZE "{args.schema}".{table}'))
            except Exception as exc:
                print(f"[{args.schema}] WARNING: ANALYZE {table} skipped: {exc}", flush=True)

    if deferred:
        print("DEFERRED_INDEXES=" + ",".join(deferred), flush=True)
    else:
        print("PERFORMANCE_INDEXES=ready", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
