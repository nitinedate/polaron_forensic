#!/usr/bin/env python3
"""Diagnose Artifact Explorer index coverage and the EML list query.

Examples:
  python scripts/diagnose_artifact_explorer_v37.py --schema firm_polaron
  python scripts/diagnose_artifact_explorer_v37.py --schema firm_polaron --job-id <uuid>

The script is read-only. It prints index presence, table statistics, and an
EXPLAIN plan for the hot EML(X) Files query when a job id is supplied.
"""
from __future__ import annotations

import argparse
import re
from sqlalchemy import text

from app.db.session import engine

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REQUIRED = (
    "ix_job_artifacts_job_path",
    "ix_job_artifacts_job_ext",
    "ix_job_artifacts_job_mime_resolved_lower",
    "ix_job_artifacts_job_mime_lower",
    "ix_job_artifacts_job_mime_scan_version",
    "ix_job_axiom_results_job_artifact_status",
)


def qident(value: str) -> str:
    if not IDENT.fullmatch(value or ""):
        raise ValueError(f"unsafe schema: {value!r}")
    return f'"{value}"'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    ap.add_argument("--job-id")
    args = ap.parse_args()
    schema = args.schema
    qs = qident(schema)

    with engine.connect() as conn:
        names = {
            str(row[0])
            for row in conn.execute(
                text("SELECT indexname FROM pg_indexes WHERE schemaname=:s"),
                {"s": schema},
            ).all()
        }
        print(f"[{schema}] index health")
        missing = False
        for name in REQUIRED:
            ok = name in names
            print(f"  {'OK' if ok else 'MISSING':7} {name}")
            missing = missing or not ok

        rows = conn.execute(text(f"SELECT count(*) FROM {qs}.job_artifacts")).scalar_one()
        print(f"  rows    job_artifacts={int(rows or 0):,}")

        if args.job_id:
            print("\nEML(X) Files EXPLAIN:")
            sql = text(
                f"""EXPLAIN (COSTS TRUE, VERBOSE FALSE)
                SELECT id, file_path, file_name, extension, size_bytes
                FROM {qs}.job_artifacts
                WHERE job_id=:jid AND (
                    lower(coalesce(extension,'')) IN ('.eml', '.emlx')
                    OR lower(coalesce(metadata->>'resolved_content_type',''))='message/rfc822'
                    OR lower(coalesce(metadata->>'content_type',''))='message/rfc822'
                )
                ORDER BY file_path
                LIMIT 50"""
            )
            for row in conn.execute(sql, {"jid": args.job_id}).all():
                print("  " + str(row[0]))
    return 2 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
