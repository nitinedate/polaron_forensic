#!/usr/bin/env python3
"""Verify V37 Artifact Explorer indexes for every active firm schema.

Usage from the api container / backend environment:
    python scripts/verify_artifact_browse_indexes_v37.py
    python scripts/verify_artifact_browse_indexes_v37.py --schema firm_polaron

Exit code 0 = all required indexes present; 2 = one or more missing.
"""

from __future__ import annotations

import argparse
from sqlalchemy import text

from app.db.session import engine

REQUIRED = (
    "ix_job_artifacts_job_path",
    "ix_job_artifacts_job_file_name",
    "ix_job_artifacts_job_file_name_lower",
    "ix_job_artifacts_job_ext",
    "ix_job_artifacts_job_enc",
    "ix_job_artifacts_job_mime_resolved",
    "ix_job_artifacts_job_mime",
    "ix_job_artifacts_job_mime_resolved_lower",
    "ix_job_artifacts_job_mime_lower",
    "ix_job_artifacts_job_mime_scan_version",
    "ix_job_artifacts_job_size",
    "ix_artifact_parse_results_artifact_created",
    "ix_artifact_parse_results_parser_artifact",
)
OPTIONAL = (
    "ix_job_artifacts_path_trgm",
    "ix_job_artifacts_name_trgm",
)


def schemas(conn, only: str | None) -> list[str]:
    if only:
        return [only]
    return [
        str(r[0])
        for r in conn.execute(
            text("SELECT schema_name FROM public.firms WHERE lower(coalesce(status,''))='active' ORDER BY schema_name")
        ).all()
    ]


def index_names(conn, schema: str) -> set[str]:
    return {
        str(r[0])
        for r in conn.execute(
            text("SELECT indexname FROM pg_indexes WHERE schemaname=:s"),
            {"s": schema},
        ).all()
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema")
    args = ap.parse_args()
    missing_any = False
    with engine.connect() as conn:
        for schema in schemas(conn, args.schema):
            names = index_names(conn, schema)
            print(f"[{schema}]")
            for name in REQUIRED:
                ok = name in names
                print(f"  {'OK     ' if ok else 'MISSING'} {name}")
                missing_any = missing_any or not ok
            for name in OPTIONAL:
                print(f"  {'OK     ' if name in names else 'OPTION '} {name}")
            stats = conn.execute(
                text(f'SELECT count(*) AS c FROM "{schema}".job_artifacts')
            ).scalar_one_or_none()
            print(f"  rows    job_artifacts={int(stats or 0):,}")
    return 2 if missing_any else 0


if __name__ == "__main__":
    raise SystemExit(main())
