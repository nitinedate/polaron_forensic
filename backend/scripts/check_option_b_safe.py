#!/usr/bin/env python3
"""Request cooperative stop, wait for paused, recreate worker-disk, resume.

WARNING: If completed_shards is empty, in-flight extract progress is lost.
"""

from __future__ import annotations

import json
import os
import sys
import time

import psycopg2

JOB_ID = os.environ.get("JOB_ID", "5ea7301b-62c7-4271-bda7-ea85e2bae65f")
SCHEMA = os.environ.get("FIRM_SCHEMA", "firm_aetheris")
DSN = os.environ.get(
    "DATABASE_URL_PSYCOPG",
    "postgresql://forensic:forensic@postgres:5432/forensic",
)


def main() -> int:
    conn = psycopg2.connect(DSN)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(f'SET search_path TO "{SCHEMA}", public')
    cur.execute(
        "SELECT status, files_extracted, files_total, "
        "extraction_checkpoint FROM jobs WHERE id=%s",
        (JOB_ID,),
    )
    row = cur.fetchone()
    if not row:
        print("job not found", file=sys.stderr)
        return 1
    status, fe, ft, cp = row
    if isinstance(cp, str):
        cp = json.loads(cp)
    completed = (cp or {}).get("completed_shards") or []
    print(f"status={status} extracted={fe}/{ft} completed_shards={len(completed)}")
    if status == "building_disk" and len(completed) == 0 and int(fe or 0) > 1000:
        print(
            "REFUSING destructive pause: 0 shards uploaded; pause would discard "
            f"~{fe:,} in-flight files. Leave job running or confirm data loss.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
