#!/usr/bin/env python3
"""Ensure only one extract runs — pause sibling, queue target job."""
from __future__ import annotations

import sys

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.routers.jobs import _queue_disk_build

TARGET = "44e9b386-9264-4857-a55a-bc032ed3c5d0"
SIBLING = "234ce615-8538-4ff9-a80f-460826e4de10"
SCHEMA = "firm_aetheris"


def main() -> int:
    with firm_session(SCHEMA) as db:
        execute(
            db,
            """UPDATE jobs SET status='paused', celery_task_id=NULL, stop_requested=TRUE,
                   error='Paused — only one E01 extract allowed for speed', updated_at=NOW()
               WHERE id=:id""",
            {"id": SIBLING},
        )
        execute(
            db,
            """UPDATE jobs SET status='processing', stop_requested=FALSE, error=NULL,
                   celery_task_id=NULL, updated_at=NOW()
               WHERE id=:id""",
            {"id": TARGET},
        )
        db.commit()
        _queue_disk_build(db, SCHEMA, TARGET, force=True)
        row = fetchone(
            db,
            "SELECT id, status, files_extracted, files_total, celery_task_id FROM jobs WHERE id=:id",
            {"id": TARGET},
        )
        sib = fetchone(
            db,
            "SELECT id, status, files_extracted FROM jobs WHERE id=:id",
            {"id": SIBLING},
        )
        print("target", dict(row))
        print("sibling", dict(sib))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
