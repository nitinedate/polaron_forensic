"""Mark Drive Mount done when Docker already has the Windows letters."""

from __future__ import annotations

import sys

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.drive_mount_agent import mounted_letters
from app.services.pipeline_orchestrator import persist_drive_mount_complete


def main() -> int:
    letters = mounted_letters()
    print("mounted", letters)
    if not letters:
        return 1
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))
    row = db.execute(
        text(
            """
            SELECT id, status
            FROM jobs
            ORDER BY created_at DESC
            LIMIT 1
            """
        )
    ).mappings().first()
    if not row:
        print("no job")
        return 0
    job_id = str(row["id"])
    persist_drive_mount_complete(
        db,
        job_id,
        mounted=letters,
        detail="Drives already mounted (" + ", ".join(letters) + ") — no remount",
    )
    db.commit()
    print("healed", job_id, "status", row.get("status"), "letters", letters)
    return 0


if __name__ == "__main__":
    sys.exit(main())
