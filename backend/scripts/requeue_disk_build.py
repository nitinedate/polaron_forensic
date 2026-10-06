"""Re-queue disk build after segment readiness fix."""
from __future__ import annotations

import json
import sys

from sqlalchemy import text

from app.db.session import SessionLocal
from app.services.disk import segment_readiness

JOB_ID = sys.argv[1] if len(sys.argv) > 1 else "06cb1f14-2149-428c-8264-322f5b9c4779"
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"


def main() -> None:
    with SessionLocal() as db:
        files = db.execute(
            text(f"SELECT original_name, status FROM {SCHEMA}.evidence_files WHERE job_id=:j"),
            {"j": JOB_ID},
        ).fetchall()
        sr = segment_readiness([{"original_name": r[0], "status": r[1]} for r in files])
        db.execute(
            text(
                f"UPDATE {SCHEMA}.jobs SET segment_readiness=CAST(:sr AS jsonb), "
                "status='registered', updated_at=NOW() WHERE id=:j"
            ),
            {"sr": json.dumps(sr), "j": JOB_ID},
        )
        db.commit()
        print("readiness ready=", sr["ready"])

    from app.tasks import build_extracted_disk_task

    result = build_extracted_disk_task.delay(SCHEMA, JOB_ID)
    print("queued build_extracted_disk_task", result.id)


if __name__ == "__main__":
    main()
