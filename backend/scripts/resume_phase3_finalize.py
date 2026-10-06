"""Resume Phase 3 finalize for a job on GPU."""

from __future__ import annotations

import json
import sys

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import write_disk_log
from app.tasks import phase3_finalize_task

JOB_ID = sys.argv[1] if len(sys.argv) > 1 else "5ea7301b-62c7-4271-bda7-ea85e2bae65f"
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"


def main() -> None:
    with firm_session(SCHEMA) as db:
        chunks = fetchone(db, "SELECT count(*) c FROM rag_chunks WHERE job_id=:j", {"j": JOB_ID})
        arts = fetchone(
            db,
            """SELECT count(*) c FROM job_artifacts
               WHERE job_id=:j AND (parse_status='parsed' OR ocr_status='done')""",
            {"j": JOB_ID},
        )
        n_chunks = int(chunks["c"] or 0) if chunks else 0
        n_arts = int(arts["c"] or 0) if arts else 0
        print(f"chunks={n_chunks} parsable_artifacts={n_arts}")
        write_disk_log(
            db,
            JOB_ID,
            f"Resuming Phase 3 finalize on GPU — {n_chunks:,} chunks so far; skip already-indexed",
            stage="phase3",
            level="warn",
            metadata={"resume": True, "device": "cuda"},
        )
        execute(
            db,
            """UPDATE jobs SET status='indexing',
               pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
            {
                "pp": json.dumps({
                    "phase": "rag",
                    "completed": n_chunks,
                    "total": max(n_arts, n_chunks, 1),
                    "label": "Resuming RAG on GPU",
                }),
                "id": JOB_ID,
            },
        )
        db.commit()
    result = phase3_finalize_task.delay(SCHEMA, JOB_ID)
    print(f"queued finalize {result.id}")


if __name__ == "__main__":
    main()
