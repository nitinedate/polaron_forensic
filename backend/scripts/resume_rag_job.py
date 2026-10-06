"""Resume interrupted GPU RAG embedding for a job."""
from __future__ import annotations

import json
import sys

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import write_disk_log
from app.services.dual_rag_index import _count_indexable_artifacts, _count_indexable_without_chunks
from app.tasks import rag_append_task


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: resume_rag_job.py <schema> <job_id>", file=sys.stderr)
        raise SystemExit(2)
    schema, job_id = sys.argv[1], sys.argv[2]
    with firm_session(schema) as db:
        remaining = _count_indexable_without_chunks(db, job_id)
        chunks = fetchone(
            db,
            "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
            {"jid": job_id},
        )
        chunk_n = int(chunks["c"]) if chunks else 0
        total = _count_indexable_artifacts(db, job_id)
        print(f"chunks={chunk_n} remaining={remaining} total={total}")
        if remaining <= 0:
            print("Nothing to resume.")
            return
        execute(
            db,
            """UPDATE jobs SET status='indexing', error=NULL, stop_requested=FALSE,
               pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
            {
                "pp": json.dumps({
                    "phase": "rag",
                    "completed": chunk_n,
                    "total": max(total, chunk_n + remaining, 1),
                    "label": f"Resuming RAG — {remaining:,} artifacts to embed",
                }),
                "id": job_id,
            },
        )
        write_disk_log(
            db,
            job_id,
            f"Manual RAG resume — {chunk_n:,} chunks embedded, {remaining:,} artifacts pending",
            stage="rag_index",
        )
        db.commit()
    rag_append_task.delay(schema, job_id)
    print("queued rag_append_task")


if __name__ == "__main__":
    main()
