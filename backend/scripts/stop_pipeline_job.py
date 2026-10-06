"""Stop a running pipeline job (extraction or RAG/indexing)."""
from __future__ import annotations

import sys

from app.db.session import firm_session
from app.services.disk_build_log import write_disk_log
from app.services.job_control import request_job_stop


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: stop_pipeline_job.py <schema> <job_id>", file=sys.stderr)
        raise SystemExit(2)
    schema, job_id = sys.argv[1], sys.argv[2]
    with firm_session(schema) as db:
        result = request_job_stop(db, job_id)
        write_disk_log(db, job_id, result["message"], stage="supervisor", level="info")
        db.commit()
        print(result)


if __name__ == "__main__":
    main()
