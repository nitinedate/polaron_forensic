"""Stop a forensic job and hard-delete every related row, file, and object."""
from __future__ import annotations

import json
import sys

from app.db.session import firm_session
from app.services.job_delete import hard_delete_job


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: hard_delete_job.py <schema> <job_id>", file=sys.stderr)
        raise SystemExit(2)
    schema, job_id = sys.argv[1], sys.argv[2]
    with firm_session(schema) as db:
        result = hard_delete_job(db, job_id)
    print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
