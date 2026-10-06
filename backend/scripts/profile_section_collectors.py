"""Profile artifact section collector timing for a job."""
import sys
import time

from app.db.session import firm_session
from app.services.artifact_sections import SECTION_CATALOG


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: profile_section_collectors.py <schema> <job_id>", file=sys.stderr)
        sys.exit(1)
    schema, job_id = sys.argv[1], sys.argv[2]
    with firm_session(schema) as db:
        for sec in SECTION_CATALOG:
            for item in sec["items"]:
                t0 = time.time()
                try:
                    with db.begin_nested():
                        data = item["collector"](db, job_id) or {}
                    dt = time.time() - t0
                    label = f"{sec['key']}/{item['key']}"
                    print(f"{dt:6.1f}s  {label:40s}  count={data.get('count')}")
                except Exception as exc:
                    print(f"ERR    {sec['key']}/{item['key']}: {exc}")


if __name__ == "__main__":
    main()
