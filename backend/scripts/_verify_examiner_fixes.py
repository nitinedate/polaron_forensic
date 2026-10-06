"""Quick verification of examiner UX fixes for a mobile job."""
from __future__ import annotations

import sys

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone
from app.services.artifact_family_browse import family_where_sql
from app.services.artifact_preview import build_artifact_preview

JOB = sys.argv[1] if len(sys.argv) > 1 else "02bcb441-d1de-45b0-8a79-9c9139f08875"
SCHEMA = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"


def main() -> None:
    db = SessionLocal()
    apply_firm_search_path(db, SCHEMA)
    try:
        sql, _ = family_where_sql("email_attachments")
        c = fetchone(
            db,
            f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j {sql}",
            {"j": JOB},
        )
        print("email_attachments count", c["c"] if c else None)

        bad = fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts
               WHERE job_id=:j AND lower(file_name)='observations.db'""",
            {"j": JOB},
        )
        print("observations.db in job (raw)", bad["c"] if bad else None)

        heic = fetchone(
            db,
            """SELECT id, file_name FROM job_artifacts
               WHERE job_id=:j AND lower(file_name) LIKE '%.heic'
               ORDER BY size_bytes DESC NULLS LAST LIMIT 1""",
            {"j": JOB},
        )
        print("heic sample", dict(heic) if heic else None)
        if heic:
            preview = build_artifact_preview(db, JOB, str(heic["id"]))
            print(
                "heic preview",
                preview.get("content_type"),
                preview.get("encoding"),
                str(preview.get("body") or "")[:48],
            )
    finally:
        db.close()


if __name__ == "__main__":
    main()
