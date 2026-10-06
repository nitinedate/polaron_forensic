"""Seed case intake defaults for mobile extraction jobs."""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchone
from app.services.mobile_os import mobile_os_to_axiom_platform, normalize_mobile_os


def ensure_mobile_intake_defaults(db: Session, job_id: str, *, mobile_os: str | None = None) -> None:
    """Create or lightly update case_intake for mobile_device / mobile_forensic."""
    existing = fetchone(db, "SELECT id, case_type, report_type FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    os_id = normalize_mobile_os(mobile_os)
    platform = mobile_os_to_axiom_platform(os_id)
    os_focus = []
    if platform == "Android":
        os_focus = ["android"]
    elif platform == "iOS":
        os_focus = ["ios"]
    else:
        os_focus = ["android", "ios"]

    if existing:
        # Only fill blanks — never overwrite examiner edits.
        if not existing.get("case_type") or not existing.get("report_type"):
            execute(
                db,
                """UPDATE case_intake SET
                     case_type=COALESCE(NULLIF(case_type, ''), 'mobile_device'),
                     report_type=COALESCE(NULLIF(report_type, ''), 'mobile_forensic'),
                     updated_at=NOW()
                   WHERE job_id=:jid""",
                {"jid": job_id},
            )
        return

    execute(
        db,
        """INSERT INTO case_intake (
               job_id, case_type, report_type, organization, background, incident_summary,
               objective_ids, custom_objectives, subjects, scan_scope_json, vol18_form_json
           ) VALUES (
               :jid, 'mobile_device', 'mobile_forensic', NULL, NULL, NULL,
               CAST('[]' AS jsonb), CAST('[]' AS jsonb), CAST('[]' AS jsonb),
               CAST(:scope AS jsonb), CAST('{}' AS jsonb)
           )""",
        {
            "jid": job_id,
            "scope": json.dumps({"os_focus": os_focus, "mobile_os": os_id}),
        },
    )
