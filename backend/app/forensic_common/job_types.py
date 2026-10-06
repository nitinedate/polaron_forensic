"""Single source of truth for disk vs mobile job domain detection."""

from __future__ import annotations

import json
from typing import Any, Literal

from app.db.sql_helpers import fetchone

MOBILE_JOB_TYPES = frozenset({"mobile_extraction", "android_mobile", "ios_mobile", "ios_backup", "android_backup"})
DISK_JOB_TYPES = frozenset({"host_disk", "forensic", "disk"})

JobDomain = Literal["disk", "mobile", "other"]


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def is_mobile_job(db, job_id: str) -> bool:
    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    if not row:
        return False
    if str(row.get("type") or "") in MOBILE_JOB_TYPES:
        return True
    ds = _as_dict(row.get("disk_source"))
    platform = str(
        ds.get("axiom_platform") or ds.get("evidence_platform") or ds.get("mobile_os") or ""
    ).lower()
    if platform in {"android", "ios"}:
        return True
    return str(ds.get("source_type") or "").lower() == "mobile"


def is_disk_job(db, job_id: str) -> bool:
    """True for host-disk / general forensic jobs that are not mobile."""
    if is_mobile_job(db, job_id):
        return False
    row = fetchone(db, "SELECT type FROM jobs WHERE id=:jid", {"jid": job_id})
    if not row:
        return False
    jtype = str(row.get("type") or "")
    if jtype in DISK_JOB_TYPES or not jtype:
        return True
    # Unknown forensic job types that are not mobile default to disk pipeline.
    if jtype in {"vulnerability"}:
        return False
    return True


def job_domain(db, job_id: str) -> JobDomain:
    if is_mobile_job(db, job_id):
        return "mobile"
    if is_disk_job(db, job_id):
        return "disk"
    return "other"


def mobile_os_family(db, job_id: str) -> str | None:
    """Return 'ios' or 'android' when the job is a phone of that platform."""
    from app.services.mobile_platform_agents import mobile_os_family_from_job_row

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    return mobile_os_family_from_job_row(row)


def is_ios_job(db, job_id: str) -> bool:
    return mobile_os_family(db, job_id) == "ios"


def is_android_job(db, job_id: str) -> bool:
    return mobile_os_family(db, job_id) == "android"


def mobile_platform(db, job_id: str) -> str:
    """Return Android / iOS / Mobile for labeling."""
    family = mobile_os_family(db, job_id)
    if family == "android":
        return "Android"
    if family == "ios":
        return "iOS"
    return "Mobile"
