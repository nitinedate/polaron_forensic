"""Android/iOS-specific image extraction orchestration.

This module is intentionally separate from the Disk orchestration entrypoint.
It validates that the active service owns the job before invoking the neutral
low-level image engine. Android and iOS services therefore cannot process each
other's jobs even if a task is accidentally published to the wrong broker.
"""

from __future__ import annotations

from app.db.session import firm_session
from app.db.sql_helpers import fetchone
from app.service_identity import (
    MOBILE_ANDROID,
    MOBILE_IOS,
    current_service,
    job_type_platform,
    mobile_service_platform,
    service_allows_job_type,
)
from app.services.disk import build_extracted_image
from app.services.mobile_platform_agents import detect_mobile_platform, mobile_os_family_from_job_row


class MobileExtractionBoundaryError(ValueError):
    """Raised when a mobile backend receives a job outside its platform."""


class MobileExtractionHandoff(Exception):
    """Evidence belongs to the other mobile product. Not a worker death."""

    def __init__(self, platform: str, job_type: str) -> None:
        self.platform = platform
        self.job_type = job_type
        super().__init__(
            f"Evidence belongs to {platform}; job type set to {job_type}"
        )


def canonical_type_for_platform(platform: str | None) -> str | None:
    if platform == "ios":
        return "ios_mobile"
    if platform == "android":
        return "android_mobile"
    return None


def _mobile_job_row(db, job_id: str) -> dict:
    row = fetchone(
        db,
        "SELECT id, type, disk_source FROM jobs WHERE id=:jid",
        {"jid": job_id},
    )
    if not row:
        raise MobileExtractionBoundaryError(f"Mobile job not found: {job_id}")
    return dict(row)


def assert_mobile_extraction_ownership(db, job_id: str) -> tuple[dict, str | None]:
    row = _mobile_job_row(db, job_id)
    service = current_service()
    job_type = str(row.get("type") or "")

    # Resolve the job owner and the evidence hints independently.  Do not let
    # a canonical Android/iOS job type mask evidence metadata that clearly
    # belongs to the opposite platform.
    from app.forensic_common.job_types import _as_dict

    disk_source = _as_dict(row.get("disk_source"))
    type_platform = job_type_platform(job_type)
    source_platforms: set[str] = set()
    for hint in (
        disk_source.get("owner_agent"),
        disk_source.get("mobile_os"),
        disk_source.get("axiom_platform"),
        disk_source.get("evidence_platform"),
        disk_source.get("adapter"),
        disk_source.get("os_family"),
        disk_source.get("source_type"),
        disk_source.get("device_label"),
        disk_source.get("model"),
        disk_source.get("path"),
        disk_source.get("host_path"),
        disk_source.get("evidence_folder"),
        disk_source.get("working"),
    ):
        detected = detect_mobile_platform(hint)
        if detected:
            source_platforms.add(detected)

    if len(source_platforms) > 1:
        raise MobileExtractionBoundaryError(
            f"{service} received conflicting Android/iOS evidence metadata"
        )
    source_platform = next(iter(source_platforms), None)
    if type_platform and source_platform and type_platform != source_platform:
        corrected = canonical_type_for_platform(source_platform)
        # Job type is {type_platform} but evidence metadata is {source_platform}.
        # Correct the type and let the owning product extract. Leaving status
        # at processing made the supervisor report "no heartbeat" every minute.
        if corrected and corrected != job_type:
            from app.db.sql_helpers import execute
            from app.services.disk_build_log import write_disk_log

            execute(
                db,
                "UPDATE jobs SET type=:t, updated_at=NOW() WHERE id=:id",
                {"t": corrected, "id": row["id"]},
            )
            write_disk_log(
                db,
                str(row["id"]),
                (
                    f"Job type is {type_platform} but evidence metadata is {source_platform}. "
                    f"Corrected job type to {corrected} for the owning product."
                ),
                stage="extract",
                level="warning",
            )
            db.commit()
            job_type = corrected
            row["type"] = corrected
            type_platform = source_platform
        service_platform = mobile_service_platform(service)
        if service_platform and service_platform != source_platform:
            raise MobileExtractionHandoff(source_platform, job_type)

    if not service_allows_job_type(job_type, service=service):
        owner = source_platform or type_platform or "other"
        raise MobileExtractionHandoff(str(owner), job_type)

    platform = source_platform or type_platform or mobile_os_family_from_job_row(row)
    service_platform = mobile_service_platform(service)
    if service in {MOBILE_ANDROID, MOBILE_IOS}:
        if platform is None:
            raise MobileExtractionBoundaryError(
                f"{service} requires an explicit Android/iOS job owner"
            )
        if platform != service_platform:
            raise MobileExtractionHandoff(str(platform), job_type)
    return row, platform


def build_extracted_mobile(db, job_id: str, *, schema_name: str) -> dict:
    """Mobile-only orchestration entrypoint for Android/iOS image extraction."""
    assert_mobile_extraction_ownership(db, job_id)
    return build_extracted_image(db, job_id, schema_name=schema_name)


def build_extracted_mobile_sync(schema_name: str, job_id: str) -> dict:
    """Synchronous Celery bridge for the mobile-only extraction service."""
    from celery import current_task

    from app.services.db_resilience import wait_for_database
    from app.services.job_control import set_celery_task_id

    wait_for_database(timeout_sec=120)
    task_id = current_task.request.id if current_task and current_task.request else None
    with firm_session(schema_name) as db:
        if task_id:
            set_celery_task_id(db, job_id, task_id)
            db.commit()
        return build_extracted_mobile(db, job_id, schema_name=schema_name)
