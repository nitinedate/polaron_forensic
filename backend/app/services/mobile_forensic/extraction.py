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

    if not service_allows_job_type(job_type, service=service):
        raise MobileExtractionBoundaryError(
            f"{service} cannot process job type {job_type or '<empty>'}"
        )

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
        raise MobileExtractionBoundaryError(
            f"Job type is {type_platform} but evidence metadata is {source_platform}"
        )

    platform = source_platform or type_platform or mobile_os_family_from_job_row(row)
    service_platform = mobile_service_platform(service)
    if service in {MOBILE_ANDROID, MOBILE_IOS}:
        if platform is None:
            raise MobileExtractionBoundaryError(
                f"{service} requires an explicit Android/iOS job owner"
            )
        if platform != service_platform:
            raise MobileExtractionBoundaryError(
                f"{service} cannot process {platform} mobile evidence"
            )
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
