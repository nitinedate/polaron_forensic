"""Thin shared forensic helpers — domain-neutral job typing and path utils."""

from app.forensic_common.job_types import (
    DISK_JOB_TYPES,
    MOBILE_JOB_TYPES,
    is_disk_job,
    is_mobile_job,
    job_domain,
    mobile_platform,
)

__all__ = [
    "DISK_JOB_TYPES",
    "MOBILE_JOB_TYPES",
    "is_disk_job",
    "is_mobile_job",
    "job_domain",
    "mobile_platform",
]
