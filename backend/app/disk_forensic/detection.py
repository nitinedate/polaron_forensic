"""Disk job detection — re-exports forensic_common."""

from app.forensic_common.job_types import DISK_JOB_TYPES, is_disk_job

__all__ = ["DISK_JOB_TYPES", "is_disk_job"]
