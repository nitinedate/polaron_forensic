"""Detect mobile jobs — keep disk/EWF collectors out of this path."""

from __future__ import annotations

from app.forensic_common.job_types import (
    MOBILE_JOB_TYPES as _MOBILE_TYPES,
    is_mobile_job,
    mobile_platform,
)

__all__ = ["_MOBILE_TYPES", "is_mobile_job", "mobile_platform"]
