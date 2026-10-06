"""Per-job parse lock — prevents duplicate parse_drain tasks on the same job.

Compatibility shim — prefer app.services.job_locks.
"""

from __future__ import annotations

from app.services.job_locks import parse_job_lock  # noqa: F401

__all__ = ["parse_job_lock"]
