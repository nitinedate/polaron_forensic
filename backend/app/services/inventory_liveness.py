"""Artifact-inventory liveness (V45.2) - now a thin wrapper over job_liveness (V45.5).

Kept for import compatibility with catalog_artifact_runner. In addition to the
lock refresh and the step log it now also bumps ``jobs.updated_at`` every 20 s,
so the API/UI stall detectors treat a running inventory as alive.
"""

from __future__ import annotations

from app.services.job_liveness import JobLiveness

LIVENESS_PREFIX = "Artifact inventory liveness"


class InventoryLiveness(JobLiveness):
    def __init__(self, schema_name: str | None, job_id: str, *, refresh_sec: float = 45.0, log_sec: float = 90.0) -> None:
        super().__init__(
            schema_name,
            job_id,
            stage="artifact_inventory",
            label="Artifact inventory",
            lock_kind="inventory",
            refresh_sec=refresh_sec,
            log_sec=log_sec,
        )
