"""Background List-folder runs so a slow bind-mount walk never blocks the API.

The HTTP request used to run the whole directory walk inline. On a Docker
Desktop drvfs mount a phone-sized tree takes hours, the browser aborted at
120 s, the request thread stayed busy, and every retry stacked another walk
on top — the pipeline then looked frozen and the gateway answered 502.

Now ``list-folder`` either finishes inline (case-layout fast path, tiny
folders) or hands the walk to one daemon thread per job and returns
``{"status": "running"}``. The UI polls ``list-folder/status``.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_RUNS: dict[str, dict[str, Any]] = {}
# Never keep more than this many finished results around.
_MAX_FINISHED = 200


def _prune_locked() -> None:
    finished = [k for k, v in _RUNS.items() if v.get("status") in ("done", "error")]
    if len(finished) <= _MAX_FINISHED:
        return
    finished.sort(key=lambda k: _RUNS[k].get("finished_at") or 0.0)
    for key in finished[: len(finished) - _MAX_FINISHED]:
        _RUNS.pop(key, None)


def snapshot(job_id: str) -> dict[str, Any] | None:
    with _LOCK:
        run = _RUNS.get(job_id)
        return dict(run) if run else None


def is_running(job_id: str) -> bool:
    with _LOCK:
        run = _RUNS.get(job_id)
        return bool(run and run.get("status") == "running")


def start_background_listing(
    *,
    schema_name: str,
    job_id: str,
    path: str | None,
    drive: str = "",
    browse_path: str = "",
) -> dict[str, Any]:
    """Kick off (or reuse) the listing thread for *job_id*."""
    with _LOCK:
        existing = _RUNS.get(job_id)
        if existing and existing.get("status") == "running":
            return dict(existing)
        _prune_locked()
        run: dict[str, Any] = {
            "job_id": job_id,
            "status": "running",
            "path": path or (f"{drive}:\\{browse_path}" if drive else browse_path),
            "started_at": time.time(),
            "finished_at": None,
            "result": None,
            "error": None,
        }
        _RUNS[job_id] = run

    def _worker() -> None:
        from app.db.session import firm_session
        from app.services.host_evidence import list_folder_contents

        try:
            with firm_session(schema_name) as db:
                result = list_folder_contents(
                    db, job_id, path=path, drive=drive, browse_path=browse_path
                )
            with _LOCK:
                _RUNS[job_id].update(
                    {"status": "done", "result": result, "finished_at": time.time()}
                )
        except Exception as exc:  # noqa: BLE001 — surfaced to the poller
            log.warning("background list-folder failed job=%s: %s", job_id, exc)
            with _LOCK:
                _RUNS[job_id].update(
                    {"status": "error", "error": str(exc), "finished_at": time.time()}
                )

    threading.Thread(target=_worker, name=f"list-folder-{job_id[:8]}", daemon=True).start()
    return dict(run)
