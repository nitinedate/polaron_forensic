"""Complete, bounded per-target snapshots for the central progress API."""

from __future__ import annotations

import math
from typing import Any


def progress_percent(value: Any, *, terminal: bool = False) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        number = 0.0
    if not math.isfinite(number):
        number = 0.0
    return max(0, min(100 if terminal else 99, int(number)))


def build_target_progress(
    all_targets: list[str],
    *,
    chunks: list[list[str]],
    in_flight: dict[int, str],
    done_details: dict[int, dict[str, Any]],
    poll_results: dict[int, dict[str, Any]] | None = None,
    skipped_hosts: list[dict[str, Any]] | None = None,
    assessed_hosts: list[str] | None = None,
    event_seq: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Return every selected host, including waiting, skipped and failed hosts.

    Task completion is separate from coverage: a finished truncated assessment
    is incomplete, and a skipped host never receives a green completed state.
    """
    states = {str(h): {"status": "pending", "activity": "Waiting", "progress_pct": 0}
              for h in all_targets if str(h).strip()}
    for host in assessed_hosts or []:
        if host in states:
            states[host] = {"status": "completed", "activity": "Previously assessed", "progress_pct": 100}
    for item in skipped_hosts or []:
        host = str(item.get("host") or item.get("ip") or "")
        if host not in states:
            continue
        reason = str(item.get("reason") or "skipped")
        failed = reason in {"start_error", "poll_error", "scan_failed", "scan_stopped"}
        states[host] = {"status": "failed" if failed else "skipped",
                        "activity": ("Failed: " if failed else "Skipped: ") + reason[:160],
                        "progress_pct": 0}
    for idx, chunk in enumerate(chunks):
        finished = idx in done_details
        details = done_details.get(idx) if finished else (poll_results or {}).get(idx, {})
        details = details or {}
        for host in chunk:
            if host not in states:
                continue
            if finished:
                reason = str(details.get("_agent_skip_reason") or "")
                cov = ((details.get("evidence") or {}).get("host_coverage") or {}).get(host) or {}
                if reason:
                    state = states[host]
                    if state["status"] == "pending":
                        state = {"status": "failed", "activity": "Failed: " + reason[:160], "progress_pct": 0}
                elif str(details.get("status") or "").lower() in {"failed", "stopped"}:
                    state = {"status": "failed", "activity": "Failed", "progress_pct": progress_percent(details.get("progress"))}
                elif str(cov.get("verdict") or "").startswith("degraded") or (details.get("evidence") or {}).get("assessment_complete") is False:
                    state = {"status": "incomplete", "activity": "Incomplete: " + str(cov.get("reason") or "assessment coverage not verified")[:160], "progress_pct": 100}
                else:
                    state = {"status": "completed", "activity": "Completed", "progress_pct": 100}
            elif idx in in_flight:
                pct = progress_percent(details.get("progress"))
                state = {"status": "scanning", "activity": f"In progress ({pct}%)", "progress_pct": pct}
            else:
                continue
            task_id = in_flight.get(idx) or details.get("task_id")
            if task_id:
                state = dict(state, task_id=str(task_id)[:128])
            states[host] = state
    if event_seq is not None:
        for state in states.values():
            state["event_seq"] = event_seq
    return states
