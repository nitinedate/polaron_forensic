"""Download Agent — receive client E01/EWF segments before any other pipeline work.

Browser uploads run with DOWNLOAD_PARALLELISM concurrent HTTP copies. Every other
action agent stays blocked until this agent writes upload_status=complete.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.services.disk_build_log import write_disk_log

log = logging.getLogger("download_agent")

DOWNLOAD_PARALLELISM = 5
DOWNLOAD_STAGE = "download"


def download_counts(ds: dict | None) -> tuple[int, int]:
    if not isinstance(ds, dict):
        return 0, 0
    return int(ds.get("upload_received_files") or 0), int(ds.get("upload_expected_files") or 0)


def download_progress_pct(received: int, expected: int) -> int:
    if expected <= 0:
        return 5 if received <= 0 else min(99, max(5, received * 10))
    return min(99, max(1, int(100 * received / expected)))


def download_running_detail(ds: dict | None) -> str:
    received, expected = download_counts(ds)
    total = expected if expected > 0 else "?"
    return (
        f"Download Agent receiving {received}/{total} segment(s) — "
        f"{DOWNLOAD_PARALLELISM} parallel slots. All other agents blocked."
    )


def download_block_reason(ds: dict | None) -> str:
    received, expected = download_counts(ds)
    total = expected if expected > 0 else "?"
    return (
        f"Waiting for Download Agent to finish uploading client segments "
        f"({received}/{total}, parallelism={DOWNLOAD_PARALLELISM})"
    )


def begin_client_download(db: Session, job_id: str, *, expected_files: int) -> dict[str, Any]:
    """Mark receiving BEFORE the first byte so huddle cannot start extract/list."""
    from app.services.client_intake import count_staged_files
    from app.services.host_evidence import mark_client_upload_progress

    staged_now = count_staged_files(job_id)
    ds = mark_client_upload_progress(
        db,
        job_id,
        expected_files=max(0, int(expected_files or 0)),
        received_delta=0,
        received_files=staged_now,
    )
    persist_download_agent_card(
        db,
        job_id,
        state="running",
        pct=download_progress_pct(*download_counts(ds)),
        detail=download_running_detail(ds),
        current=True,
    )
    received, expected = download_counts(ds)
    msg = (
        f"[Download Agent] started — expecting {expected or expected_files} segment(s), "
        f"copying {DOWNLOAD_PARALLELISM} at a time. "
        "List Folder, Get Segments, Extraction, and every later agent stay stopped "
        "until Download Agent signals complete."
    )
    write_disk_log(
        db,
        job_id,
        msg,
        stage=DOWNLOAD_STAGE,
        metadata={
            "agent_id": "download_agent",
            "event": "start",
            "expected_files": expected or expected_files,
            "received_files": received,
            "parallelism": DOWNLOAD_PARALLELISM,
            "blocks_agents": True,
        },
    )
    log.info(
        "download_agent start job=%s expected=%s parallelism=%s",
        job_id,
        expected or expected_files,
        DOWNLOAD_PARALLELISM,
    )
    return ds


def note_segment_received(
    db: Session,
    job_id: str,
    *,
    name: str | None = None,
    received_delta: int = 1,
    received_bytes_delta: int = 0,
    expected_files: int | None = None,
) -> dict[str, Any]:
    """Record one finished parallel slot and refresh the Download Agent card."""
    from app.services.host_evidence import mark_client_upload_progress

    ds = mark_client_upload_progress(
        db,
        job_id,
        expected_files=expected_files,
        received_delta=received_delta,
        received_bytes_delta=received_bytes_delta,
    )
    received, expected = download_counts(ds)
    label = name or "segment"
    persist_download_agent_card(
        db,
        job_id,
        state="running",
        pct=download_progress_pct(received, expected),
        detail=download_running_detail(ds),
        current=True,
    )
    write_disk_log(
        db,
        job_id,
        (
            f"[Download Agent] slot finished {label} — {received}/{expected or '?'} on server. "
            f"Parallelism={DOWNLOAD_PARALLELISM}. Other agents still blocked."
        ),
        stage=DOWNLOAD_STAGE,
        metadata={
            "agent_id": "download_agent",
            "event": "slot_done",
            "file": label,
            "received_files": received,
            "expected_files": expected,
            "parallelism": DOWNLOAD_PARALLELISM,
        },
    )
    log.info(
        "download_agent slot job=%s file=%s received=%s/%s",
        job_id,
        label,
        received,
        expected,
    )
    return ds


def signal_download_complete(db: Session, job_id: str, *, received_files: int | None = None) -> None:
    """Release the huddle gate. List Folder and later agents may start."""
    from app.services.host_evidence import is_client_upload_pending
    from app.services.mobile_os import load_job_disk_source

    row = None
    try:
        from app.db.sql_helpers import fetchone

        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    except Exception:
        row = {}
    ds = load_job_disk_source(row) if row else {}
    if is_client_upload_pending(ds):
        log.warning("download_agent signal ignored — upload still receiving job=%s", job_id)
        return
    received, expected = download_counts(ds)
    n = received_files if received_files is not None else received
    detail = (
        f"Download Agent complete — {n} segment(s) on the server"
        + (f" (expected {expected})" if expected else "")
        + ". Signaling List Folder and remaining agents to start."
    )
    persist_download_agent_card(
        db,
        job_id,
        state="done",
        pct=100,
        detail=detail,
        current=False,
    )
    write_disk_log(
        db,
        job_id,
        f"[Download Agent] complete — {detail}",
        stage=DOWNLOAD_STAGE,
        metadata={
            "agent_id": "download_agent",
            "event": "complete",
            "received_files": n,
            "expected_files": expected,
            "parallelism": DOWNLOAD_PARALLELISM,
            "signal": "go",
        },
    )
    log.info("download_agent complete job=%s received=%s — signaling other agents", job_id, n)


def persist_download_agent_card(
    db: Session,
    job_id: str,
    *,
    state: str,
    pct: int,
    detail: str,
    current: bool,
) -> None:
    """Write the Download Agent card without advancing List Folder / extract."""
    import json
    from datetime import datetime, timezone

    from app.db.sql_helpers import execute, fetchone
    from app.services.pipeline_orchestrator import (
        _empty_agent_states,
        _parse_pp,
        _set_agent,
        compute_overall_pct,
    )

    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = _parse_pp((row or {}).get("pipeline_progress"))
    orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    existing = orch.get("agents") if isinstance(orch.get("agents"), dict) else {}
    states = _empty_agent_states()
    if existing:
        for agent_id, entry in existing.items():
            if agent_id in states and isinstance(entry, dict):
                states[agent_id] = {**states[agent_id], **entry}
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    prev = states.get("download_agent") if isinstance(states.get("download_agent"), dict) else {}
    _set_agent(states, "download_agent", state=state, pct=int(pct), detail=detail)
    if state == "running" and not prev.get("started_at"):
        states["download_agent"]["started_at"] = now
    if state == "done":
        if not states["download_agent"].get("started_at"):
            states["download_agent"]["started_at"] = prev.get("started_at") or now
        states["download_agent"]["finished_at"] = now
    if state in ("pending", "running"):
        for aid in (
            "list_folder_agent",
            "segments_agent",
            "virtual_disk_agent",
            "extraction_agent",
            "materialize_agent",
        ):
            card = states.get(aid) if isinstance(states.get(aid), dict) else {}
            if card.get("state") in ("running", "pending") or not card.get("state"):
                _set_agent(
                    states,
                    aid,
                    state="pending",
                    pct=0,
                    detail="Waiting for Download Agent",
                )
    orch = {
        **orch,
        "agents": states,
        "overall_pct": compute_overall_pct(states),
        "current_agent_id": "download_agent" if current else orch.get("current_agent_id"),
        "current_agent_label": "Download" if current else orch.get("current_agent_label"),
        "current_agent_state": "running" if current else orch.get("current_agent_state"),
    }
    if current:
        pp["phase"] = "download"
        pp["label"] = detail
    pp["orchestration"] = orch
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct, updated_at=NOW()
           WHERE id=:id""",
        {"pp": json.dumps(pp), "pct": orch["overall_pct"], "id": job_id},
    )
