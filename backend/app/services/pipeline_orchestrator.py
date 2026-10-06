"""Sequential forensic pipeline orchestration — one agent at a time with unified progress."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("pipeline_orchestrator")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _purge_browser_upload_dump(db, job_id: str) -> None:
    """Delete DATA_ROOT/uploads/{job} after every pipeline agent is done."""
    try:
        from app.services.client_intake import purge_job_staging
        from app.services.disk_build_log import write_disk_log
        from app.services.mobile_os import load_job_disk_source

        row = fetchone(
            db,
            """SELECT disk_source, status, progress_pct, pipeline_progress,
                      files_total, files_extracted
                 FROM jobs WHERE id=:id""",
            {"id": job_id},
        ) or {}
        ds = dict(load_job_disk_source(row))
        if str(ds.get("intake") or "") != "browser_upload" or ds.get("staging_purged"):
            return

        # Never delete source images while extraction, parsing, OCR, RAG, reporting,
        # or recovery work may still need them. Cleanup is success-only so a failed
        # or interrupted case can be resumed from the uploaded forensic source.
        pp = _parse_pp(row.get("pipeline_progress"))
        status = str(row.get("status") or "").lower()
        phase = str(pp.get("phase") or "").lower()
        total = int(row.get("files_total") or 0)
        extracted = int(row.get("files_extracted") or 0)
        extraction_complete = total <= 0 or extracted >= total
        terminal_success = (
            status == "ready"
            and int(row.get("progress_pct") or 0) >= 100
            and phase == "complete"
            and extraction_complete
        )
        if not terminal_success:
            ds["staging_purge_pending"] = True
            ds["staging_purge_reason"] = (
                f"waiting for verified success: status={status or 'unknown'} "
                f"phase={phase or 'unknown'} extracted={extracted}/{total}"
            )
            execute(
                db,
                "UPDATE jobs SET disk_source=CAST(:ds AS jsonb) WHERE id=:id",
                {"ds": json.dumps(ds), "id": job_id},
            )
            return

        cleaned = purge_job_staging(job_id)
        purged_ok = bool(cleaned.get("purged"))
        ds["staging_purged"] = purged_ok
        ds["staging_purge_pending"] = not purged_ok
        if purged_ok:
            ds["staging_purged_at"] = _utc_now_iso()
            ds.pop("staging_purge_reason", None)
        else:
            ds["staging_purge_reason"] = "cleanup attempt incomplete; retry required"
        ds["staging_purge"] = cleaned
        execute(
            db,
            "UPDATE jobs SET disk_source=CAST(:ds AS jsonb) WHERE id=:id",
            {"ds": json.dumps(ds), "id": job_id},
        )
        write_disk_log(
            db,
            job_id,
            (
                f"Deleted client dump {cleaned.get('local_path')} "
                f"({cleaned.get('objects') or 0} object(s) removed)"
                if purged_ok
                else f"Client dump cleanup incomplete for {cleaned.get('local_path')} — will require retry"
            ),
            stage="cleanup",
            metadata={**cleaned, "purged_ok": purged_ok},
        )
    except Exception:
        log.warning("staging purge failed for job %s", job_id, exc_info=True)


def ocr_agent_progress(
    *,
    ocr_done: int,
    ocr_pending: int,
    ocr_eligible: int,
    parse_pending: int,
    extract_incomplete: bool,
    artifacts_registered: int = 0,
    ocr_unfinished: int | None = None,
) -> dict[str, Any]:
    """Honest OCR card. Zero pending is complete once parse is no longer feeding files."""
    unfinished = int(ocr_pending if ocr_unfinished is None else ocr_unfinished)
    if extract_incomplete and unfinished <= 0 and ocr_done <= 0:
        return {"state": "pending", "pct": 0, "detail": "Waiting for extracted files"}
    if artifacts_registered <= 0 and unfinished <= 0 and ocr_done <= 0:
        return {"state": "pending", "pct": 0, "detail": "Waiting for materialized files"}
    if unfinished > 0:
        total = max(ocr_done + unfinished, ocr_eligible, 1)
        pct = int(100 * ocr_done / total)
        if ocr_pending > 0 and pct < 1:
            pct = 1
        return {
            "state": "running" if (ocr_pending > 0 or ocr_done > 0 or parse_pending <= 0) else "pending",
            "pct": min(99, pct),
            "detail": f"OCR — {ocr_done:,} done / {total:,}",
        }
    if parse_pending > 0 and ocr_eligible > ocr_done:
        total = max(ocr_eligible, ocr_done, 1)
        pct = min(99, int(100 * ocr_done / total)) if ocr_done > 0 else 0
        return {
            "state": "pending",
            "pct": pct,
            "detail": f"Waiting for parse — {ocr_eligible:,} document(s) eligible",
        }
    if ocr_done > 0:
        return {"state": "done", "pct": 100, "detail": f"{ocr_done:,} OCR'd"}
    if parse_pending > 0:
        if ocr_eligible > 0:
            return {
                "state": "pending",
                "pct": 0,
                "detail": f"Waiting for parse — {ocr_eligible:,} document(s) eligible",
            }
        return {"state": "pending", "pct": 0, "detail": "Waiting for parse"}
    if ocr_eligible > 0:
        return {
            "state": "done",
            "pct": 100,
            "detail": f"{ocr_eligible:,} document(s) OCR finished (skipped/not required)",
        }
    if not extract_incomplete and artifacts_registered > 0 and parse_pending <= 0:
        return {"state": "done", "pct": 100, "detail": "No OCR-eligible documents"}
    return {"state": "pending", "pct": 0, "detail": "Waiting for extracted files"}


def _duration_sec(started_at: str | None, finished_at: str | None) -> int | None:
    if not started_at or not finished_at:
        return None
    try:
        a = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        b = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
        return max(0, int((b - a).total_seconds()))
    except Exception:
        return None


# Map orchestration agents → disk_build_logs.stage values for duration backfill.
_AGENT_LOG_STAGES: dict[str, tuple[str, ...]] = {
    "iosagent": ("extract", "parse", "rag_index", "artifact_inventory"),
    "androidagent": ("extract", "parse", "rag_index", "artifact_inventory"),
    "drive_mount_agent": ("drive_mount",),
    "download_agent": ("download",),
    "list_folder_agent": ("folder_list",),
    "segments_agent": ("evidence_register",),
    "virtual_disk_agent": ("virtual_disk",),
    "extraction_agent": ("extract",),
    "materialize_agent": ("materialize", "phase3"),
    "ocr_agent": ("ocr",),
    "parse_agent": ("parse",),
    "chunk_agent": ("rag_index",),
    "embed_agent": ("rag_index",),
    "entity_agent": ("rag_enrich",),
    "neo4j_agent": ("graph_sync",),
    "annotation_agent": ("rag_enrich",),
    "ontology_agent": ("rag_enrich",),
    "artifacts_agent": ("artifact_inventory", "axiom_artifacts"),
}


def _merge_agent_timings(
    previous: dict[str, dict[str, Any]],
    states: dict[str, dict[str, Any]],
    *,
    pipeline_started_at: str | None = None,
) -> None:
    """Preserve started_at / finished_at / duration_sec across snapshot rebuilds.

    Critical: when an agent jumps pending→done between polls, do NOT set
    started_at=finished_at=now (that yields duration_sec=0 / UI 00:00). Use the
    previous agent's finish time (or pipeline start) instead.
    """
    now = _utc_now_iso()
    order = [a["id"] for a in PIPELINE_AGENTS]
    prev_end: str | None = pipeline_started_at

    for agent_id in order:
        entry = states.get(agent_id)
        if not isinstance(entry, dict):
            continue
        old = previous.get(agent_id) or {}
        new_state = entry.get("state") or "pending"
        old_state = old.get("state") or "pending"
        started = old.get("started_at")
        finished = old.get("finished_at")
        prior_dur = old.get("duration_sec")

        if new_state == "running":
            if old_state != "running" or not started:
                started = started or prev_end or now
            finished = None
        elif new_state in ("done", "failed"):
            if old_state in ("done", "failed"):
                # Keep historical timings; only fill gaps.
                started = started or old.get("started_at")
                finished = finished or old.get("finished_at") or now
            elif old_state == "running":
                started = started or prev_end or now
                finished = now
            else:
                # pending → done in one snapshot: start at prior agent end, end now.
                started = started or prev_end or pipeline_started_at
                finished = now
                # If we still have no start, leave duration for log backfill.
        else:
            # A later snapshot reopened this card (false-complete → pending).
            # Drop leftover 00:01 done stamps so the UI does not stay green.
            if old_state in ("done", "failed"):
                started = None
                finished = None
                entry.pop("duration_sec", None)
            else:
                started = old.get("started_at")
                finished = old.get("finished_at")

        if started:
            entry["started_at"] = started
        else:
            entry.pop("started_at", None)
        if finished:
            entry["finished_at"] = finished
        else:
            entry.pop("finished_at", None)

        dur = _duration_sec(entry.get("started_at"), entry.get("finished_at"))
        if new_state == "running" and entry.get("started_at"):
            live = _duration_sec(entry.get("started_at"), now)
            if live is not None:
                entry["duration_sec"] = live
        elif dur is not None and dur > 0:
            entry["duration_sec"] = dur
        elif isinstance(prior_dur, (int, float)) and int(prior_dur) > 0 and new_state in ("done", "failed"):
            # Preserve a previously computed non-zero duration.
            entry["duration_sec"] = int(prior_dur)
            if not entry.get("started_at") and entry.get("finished_at"):
                entry["started_at"] = entry["finished_at"]
        elif dur is not None:
            entry["duration_sec"] = dur

        if new_state in ("done", "failed") and entry.get("finished_at"):
            prev_end = entry["finished_at"]
        elif new_state == "running" and entry.get("started_at"):
            # Keep chaining from this start for later agents once this finishes.
            prev_end = entry.get("finished_at") or prev_end


def _backfill_agent_timings_from_logs(db, job_id: str, states: dict[str, dict[str, Any]]) -> None:
    """Fill zero/missing agent durations from disk_build_logs stage timestamps."""
    try:
        rows = fetchall(
            db,
            """SELECT stage, MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts
               FROM disk_build_logs
               WHERE job_id=:jid
               GROUP BY stage""",
            {"jid": job_id},
        )
    except Exception:
        return
    if not rows:
        return

    stage_bounds: dict[str, tuple[str, str]] = {}
    for row in rows:
        stage = str(row.get("stage") or "").strip()
        first = row.get("first_ts")
        last = row.get("last_ts")
        if not stage or first is None or last is None:
            continue
        first_iso = first.isoformat().replace("+00:00", "Z") if hasattr(first, "isoformat") else str(first)
        last_iso = last.isoformat().replace("+00:00", "Z") if hasattr(last, "isoformat") else str(last)
        stage_bounds[stage] = (first_iso, last_iso)

    # Agents that share a log stage (chunk/embed, enrich trio) get sequential slices.
    shared_groups: list[tuple[str, list[str]]] = [
        ("rag_index", ["chunk_agent", "embed_agent"]),
        ("rag_enrich", ["entity_agent", "annotation_agent", "ontology_agent"]),
    ]
    claimed: set[str] = set()

    for log_stage, agent_ids in shared_groups:
        bounds = stage_bounds.get(log_stage)
        if not bounds:
            continue
        start_iso, end_iso = bounds
        total = _duration_sec(start_iso, end_iso) or 0
        if total <= 0:
            continue
        n = len(agent_ids)
        try:
            start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        except Exception:
            continue
        slice_sec = max(1, total // n) if total >= n else max(0, total)
        cursor = start_dt
        for i, agent_id in enumerate(agent_ids):
            entry = states.get(agent_id)
            if not isinstance(entry, dict) or entry.get("state") not in ("done", "failed", "running"):
                continue
            existing = entry.get("duration_sec")
            if isinstance(existing, (int, float)) and int(existing) > 0:
                claimed.add(agent_id)
                continue
            if i == n - 1:
                end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
            else:
                end_dt = cursor + timedelta(seconds=slice_sec)
            entry["started_at"] = cursor.isoformat().replace("+00:00", "Z")
            entry["finished_at"] = end_dt.isoformat().replace("+00:00", "Z")
            entry["duration_sec"] = _duration_sec(entry["started_at"], entry["finished_at"]) or 0
            cursor = end_dt
            claimed.add(agent_id)

    for agent_id, log_stages in _AGENT_LOG_STAGES.items():
        if agent_id in claimed:
            continue
        entry = states.get(agent_id)
        if not isinstance(entry, dict) or entry.get("state") not in ("done", "failed", "running"):
            continue
        existing = entry.get("duration_sec")
        if isinstance(existing, (int, float)) and int(existing) > 0:
            continue
        firsts: list[str] = []
        lasts: list[str] = []
        for st in log_stages:
            b = stage_bounds.get(st)
            if not b:
                continue
            firsts.append(b[0])
            lasts.append(b[1])
        if not firsts:
            continue
        start_iso = min(firsts)
        end_iso = max(lasts)
        dur = _duration_sec(start_iso, end_iso)
        if dur is None:
            continue
        # Allow 0 for instantaneous list/register, but prefer >= 0 always set.
        entry["started_at"] = start_iso
        entry["finished_at"] = end_iso
        entry["duration_sec"] = max(0, int(dur))
        # Instant steps still show at least 1s when they produced log lines.
        if entry["duration_sec"] == 0 and entry.get("state") == "done":
            entry["duration_sec"] = 1

    # Any remaining done/failed agents with 0s get 1s so the UI never shows blank 00:00.
    for agent_id, entry in states.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("state") not in ("done", "failed"):
            continue
        if int(entry.get("duration_sec") or 0) <= 0:
            entry["duration_sec"] = 1

# Ordered agents (display + progress weights). Supervisor task keys group related work.
PIPELINE_AGENTS: list[dict[str, Any]] = [
    {"id": "iosagent", "label": "iOS Agent", "weight": 0, "supervisor_key": "extract_agent"},
    {"id": "androidagent", "label": "Android Agent", "weight": 0, "supervisor_key": "extract_agent"},
    {"id": "drive_mount_agent", "label": "Drive mount", "weight": 1, "supervisor_key": "drive_mount_agent"},
    {"id": "download_agent", "label": "Download", "weight": 2, "supervisor_key": "download_agent"},
    {"id": "list_folder_agent", "label": "List folder", "weight": 1, "supervisor_key": "extract_agent"},
    {"id": "segments_agent", "label": "Get segments", "weight": 3, "supervisor_key": "extract_agent"},
    {"id": "virtual_disk_agent", "label": "Virtual disk", "weight": 5, "supervisor_key": "extract_agent"},
    {"id": "extraction_agent", "label": "Extraction", "weight": 14, "supervisor_key": "extract_agent"},
    {"id": "materialize_agent", "label": "Register artifacts", "weight": 10, "supervisor_key": "extract_agent"},
    {"id": "ocr_agent", "label": "OCR enrich", "weight": 6, "supervisor_key": "ocr_agent"},
    {"id": "parse_agent", "label": "Parse forensic files", "weight": 10, "supervisor_key": "parse_agent"},
    {"id": "chunk_agent", "label": "RAG chunking", "weight": 8, "supervisor_key": "rag_agent"},
    {"id": "embed_agent", "label": "RAG embedding", "weight": 0, "supervisor_key": "rag_agent"},
    {"id": "entity_agent", "label": "Entity extraction", "weight": 4, "supervisor_key": "rag_enrich_agent"},
    {"id": "neo4j_agent", "label": "Neo4j graph sync", "weight": 5, "supervisor_key": "graph_agent"},
    {"id": "annotation_agent", "label": "Annotation", "weight": 3, "supervisor_key": "rag_enrich_agent"},
    {"id": "ontology_agent", "label": "Ontology linking", "weight": 3, "supervisor_key": "rag_enrich_agent"},
    {"id": "artifacts_agent", "label": "Artifact inventory", "weight": 14, "supervisor_key": "inventory_agent"},
]

SUPERVISOR_DISPATCH_ORDER: list[str] = [
    "drive_mount_agent",
    "download_agent",
    "extract_agent",
    "parse_agent",
    "rag_agent",
    "graph_agent",
    "rag_enrich_agent",
    "inventory_agent",
]

_AGENT_BY_ID = {a["id"]: a for a in PIPELINE_AGENTS}
_TOTAL_WEIGHT = sum(int(a["weight"]) for a in PIPELINE_AGENTS)


def list_pipeline_agents() -> list[dict[str, Any]]:
    return [dict(a) for a in PIPELINE_AGENTS]


def _empty_agent_states() -> dict[str, dict[str, Any]]:
    return {
        a["id"]: {"state": "pending", "pct": 0, "label": a["label"]}
        for a in PIPELINE_AGENTS
    }


def _parse_pp(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def pipeline_intake_started(row: dict[str, Any] | None) -> bool:
    """Return True only after the examiner has actually supplied evidence.

    A freshly-created job is intentionally inert. Host drive discovery, mounted
    letters, disabled optional stages, or an empty orchestration ledger are not
    evidence selection and must never start the pipeline.
    """
    if not row:
        return False

    status = str(row.get("status") or "").strip().lower()
    if row.get("extracted_disk_uri"):
        return True
    if (
        int(row.get("files_total") or 0) > 0
        or int(row.get("files_extracted") or 0) > 0
        or int(row.get("evidence_count") or 0) > 0
    ):
        return True

    raw_sr = row.get("segment_readiness")
    if isinstance(raw_sr, str):
        try:
            raw_sr = json.loads(raw_sr)
        except json.JSONDecodeError:
            raw_sr = {}
    if isinstance(raw_sr, dict) and bool(raw_sr.get("ready")):
        return True

    try:
        from app.services.mobile_os import load_job_disk_source

        ds = load_job_disk_source(row)
    except Exception:
        raw = row.get("disk_source")
        ds = raw if isinstance(raw, dict) else {}

    for key in (
        "evidence_folder",
        "staging_container_path",
        "path",
        "host_path",
        "last_host_path",
        "working",
    ):
        if str(ds.get(key) or "").strip():
            return True

    # Browser upload becomes a real intake only after the user selected files and
    # opened the Download Agent gate. The mere existence of a disk_source seed
    # (notably mobile OS metadata) must not count as evidence selection.
    if str(ds.get("intake") or "").strip().lower() == "browser_upload":
        upload_status = str(ds.get("upload_status") or "").strip().lower()
        if upload_status in {"receiving", "verifying", "complete"}:
            return True
        if int(ds.get("upload_expected_files") or 0) > 0 or int(ds.get("upload_received_files") or 0) > 0:
            return True

    # Recovery/resume compatibility for older rows that predate the newer path
    # keys. Early intake states by themselves are deliberately NOT sufficient:
    # `registered`/`awaiting_segments` must still have a path, readiness, counts,
    # or upload gate above before any agent may run.
    if status in {
        "processing",
        "building_disk",
        "disk_ready",
        "extracting",
        "extracted",
        "artifacts_registered",
        "parsed",
        "indexing",
        "indexed",
        "ready",
        "completed",
        "classified",
        "report_ready",
        "report_generating",
        "paused",
        "failed",
    }:
        return True
    return False


def idle_orchestration_snapshot() -> dict[str, Any]:
    """Canonical zero-work view before evidence selection."""
    return {
        "agents": _empty_agent_states(),
        "overall_pct": 0,
        "progress_high_water": 0,
        "current_agent_id": None,
        "current_agent_label": None,
        "current_agent_state": None,
        "sequential": get_settings().pipeline_sequential_agents,
        "pipeline_started_at": None,
        "total_duration_sec": None,
        "intake_started": False,
    }


def _agent_state(states: dict[str, dict[str, Any]], agent_id: str) -> str:
    return (states.get(agent_id) or {}).get("state") or "pending"


def _set_agent(
    states: dict[str, dict[str, Any]],
    agent_id: str,
    *,
    state: str,
    pct: int,
    detail: str | None = None,
) -> None:
    meta = _AGENT_BY_ID.get(agent_id, {})
    entry = states.setdefault(agent_id, {"label": meta.get("label", agent_id)})
    entry["state"] = state
    entry["pct"] = max(0, min(100, int(pct)))
    entry["label"] = meta.get("label", entry.get("label", agent_id))
    if detail:
        entry["detail"] = detail


_EXTRACT_MUST_NOT_FINISH = frozenset(
    {
        "materialize_agent",
        "ocr_agent",
        "parse_agent",
        "chunk_agent",
        "embed_agent",
        "entity_agent",
        "neo4j_agent",
        "annotation_agent",
        "ontology_agent",
        "artifacts_agent",
    }
)


def _sync_platform_owner_cards(db, job_id: str, states: dict[str, dict[str, Any]]) -> None:
    """iOS Agent / Android Agent own extract+RAG; the other platform stands down."""
    from app.forensic_common.job_types import is_mobile_job, mobile_os_family
    from app.services.mobile_platform_agents import (
        ANDROIDAGENT_ID,
        ANDROIDAGENT_LABEL,
        IOSAGENT_ID,
        IOSAGENT_LABEL,
        owner_progress_from_stage_states,
    )

    if not is_mobile_job(db, job_id):
        _set_agent(states, IOSAGENT_ID, state="done", pct=100, detail="Disk job — iOS Agent not in play")
        _set_agent(states, ANDROIDAGENT_ID, state="done", pct=100, detail="Disk job — Android Agent not in play")
        return
    family = mobile_os_family(db, job_id)
    state, pct, detail = owner_progress_from_stage_states(states)
    if family == "ios":
        _set_agent(states, IOSAGENT_ID, state=state, pct=pct, detail=detail)
        _set_agent(
            states,
            ANDROIDAGENT_ID,
            state="done",
            pct=100,
            detail="iPhone job — Android Agent standing down",
        )
        states[IOSAGENT_ID]["label"] = IOSAGENT_LABEL
    elif family == "android":
        _set_agent(states, ANDROIDAGENT_ID, state=state, pct=pct, detail=detail)
        _set_agent(
            states,
            IOSAGENT_ID,
            state="done",
            pct=100,
            detail="Android job — iOS Agent standing down",
        )
        states[ANDROIDAGENT_ID]["label"] = ANDROIDAGENT_LABEL
    else:
        _set_agent(states, IOSAGENT_ID, state="pending", pct=0, detail="Waiting to detect iPhone vs Android")
        _set_agent(states, ANDROIDAGENT_ID, state="pending", pct=0, detail="Waiting to detect iPhone vs Android")


def _own_work_pct(done: int, total: int) -> int:
    """Live ratio for this agent's own units — never borrow another agent's %."""
    d = max(0, int(done or 0))
    t = max(int(total or 0), d, 1)
    if d <= 0:
        return 0
    return min(99, max(1, int(100 * d / t)))


def _set_agent_live(
    states: dict[str, dict[str, Any]],
    agent_id: str,
    *,
    state: str,
    pct: int,
    detail: str | None = None,
) -> None:
    """Write a card without wiping real progress back to 0%."""
    prev = states.get(agent_id) if isinstance(states.get(agent_id), dict) else {}
    prev_pct = int(prev.get("pct") or 0)
    next_pct = max(0, min(99 if state != "done" else 100, int(pct)))
    if state == "pending" and prev_pct > 0:
        state = "running"
        next_pct = min(99, prev_pct)
    elif state == "running" and next_pct <= 0 and prev_pct > 0:
        next_pct = min(99, prev_pct)
    _set_agent(states, agent_id, state=state, pct=next_pct, detail=detail)


def reopen_false_complete_during_extract(
    states: dict[str, dict[str, Any]],
    *,
    extract_pct: int,
    registered: int,
    parsed_n: int,
    pending_n: int,
    chunk_n: int,
    ocr_n: int = 0,
    ocr_pending_n: int = 0,
    embed_on: bool = False,
    files_total: int = 0,
    indexable: int = 0,
) -> None:
    """Park every post-extract card behind the evidence extraction barrier.

    Older streaming builds could leave partial materialize/OCR/parse/RAG rows in
    the database.  They remain useful after extraction, but they must not appear
    as active work while the source image is still being walked/copied.
    """
    del extract_pct, registered, parsed_n, pending_n, chunk_n, ocr_n, ocr_pending_n, files_total, indexable
    for aid in _EXTRACT_MUST_NOT_FINISH:
        if aid == "embed_agent" and not embed_on:
            _set_agent(states, aid, state="done", pct=100, detail="Embeddings disabled — skipped")
            continue
        _set_agent(
            states,
            aid,
            state="pending",
            pct=0,
            detail="Waiting for evidence extraction to finish",
        )
        for key in ("started_at", "finished_at", "duration_sec"):
            states[aid].pop(key, None)


_LIVE_RATIO_AGENTS = frozenset(
    {
        "download_agent",
        "extraction_agent",
        "materialize_agent",
        "ocr_agent",
        "parse_agent",
        "chunk_agent",
        "artifacts_agent",
    }
)
_FALSE_COMPLETE_PENDING_OK = frozenset({"ocr_agent"})
_STRUCTURAL_STICKY_DONE = frozenset(
    {
        "drive_mount_agent",
        "download_agent",
        "list_folder_agent",
        "segments_agent",
        "virtual_disk_agent",
        "extraction_agent",
    }
)
_ENRICH_MUST_NOT_FINISH = frozenset(
    {
        "entity_agent",
        "annotation_agent",
        "ontology_agent",
    }
)


def _stick_agent_progress(
    previous: dict[str, dict[str, Any]],
    states: dict[str, dict[str, Any]],
    *,
    extract_incomplete: bool = False,
    enrich_incomplete: bool = False,
) -> None:
    """Percents never go backwards while an agent is still working.

    Rebuilds used to mark parse/OCR/chunk 100% then recount them at ~70%. A real
    leftover reopen (done → running) stays at 99%. OCR may return to pending only
    while extract is still copying files (empty-catalog false complete). Finished
    list/extract/parse cards must not snap back to 0%.
    """
    for agent_id, entry in states.items():
        if not isinstance(entry, dict):
            continue
        old = previous.get(agent_id) if isinstance(previous.get(agent_id), dict) else {}
        old_state = str(old.get("state") or "pending")
        old_pct = int(old.get("pct") or 0)
        new_state = str(entry.get("state") or "pending")
        new_pct = int(entry.get("pct") or 0)
        if extract_incomplete and agent_id in _EXTRACT_MUST_NOT_FINISH:
            if agent_id == "embed_agent" and new_state == "done" and "disabled" in str(entry.get("detail") or "").lower():
                entry["pct"] = 100
                continue
            # Hard barrier beats sticky historical progress. Partial work from
            # an older streaming run will be rediscovered after extraction.
            entry["state"] = "pending"
            entry["pct"] = 0
            entry["detail"] = "Waiting for evidence extraction to finish"
            for key in ("started_at", "finished_at", "duration_sec"):
                entry.pop(key, None)
            continue
        if enrich_incomplete and agent_id in _ENRICH_MUST_NOT_FINISH:
            if new_state == "done":
                entry["state"] = "running"
                entry["pct"] = min(99, max(new_pct, 1))
            elif new_state == "running":
                entry["pct"] = min(99, max(new_pct, 1))
            continue
        if old_state == "done" and new_state != "failed":
            if new_state == "running":
                # Real leftover work — keep the card moving, never drop below 99.
                entry["pct"] = min(99, max(old_pct, new_pct, 1))
            elif new_state == "pending":
                # OCR 100% before extract may wait again. Every other finished
                # card — and OCR after extract — stays done at 100%.
                if extract_incomplete and agent_id in _FALSE_COMPLETE_PENDING_OK:
                    continue
                entry["state"] = "done"
                entry["pct"] = 100
                if old.get("detail") and not entry.get("detail"):
                    entry["detail"] = old.get("detail")
            else:
                entry["state"] = "done"
                entry["pct"] = 100
                if old.get("detail") and not entry.get("detail"):
                    entry["detail"] = old.get("detail")
            continue
        if (
            new_state == "pending"
            and old_state == "running"
            and old_pct > 0
            and agent_id in _STRUCTURAL_STICKY_DONE
            and not extract_incomplete
        ):
            entry["state"] = "done" if old_pct >= 100 else "running"
            entry["pct"] = 100 if old_pct >= 100 else min(99, old_pct)
            if old.get("detail") and not entry.get("detail"):
                entry["detail"] = old.get("detail")
            continue
        if new_state == "done":
            entry["pct"] = 100
        elif new_state == "running":
            # Count-based agents show the live ratio (denominator can grow).
            # Never snap a working card to 0%.
            if agent_id in _LIVE_RATIO_AGENTS:
                entry["pct"] = min(99, old_pct if new_pct <= 0 and old_pct > 0 else max(new_pct, 1))
            else:
                entry["pct"] = min(99, max(old_pct, new_pct, 1))
        elif new_state == "pending" and old_pct > 0 and not (
            extract_incomplete and agent_id in _FALSE_COMPLETE_PENDING_OK
        ):
            entry["state"] = "running"
            entry["pct"] = min(99, old_pct)
        else:
            entry["pct"] = new_pct


def compute_overall_pct(states: dict[str, dict[str, Any]]) -> int:
    if _TOTAL_WEIGHT <= 0:
        return 0
    acc = 0.0
    for agent in PIPELINE_AGENTS:
        weight = int(agent["weight"] or 0)
        if weight <= 0:
            continue
        st = states.get(agent["id"]) or {}
        pct = int(st.get("pct") or 0)
        if st.get("state") == "done":
            pct = 100
        acc += (pct / 100.0) * weight
    raw = max(0, min(100, int(round(acc * 100 / _TOTAL_WEIGHT))))
    required_done = all(
        int(agent["weight"] or 0) <= 0 or (states.get(agent["id"]) or {}).get("state") == "done"
        for agent in PIPELINE_AGENTS
    )
    if not required_done:
        return min(99, raw)
    return raw


def patch_extract_orchestration(
    db,
    job_id: str,
    *,
    files_done: int,
    files_total: int,
    extract_pct: int,
) -> None:
    """Keep Get segments / Extraction cards honest while MinIO extract runs."""
    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = _parse_pp(row.get("pipeline_progress") if row else None)
    prev = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    states = prev.get("agents") if isinstance(prev.get("agents"), dict) else _empty_agent_states()
    now = _utc_now_iso()
    _set_agent(states, "drive_mount_agent", state="done", pct=100)
    _set_agent(states, "list_folder_agent", state="done", pct=100)
    _set_agent(states, "segments_agent", state="done", pct=100)
    _set_agent(states, "virtual_disk_agent", state="done", pct=100)
    detail = f"{files_done:,} / {files_total:,} files → MinIO" if files_total else "Extracting files"
    _set_agent(
        states,
        "extraction_agent",
        state="running",
        pct=max(1, min(99, int(extract_pct))),
        detail=detail,
    )
    if not states["extraction_agent"].get("started_at"):
        states["extraction_agent"]["started_at"] = now
    embed_on = bool(getattr(get_settings(), "rag_embedding_enabled", False))
    for aid in _EXTRACT_MUST_NOT_FINISH:
        if aid == "embed_agent" and not embed_on:
            _set_agent(states, aid, state="done", pct=100, detail="Embeddings disabled — skipped")
            continue
        _set_agent(
            states,
            aid,
            state="pending",
            pct=0,
            detail="Waiting for evidence extraction to finish",
        )
        for key in ("started_at", "finished_at", "duration_sec"):
            states[aid].pop(key, None)
    _merge_agent_timings(
        prev.get("agents") if isinstance(prev.get("agents"), dict) else {},
        states,
        pipeline_started_at=prev.get("pipeline_started_at") if isinstance(prev, dict) else None,
    )
    file_pct = (
        min(99, int(100 * files_done / files_total))
        if files_total > 0
        else max(1, min(99, int(extract_pct)))
    )
    orch = {
        **prev,
        "agents": states,
        "overall_pct": file_pct,
        "progress_high_water": file_pct,
        "current_agent_id": "extraction_agent",
        "current_agent_label": "Extraction",
        "current_agent_state": "running",
    }
    pp["orchestration"] = orch
    pp["phase"] = "extract"
    pp["completed"] = int(files_done)
    pp["total"] = int(files_total)
    pp["label"] = f"Extraction — {detail}"
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "pp": json.dumps(pp)},
    )


def current_agent(states: dict[str, dict[str, Any]]) -> tuple[str | None, str | None, str | None]:
    """Return (agent_id, label, state) preferring a running agent over the next pending one."""
    pending_id: str | None = None
    pending_label: str | None = None
    for owner_id in ("iosagent", "androidagent"):
        if _agent_state(states, owner_id) == "running":
            return owner_id, (_AGENT_BY_ID.get(owner_id) or {}).get("label") or owner_id, "running"
    for agent in PIPELINE_AGENTS:
        if int(agent.get("weight") or 0) <= 0:
            continue
        st = _agent_state(states, agent["id"])
        if st == "running":
            return agent["id"], agent["label"], "running"
        if st == "pending" and pending_id is None:
            pending_id, pending_label = agent["id"], agent["label"]
    if pending_id:
        return pending_id, pending_label, "pending"
    return None, None, None


def supervisor_key_for_agent(agent_id: str) -> str | None:
    return (_AGENT_BY_ID.get(agent_id) or {}).get("supervisor_key")


def _rag_enrich_status(db, job_id: str, *, stale_sec: int = 600) -> tuple[bool, bool]:
    """Return (complete, in_flight) for entity/annotation/ontology enrichment.

    Complete means persisted enrichment_stats finished a real parse scan.
    Log lines alone (the old 6ms stub) are not enough.
    """
    from app.services.rag_enrich import load_enrichment_stats

    stats = load_enrichment_stats(db, job_id)
    if stats.get("complete"):
        return True, False
    try:
        from app.services.job_locks import job_lock_held

        if job_lock_held("rag_enrich", job_id):
            return False, True
    except Exception:
        pass
    # A dispatch log is not in-flight work. Entity/Annotation/Ontology Agents
    # must vote run until a worker holds the lock (or stats complete).
    return False, False


def prior_supervisor_keys_done(states: dict[str, dict[str, Any]], supervisor_key: str) -> bool:
    """True when every agent mapped to earlier supervisor keys is done."""
    idx = SUPERVISOR_DISPATCH_ORDER.index(supervisor_key) if supervisor_key in SUPERVISOR_DISPATCH_ORDER else -1
    if idx <= 0:
        return True
    prior_keys = set(SUPERVISOR_DISPATCH_ORDER[:idx])
    for agent in PIPELINE_AGENTS:
        if int(agent.get("weight") or 0) <= 0:
            continue
        sk = agent.get("supervisor_key")
        if sk not in prior_keys:
            continue
        if _agent_state(states, agent["id"]) != "done":
            return False
    return True


def sync_orchestration_from_job(db, job_id: str) -> dict[str, Any]:
    """Derive per-agent states from job status, counts, and pipeline_progress."""
    from app.services.forensic_serial_pipeline import serial_progress_snapshot

    serial = serial_progress_snapshot(db, job_id)
    if serial is not None:
        return serial["orchestration"]
    row = fetchone(
        db,
        """SELECT status, progress_pct, files_total, files_extracted, bytes_extracted,
                  pipeline_progress, disk_source, extracted_disk_uri, segment_readiness
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    if not row:
        return {"agents": _empty_agent_states(), "overall_pct": 0}
    if not pipeline_intake_started(row):
        return idle_orchestration_snapshot()

    pp = _parse_pp(row.get("pipeline_progress"))
    prev_orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    prev_agents = prev_orch.get("agents") if isinstance(prev_orch.get("agents"), dict) else {}
    pipeline_started_at = prev_orch.get("pipeline_started_at")
    states = _empty_agent_states()
    status = (row.get("status") or "").lower()
    phase = (pp.get("phase") or "").lower()
    files_total = int(row.get("files_total") or 0)
    files_done = int(row.get("files_extracted") or 0)
    extract_pct = min(99, int(100 * files_done / files_total)) if files_total > 0 else 0

    reg = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid", {"jid": job_id})
    registered = int(reg["c"]) if reg else 0
    from app.services.artifact_parse import count_pending_parse

    pending_n = count_pending_parse(db, job_id)
    parsed_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
        {"jid": job_id},
    )
    parsed_n = int(parsed_row["c"]) if parsed_row else 0
    ocr_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND ocr_status='done'",
        {"jid": job_id},
    )
    ocr_n = int(ocr_row["c"]) if ocr_row else 0
    try:
        from app.services.ocr_gpu import count_ocr_eligible, count_ocr_unfinished

        ocr_eligible_n = int(count_ocr_eligible(db, job_id) or 0)
        ocr_unfinished_n = int(count_ocr_unfinished(db, job_id) or 0)
    except Exception:
        ocr_eligible_n = 0
        ocr_unfinished_n = 0
    chunks_row = fetchone(
        db,
        "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
        {"jid": job_id},
    )
    chunk_n = int(chunks_row["c"]) if chunks_row else 0
    from app.services.dual_rag_index import _count_indexable_artifacts, _count_indexable_without_chunks

    indexable = _count_indexable_artifacts(db, job_id)
    rag_remaining = _count_indexable_without_chunks(db, job_id)
    rag_total = max(indexable, chunk_n, 1)
    settings = get_settings()
    # Small mobile/disk jobs often have <<500 chunks. Treat embed as done when nothing
    # remains to embed; the 500-chunk soft baseline only applies when background RAG continues.
    embed_on = bool(getattr(settings, "rag_embedding_enabled", False))
    if not embed_on:
        baseline_embed_done = chunk_n > 0 and rag_remaining <= 0
    elif chunk_n > 0 and rag_remaining <= 0:
        baseline_embed_done = True
    elif settings.rag_background_after_baseline and chunk_n >= 500:
        baseline_embed_done = True
    else:
        baseline_embed_done = False

    gs = fetchone(
        db,
        "SELECT status, last_sync_at, nodes_synced, edges_synced, error FROM graph_sync_state WHERE job_id=:jid",
        {"jid": job_id},
    )
    graph_status = (gs or {}).get("status") or ""
    graph_error = str((gs or {}).get("error") or "")
    graph_nodes = int((gs or {}).get("nodes_synced") or 0)
    graph_edges = int((gs or {}).get("edges_synced") or 0)
    graph_last = (gs or {}).get("last_sync_at")
    graph_stale_queued = graph_status in ("queued", "syncing") and not graph_last
    graph_unavailable = "unavailable" in graph_error.lower()

    from app.services.catalog_artifact_runner import axiom_inventory_progress

    inv = axiom_inventory_progress(db, job_id)

    # --- list folder / segments / virtual disk / extraction / materialize ---
    ds_preview: dict[str, Any] = {}
    try:
        from app.services.mobile_os import load_job_disk_source

        ds_preview = load_job_disk_source(row)
    except Exception:
        ds_preview = {}
    seg_ready = bool(
        row.get("extracted_disk_uri")
        or ds_preview.get("evidence_folder")
        or ds_preview.get("path")
        or ds_preview.get("host_path")
        or ds_preview.get("last_host_path")
    )
    list_done = False
    upload_pending = False
    ds: dict[str, Any] = {}
    try:
        from app.services.host_evidence import is_client_upload_pending, listing_complete
        from app.services.mobile_os import load_job_disk_source

        ds = load_job_disk_source(row)
        upload_pending = is_client_upload_pending(ds)
        list_done = False if upload_pending else listing_complete(db, job_id)
        if str(ds.get("intake") or "") == "browser_upload":
            seg_ready = bool(ds.get("upload_status") == "complete" and (ds.get("evidence_folder") or ds.get("staging_container_path")))
    except Exception:
        list_done = False

    prev_mount_state = str((prev_agents.get("drive_mount_agent") or {}).get("state") or "")
    drives_ready = prev_mount_state == "done"
    if not drives_ready:
        try:
            from app.services.drive_mount_agent import mounts_ready

            drives_ready = mounts_ready()
        except Exception:
            drives_ready = False
    if upload_pending:
        drives_ready = True
    if drives_ready or list_done or status not in ("created", "registered", "pending", "uploaded"):
        detail = "Client upload — no office disk mount" if upload_pending else "Host drives mounted"
        _set_agent(states, "drive_mount_agent", state="done", pct=100, detail=detail)
    elif status in ("created", "registered", "pending", "uploaded"):
        _set_agent(
            states,
            "drive_mount_agent",
            state="running",
            pct=40,
            detail="Scanning and remounting attached drives",
        )

    if upload_pending:
        from app.services.download_agent import download_progress_pct, download_running_detail

        recv = int(ds.get("upload_received_files") or 0) if isinstance(ds, dict) else 0
        exp = int(ds.get("upload_expected_files") or 0) if isinstance(ds, dict) else 0
        _set_agent(
            states,
            "download_agent",
            state="running",
            pct=download_progress_pct(recv, exp),
            detail=download_running_detail(ds if isinstance(ds, dict) else None),
        )
        _set_agent(
            states,
            "list_folder_agent",
            state="pending",
            pct=0,
            detail="Waiting for Download Agent to finish uploading client segments",
        )
    elif list_done or status not in ("created", "registered", "pending", "uploaded", "awaiting_segments"):
        _set_agent(states, "list_folder_agent", state="done", pct=100)
    elif status in ("created", "registered", "pending", "uploaded", "awaiting_segments"):
        _set_agent(
            states,
            "list_folder_agent",
            state="pending" if not drives_ready else "running",
            pct=0 if not drives_ready else 10,
            detail="Waiting for Drive Mount Agent" if not drives_ready else "Listing evidence folder",
        )

    if not upload_pending:
        _set_agent(
            states,
            "download_agent",
            state="done",
            pct=100,
            detail=(
                "All client segments received — other agents may start"
                if str((ds or {}).get("intake") or "") == "browser_upload"
                else "Download skipped — server-local evidence is processed in place (zero copy)"
            ),
        )

    if upload_pending:
        _set_agent(
            states,
            "segments_agent",
            state="pending",
            pct=0,
            detail="Waiting for Download Agent to finish uploading client segments",
        )
        for parked in (
            "virtual_disk_agent",
            "extraction_agent",
            "materialize_agent",
        ):
            _set_agent(
                states,
                parked,
                state="pending",
                pct=0,
                detail="Waiting for Download Agent to finish uploading client segments",
            )
    elif status in ("created", "registered", "pending", "uploaded"):
        _set_agent(states, "segments_agent", state="running" if seg_ready else "pending", pct=50 if seg_ready else 0)
    elif seg_ready or status not in ("created", "registered"):
        _set_agent(states, "segments_agent", state="done", pct=100)

    # A finalized extracted_disk_uri is the barrier-open signal.  Historical
    # streaming runs may have status=indexing plus partial downstream rows even
    # though extraction is still active; keep every post-extract card parked.
    extract_activity = pp.get("extraction_activity") if isinstance(pp.get("extraction_activity"), dict) else {}
    extract_incomplete = (not upload_pending) and (not row.get("extracted_disk_uri")) and (
        status in ("processing", "building_disk", "extracting", "indexing", "awaiting_segments", "registered", "created")
        or (files_total > 0 and files_done < files_total)
        or (not seg_ready and files_done <= 0)
    )
    if extract_incomplete:
        if (
            status in ("processing", "building_disk")
            and not extract_activity
            and not (files_total > 0 and files_done > 0)
        ):
            _set_agent(states, "virtual_disk_agent", state="running", pct=min(90, extract_pct or 10))
        else:
            _set_agent(states, "virtual_disk_agent", state="done", pct=100)
        if str(extract_activity.get("subphase") or "") == "enumerating":
            found = int(extract_activity.get("files_found") or 0)
            extract_detail = (
                f"Filesystem inventory — {found:,} files discovered; total still growing"
                if found > 0
                else "Enumerating filesystem tree — total not known yet"
            )
        else:
            remaining = max(files_total - files_done, 0)
            extract_detail = (
                f"{files_done:,} / {files_total:,} files → MinIO · {remaining:,} remaining"
                if files_total
                else str(extract_activity.get("label") or "Preparing extraction plan")
            )
        _set_agent(
            states,
            "extraction_agent",
            state="running",
            pct=extract_pct,
            detail=extract_detail,
        )
    elif status in ("disk_ready", "extracted", "artifacts_registered", "parsed", "indexing", "indexed", "ready", "completed", "classified"):
        _set_agent(states, "virtual_disk_agent", state="done", pct=100)
        _set_agent(states, "extraction_agent", state="done", pct=100)

    if registered > 0 or phase == "materialize":
        mat_pct = pp.get("completed", 0) if phase == "materialize" else registered
        mat_total = pp.get("total") or max(registered, 1) if phase == "materialize" else max(registered, 1)
        mat_pct_i = min(99, int(100 * int(mat_pct) / int(mat_total))) if mat_total else 100
        if extract_incomplete and registered > 0:
            _set_agent(
                states,
                "materialize_agent",
                state="running",
                pct=min(99, extract_pct or mat_pct_i or 1),
                detail=f"{registered:,} artifacts so far — extract still running",
            )
        elif phase == "materialize" and status in ("building_disk", "extracting", "extracted", "indexing"):
            _set_agent(states, "materialize_agent", state="running", pct=mat_pct_i, detail=pp.get("label"))
        elif registered > 0 or status in ("artifacts_registered", "parsed", "indexing", "indexed", "ready", "completed"):
            _set_agent(states, "materialize_agent", state="done", pct=100, detail=f"{registered:,} artifacts registered")

    # --- OCR / parse ---
    ocr_pending_row = fetchone(
        db,
        """SELECT count(*) c FROM job_artifacts
           WHERE job_id=:jid AND ocr_status='pending'
             AND lower(coalesce(extension, '')) IN (
               '.pdf', '.png', '.jpg', '.jpeg', '.tif', '.tiff', '.webp', '.bmp', '.gif', '.heic'
             )""",
        {"jid": job_id},
    )
    ocr_pending_n = int(ocr_pending_row["c"]) if ocr_pending_row else 0
    ocr_view = ocr_agent_progress(
        ocr_done=ocr_n,
        ocr_pending=ocr_pending_n,
        ocr_eligible=ocr_eligible_n,
        parse_pending=pending_n,
        extract_incomplete=extract_incomplete,
        artifacts_registered=registered,
        ocr_unfinished=ocr_unfinished_n,
    )
    _set_agent(states, "ocr_agent", **ocr_view)
    if phase in ("ocr", "parse") and status in ("indexing", "extracted", "artifacts_registered", "parsed"):
        sub_pct = min(99, int(100 * int(pp.get("completed") or 0) / max(int(pp.get("total") or 1), 1)))
        if phase == "ocr" and ocr_view["state"] != "done":
            _set_agent(states, "ocr_agent", state="running", pct=sub_pct, detail=pp.get("label") or ocr_view["detail"])
        elif phase == "parse":
            _set_agent(states, "parse_agent", state="running", pct=sub_pct, detail=pp.get("label"))
    if pending_n == 0 and parsed_n > 0:
        if extract_incomplete:
            _set_agent(
                states,
                "parse_agent",
                state="running",
                pct=_own_work_pct(parsed_n, max(files_total, parsed_n)),
                detail=f"{parsed_n:,} parsed so far — extract still running",
            )
        else:
            _set_agent(states, "parse_agent", state="done", pct=100, detail=f"{parsed_n:,} forensic files parsed")
    elif pending_n == 0 and parsed_n == 0 and not extract_incomplete and registered >= 0:
        _set_agent(
            states,
            "parse_agent",
            state="done",
            pct=100,
            detail="No forensic files left to parse",
        )
    elif pending_n > 0 and status in ("indexing", "indexed", "parsed", "artifacts_registered"):
        parse_pct = min(99, int(100 * parsed_n / max(parsed_n + pending_n, 1)))
        _set_agent(states, "parse_agent", state="running", pct=parse_pct, detail=f"{parsed_n:,} / {parsed_n + pending_n:,}")

    # --- RAG chunk (required) / embed (optional) ---
    if not embed_on:
        _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings disabled — 100%")
        if extract_incomplete and chunk_n <= 0:
            _set_agent(states, "chunk_agent", state="pending", pct=0, detail="Waiting for extracted files")
        elif extract_incomplete and chunk_n > 0:
            _set_agent(
                states,
                "chunk_agent",
                state="running",
                pct=min(99, extract_pct or 1),
                detail=f"{chunk_n:,} chunks so far — extract still running",
            )
        elif chunk_n > 0 and rag_remaining <= 0:
            _set_agent(states, "chunk_agent", state="done", pct=100, detail=f"{chunk_n:,} chunks")
        elif indexable > 0 or chunk_n > 0 or rag_remaining > 0:
            chunked_arts = max(indexable - rag_remaining, 0)
            chunk_pct = min(99, int(100 * chunked_arts / max(indexable, 1)))
            _set_agent(
                states,
                "chunk_agent",
                state="running",
                pct=chunk_pct,
                detail=f"{chunk_n:,} chunks · {rag_remaining:,} artifacts left",
            )
        elif not extract_incomplete and registered > 0 and pending_n == 0 and parsed_n == 0:
            _set_agent(states, "chunk_agent", state="done", pct=100, detail="No indexable text after parse")
            _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings skipped — empty corpus")
        elif not extract_incomplete and registered > 0:
            _set_agent(states, "chunk_agent", state="pending", pct=0, detail="Waiting for parsed/OCR text")
        else:
            _set_agent(states, "chunk_agent", state="pending", pct=0)
    elif not extract_incomplete and (phase == "rag" or status in ("indexing", "indexed")):
        rag_pct = min(99, int(100 * chunk_n / rag_total))
        if chunk_n > 0 and rag_remaining <= 0:
            _set_agent(states, "chunk_agent", state="done", pct=100, detail=f"{chunk_n:,} chunks")
            _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings complete")
        elif chunk_n > 0:
            # Baseline may be searchable, but corpus embed is still running — show honest %.
            _set_agent(states, "chunk_agent", state="done", pct=100, detail=f"{chunk_n:,} chunks")
            embed_pct = min(99, max(1, int(100 * chunk_n / max(rag_total, chunk_n, 1))))
            detail = pp.get("label") or f"{chunk_n:,} / {max(rag_total, chunk_n):,} embedded"
            if baseline_embed_done and rag_remaining > 0:
                detail = (
                    f"Baseline ready — {chunk_n:,} searchable "
                    f"({rag_remaining:,} still embedding)"
                )
            _set_agent(states, "embed_agent", state="running", pct=embed_pct, detail=detail)
        elif status == "indexing":
            _set_agent(states, "chunk_agent", state="running", pct=5, detail="Chunking evidence…")

    # --- entity / neo4j / annotation / ontology ---
    rag_done = baseline_embed_done
    rag_enrich_complete, rag_enrich_in_flight = _rag_enrich_status(db, job_id)
    from app.services.rag_enrich import read_enrichment_stats

    enrich_stats = read_enrichment_stats(pp)
    scanned_n = int(enrich_stats.get("scanned") or 0)
    parse_total_n = int(enrich_stats.get("parse_total") or parsed_n)
    mention_n = int(enrich_stats.get("entity_mentions") or 0)
    ontology_n = int(enrich_stats.get("ontology_mapped") or 0)
    enrich_pct = (
        min(99, int(100 * scanned_n / max(parse_total_n, 1)))
        if parse_total_n > 0 and not rag_enrich_complete
        else (100 if rag_enrich_complete else 0)
    )
    if rag_enrich_in_flight and rag_done:
        entity_detail = (
            f"{mention_n:,} entities from {scanned_n:,} / {max(parse_total_n, 1):,} parsed files"
        )
        _set_agent(
            states,
            "entity_agent",
            state="running",
            pct=max(enrich_pct, 1),
            detail=entity_detail,
        )
        _set_agent(
            states,
            "annotation_agent",
            state="running",
            pct=max(min(enrich_pct, 90), 1),
            detail=f"{mention_n:,} evidence spans annotated ({scanned_n:,} / {max(parse_total_n, 1):,} files)",
        )
        onto_detail = (
            f"{ontology_n:,} artifacts mapped to encyclopedia"
            if ontology_n > 0
            else f"Linking forensic ontology — {scanned_n:,} / {max(parse_total_n, 1):,} files"
        )
        _set_agent(
            states,
            "ontology_agent",
            state="running" if not rag_enrich_complete else "done",
            pct=100 if ontology_n > 0 and rag_enrich_complete else max(enrich_pct, 1),
            detail=onto_detail,
        )
    elif rag_done and rag_enrich_complete and not extract_incomplete:
        _set_agent(
            states,
            "entity_agent",
            state="done",
            pct=100,
            detail=f"{mention_n:,} structured entities from {scanned_n:,} parsed files",
        )
        _set_agent(
            states,
            "annotation_agent",
            state="done",
            pct=100,
            detail=f"{mention_n:,} evidence spans annotated",
        )
        _set_agent(
            states,
            "ontology_agent",
            state="done",
            pct=100,
            detail=f"{ontology_n:,} artifacts mapped to encyclopedia",
        )
    elif rag_done and graph_status in ("ok", "skipped") and not rag_enrich_complete:
        _set_agent(
            states,
            "entity_agent",
            state="running",
            pct=max(enrich_pct, 1),
            detail=f"Entity Agent starting — {scanned_n:,} / {max(parse_total_n, 1):,} parsed files",
        )
        _set_agent(
            states,
            "annotation_agent",
            state="running",
            pct=max(enrich_pct, 1),
            detail=f"Annotation Agent starting — {scanned_n:,} / {max(parse_total_n, 1):,} files",
        )
        _set_agent(
            states,
            "ontology_agent",
            state="running",
            pct=max(enrich_pct, 1),
            detail=f"Ontology Agent starting — {scanned_n:,} / {max(parse_total_n, 1):,} files",
        )
    if graph_status == "ok" and not extract_incomplete:
        neo_detail = f"{graph_nodes:,} nodes / {graph_edges:,} edges"
        if ontology_n > 5000:
            neo_detail += f" — cap 5,000 of {ontology_n:,} encyclopedia-mapped files"
        _set_agent(states, "neo4j_agent", state="done", pct=100, detail=neo_detail)
    elif (graph_status == "skipped" or graph_unavailable) and not extract_incomplete:
        _set_agent(states, "neo4j_agent", state="done", pct=100, detail="Graph sync skipped")
    elif graph_status == "syncing" and rag_done and not graph_stale_queued:
        if graph_nodes > 0:
            neo_pct = min(95, max(15, 15 + min(graph_nodes // 50, 80)))
            _set_agent(
                states,
                "neo4j_agent",
                state="running",
                pct=neo_pct,
                detail=f"Syncing Neo4j — {graph_nodes:,} nodes",
            )
        else:
            _set_agent(states, "neo4j_agent", state="running", pct=15, detail="Syncing Neo4j…")
    elif graph_stale_queued and rag_done:
        _set_agent(
            states,
            "neo4j_agent",
            state="pending",
            pct=0,
            detail="Graph sync stalled — restarting",
        )
    elif graph_status in ("queued", "pending") and rag_done:
        _set_agent(states, "neo4j_agent", state="pending", pct=0, detail="Graph sync waiting to start")
    elif rag_done and graph_status not in ("ok", "skipped", "syncing", "queued", "pending"):
        _set_agent(states, "neo4j_agent", state="pending", pct=0)

    # --- artifact inventory ---
    inv_platform = inv.get("platform") or "Windows"
    if inv["total"] > 0:
        # Prefer live pipeline_progress during counting — DB result rows are written at the end.
        live_completed = int(inv["completed"] or 0)
        live_total = int(inv["total"] or 0)
        inv_stage = str((pp or {}).get("inventory_stage") or "")
        ui_pct_raw = (pp or {}).get("inventory_ui_pct")
        if phase in ("artifact_inventory", "axiom_artifacts"):
            pp_completed = int((pp or {}).get("completed") or 0)
            pp_total = int((pp or {}).get("total") or 0) or live_total
            if pp_total > 0 and pp_completed >= live_completed:
                live_completed = pp_completed
                live_total = pp_total
        # Authoritative UI percent from runner (prewarm + counting). Never invent 1%.
        if ui_pct_raw is not None and not inv["done"]:
            inv_pct = min(99, max(1, int(ui_pct_raw)))
        elif inv_stage and inv_stage not in ("counting", "done", "complete") and not inv["done"]:
            from app.services.catalog_artifact_runner import inventory_ui_pct_for

            inv_pct = inventory_ui_pct_for(stage=inv_stage)
        else:
            inv_pct = min(99, int(100 * live_completed / max(live_total, 1)))
        # Done only from DB catalog rows — never from prewarm fake completed values.
        counts_caught_up = int(inv["total"] or 0) > 0 and int(inv["completed"] or 0) >= int(inv["total"] or 0)
        if not extract_incomplete and (
            inv["done"] or (counts_caught_up and status in ("indexed", "ready", "completed", "classified"))
        ):
            inv_detail = f"{inv['completed']:,} / {inv['total']:,} {inv_platform} artifacts counted"
            if counts_caught_up and inv["completed"] < live_completed:
                inv_detail = f"{live_completed:,} / {live_total:,} {inv_platform} artifacts counted"
            _set_agent(states, "artifacts_agent", state="done", pct=100, detail=inv_detail)
            # Inventory finishing must NOT fake-complete OCR that never ran.
            _set_agent(
                states,
                "ocr_agent",
                **ocr_agent_progress(
                    ocr_done=ocr_n,
                    ocr_pending=ocr_pending_n,
                    ocr_eligible=ocr_eligible_n,
                    parse_pending=pending_n,
                    extract_incomplete=False,
                    artifacts_registered=registered,
                    ocr_unfinished=ocr_unfinished_n,
                ),
            )
            if rag_enrich_complete:
                _set_agent(
                    states,
                    "entity_agent",
                    state="done",
                    pct=100,
                    detail=f"{mention_n:,} structured entities from {scanned_n:,} parsed files",
                )
                _set_agent(
                    states,
                    "annotation_agent",
                    state="done",
                    pct=100,
                    detail=f"{mention_n:,} evidence spans annotated",
                )
                _set_agent(
                    states,
                    "ontology_agent",
                    state="done",
                    pct=100,
                    detail=f"{ontology_n:,} artifacts mapped to encyclopedia",
                )
            if graph_status == "ok":
                neo_detail = f"{graph_nodes:,} nodes / {graph_edges:,} edges"
                if ontology_n > 5000:
                    neo_detail += f" — cap 5,000 of {ontology_n:,} encyclopedia-mapped files"
                _set_agent(states, "neo4j_agent", state="done", pct=100, detail=neo_detail)
            elif graph_status == "skipped" or graph_unavailable:
                _set_agent(states, "neo4j_agent", state="done", pct=100, detail="Graph sync skipped")
            elif graph_status not in ("ok", "syncing", "queued", "pending") and rag_enrich_complete and ocr_pending_n <= 0:
                _set_agent(states, "neo4j_agent", state="done", pct=100, detail="Graph sync skipped")
            if status in ("indexed", "ready", "completed", "classified") and pending_n == 0:
                parse_detail = (
                    f"{parsed_n:,} forensic files parsed"
                    if parsed_n > 0
                    else "No pending forensic parses"
                )
                _set_agent(states, "parse_agent", state="done", pct=100, detail=parse_detail)
                if not embed_on:
                    _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings disabled — 100%")
                    if chunk_n > 0 and rag_remaining <= 0:
                        _set_agent(states, "chunk_agent", state="done", pct=100, detail=f"{chunk_n:,} chunks")
                    elif rag_remaining > 0 or chunk_n > 0:
                        chunked_arts = max(indexable - rag_remaining, 0)
                        chunk_pct = min(99, int(100 * chunked_arts / max(indexable, 1)))
                        _set_agent(
                            states,
                            "chunk_agent",
                            state="running",
                            pct=chunk_pct,
                            detail=f"{chunk_n:,} chunks · {rag_remaining:,} artifacts left",
                        )
                elif chunk_n > 0:
                    _set_agent(states, "chunk_agent", state="done", pct=100, detail=f"{chunk_n:,} chunks")
                    if rag_remaining <= 0:
                        _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings complete")
                    elif baseline_embed_done:
                        # Baseline searchable but corpus still embedding — stay running.
                        embed_pct = min(99, int(100 * (rag_total - rag_remaining) / max(rag_total, 1)))
                        _set_agent(
                            states,
                            "embed_agent",
                            state="running",
                            pct=max(embed_pct, 1),
                            detail=(
                                f"Baseline ready — {chunk_n:,} chunks searchable "
                                f"({rag_remaining:,} still embedding)"
                            ),
                        )
                elif registered <= 10 and inv_platform in ("Android", "iOS"):
                    _set_agent(states, "chunk_agent", state="done", pct=100, detail="Mobile extraction — minimal corpus")
                    _set_agent(states, "embed_agent", state="done", pct=100, detail="Re-process to expand RAG corpus")
                elif chunk_n == 0 and registered > 0:
                    _set_agent(states, "chunk_agent", state="done", pct=100, detail="No indexable chunks")
                    _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings skipped")
        elif (
            not extract_incomplete
            and pending_n == 0
            and (
                inv["completed"] > 0
                or phase in ("artifact_inventory", "axiom_artifacts", "complete")
                or status in ("indexing", "indexed", "ready")
            )
        ):
            _set_agent(
                states,
                "artifacts_agent",
                state="running",
                pct=max(inv_pct, 1),
                detail=pp.get("label") or f"{live_completed:,} / {live_total:,}",
            )

    if extract_incomplete:
        reopen_false_complete_during_extract(
            states,
            extract_pct=extract_pct,
            registered=registered,
            parsed_n=parsed_n,
            pending_n=pending_n,
            chunk_n=chunk_n,
            ocr_n=ocr_n,
            ocr_pending_n=ocr_pending_n,
            embed_on=embed_on,
            files_total=files_total,
            indexable=indexable,
        )
    _sync_platform_owner_cards(db, job_id, states)
    _stick_agent_progress(
        prev_agents,
        states,
        extract_incomplete=extract_incomplete,
        enrich_incomplete=bool(rag_done and not rag_enrich_complete),
    )
    _merge_agent_timings(prev_agents, states, pipeline_started_at=pipeline_started_at)
    _backfill_agent_timings_from_logs(db, job_id, states)
    if graph_status == "ok" and graph_last:
        neo = states.get("neo4j_agent") if isinstance(states.get("neo4j_agent"), dict) else None
        if neo and neo.get("state") == "done":
            finished = graph_last.isoformat().replace("+00:00", "Z") if hasattr(graph_last, "isoformat") else str(graph_last)
            started = neo.get("started_at")
            dur = _duration_sec(started, finished)
            if dur and dur > int(neo.get("duration_sec") or 0):
                neo["finished_at"] = finished
                neo["duration_sec"] = dur
    # Extraction owns the whole progress meter until the evidence manifest is
    # finalized. During filesystem enumeration the denominator is intentionally
    # unknown, so never inherit a stale 99% from an older streaming run.
    if extract_incomplete:
        if files_total > 0:
            overall = min(99, int(100 * files_done / files_total))
        else:
            previous_overall = int(prev_orch.get("overall_pct") or 0) if isinstance(prev_orch, dict) else 0
            overall = min(10, max(1, previous_overall if previous_overall < 11 else 1))
    else:
        overall = compute_overall_pct(states)
    cur_id, cur_label, cur_state = current_agent(states)
    # Wall-clock start: first time any agent leaves pending after segments are selected.
    if not pipeline_started_at:
        starts = [st.get("started_at") for st in states.values() if st.get("started_at")]
        if starts:
            pipeline_started_at = min(starts)
        elif any((st.get("state") in ("running", "done")) for st in states.values()):
            pipeline_started_at = _utc_now_iso()
    # Wall-clock elapsed from pipeline start — never sum overlapping step durations.
    total_sec = None
    if pipeline_started_at:
        end_iso = _utc_now_iso()
        all_done = all(
            int(_AGENT_BY_ID.get(aid, {}).get("weight") or 0) <= 0
            or (st.get("state") == "done")
            for aid, st in states.items()
            if isinstance(st, dict)
        )
        if overall >= 100 and all_done:
            prev_total = prev_orch.get("total_duration_sec") if isinstance(prev_orch, dict) else None
            if prev_total:
                total_sec = int(prev_total)
            else:
                ends = [st.get("finished_at") for st in states.values() if st.get("finished_at")]
                if ends:
                    end_iso = max(ends)
                total_sec = _duration_sec(pipeline_started_at, end_iso)
        else:
            total_sec = _duration_sec(pipeline_started_at, end_iso)
    # Cap reported overall at 99 until every required agent is done (optional embed excluded).
    all_agents_done = all(
        int(_AGENT_BY_ID.get(aid, {}).get("weight") or 0) <= 0
        or (st.get("state") == "done")
        for aid, st in states.items()
        if isinstance(st, dict)
    )
    if overall >= 100 and not all_agents_done:
        overall = 99
    # The extraction percentage is a phase-local percentage, not a lifetime
    # pipeline high-water mark. If extraction finished at 99%, the first
    # post-extract sync must be free to show Materialize/Parse/RAG starting at
    # their real percentages instead of pinning the complete pipeline at 99%.
    previous_agent_id = str(prev_orch.get("current_agent_id") or "") if isinstance(prev_orch, dict) else ""
    previous_was_extract = previous_agent_id == "extraction_agent"
    if extract_incomplete or previous_was_extract:
        high_water = overall
    else:
        high_water = max(int(prev_orch.get("progress_high_water") or 0) if isinstance(prev_orch, dict) else 0, overall)
        overall = high_water if overall < 100 else overall
    return {
        "agents": states,
        "overall_pct": overall,
        "progress_high_water": high_water,
        "current_agent_id": cur_id,
        "current_agent_label": cur_label,
        "current_agent_state": cur_state,
        "sequential": get_settings().pipeline_sequential_agents,
        "pipeline_started_at": pipeline_started_at,
        "total_duration_sec": total_sec,
    }


_PRE_EXTRACT_AGENTS = (
    "segments_agent",
    "virtual_disk_agent",
    "extraction_agent",
    "materialize_agent",
    "ocr_agent",
    "parse_agent",
    "chunk_agent",
    "entity_agent",
    "neo4j_agent",
    "annotation_agent",
    "ontology_agent",
    "artifacts_agent",
)


def reset_pre_extract_agent_cards(states: dict[str, dict[str, Any]]) -> None:
    """OCR/parse/etc must stay pending until files exist — never 100% on a created job."""
    from app.config import get_settings

    embed_on = bool(getattr(get_settings(), "rag_embedding_enabled", False))
    for aid in _PRE_EXTRACT_AGENTS:
        _set_agent(states, aid, state="pending", pct=0)
    if not embed_on:
        _set_agent(states, "embed_agent", state="done", pct=100, detail="Embeddings disabled — 100%")
    else:
        _set_agent(states, "embed_agent", state="pending", pct=0)


def persist_drive_mount_complete(
    db,
    job_id: str,
    *,
    mounted: list[str] | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    """Mark Drive Mount 100% and start Download (client) or List Folder (host)."""
    row = fetchone(
        db,
        """SELECT status, pipeline_progress, disk_source, segment_readiness,
                  files_total, files_extracted, extracted_disk_uri
           FROM jobs WHERE id=:id""",
        {"id": job_id},
    )
    pp = _parse_pp((row or {}).get("pipeline_progress"))
    if not pipeline_intake_started(row):
        # Mounted host drives are infrastructure readiness, not evidence intake.
        # Do not start or complete any job agent until the examiner selects data.
        return pp
    orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    existing_agents = orch.get("agents") if isinstance(orch.get("agents"), dict) else None
    states = existing_agents if existing_agents else _empty_agent_states()
    if "download_agent" not in states:
        states["download_agent"] = _empty_agent_states()["download_agent"]
    mount = states.get("drive_mount_agent") if isinstance(states.get("drive_mount_agent"), dict) else {}
    list_st = states.get("list_folder_agent") if isinstance(states.get("list_folder_agent"), dict) else {}
    upload_pending = False
    try:
        from app.services.host_evidence import is_client_upload_pending
        from app.services.mobile_os import load_job_disk_source

        upload_pending = is_client_upload_pending(load_job_disk_source(row))
    except Exception:
        upload_pending = False
    if (
        not upload_pending
        and mount.get("state") == "done"
        and list_st.get("state") in ("running", "done")
    ):
        status = str((row or {}).get("status") or "").lower()
        if status in ("created", "registered", "pending", "uploaded"):
            ocr = states.get("ocr_agent") if isinstance(states.get("ocr_agent"), dict) else {}
            if ocr.get("state") == "done" and int(ocr.get("pct") or 0) >= 100:
                reset_pre_extract_agent_cards(states)
                orch = {**orch, "agents": states, "current_agent_id": "list_folder_agent"}
                pp["orchestration"] = orch
                execute(
                    db,
                    """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id""",
                    {"pp": json.dumps(pp), "id": job_id},
                )
        return pp
    now = _utc_now_iso()
    letters = ", ".join(mounted or []) or "host drives"
    _set_agent(
        states,
        "drive_mount_agent",
        state="done",
        pct=100,
        detail=detail or f"Drives already mounted ({letters}) — no remount",
    )
    if not mount.get("started_at"):
        states["drive_mount_agent"]["started_at"] = now
    states["drive_mount_agent"]["finished_at"] = now
    status = str((row or {}).get("status") or "").lower()
    post_extract = status not in (
        "created",
        "registered",
        "pending",
        "uploaded",
        "awaiting_segments",
    )
    if status in ("created", "registered", "pending", "uploaded"):
        reset_pre_extract_agent_cards(states)
    if post_extract:
        if not existing_agents:
            # Missing agents on a live job — do not persist a pending 0% ledger.
            return pp
        # Never rebuild a live ledger or drop overall % / elapsed start.
        orch = {**orch, "agents": states}
        if orch.get("current_agent_id") in (None, "", "drive_mount_agent"):
            orch["current_agent_id"] = "list_folder_agent"
            orch["current_agent_label"] = "List folder"
            orch["current_agent_state"] = "running"
        pp["orchestration"] = orch
        execute(
            db,
            """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb) WHERE id=:id""",
            {"pp": json.dumps(pp), "id": job_id},
        )
        return pp
    list_already_done = list_st.get("state") == "done" or status not in (
        "created",
        "registered",
        "pending",
        "uploaded",
    )
    if upload_pending:
        from app.services.download_agent import download_progress_pct, download_running_detail
        from app.services.mobile_os import load_job_disk_source

        ds_now = load_job_disk_source(row)
        recv = int(ds_now.get("upload_received_files") or 0)
        exp = int(ds_now.get("upload_expected_files") or 0)
        _set_agent(
            states,
            "download_agent",
            state="running",
            pct=download_progress_pct(recv, exp),
            detail=download_running_detail(ds_now),
        )
        if not states["download_agent"].get("started_at"):
            states["download_agent"]["started_at"] = now
        _set_agent(
            states,
            "list_folder_agent",
            state="pending",
            pct=0,
            detail="Waiting for Download Agent to finish uploading client segments",
        )
        current = "download_agent"
        current_label = "Download"
    elif list_already_done:
        _set_agent(
            states,
            "download_agent",
            state="done",
            pct=100,
            detail="Download skipped — server-local evidence is processed in place (zero copy)",
        )
        current = orch.get("current_agent_id") or "list_folder_agent"
        current_label = "List folder" if current == "list_folder_agent" else orch.get("current_agent_label")
    else:
        _set_agent(
            states,
            "download_agent",
            state="done",
            pct=100,
            detail="Download skipped — server-local evidence is processed in place (zero copy)",
        )
        _set_agent(
            states,
            "list_folder_agent",
            state="running",
            pct=max(10, int(list_st.get("pct") or 0)),
            detail="Choose the .E01 folder",
        )
        if not list_st.get("started_at"):
            states["list_folder_agent"]["started_at"] = now
        current = "list_folder_agent"
        current_label = "List folder"
    overall = compute_overall_pct(states)
    prev_high = max(int(orch.get("progress_high_water") or 0), int(orch.get("overall_pct") or 0))
    high_water = max(prev_high, overall)
    orch = {
        **orch,
        "agents": states,
        "overall_pct": overall,
        "progress_high_water": high_water,
        "current_agent_id": current,
        "current_agent_label": current_label,
        "current_agent_state": "running",
        "pipeline_started_at": orch.get("pipeline_started_at"),
    }
    pp["orchestration"] = orch
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct, updated_at=NOW()
           WHERE id=:id""",
        {"pp": json.dumps(pp), "pct": overall, "id": job_id},
    )
    return pp


def mark_list_folder_done(db, job_id: str, *, path: str, count: int) -> None:
    """Mark the List folder agent done after directory contents are logged."""
    states = _empty_agent_states()
    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = _parse_pp(row.get("pipeline_progress") if row else None)
    prev = (pp.get("orchestration") or {}).get("agents") or {}
    if isinstance(prev, dict) and prev:
        for agent_id, entry in prev.items():
            if agent_id in states and isinstance(entry, dict):
                states[agent_id] = {**states[agent_id], **entry}
    now = _utc_now_iso()
    _set_agent(
        states,
        "list_folder_agent",
        state="done",
        pct=100,
        detail=f"Listed {count} item(s) in {path}",
    )
    states["list_folder_agent"]["finished_at"] = now
    if not states["list_folder_agent"].get("started_at"):
        states["list_folder_agent"]["started_at"] = now
    if count > 0:
        _set_agent(
            states,
            "segments_agent",
            state="running",
            pct=10,
            detail="Registering segments from listed folder",
        )
        if not states["segments_agent"].get("started_at"):
            states["segments_agent"]["started_at"] = now
    orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    orch = {
        **orch,
        "agents": states,
        "overall_pct": compute_overall_pct(states),
        "current_agent_id": "segments_agent",
        "current_agent_label": "Get segments",
        "current_agent_state": "running",
        "sequential": get_settings().pipeline_sequential_agents,
        "pipeline_started_at": orch.get("pipeline_started_at") or now,
    }
    _merge_agent_timings(prev if isinstance(prev, dict) else {}, states)
    orch["agents"] = states
    orch["overall_pct"] = compute_overall_pct(states)
    pp["phase"] = "segments"
    pp["orchestration"] = orch
    pp["label"] = f"Get segments — {orch['overall_pct']}% overall"
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct, updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "pp": json.dumps(pp), "pct": orch["overall_pct"]},
    )
    db.flush()


def init_pipeline_orchestration(db, job_id: str, *, message: str | None = None) -> None:
    """Initialize sequential orchestration ledger when processing starts."""
    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = _parse_pp(row.get("pipeline_progress") if row else None)
    prev_orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    prev_agents = prev_orch.get("agents") if isinstance(prev_orch.get("agents"), dict) else {}
    later_done = any(
        aid not in ("drive_mount_agent", "list_folder_agent")
        and isinstance(entry, dict)
        and entry.get("state") == "done"
        for aid, entry in prev_agents.items()
    )
    if later_done:
        return
    states = _empty_agent_states()
    now = _utc_now_iso()
    _set_agent(
        states,
        "download_agent",
        state="done",
        pct=100,
        detail="Download Agent complete — other agents may start",
    )
    _set_agent(
        states,
        "list_folder_agent",
        state="done",
        pct=100,
        detail="Folder listing complete",
    )
    states["list_folder_agent"]["started_at"] = now
    states["list_folder_agent"]["finished_at"] = now
    _set_agent(
        states,
        "segments_agent",
        state="running",
        pct=5,
        detail=message or "Sequential pipeline — validating segments",
    )
    states["segments_agent"]["started_at"] = now
    orch = {
        "agents": states,
        "overall_pct": compute_overall_pct(states),
        "current_agent_id": "segments_agent",
        "current_agent_label": "Get segments",
        "current_agent_state": "running",
        "sequential": get_settings().pipeline_sequential_agents,
        "pipeline_started_at": prev_orch.get("pipeline_started_at") or now,
        "progress_high_water": int(prev_orch.get("progress_high_water") or 0),
        "total_duration_sec": 0,
    }
    pp["phase"] = "segments"
    pp["completed"] = 0
    pp["total"] = len(PIPELINE_AGENTS)
    pp["orchestration"] = orch
    pp["label"] = f"Get segments — {orch['overall_pct']}% overall"
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct, updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "pp": json.dumps(pp), "pct": orch["overall_pct"]},
    )
    log_agent(
        db,
        job_id,
        "segments_agent",
        message or "Sequential pipeline started — agents run one group at a time",
        stage="agent",
    )
    db.flush()


def record_pipeline_milestone(
    db,
    job_id: str,
    *,
    status: str,
    progress: dict[str, Any],
    writer: str = "generic",
    extract_coverage: dict[str, Any] | None = None,
    clear_error: bool = False,
) -> dict[str, Any] | None:
    """Persist a stage milestone WITHOUT lying about overall completion.

    Several stage writers used to run ``UPDATE jobs SET status='indexed',
    progress_pct=100, pipeline_progress=<fresh blob>``. That wiped the
    ``orchestration`` block (per-agent states/timings) and forced 100% while
    parse/chunk/enrich/inventory still had work. Because normal UI polling
    returns the persisted row untouched, the UI then showed "Overall 100% /
    Pipeline finished" with the running stage pinned at 99% (frontend fallback
    inference) and every later stage at 0%.

    This helper merges the stage blob into the existing pipeline_progress
    (keeping orchestration/inventory fields), writes status/extract_coverage,
    then re-derives per-agent states and the weighted overall via
    ``sync_orchestration_from_job`` — which caps overall at 99 until every
    required agent is done — and persists that as ``progress_pct``.
    """
    from app.services.pipeline_progress import write_merged_pipeline_progress

    extra_sets = ""
    extra_params: dict[str, Any] = {}
    if extract_coverage is not None:
        extra_sets = "extract_coverage=CAST(:ec AS jsonb)"
        extra_params["ec"] = json.dumps(extract_coverage)
    if clear_error:
        extra_sets = (extra_sets + ", " if extra_sets else "") + "error=NULL"
    write_merged_pipeline_progress(
        db,
        job_id,
        dict(progress or {}),
        writer=writer,
        status_sql=f"status='{status}'" if status else None,
        extra_sets=extra_sets,
        extra_params=extra_params or None,
    )
    db.flush()

    try:
        orch = sync_orchestration_from_job(db, job_id)
    except Exception:
        log.exception("record_pipeline_milestone: orchestration sync failed for job %s", job_id)
        return None
    overall = int(orch.get("overall_pct") or 0)
    all_done = all(
        int(a.get("weight") or 0) <= 0 or _agent_state(orch.get("agents") or {}, a["id"]) == "done"
        for a in PIPELINE_AGENTS
    )
    if not all_done:
        overall = min(99, overall)
    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    pp = _parse_pp((row or {}).get("pipeline_progress"))
    pp["orchestration"] = orch
    execute(
        db,
        """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:pct,
           updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "pp": json.dumps(pp), "pct": overall},
    )
    db.flush()
    return pp


def finalize_pipeline_after_inventory(db, job_id: str) -> dict[str, Any] | None:
    """Finalize only when inventory AND every agent are truly done.

    Never force-mark OCR/RAG/enrich agents as 100% while work remains — that caused
    the UI contradiction of all steps at 100% with overall stuck at 99%.
    """
    from app.services.forensic_serial_pipeline import serial_progress_snapshot

    serial = serial_progress_snapshot(db, job_id)
    if serial is not None:
        return serial if serial["serial_pipeline"]["complete"] else None
    from app.services.catalog_artifact_runner import axiom_inventory_progress
    from app.services.dual_rag_index import _count_indexable_without_chunks

    inv = axiom_inventory_progress(db, job_id)
    if not inv.get("done"):
        return None

    row = fetchone(
        db,
        "SELECT status, pipeline_progress FROM jobs WHERE id=:id",
        {"id": job_id},
    )
    if not row:
        return None

    pp = _parse_pp(row.get("pipeline_progress"))

    orch = sync_orchestration_from_job(db, job_id)
    agents = orch.get("agents") or _empty_agent_states()
    ocr_pending_row = fetchone(
        db,
        """SELECT count(*) c FROM job_artifacts
           WHERE job_id=:jid AND ocr_status='pending'
             AND lower(coalesce(extension, '')) IN (
               '.pdf', '.png', '.jpg', '.jpeg', '.tif', '.tiff', '.webp', '.bmp', '.gif', '.heic'
             )""",
        {"jid": job_id},
    )
    ocr_pending_n = int(ocr_pending_row["c"]) if ocr_pending_row else 0
    rag_remaining = int(_count_indexable_without_chunks(db, job_id) or 0)
    settings = get_settings()
    rag_incomplete = rag_remaining > 0

    pipeline_agents_done = all(
        int(agent.get("weight") or 0) <= 0 or _agent_state(agents, agent["id"]) == "done"
        for agent in PIPELINE_AGENTS
    )
    truly_complete = pipeline_agents_done and ocr_pending_n <= 0 and not rag_incomplete

    # Already finalized correctly — skip rewrite.
    phase = (pp.get("phase") or "").lower()
    status = (row.get("status") or "").lower()
    prev_orch = pp.get("orchestration") if isinstance(pp.get("orchestration"), dict) else {}
    if (
        truly_complete
        and phase == "complete"
        and status == "ready"
        and int(prev_orch.get("overall_pct") or 0) >= 100
    ):
        return pp

    platform = inv.get("platform") or "Windows"
    completed = int(inv.get("completed") or 0)
    total = int(inv.get("total") or 0)
    orch["agents"] = agents

    if not truly_complete:
        # Inventory finished; keep honest agent cards and cap overall under 100.
        overall = min(99, max(1, compute_overall_pct(agents)))
        orch["overall_pct"] = overall
        cur_id, cur_label, cur_state = current_agent(agents)
        orch["current_agent_id"] = cur_id
        orch["current_agent_label"] = cur_label
        orch["current_agent_state"] = cur_state
        pp["phase"] = "artifact_inventory"
        pp["completed"] = completed
        pp["total"] = total
        pp["inventory_ui_pct"] = 100
        pp["inventory_stage"] = "done"
        pp["label"] = (
            f"Artifact inventory complete — {completed:,} / {total:,} {platform}; "
            f"background work continuing"
        )
        pp["orchestration"] = orch
        execute(
            db,
            """UPDATE jobs SET status='indexing', progress_pct=:pct,
               pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
            {"id": job_id, "pp": json.dumps(pp), "pct": overall},
        )
        db.flush()
        return pp

    orch["overall_pct"] = 100
    orch["current_agent_id"] = None
    orch["current_agent_label"] = None
    orch["current_agent_state"] = None

    pp["phase"] = "complete"
    pp["completed"] = completed
    pp["total"] = total
    pp["inventory_ui_pct"] = 100
    pp["inventory_stage"] = "done"
    pp["label"] = (
        f"Pipeline complete — {completed:,} / {total:,} {platform} artifacts inventoried"
    )
    pp["orchestration"] = orch

    execute(
        db,
        """UPDATE jobs SET status='ready', progress_pct=100,
           pipeline_progress=CAST(:pp AS jsonb), updated_at=NOW() WHERE id=:id""",
        {"id": job_id, "pp": json.dumps(pp)},
    )
    log_agent(
        db,
        job_id,
        "artifacts_agent",
        f"Pipeline complete — {completed:,} / {total:,} {platform} artifacts inventoried",
        stage="agent",
    )
    _purge_browser_upload_dump(db, job_id)
    db.flush()
    return pp


def build_orchestration_progress_snapshot(
    db,
    job_id: str,
    *,
    row: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Compute pipeline_progress + orchestration for UI without persisting (safe during active parse)."""
    from app.services.forensic_serial_pipeline import serial_progress_snapshot

    serial = serial_progress_snapshot(db, job_id, row=row)
    if serial is not None:
        return serial
    if row is None:
        row = fetchone(
            db,
            """SELECT pipeline_progress, progress_pct, status, disk_source,
                      files_total, files_extracted, extracted_disk_uri, segment_readiness
               FROM jobs WHERE id=:id""",
            {"id": job_id},
        )
    if not row:
        return None
    pp = _parse_pp(row.get("pipeline_progress"))
    if not pipeline_intake_started(row):
        orch = idle_orchestration_snapshot()
        # Discard stale progress created by old huddles that ran before evidence
        # selection. A new job must be visually and operationally inert.
        pp = {
            "phase": "idle",
            "completed": 0,
            "total": None,
            "label": "Waiting for evidence selection",
            "orchestration": orch,
            "progress_pct": 0,
        }
        return pp
    orch = sync_orchestration_from_job(db, job_id)
    pp["orchestration"] = orch
    overall = int(orch.get("overall_pct") or 0)
    from app.services.catalog_artifact_runner import axiom_inventory_progress, parse_pending_count

    inv = axiom_inventory_progress(db, job_id)
    pending_parse = parse_pending_count(db, job_id)
    status_l = str(row.get("status") or "").lower()
    files_total = int(row.get("files_total") or 0)
    files_done = int(row.get("files_extracted") or 0)
    extract_incomplete = (not row.get("extracted_disk_uri")) and (
        status_l in ("processing", "building_disk", "extracting", "indexing")
        or (files_total > 0 and files_done < files_total)
    )
    if extract_incomplete:
        activity = pp.get("extraction_activity") if isinstance(pp.get("extraction_activity"), dict) else {}
        subphase = str(activity.get("subphase") or "")
        found = int(activity.get("files_found") or 0)
        pp["phase"] = "extract"
        if files_total > 0:
            remaining = max(files_total - files_done, 0)
            pp["completed"] = files_done
            pp["total"] = files_total
            pp["label"] = f"Extraction — {files_done:,} / {files_total:,} files · {remaining:,} remaining"
            overall = min(99, int(100 * files_done / files_total))
        else:
            pp["completed"] = found
            pp["total"] = None
            pp["label"] = (
                f"Filesystem inventory — {found:,} files discovered; total still growing"
                if subphase == "enumerating" and found > 0
                else str(activity.get("label") or "Preparing evidence extraction")
            )
            # Enumeration has an unknown denominator: do not present a fake 99%.
            overall = min(10, max(1, int(orch.get("overall_pct") or 1)))
        orch["overall_pct"] = overall
        orch["current_agent_id"] = "extraction_agent"
        orch["current_agent_label"] = "Extraction"
        orch["current_agent_state"] = "running"
        pp["orchestration"] = orch
        pending_parse = 0
    if pending_parse > 0 and (pp.get("phase") or "") in ("artifact_inventory", "axiom_artifacts"):
        parsed_row = fetchone(
            db,
            "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
            {"jid": job_id},
        )
        parsed_n = int(parsed_row["c"]) if parsed_row else 0
        pp["phase"] = "parse"
        pp["completed"] = parsed_n
        pp["total"] = max(parsed_n + pending_parse, 1)
        pp["label"] = f"Background parse — {parsed_n:,} / {parsed_n + pending_parse:,} forensic files"
    elif pending_parse > 0 and (pp.get("phase") or "") not in ("parse", "rag", "ocr"):
        parsed_row = fetchone(
            db,
            "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
            {"jid": job_id},
        )
        parsed_n = int(parsed_row["c"]) if parsed_row else 0
        pp["phase"] = "parse"
        pp["completed"] = parsed_n
        pp["total"] = max(parsed_n + pending_parse, 1)
        pp["label"] = f"Background parse — {parsed_n:,} / {parsed_n + pending_parse:,} forensic files"
    agents_snap = orch.get("agents") or {}
    pipeline_agents_done = all(
        int(a.get("weight") or 0) <= 0 or (agents_snap.get(a["id"]) or {}).get("state") == "done"
        for a in PIPELINE_AGENTS
    )
    if extract_incomplete:
        overall = min(99, overall if files_total <= 0 else int(100 * files_done / files_total))
        orch["overall_pct"] = overall
        pp["orchestration"] = orch
    elif inv.get("done") and pipeline_agents_done:
        overall = 100
        platform = inv.get("platform") or "Windows"
        completed = int(inv.get("completed") or 0)
        inv_total = int(inv.get("total") or 0)
        pp["phase"] = "complete"
        pp["completed"] = completed
        pp["total"] = inv_total
        pp["label"] = (
            f"Pipeline complete — {completed:,} / {inv_total:,} {platform} artifacts inventoried"
        )
        orch["overall_pct"] = 100
        orch["current_agent_id"] = None
        orch["current_agent_label"] = None
        orch["current_agent_state"] = None
        pp["orchestration"] = orch
    elif inv.get("done") and not pipeline_agents_done:
        # Inventory finished early — keep honest overall under 100 while OCR/RAG/enrich run.
        overall = min(99, max(overall, 1))
        orch["overall_pct"] = overall
        pp["orchestration"] = orch
    else:
        # Keep progress honest when catalog still has uncounted artifacts.
        # CRITICAL: do NOT overwrite live prewarm completed/label with DB zeros —
        # that stuck the UI at 1% for the entire census/path-index/carve phase.
        inv_total = int(inv.get("total") or 0)
        inv_completed = int(inv.get("completed") or 0)
        live_completed = int(pp.get("completed") or 0)
        live_total = int(pp.get("total") or 0) or inv_total
        live_ui = pp.get("inventory_ui_pct")
        live_stage = str(pp.get("inventory_stage") or "")
        live_label = pp.get("label")
        if inv_total > 0 and inv_completed < inv_total:
            platform = inv.get("platform") or "Windows"
            pp["phase"] = "artifact_inventory"
            pp["total"] = live_total if live_total > 0 else inv_total
            if live_ui is not None or (
                live_stage
                and live_stage not in ("counting", "done", "complete")
                and live_completed > inv_completed
            ):
                # Preserve runner-published prewarm/count progress.
                if live_completed > inv_completed:
                    pp["completed"] = live_completed
                else:
                    pp["completed"] = max(live_completed, inv_completed)
                if live_ui is not None:
                    pp["inventory_ui_pct"] = live_ui
                if live_stage:
                    pp["inventory_stage"] = live_stage
                if live_label:
                    pp["label"] = live_label
                elif live_ui is not None:
                    pp["label"] = (
                        f"Artifact inventory — {live_stage or 'running'} ({int(live_ui)}%)"
                    )
            else:
                pp["completed"] = inv_completed
                pp["label"] = (
                    f"Artifact inventory — {inv_completed:,} / {inv_total:,} ({platform})"
                )
            # Patch artifacts_agent card from live UI pct even when sync writes are skipped.
            agents = orch.get("agents") if isinstance(orch.get("agents"), dict) else {}
            art = agents.get("artifacts_agent") if isinstance(agents, dict) else None
            if isinstance(art, dict) and art.get("state") != "done":
                patch_pct = None
                if live_ui is not None:
                    patch_pct = min(99, max(1, int(live_ui)))
                elif live_total > 0 and live_completed > 0:
                    patch_pct = min(99, max(1, int(100 * live_completed / live_total)))
                if patch_pct is not None:
                    art = dict(art)
                    art["state"] = "running"
                    art["pct"] = patch_pct
                    if live_label:
                        art["detail"] = live_label
                    agents = dict(agents)
                    agents["artifacts_agent"] = art
                    orch["agents"] = agents
                    orch["overall_pct"] = min(99, compute_overall_pct(agents))
                    overall = int(orch["overall_pct"])
                    pp["orchestration"] = orch
        else:
            cur_label = orch.get("current_agent_label")
            if cur_label and orch.get("current_agent_id"):
                pp["label"] = f"{cur_label} — {overall}% overall"
    # Cap overall under 100 while inventory/OCR/RAG still running.
    if overall >= 100 and not (
        inv.get("done")
        and pipeline_agents_done
    ):
        overall = 99
        orch["overall_pct"] = 99
        pp["orchestration"] = orch
    pp["progress_pct"] = overall
    return pp


def merge_orchestration_into_progress(db, job_id: str) -> dict[str, Any] | None:
    """Refresh pipeline_progress.orchestration and overall progress_pct on the job."""
    from app.services.forensic_serial_pipeline import persist_snapshot

    serial = persist_snapshot(db, job_id)
    if serial is not None:
        return serial
    try:
        gate_row = fetchone(
            db,
            """SELECT status, disk_source, extracted_disk_uri, files_total, files_extracted,
                      segment_readiness, pipeline_progress
               FROM jobs WHERE id=:id""",
            {"id": job_id},
        )
        if gate_row and not pipeline_intake_started(gate_row):
            pp = build_orchestration_progress_snapshot(db, job_id, row=gate_row)
            if not pp:
                return None
            overall = int(pp.pop("progress_pct", 0))
            execute(
                db,
                """UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb), progress_pct=:overall
                   WHERE id=:id""",
                {"id": job_id, "pp": json.dumps(pp), "overall": overall},
            )
            db.flush()
            return pp

        from app.services.catalog_artifact_runner import axiom_inventory_progress

        inv = axiom_inventory_progress(db, job_id)
        enrich_running = False
        try:
            from app.services.rag_enrich import read_enrichment_stats

            live_row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
            live_stats = read_enrichment_stats(_parse_pp((live_row or {}).get("pipeline_progress")))
            enrich_running = bool(live_stats) and not live_stats.get("complete")
        except Exception:
            enrich_running = False
        # Finalize walks the full inventory/OCR/RAG counts. Do not do that on every
        # enrich heartbeat — it capped Entity/Annotation/Ontology at ~10 rows/s.
        if inv.get("done") and not enrich_running:
            finalized = finalize_pipeline_after_inventory(db, job_id)
            if finalized:
                return finalized

        pp = build_orchestration_progress_snapshot(db, job_id)
        if not pp:
            return None
        overall = int(pp.pop("progress_pct", 0))
        status_sql = ", status='ready'" if inv.get("done") else ""
        execute(
            db,
            f"""UPDATE jobs SET pipeline_progress=CAST(:pp AS jsonb),
               progress_pct=:overall{status_sql},
               updated_at=NOW() WHERE id=:id""",
            {"id": job_id, "pp": json.dumps(pp), "overall": overall},
        )
        db.flush()
        return pp
    except Exception:
        log.exception("merge_orchestration_into_progress failed for job %s", job_id)
        try:
            db.rollback()
        except Exception:
            pass
        return None


def format_agent_log_message(agent_id: str, message: str) -> str:
    label = (_AGENT_BY_ID.get(agent_id) or {}).get("label") or agent_id
    return f"[{label}] {message}"


def log_agent(
    db,
    job_id: str,
    agent_id: str,
    message: str,
    *,
    stage: str = "agent",
    level: str = "info",
    metadata: dict[str, Any] | None = None,
) -> None:
    from app.services.disk_build_log import write_disk_log

    meta = {"agent_id": agent_id, **(metadata or {})}
    write_disk_log(
        db,
        job_id,
        format_agent_log_message(agent_id, message),
        stage=stage,
        level=level,
        metadata=meta,
    )
