"""Agent duties shared by OCR, Observe, and Performance.

These rules exist so the huddle cannot re-learn the same failures:
1. OCR Agent owns queue completeness — skipped/eligible gaps are not leftover work.
2. Performance/OCR own chassis heat — CPU throttle (~80°C) with a cool GPU is not abort.
3. Entity/Annotation/Ontology own enrichment — a start log or frozen lock is not progress.
4. Extraction Agent owns extract completeness — files_extracted >= files_total is finished.
   Status=processing or a leftover checkpoint must not resume a completed copy.
5. Report Generator Agent owns A4 letterhead, table row keep-together, and every selected objective.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

ENRICH_FROZEN_SEC = 180


def _settings_thermal() -> dict[str, int]:
    try:
        from app.config import get_settings

        s = get_settings()
        return {
            "gpu_throttle_c": int(getattr(s, "gpu_thermal_throttle_c", 87) or 87),
            "gpu_pause_c": int(getattr(s, "gpu_thermal_pause_c", 92) or 92),
            "gpu_abort_c": int(getattr(s, "gpu_thermal_abort_c", 94) or 94),
            "cpu_throttle_c": int(getattr(s, "cpu_thermal_throttle_c", 86) or 86),
            "cpu_pause_c": int(getattr(s, "cpu_thermal_pause_c", 94) or 94),
        }
    except Exception:
        return {
            "gpu_throttle_c": 87,
            "gpu_pause_c": 92,
            "gpu_abort_c": 94,
            "cpu_throttle_c": 86,
            "cpu_pause_c": 94,
        }


def ocr_queue_health(snap: dict[str, Any] | None) -> dict[str, Any]:
    """OCR Agent view of remaining work.

    Unfinished = pending + failed-without-text. Eligible minus done is often
    skipped photos/cache — that gap must not keep the card at ~85% or vote run.
    """
    snap = snap or {}
    pending = int(snap.get("ocr_pending") or 0)
    unfinished_raw = snap.get("ocr_unfinished")
    unfinished = int(pending if unfinished_raw is None else unfinished_raw)
    eligible = int(snap.get("ocr_eligible") or 0)
    done = int(snap.get("ocr_done") or 0)
    parse_pending = int(snap.get("parse_pending") or 0)
    artifacts = int(snap.get("artifact_n") or 0)
    card = ((snap.get("agent_states") or {}).get("ocr_agent") or {}) if isinstance(snap.get("agent_states"), dict) else {}
    card_state = str(card.get("state") or "")
    card_pct = int(card.get("pct") or 0)
    queue_clear = pending <= 0 and unfinished <= 0
    skipped_gap = queue_clear and eligible > done
    fake_running = (
        queue_clear
        and parse_pending <= 0
        and artifacts > 0
        and card_state == "running"
        and 0 < card_pct < 100
    )
    should_run = (pending > 0 or unfinished > 0)
    should_stand_down = queue_clear and parse_pending <= 0 and artifacts > 0
    return {
        "pending": pending,
        "unfinished": unfinished,
        "eligible": eligible,
        "done": done,
        "parse_pending": parse_pending,
        "queue_clear": queue_clear,
        "skipped_gap": skipped_gap,
        "fake_running": fake_running,
        "should_run": should_run,
        "should_stand_down": should_stand_down,
        "duty": (
            "OCR Agent owns completeness: drain pending and failed-without-text; "
            "skipped/eligible gaps are finished; stand down so entity/annotation/ontology can run."
        ),
    }


def assess_chassis_for_ocr(
    gpu_c: float | None,
    cpu_c: float | None,
    *,
    gpu_throttle_c: int | None = None,
    gpu_pause_c: int | None = None,
    gpu_abort_c: int | None = None,
    cpu_throttle_c: int | None = None,
    cpu_pause_c: int | None = None,
) -> dict[str, Any]:
    """Performance + OCR Agent chassis rule.

    CPU at throttle (often ~80°C under OCR) is normal laptop load. It is not
    chassis abort while the GPU is below pause. Hold OCR only at GPU pause/abort
    or CPU pause (below OEM shutdown).
    """
    t = _settings_thermal()
    gpu_throttle_c = int(gpu_throttle_c if gpu_throttle_c is not None else t["gpu_throttle_c"])
    gpu_pause_c = int(gpu_pause_c if gpu_pause_c is not None else t["gpu_pause_c"])
    gpu_abort_c = int(gpu_abort_c if gpu_abort_c is not None else t["gpu_abort_c"])
    cpu_throttle_c = int(cpu_throttle_c if cpu_throttle_c is not None else t["cpu_throttle_c"])
    cpu_pause_c = int(cpu_pause_c if cpu_pause_c is not None else t["cpu_pause_c"])

    gpu_abort = gpu_c is not None and gpu_c >= gpu_abort_c
    gpu_pause = gpu_c is not None and gpu_c >= gpu_pause_c
    cpu_pause = cpu_c is not None and cpu_c >= cpu_pause_c
    cpu_at_throttle = cpu_c is not None and cpu_c >= cpu_throttle_c and not cpu_pause
    gpu_cool = gpu_c is None or gpu_c < gpu_throttle_c
    hold = bool(gpu_abort or gpu_pause or cpu_pause)
    cpu_throttle_only = bool(cpu_at_throttle and gpu_cool and not hold)
    cpu_warm_gpu_cool = bool(
        cpu_c is not None and cpu_c >= 70 and gpu_cool and not hold
    )
    gpu_warm = gpu_c is not None and gpu_c >= gpu_throttle_c and not hold
    slow_batches = bool((cpu_at_throttle or gpu_warm) and not hold)

    if gpu_abort:
        reason = (
            f"GPU {gpu_c:.0f}°C at abort ({gpu_abort_c}°C) — Performance holds new GLM OCR "
            "to prevent thermal shutdown"
        )
        advice = "hold"
    elif gpu_pause:
        reason = (
            f"GPU {gpu_c:.0f}°C at pause ({gpu_pause_c}°C) — OCR Agent cools the card, then continues"
        )
        advice = "hold"
    elif cpu_pause:
        reason = (
            f"CPU {cpu_c:.0f}°C at pause ({cpu_pause_c}°C) — hold new GPU OCR to prevent shutdown"
        )
        advice = "hold"
    elif cpu_throttle_only or cpu_warm_gpu_cool:
        gpu_txt = f"{gpu_c:.0f}°C" if gpu_c is not None else "unreadable"
        reason = (
            f"CPU {cpu_c:.0f}°C is not chassis abort (pause {cpu_pause_c}°C). "
            f"GPU {gpu_txt} cool — OCR Agent keeps draining"
        )
        advice = "go"
    elif slow_batches:
        reason = (
            f"Warm path — GPU {gpu_c if gpu_c is not None else '?'}°C / "
            f"CPU {cpu_c if cpu_c is not None else '?'}°C under pause; OCR continues with smaller batches"
        )
        advice = "go"
    else:
        reason = (
            f"GPU {gpu_c if gpu_c is not None else '?'}°C / "
            f"CPU {cpu_c if cpu_c is not None else '?'}°C under pause — OCR Agent continues"
        )
        advice = "go"

    return {
        "gpu_c": gpu_c,
        "cpu_c": cpu_c,
        "too_hot": hold,
        "ocr_may_run": not hold,
        "slow_batches": slow_batches,
        "cpu_throttle_only": cpu_throttle_only,
        "cpu_warm_gpu_cool": cpu_warm_gpu_cool,
        "advice": advice,
        "reason": reason,
        "gpu_pause_c": gpu_pause_c,
        "gpu_abort_c": gpu_abort_c,
        "cpu_throttle_c": cpu_throttle_c,
        "cpu_pause_c": cpu_pause_c,
        "duty": (
            "Performance Agent owns chassis abort (GPU pause/abort or CPU pause). "
            "CPU throttle with a cool GPU is OCR Agent's to keep working, not freeze."
        ),
    }


def extract_counts_complete(files_total: Any, files_done: Any) -> bool:
    """True when extract copied every planned file. Status is not part of this."""
    total = int(files_total or 0)
    done = int(files_done or 0)
    return total > 0 and done >= total


def extract_agent_health(snap: dict[str, Any] | None) -> dict[str, Any]:
    """Extraction Agent view of remaining MinIO copy work.

    File counts are the source of truth. A completed job flipped back to
    processing/building_disk is finished work, not leftover — do not resume.
    """
    snap = snap or {}
    files_total = int(snap.get("files_total") or 0)
    files_done = int(snap.get("files_done") or 0)
    status = str(snap.get("status") or "")
    live = bool(snap.get("extract_live"))
    extracting_status = status in ("processing", "building_disk", "extracting")
    complete = extract_counts_complete(files_total, files_done)
    mobile_needs_start = bool(snap.get("is_mobile")) and status in (
        "created",
        "registered",
        "awaiting_segments",
    ) and files_done <= 0
    unfinished = (not complete) and (
        extracting_status
        or (files_total > 0 and files_done < files_total)
        or mobile_needs_start
    )
    stuck_restarting = complete and extracting_status
    should_run = unfinished and not live and not complete
    return {
        "complete": complete,
        "live": live and not complete,
        "unfinished": unfinished,
        "stuck_restarting": stuck_restarting,
        "should_run": should_run,
        "should_stand_down": complete,
        "files_done": files_done,
        "files_total": files_total,
        "duty": (
            "Extraction Agent owns completeness: when files_extracted >= files_total, "
            "stand down. Do not resume because status is processing or a checkpoint remains."
        ),
    }


def report_generator_health(snap: dict[str, Any] | None) -> dict[str, Any]:
    """Report Evidence & Content Agent — forensic content, not document formation.

    Huddle must not auto-start a report. Recreate report is the examiner trigger.
    """
    snap = snap or {}
    status = str(snap.get("status") or "")
    generating = status == "report_generating"
    complete = status in ("completed", "classified", "ready", "report_ready")
    return {
        "complete": complete and not generating,
        "generating": generating,
        "should_run": False,
        "should_stand_down": complete and not generating,
        "duty": (
            "Report Evidence & Content Agent owns forensic meaning only. It hydrates each selected catalog objective (never printing RPT-O920-style IDs), uses the "
            "integrated AXIOM KB and the methodology/writing style learned from all supplied reference reports to select record-level evidence, excludes noise, "
            "deduplicates/correlates artifacts, and creates Objective / Procedure / Observation, Annexure and Analysis Summary. "
            "The LLM is the final wording step only and cannot choose evidence or change counts. Raw XML/JSON, unrelated totals "
            "and device banners such as Laptop [1] are never report content. A4 pagination, letterhead placement, page number "
            "clearance, page-space optimisation and PDF/DOCX creation belong exclusively to Report Formation Agent."
        ),
    }


def enrich_updated_age_sec(updated_at: Any) -> float | None:
    if not updated_at:
        return None
    text = str(updated_at).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds()


def enrich_agent_health(snap: dict[str, Any] | None) -> dict[str, Any]:
    """Entity / Annotation / Ontology Agent view of remaining work.

    Live means a worker holds the rag_enrich lock and heartbeats. A lock with
    a stale updated_at (or a dispatch log with no lock) is not progress.
    """
    snap = snap or {}
    done = bool(snap.get("enrich_done"))
    lock_held = bool(snap.get("enrich_lock_held"))
    graph = str(snap.get("graph_status") or "")
    graph_ok = graph in ("ok", "skipped")
    scanned = int(snap.get("enrich_scanned") or 0)
    age = enrich_updated_age_sec(snap.get("enrich_updated_at"))
    try:
        lock_age = float(snap["enrich_lock_age_sec"]) if snap.get("enrich_lock_age_sec") is not None else None
    except (TypeError, ValueError):
        lock_age = None
    frozen = False
    if lock_held and not done:
        if age is not None and age > ENRICH_FROZEN_SEC:
            frozen = True
        elif age is None and lock_age is not None and lock_age > ENRICH_FROZEN_SEC:
            # Lock never heartbeated (old 4,000-row walker) — Repair must restart.
            frozen = True
    live = lock_held and not done and not frozen
    stalled = (not done) and graph_ok and not lock_held
    should_run = (not done) and graph_ok and (not lock_held or frozen)
    return {
        "done": done,
        "lock_held": lock_held,
        "graph_ok": graph_ok,
        "live": live,
        "stalled": stalled,
        "frozen": frozen,
        "scanned": scanned,
        "parse_total": int(snap.get("enrich_parse_total") or 0),
        "updated_age_sec": age,
        "should_run": should_run,
        "should_stand_down": done,
        "duty": (
            "Entity, Annotation, and Ontology Agents own enrichment: if Neo4j is ready "
            "and the rag_enrich lock is not held, start scanning parse results. "
            "If the lock is held but scanned/updated_at is frozen, release and restart. "
            "Do not sit idle at 1% because a start log said the lane was already running."
        ),
    }
