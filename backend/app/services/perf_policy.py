"""Deterministic performance policy for extract / RAG / OCR / inventory.

Sensors + Redis-published plan drive throughput. An optional fast LLM may
*confirm* the plan when the GPU is idle — it never overrides thermal abort
ceilings and never loads during OCR/RAG.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from app.config import get_settings

log = logging.getLogger("perf_policy")

_SAFE_PARALLEL_AFTER_BASELINE = frozenset(
    {"graph_agent", "inventory_agent", "parse_agent", "rag_enrich_agent"}
)


def _clamp_int(val: int, lo: int, hi: int) -> int:
    return max(lo, min(int(val), hi))


def _env_ceiling(key: str, fallback: int) -> int:
    """Hard max from process env / settings — adaptive plans must not exceed this."""
    raw = os.environ.get(key)
    if raw is not None and str(raw).strip() != "":
        try:
            return int(float(str(raw).strip()))
        except Exception:
            pass
    return int(fallback)


def _gpu_pace(temp_c: int | None, *, throttle_c: int, pause_c: int, abort_c: int) -> float:
    if temp_c is None:
        return 0.85
    if temp_c >= abort_c or temp_c >= pause_c:
        return 0.0
    if temp_c >= throttle_c:
        return 0.30
    if temp_c >= throttle_c - 3:
        return 0.55
    if temp_c <= throttle_c - 10:
        return 1.0
    span = max(throttle_c - 3 - (throttle_c - 10), 1)
    return 0.55 + 0.45 * (throttle_c - 3 - temp_c) / span


def build_live_plan(
    db=None,
    job_id: str | None = None,
    *,
    capacity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a cross-worker performance plan from host/GPU sensors and .env ceilings."""
    settings = get_settings()
    notes: list[str] = []
    policy_mode = str(getattr(settings, "perf_policy_mode", "throughput") or "throughput").strip().lower()
    sequential_requested = bool(getattr(settings, "pipeline_sequential_agents", False)) and policy_mode in {
        "sequential", "respect_env"
    }
    responsive_mode = sequential_requested

    # Host snapshot via capacity planner when available.
    snap = None
    profile = "unknown"
    try:
        from app.services.host_capacity import get_last_plan, probe_host

        last = get_last_plan()
        snap = (last.snapshot if last else None) or probe_host()
        profile = getattr(snap, "profile", None) or (last.profile if last else "unknown")
    except Exception as exc:
        notes.append(f"host_probe_failed:{exc}"[:120])

    gpu_temp = getattr(snap, "gpu_temp_c", None) if snap else None
    try:
        from app.services.gpu_thermal import get_gpu_stats

        stats = get_gpu_stats()
        if stats.available and stats.temperature_c is not None:
            gpu_temp = stats.temperature_c
    except Exception:
        pass

    try:
        from app.services.host_capacity import cpu_thermal_pace

        cpu_pace = float(cpu_thermal_pace())
    except Exception:
        cpu_pace = 1.0

    throttle_c = int(getattr(settings, "gpu_thermal_throttle_c", 68) or 68)
    pause_c = int(getattr(settings, "gpu_thermal_pause_c", 74) or 74)
    abort_c = int(getattr(settings, "gpu_thermal_abort_c", 78) or 78)
    gpu_pace = _gpu_pace(gpu_temp, throttle_c=throttle_c, pause_c=pause_c, abort_c=abort_c)
    too_hot = gpu_pace <= 0.0 or (gpu_temp is not None and gpu_temp >= abort_c)

    # Ceilings from .env (locked keys still act as hard maxes).
    rag_ceil = _env_ceiling("RAG_BATCH_SIZE", int(getattr(settings, "rag_batch_size", 8) or 8))
    rag_cap_ceil = _env_ceiling("RAG_BATCH_SIZE_CAP", int(getattr(settings, "rag_batch_size_cap", 16) or 16))
    # v1.5: .env is a ceiling, not a promise.  Use more GPU when RAG is the
    # exclusive heavy stage, but cap automatically for smaller cards.
    vram_total = int(getattr(snap, "gpu_vram_total_mb", 0) or 0) if snap else 0
    if vram_total >= 11000:
        hw_rag_ceiling = 24
    elif vram_total >= 8000:
        hw_rag_ceiling = 16
    elif vram_total >= 6000:
        hw_rag_ceiling = 10
    elif vram_total > 0:
        hw_rag_ceiling = 6
    else:
        hw_rag_ceiling = 4
    rag_ceil = max(1, min(rag_ceil, hw_rag_ceiling))
    rag_cap_ceil = max(rag_ceil, min(rag_cap_ceil, hw_rag_ceiling))
    ocr_ceil = _env_ceiling("OCR_BATCH_LIMIT", int(getattr(settings, "ocr_batch_limit", 28) or 28))
    parse_ceil = _env_ceiling("PARSE_WORKERS", int(getattr(settings, "parse_workers", 4) or 4))
    inv_ceil = _env_ceiling("AXIOM_INVENTORY_WORKERS", int(getattr(settings, "axiom_inventory_workers", 6) or 6))
    disk_ceil = _env_ceiling("EXTRACT_DISK_WORKERS", int(getattr(settings, "extract_disk_workers", 1) or 1))
    mobile_ceil = _env_ceiling("EXTRACT_MOBILE_WORKERS", int(getattr(settings, "extract_mobile_workers", 2) or 2))

    # Cool → use ceiling; warm → scale down (never above ceiling).
    pace = min(cpu_pace, gpu_pace if gpu_pace > 0 else 0.25)
    cpus = 8
    if snap is not None:
        cpus = max(int(getattr(snap, "cpu_logical", 0) or 0), 1)
    if cpus <= 1:
        cpus = max(int(os.cpu_count() or 8), 1)
    # Keep two cores for the database and the API. Cap at 16 so a single
    # disk image is not thrashed by one reader per core.
    io_hw = min(16, max(4, cpus - 2))
    if too_hot:
        rag_batch = 2
        ocr_batch = max(4, min(ocr_ceil, 8))
        parse_workers = 1
        inv_workers = 1
        mobile_workers = 2
        disk_workers = 2
        notes.append("thermal_abort_band — minimal batches")
    elif pace >= 0.95:
        rag_batch = rag_ceil
        ocr_batch = ocr_ceil
        parse_workers = parse_ceil
        inv_workers = inv_ceil
        mobile_workers = mobile_ceil
        disk_workers = disk_ceil
        notes.append("cool_path — full configured ceilings")
    elif pace >= 0.55:
        rag_batch = max(2, int(rag_ceil * 0.75))
        ocr_batch = max(8, int(ocr_ceil * 0.75))
        parse_workers = max(1, int(parse_ceil * 0.75))
        inv_workers = max(2, int(inv_ceil * 0.75))
        mobile_workers = max(4, int(mobile_ceil * 0.75))
        disk_workers = max(4, int(disk_ceil * 0.75))
        notes.append("warm_path — scaled batches")
    else:
        rag_batch = max(2, int(rag_ceil * 0.40))
        ocr_batch = max(4, int(ocr_ceil * 0.40))
        parse_workers = max(1, int(parse_ceil * 0.40))
        inv_workers = max(1, int(inv_ceil * 0.40))
        mobile_workers = max(2, int(mobile_ceil * 0.40))
        disk_workers = max(2, int(disk_ceil * 0.40))
        notes.append("hot_path — aggressive backoff")

    rag_batch = _clamp_int(rag_batch, 1, rag_ceil)
    ocr_batch = _clamp_int(ocr_batch, 2, ocr_ceil)
    parse_workers = _clamp_int(parse_workers, 1, parse_ceil)
    inv_workers = _clamp_int(inv_workers, 1, inv_ceil)
    mobile_workers = _clamp_int(mobile_workers, 1, min(mobile_ceil, io_hw))
    disk_workers = _clamp_int(disk_workers, 1, min(disk_ceil, io_hw))
    rag_cap = _clamp_int(max(rag_batch, rag_cap_ceil), rag_batch, rag_cap_ceil)

    # Baseline used to unlock graph/inventory/parse in parallel with RAG.  On a
    # single workstation that maximizes aggregate throughput at the cost of API,
    # browser, PostgreSQL and disk responsiveness.  Responsive/sequential mode
    # keeps one pipeline group active at a time.
    _CPU_SAFE_WHEN_HOT = frozenset({"inventory_agent", "parse_agent", "graph_agent"})
    chunk_n = 0
    if db is not None and job_id:
        try:
            from app.db.sql_helpers import fetchone

            row = fetchone(
                db,
                "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
                {"jid": job_id},
            )
            chunk_n = int((row or {}).get("c") or 0)
        except Exception:
            chunk_n = 0

    allow_parallel = False
    safe_parallel: list[str] = []
    if responsive_mode or sequential_requested:
        notes.append("responsive sequential policy — no post-baseline parallel DB/IO agents")
    elif chunk_n >= 500:
        if too_hot:
            allow_parallel = True
            safe_parallel = sorted(_CPU_SAFE_WHEN_HOT)
            notes.append("thermal — prefer inventory/parse/graph while GPU cools")
            inv_workers = max(inv_workers, min(inv_ceil, 3))
        elif pace >= 0.55:
            allow_parallel = True
            safe_parallel = sorted(_SAFE_PARALLEL_AFTER_BASELINE)
        else:
            allow_parallel = True
            safe_parallel = sorted(_CPU_SAFE_WHEN_HOT)
            notes.append("warm GPU — CPU-safe parallel only")

    gpu_busy = False
    try:
        from app.services.job_locks import gpu_heavy_slot_held

        gpu_busy = bool(gpu_heavy_slot_held())
    except Exception:
        pass

    plan: dict[str, Any] = {
        "profile": profile,
        "gpu_temp_c": gpu_temp,
        "gpu_vram_total_mb": vram_total,
        "hardware_rag_ceiling": hw_rag_ceiling,
        "cpu_pace": round(cpu_pace, 3),
        "gpu_pace": round(gpu_pace, 3),
        "pace": round(pace, 3),
        "too_hot": too_hot,
        "defer_background_rag": too_hot,
        "prefer_inventory_while_gpu_busy": False if (responsive_mode or sequential_requested) else True,
        "gpu_busy": gpu_busy,
        "allow_parallel": allow_parallel,
        "safe_parallel_agents": safe_parallel,
        "rag_batch_size": rag_batch,
        "rag_batch_cap": rag_cap,
        "ocr_batch_limit": ocr_batch,
        "parse_workers": parse_workers,
        "inventory_workers": inv_workers,
        "extract_disk_workers": disk_workers,
        "extract_mobile_workers": mobile_workers,
        "baseline_chunks": chunk_n,
        "capacity": {
            k: (capacity or {}).get(k)
            for k in ("profile", "parse_workers", "rag_batch", "cpu_pace")
            if capacity and k in capacity
        }
        or None,
        "notes": notes,
        "llm_confirmed": False,
        "policy_mode": policy_mode,
    }
    return plan


def confirm_plan_with_llm(plan: dict[str, Any]) -> dict[str, Any]:
    """Optional fast-LLM confirmation when GPU is idle. Never raises thermal ceilings."""
    settings = get_settings()
    if not bool(getattr(settings, "perf_llm_advisor", False)):
        return plan
    try:
        from app.services.job_locks import gpu_heavy_slot_held

        if gpu_heavy_slot_held():
            plan = dict(plan)
            plan["llm_confirmed"] = False
            plan.setdefault("notes", []).append("llm_advisor_skipped_gpu_busy")
            return plan
    except Exception:
        pass
    if plan.get("too_hot"):
        plan = dict(plan)
        plan["llm_confirmed"] = False
        plan.setdefault("notes", []).append("llm_advisor_skipped_thermal")
        return plan

    model = getattr(settings, "llm_fast_model", None) or "qwen3.5:9b"
    prompt = (
        "You are a laptop-safe forensic pipeline performance advisor. "
        "Given this JSON plan, reply with ONLY a JSON object containing optional "
        "integer overrides for: rag_batch_size, ocr_batch_limit, inventory_workers, "
        "extract_mobile_workers, parse_workers. Never increase values above the input. "
        "Prefer keeping cool-path throughput; reduce further if temperatures look risky.\n"
        f"PLAN:\n{json.dumps({k: plan.get(k) for k in ('profile','gpu_temp_c','pace','rag_batch_size','ocr_batch_limit','inventory_workers','extract_mobile_workers','parse_workers','too_hot','notes')}, indent=2)}"
    )
    try:
        from app.services.model_router import generate_text

        raw = generate_text(prompt, model=model, temperature=0.1)
        text = (raw or "").strip()
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("no json object in advisor reply")
        overrides = json.loads(text[start : end + 1])
        out = dict(plan)
        for key in ("rag_batch_size", "ocr_batch_limit", "inventory_workers", "extract_mobile_workers", "parse_workers"):
            if key not in overrides:
                continue
            try:
                proposed = int(overrides[key])
            except Exception:
                continue
            current = int(out.get(key) or proposed)
            # Advisor may only decrease.
            out[key] = max(1, min(proposed, current))
        out["llm_confirmed"] = True
        out.setdefault("notes", []).append(f"llm_advisor:{model}")
        return out
    except Exception as exc:
        log.info("perf LLM advisor skipped: %s", exc)
        plan = dict(plan)
        plan["llm_confirmed"] = False
        plan.setdefault("notes", []).append(f"llm_advisor_error:{type(exc).__name__}")
        return plan
