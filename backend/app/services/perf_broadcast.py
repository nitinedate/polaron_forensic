"""Cross-worker live performance plan (Redis).

The Performance agent publishes a plan; extract / RAG / OCR / inventory workers
read it at batch boundaries so adaptive knobs apply process-wide — not only on
the agent worker that called apply_dynamic_performance().
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

log = logging.getLogger("perf_broadcast")

PERF_PLAN_KEY = "forensic:perf_plan"
DEFAULT_MAX_AGE_SEC = 180.0


def _redis():
    import redis

    from app.config import get_settings

    return redis.from_url(get_settings().redis_url, socket_connect_timeout=3, socket_timeout=3)


def publish_live_plan(plan: dict[str, Any], *, ttl_sec: int = 300) -> bool:
    """Publish a live performance plan for all workers."""
    payload = dict(plan or {})
    payload["version"] = float(payload.get("version") or time.time())
    payload["published_at"] = time.time()
    try:
        client = _redis()
        client.set(PERF_PLAN_KEY, json.dumps(payload), ex=max(int(ttl_sec), 60))
        return True
    except Exception as exc:
        log.warning("publish_live_plan failed: %s", exc)
        return False


def get_live_perf_plan(*, max_age_sec: float = DEFAULT_MAX_AGE_SEC) -> dict[str, Any] | None:
    """Return the latest plan if fresh enough, else None."""
    try:
        client = _redis()
        raw = client.get(PERF_PLAN_KEY)
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        published = float(data.get("published_at") or data.get("version") or 0.0)
        if published and (time.time() - published) > max(float(max_age_sec), 30.0):
            return None
        return data
    except Exception as exc:
        log.debug("get_live_perf_plan failed: %s", exc)
        return None


def _int_from_plan(plan: dict[str, Any] | None, key: str, default: int, *, lo: int = 1, hi: int = 64) -> int:
    if not plan:
        return max(lo, min(int(default), hi))
    try:
        val = int(plan.get(key, default))
    except Exception:
        val = int(default)
    return max(lo, min(val, hi))


def live_rag_batch(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "rag_batch_size", default, lo=1, hi=48)


def live_rag_batch_cap(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "rag_batch_cap", default, lo=2, hi=64)


def live_ocr_batch(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "ocr_batch_limit", default, lo=2, hi=80)


def live_inventory_workers(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "inventory_workers", default, lo=1, hi=12)


def live_parse_workers(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "parse_workers", default, lo=1, hi=24)


def live_extract_mobile_workers(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "extract_mobile_workers", default, lo=1, hi=16)


def live_extract_disk_workers(default: int) -> int:
    plan = get_live_perf_plan()
    return _int_from_plan(plan, "extract_disk_workers", default, lo=1, hi=16)


def live_defer_background_rag() -> bool:
    plan = get_live_perf_plan()
    if not plan:
        return False
    return bool(plan.get("defer_background_rag") or plan.get("too_hot"))


def live_prefer_inventory_while_gpu_busy() -> bool:
    plan = get_live_perf_plan()
    if not plan:
        return True
    return bool(plan.get("prefer_inventory_while_gpu_busy", True))
