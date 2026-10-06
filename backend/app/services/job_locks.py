"""Redis locks for long-running per-job Celery work (parse drain, inventory).

Also provides adaptive cross-worker resource slots so one physical host can run
forensic work at high throughput without CPU/GPU thermal or memory contention:
- GPU heavy (RAG / OCR) — live capacity + host-level distributed admission
- CPU heavy (extract / finalize materialize) — multi-slot adaptive admission

GPU and CPU lanes are independent: extract/parse must not wait for a GPU slot,
and RAG/OCR must not wait for extract. Per-job extract_lock is not the global
CPU-heavy slot. Local slot keys stay at their configured maximum so an in-flight
lease remains visible even if the live thermal capacity shrinks.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

log = logging.getLogger("job_locks")

# Inventory must heartbeat frequently; a dead worker must not block for hours.
# Parse uses the same short TTL + heartbeat pattern (was 7200s → post-OOM stalls).
DEFAULT_PARSE_LOCK_TTL_SEC = 180
DEFAULT_INVENTORY_LOCK_TTL_SEC = 300
DEFAULT_OCR_LOCK_TTL_SEC = 180
DEFAULT_EXTRACT_LOCK_TTL_SEC = 300

# Cross-process exclusive GPU slot (RAG / OCR). Long TTL + background heartbeat.
# Keys are namespaced by AETHERIS_SERVICE so disk/mobile/vuln never share a lane.
GPU_HEAVY_LOCK_KEY = "forensic:gpu_heavy_lock"
DEFAULT_GPU_HEAVY_TTL_SEC = 600
DEFAULT_GPU_HEAVY_WAIT_SEC = 0.0

# Cross-process CPU-heavy slot (extract / finalize). Independent of GPU.
CPU_HEAVY_LOCK_KEY = "forensic:cpu_heavy_lock"
DEFAULT_CPU_HEAVY_TTL_SEC = 600
DEFAULT_CPU_HEAVY_WAIT_SEC = 0.0
# After docker recreate the holder dies but Redis TTL can linger (up to 10 min).
STALE_HEAVY_HEARTBEAT_SEC = 90.0

# Current heavy-slot ownership is thread/context-local.  Celery prefork normally
# runs one task per process, but FastAPI/solo/threaded execution can overlap in a
# single process. Module-global tokens let one task overwrite another task's
# heartbeat/release state, so keep an independent lease stack per thread.
_heavy_tls = threading.local()


class GpuHeavySlotTimeout(Exception):
    """Could not acquire exclusive GPU slot — caller must retry later (fail-closed)."""


class CpuHeavySlotTimeout(Exception):
    """Could not acquire exclusive CPU-heavy slot — caller must retry later."""


class ExtractSlotAlreadyHeld(Exception):
    """This job already owns a live CPU extract slot in another worker."""


def parse_task_in_flight(db, job_id: str, *, idle_sec: float = 180.0) -> bool:
    """True when a live parse lock exists; force-release stale locks if the job is idle."""
    if not job_lock_held("parse", job_id):
        return False
    try:
        from app.db.sql_helpers import fetchone

        row = fetchone(
            db,
            "SELECT extract(epoch FROM (NOW() - updated_at)) AS age FROM jobs WHERE id=:id",
            {"id": job_id},
        )
        age = float(row["age"]) if row and row.get("age") is not None else 0.0
        if age > idle_sec:
            log.warning("Stale parse lock for job=%s (idle %.0fs) — force releasing", job_id, age)
            force_release_job_lock("parse", job_id)
            return False
    except Exception as exc:
        log.debug("parse_task_in_flight check failed job=%s: %s", job_id, exc)
    return job_lock_held("parse", job_id)


def extract_celery_work_active(job_id: str, *, timeout: float = 1.5) -> bool | None:
    """True when a live extract Celery task matches this job. None if inspect failed."""
    try:
        from app.celery_app import celery

        inspect = celery.control.inspect(timeout=timeout)
        active = inspect.active() or {}
        reserved = inspect.reserved() or {}
    except Exception as exc:
        log.debug("extract celery inspect failed job=%s: %s", job_id, exc)
        return None
    needle = str(job_id)
    for pool in (active, reserved):
        for tasks in pool.values():
            for task in tasks or []:
                info = task.get("request") if isinstance(task.get("request"), dict) else task
                name = str(info.get("name") or task.get("name") or task.get("type") or "")
                blob = " ".join(
                    str(info.get(key) or task.get(key) or "")
                    for key in ("args", "kwargs", "id")
                )
                if needle in blob and "build_extracted" in name:
                    return True
    return False


def _extract_heartbeat_age_sec(db, job_id: str) -> float | None:
    """Seconds since the last real extract/virtual_disk heartbeat. None if none."""
    try:
        from app.db.sql_helpers import fetchone

        log_row = fetchone(
            db,
            """SELECT extract(epoch FROM (NOW() - timestamp)) AS age
               FROM disk_build_logs
               WHERE job_id=:id AND stage IN ('extract', 'virtual_disk')
                 AND message NOT LIKE '%duplicate resume%'
                 AND message NOT LIKE '%already running%'
                 AND message NOT LIKE '%awaiting_segments%'
                 AND message NOT LIKE '%No disk image%'
                 AND message NOT LIKE '%chassis busy%'
                 AND message NOT LIKE '%Extract deferred%'
               ORDER BY timestamp DESC LIMIT 1""",
            {"id": job_id},
        )
        if log_row and log_row.get("age") is not None:
            return float(log_row["age"])
    except Exception as exc:
        log.debug("extract heartbeat age failed job=%s: %s", job_id, exc)
    return None


def extract_task_in_flight(db, job_id: str, *, idle_sec: float = 180.0) -> bool:
    """True when this job already has a live extract worker.

    Duplicate resume tasks remount the E01 and re-walk the filesystem while
    MinIO upload is still running — that looks like an extract loop.

    Do not use jobs.updated_at: huddle stamps it every 30s, so a dead worker
    after restart would look live forever and hang extraction at 1%.
    """
    try:
        if cpu_heavy_slot_owned_by_job(job_id):
            return True
    except Exception:
        pass
    if not job_lock_held("extract", job_id):
        return False
    celery_active = extract_celery_work_active(job_id)
    if celery_active is True:
        return True
    lock_age = job_lock_age_sec("extract", job_id)
    log_age = _extract_heartbeat_age_sec(db, job_id)
    if celery_active is False:
        # Inspect flakes on busy workers. A fresh extract/virtual_disk heartbeat
        # means the copier is still alive — do not steal its lock.
        if log_age is not None and log_age < idle_sec:
            return True
        if log_age is None and lock_age is not None and lock_age < 60.0:
            return True
        log.warning(
            "Stale extract lock for job=%s (celery idle, extract age %s, lock age %s) — force releasing",
            job_id,
            f"{log_age:.0f}s" if log_age is not None else "none",
            f"{lock_age:.0f}s" if lock_age is not None else "none",
        )
        force_release_job_lock("extract", job_id)
        return False
    age = log_age if log_age is not None else (lock_age if lock_age is not None else idle_sec + 1)
    if age > idle_sec:
        log.warning("Stale extract lock for job=%s (extract idle %.0fs) — force releasing", job_id, age)
        force_release_job_lock("extract", job_id)
        return False
    return job_lock_held("extract", job_id)


def extract_is_live(db, job_id: str, row: dict | None = None, *, idle_sec: float = 90.0) -> bool:
    """True when extract is actively heartbeating — do not queue another resume.

    Do not use jobs.updated_at alone: dispatch stamps it before the worker
    starts, which would make the first extract look like a duplicate.
    """
    del row  # reserved for callers; heartbeat logs/lock are authoritative
    if extract_task_in_flight(db, job_id, idle_sec=max(idle_sec, 180.0)):
        return True
    try:
        age = _extract_heartbeat_age_sec(db, job_id)
        if age is not None and age < idle_sec:
            return True
    except Exception as exc:
        log.debug("extract_is_live check failed job=%s: %s", job_id, exc)
    return False


@contextmanager
def extract_job_lock(job_id: str, *, ttl_sec: int = DEFAULT_EXTRACT_LOCK_TTL_SEC) -> Iterator[bool]:
    """One extract worker per job — stacked resumes remount and re-enumerate."""
    with job_lock("extract", job_id, ttl_sec=ttl_sec) as acquired:
        yield acquired


def _redis_client():
    import redis

    from app.config import get_settings

    # Longer timeouts than before — short 2s timeouts caused silent heartbeat
    # failures, lock TTL expiry, and dual OCR+RAG (thermal shutdown).
    return redis.from_url(get_settings().redis_url, socket_connect_timeout=5, socket_timeout=5)


def job_lock_key(kind: str, job_id: str) -> str:
    return f"forensic:{kind}_lock:{job_id}"


def job_lock_held(kind: str, job_id: str) -> bool:
    """True when another worker holds the lock for this job/kind."""
    try:
        client = _redis_client()
        return bool(client.exists(job_lock_key(kind, job_id)))
    except Exception as exc:
        log.debug("job_lock_held check failed kind=%s job=%s: %s", kind, job_id, exc)
        return False


_owned_job_locks: dict[tuple[str, str], str] = {}
_owned_job_locks_guard = threading.Lock()


def _lock_started_epoch(raw: Any) -> float | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    text = str(raw)
    try:
        return float(text)
    except ValueError:
        pass
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    try:
        return float(data.get("started") or 0) or None
    except (TypeError, ValueError):
        return None


def _lock_token(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    text = str(raw)
    try:
        data = json.loads(text)
    except Exception:
        return ""
    if isinstance(data, dict):
        return str(data.get("token") or "")
    return ""


def job_lock_age_sec(kind: str, job_id: str) -> float | None:
    """Seconds since the lock was acquired or last refreshed. None if absent."""
    try:
        client = _redis_client()
        started = _lock_started_epoch(client.get(job_lock_key(kind, job_id)))
        if started is None:
            return None
        return max(0.0, time.time() - started)
    except Exception as exc:
        log.debug("job_lock_age_sec failed kind=%s job=%s: %s", kind, job_id, exc)
        return None


def force_release_job_lock(kind: str, job_id: str) -> bool:
    """Delete a stale lock so the supervisor can re-queue work."""
    try:
        client = _redis_client()
        return bool(client.delete(job_lock_key(kind, job_id)))
    except Exception as exc:
        log.debug("force_release_job_lock failed kind=%s job=%s: %s", kind, job_id, exc)
        return False


def clear_all_ocr_job_locks() -> int:
    """Drop OCR job locks left in Redis after this worker was recreated."""
    try:
        client = _redis_client()
        n = 0
        for key in client.scan_iter("forensic:ocr_lock:*", count=200):
            client.delete(key)
            n += 1
        if n:
            log.warning("Cleared %s stale OCR lock(s) on worker start", n)
        return n
    except Exception as extra:
        log.debug("clear_all_ocr_job_locks failed: %s", extra)
        return 0


def ocr_celery_work_active(
    job_id: str,
    *,
    task_name: str,
    bucket_id: int | None = None,
    timeout: float = 1.0,
) -> bool:
    """True when a live Celery OCR task still matches this lock."""
    try:
        from app.celery_app import celery

        inspect = celery.control.inspect(timeout=timeout)
        active = inspect.active() or {}
    except Exception as exc:
        log.debug("ocr celery inspect failed job=%s: %s", job_id, exc)
        return True
    needle = str(job_id)
    bucket_needle = None if bucket_id is None else str(bucket_id)
    for tasks in active.values():
        for task in tasks or []:
            info = task.get("request") if isinstance(task.get("request"), dict) else task
            name = str(info.get("name") or task.get("name") or task.get("type") or "")
            if name != task_name:
                continue
            blob = " ".join(
                str(info.get(key) or task.get(key) or "")
                for key in ("args", "kwargs")
            )
            if needle not in blob:
                continue
            if bucket_needle is None:
                return True
            if bucket_needle in blob:
                return True
    return False


def reclaim_stale_ocr_lock(job_id: str, *, bucket_id: int | None = None) -> bool:
    """Drop an OCR Redis lock left behind after a worker recreate."""
    lock_id = f"{job_id}:bucket:{bucket_id}" if bucket_id is not None else job_id
    if not job_lock_held("ocr", lock_id):
        return False
    task_name = (
        "app.tasks.ocr_bucket_task" if bucket_id is not None else "app.tasks.ocr_drain_task"
    )
    if ocr_celery_work_active(job_id, task_name=task_name, bucket_id=bucket_id):
        return False
    log.warning("Reclaiming stale OCR lock job=%s bucket=%s", job_id, bucket_id)
    return force_release_job_lock("ocr", lock_id)


def reclaim_stale_enrich_lock(job_id: str) -> bool:
    """Drop a rag_enrich lock when no Celery worker is actually scanning."""
    if not job_lock_held("rag_enrich", job_id):
        return False
    if ocr_celery_work_active(job_id, task_name="app.tasks.rag_enrich_task"):
        return False
    log.warning("Reclaiming stale rag_enrich lock job=%s", job_id)
    return force_release_job_lock("rag_enrich", job_id)


def refresh_job_lock(kind: str, job_id: str, *, ttl_sec: int | None = None) -> None:
    """Extend lock TTL while this process still owns the lock."""
    if ttl_sec is None:
        ttl_sec = (
            DEFAULT_INVENTORY_LOCK_TTL_SEC
            if kind == "inventory"
            else DEFAULT_OCR_LOCK_TTL_SEC
            if kind == "ocr"
            else DEFAULT_EXTRACT_LOCK_TTL_SEC
            if kind == "extract"
            else DEFAULT_PARSE_LOCK_TTL_SEC
        )
    with _owned_job_locks_guard:
        token = _owned_job_locks.get((kind, job_id))
    if not token:
        return
    try:
        client = _redis_client()
        _atomic_refresh_job_lock(client, job_lock_key(kind, job_id), token, max(int(ttl_sec), 60))
    except Exception:
        pass


def _atomic_refresh_job_lock(client, key: str, token: str, ttl: int) -> bool:
    script = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, obj = pcall(cjson.decode, raw)
if not ok or tostring(obj['token'] or '') ~= ARGV[1] then return 0 end
obj['started'] = tonumber(ARGV[2])
redis.call('SET', KEYS[1], cjson.encode(obj), 'EX', tonumber(ARGV[3]))
return 1
"""
    try:
        return bool(client.eval(script, 1, key, token, time.time(), int(ttl)))
    except AttributeError:
        raw = client.get(key)
        if _lock_token(raw) != token:
            return False
        started = _lock_started_epoch(raw) or time.time()
        client.set(key, json.dumps({"token": token, "started": started}), ex=int(ttl))
        return True


def _atomic_release_job_lock(client, key: str, token: str) -> bool:
    """Delete only the lock this worker acquired. A blind DEL drops the live owner."""
    script = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, obj = pcall(cjson.decode, raw)
if not ok or tostring(obj['token'] or '') ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"""
    try:
        return bool(client.eval(script, 1, key, token))
    except AttributeError:
        if _lock_token(client.get(key)) != token:
            return False
        return bool(client.delete(key))


@contextmanager
def job_lock(kind: str, job_id: str, *, ttl_sec: int | None = None) -> Iterator[bool]:
    """Acquire a Redis lock. Yields True when acquired."""
    if ttl_sec is None:
        ttl_sec = (
            DEFAULT_INVENTORY_LOCK_TTL_SEC
            if kind == "inventory"
            else DEFAULT_OCR_LOCK_TTL_SEC
            if kind == "ocr"
            else DEFAULT_EXTRACT_LOCK_TTL_SEC
            if kind == "extract"
            else DEFAULT_PARSE_LOCK_TTL_SEC
        )
    acquired = False
    client = None
    token = uuid.uuid4().hex
    key = job_lock_key(kind, job_id)
    try:
        client = _redis_client()
        acquired = bool(
            client.set(
                key,
                json.dumps({"token": token, "started": time.time()}),
                nx=True,
                ex=max(int(ttl_sec), 60),
            )
        )
    except Exception as exc:
        log.warning("%s lock unavailable job=%s (%s) — proceeding without lock", kind, job_id, exc)
        acquired = True
        client = None
    if acquired:
        with _owned_job_locks_guard:
            _owned_job_locks[(kind, job_id)] = token
    try:
        yield acquired
    finally:
        with _owned_job_locks_guard:
            if _owned_job_locks.get((kind, job_id)) == token:
                _owned_job_locks.pop((kind, job_id), None)
        if acquired and client is not None:
            try:
                _atomic_release_job_lock(client, key, token)
            except Exception:
                pass


@contextmanager
def parse_job_lock(job_id: str, *, ttl_sec: int = DEFAULT_PARSE_LOCK_TTL_SEC) -> Iterator[bool]:
    """Acquire a Redis lock for background parse drain. Yields True when acquired."""
    with job_lock("parse", job_id, ttl_sec=ttl_sec) as acquired:
        yield acquired


@contextmanager
def inventory_job_lock(
    job_id: str, *, ttl_sec: int = DEFAULT_INVENTORY_LOCK_TTL_SEC
) -> Iterator[bool]:
    """Acquire a Redis lock for artifact inventory. Yields True when acquired."""
    with job_lock("inventory", job_id, ttl_sec=ttl_sec) as acquired:
        yield acquired


@contextmanager
def ocr_job_lock(job_id: str, *, ttl_sec: int = DEFAULT_OCR_LOCK_TTL_SEC) -> Iterator[bool]:
    """Per-shard OCR lock. Use ``{job_id}:bucket:{n}`` so Repair can run several CPU workers."""
    with job_lock("ocr", job_id, ttl_sec=ttl_sec) as acquired:
        yield acquired


def _service_lane_prefix() -> str:
    """Redis key prefix so disk, mobile, and vuln never steal each other's slots."""
    try:
        from app.service_identity import current_service

        svc = current_service()
    except Exception:
        svc = "forensic"
    if svc == "mobile-android":
        return "mobile-android"
    if svc == "mobile-ios":
        return "mobile-ios"
    if svc == "mobile-extract":
        return "mobile"
    if svc == "vuln":
        return "vuln"
    return "forensic"


def gpu_heavy_lock_key() -> str:
    return f"{_service_lane_prefix()}:gpu_heavy_lock"


def cpu_heavy_lock_key() -> str:
    return f"{_service_lane_prefix()}:cpu_heavy_lock"


def _gpu_heavy_configured_slots() -> int:
    try:
        from app.config import get_settings
        from app.services.forensic_serial_policy import serial_enabled

        if serial_enabled():
            return 1
        return max(int(getattr(get_settings(), "gpu_heavy_max_concurrent", 1) or 1), 1)
    except Exception:
        return 1


def describe_gpu_lane_state() -> str:
    """Human-readable reason the GPU lane could not be taken (V45.1).

    Distinguishes the three cases that previously all read "timed out after 0s":
    held by another GPU task (who / how long), thermal pause (capacity 0), or a
    stale lease that is about to be reclaimed.
    """
    try:
        cap = _gpu_heavy_max_slots()
    except Exception:
        cap = -1
    parts: list[str] = []
    try:
        for key in _gpu_slot_keys():
            holder = _lock_held(key)
            if not holder:
                continue
            age = time.time() - float(holder.get("started") or time.time())
            stale = heavy_holder_is_stale(holder)
            parts.append(
                f"lane held by {holder.get('reason') or '?'} (pid {holder.get('pid') or '?'}, "
                f"{age:.0f}s{', STALE — will be reclaimed' if stale else ''})"
            )
    except Exception:
        pass
    if cap == 0:
        temp = None
        try:
            from app.services.adaptive_semaphore import _host_snapshot

            temp = getattr(_host_snapshot(), "gpu_temp_c", None)
        except Exception:
            pass
        parts.append(
            f"GPU admission paused by thermal guard (capacity 0"
            + (f", temp {int(temp)}°C ≥ GPU_THERMAL_PAUSE_C" if temp is not None else "")
            + ")"
        )
    if not parts:
        parts.append(f"no holder visible, capacity={cap} — likely released between checks; retry will succeed")
    return "; ".join(parts)


def _gpu_heavy_max_slots() -> int:
    """Live GPU admission capacity (may be zero at the thermal pause point)."""
    configured = _gpu_heavy_configured_slots()
    try:
        from app.services.adaptive_semaphore import resource_capacity

        return max(min(configured, int(resource_capacity("gpu", requested=configured))), 0)
    except Exception:
        return 1


def _cpu_heavy_configured_slots() -> int:
    try:
        from app.config import get_settings

        return max(int(getattr(get_settings(), "max_concurrent_disk_builds", 2) or 2), 1)
    except Exception:
        return 1


def _cpu_heavy_max_slots() -> int:
    """Live CPU-heavy admission capacity."""
    configured = _cpu_heavy_configured_slots()
    try:
        from app.services.adaptive_semaphore import resource_capacity

        return max(min(configured, int(resource_capacity("cpu_heavy", requested=configured))), 1)
    except Exception:
        return 1


def _lock_held(key: str) -> dict | None:
    try:
        client = _redis_client()
        raw = client.get(key)
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"raw": str(raw)}
    except Exception:
        return None


def _gpu_slot_keys() -> list[str]:
    # Enumerate the configured namespace, not the live thermal capacity.  If
    # capacity shrinks while slot :1 is active we must still see/refresh it.
    n = _gpu_heavy_configured_slots()
    base = gpu_heavy_lock_key()
    keys = [base]
    for i in range(1, max(n, 1)):
        keys.append(f"{base}:{i}")
    return keys


def _cpu_slot_keys() -> list[str]:
    # Same rule as GPU: never hide an in-flight higher-index slot.
    n = _cpu_heavy_configured_slots()
    base = cpu_heavy_lock_key()
    keys = [base]
    for i in range(1, max(n, 1)):
        keys.append(f"{base}:{i}")
    return keys


def gpu_heavy_slot_held() -> dict | None:
    """Return one occupied GPU slot, or None if every slot is free."""
    for key in _gpu_slot_keys():
        held = _lock_held(key)
        if held:
            return held
    return None


def cpu_heavy_slot_held() -> dict | None:
    """Return one current CPU-heavy holder, or None when all slots are free."""
    for key in _cpu_slot_keys():
        held = _lock_held(key)
        if held:
            return held
    return None


def inspect_process_lanes(job_id: str | None = None) -> dict[str, Any]:
    """What every action agent consults before asking to start.

    GPU OCR and RAG may share a card only when both configured capacity and
    live thermal/VRAM admission leave a free slot. CPU-heavy extraction uses
    multiple slots when the host has headroom. A per-job extract_lock does not
    occupy the host CPU-heavy semaphore, and a busy GPU does not block parse.
    """
    holders: list[dict[str, Any]] = []
    used = 0
    try:
        client = _redis_client()
    except Exception:
        client = None
    for key in _gpu_slot_keys():
        holder = _lock_held(key)
        if holder and client is not None and _reclaim_stale_heavy_lock(client, key, holder, label="GPU"):
            holder = None
        if holder:
            used += 1
            holders.append(
                {
                    "reason": str(holder.get("reason") or ""),
                    "pid": holder.get("pid"),
                }
            )
    total = _gpu_heavy_max_slots()
    free = max(total - used, 0)
    host_gpu: dict[str, Any] = {}
    try:
        from app.services.adaptive_semaphore import semaphore_snapshot

        host_gpu = semaphore_snapshot("gpu", requested_limit=_gpu_heavy_configured_slots())
        if bool(host_gpu.get("enabled", True)) and not host_gpu.get("error"):
            total = min(total, int(host_gpu.get("capacity") or 0))
            used = max(used, int(host_gpu.get("used") or 0))
            free = min(free, int(host_gpu.get("free") or 0))
    except Exception:
        host_gpu = {}

    cpu_holders: list[dict[str, Any]] = []
    cpu_used = 0
    for key in _cpu_slot_keys():
        holder = _lock_held(key)
        if holder and client is not None and _reclaim_stale_heavy_lock(client, key, holder, label="CPU"):
            holder = None
        if holder:
            cpu_used += 1
            cpu_holders.append({"reason": str(holder.get("reason") or ""), "pid": holder.get("pid")})
    cpu_total = max(_cpu_heavy_max_slots(), 1)
    cpu_free = max(cpu_total - cpu_used, 0)
    host_cpu: dict[str, Any] = {}
    try:
        from app.services.adaptive_semaphore import semaphore_snapshot

        host_cpu = semaphore_snapshot("cpu_heavy", requested_limit=_cpu_heavy_configured_slots())
        if bool(host_cpu.get("enabled", True)) and not host_cpu.get("error"):
            cpu_total = max(min(cpu_total, int(host_cpu.get("capacity") or 1)), 1)
            cpu_used = max(cpu_used, int(host_cpu.get("used") or 0))
            cpu_free = min(cpu_free, int(host_cpu.get("free") or 0))
    except Exception:
        host_cpu = {}
    cpu = cpu_holders[0] if cpu_holders else None
    jid = (job_id or "").strip()
    extract_lock = bool(jid and job_lock_held("extract", jid))
    parse_lock = bool(jid and job_lock_held("parse", jid))
    ocr_lock = bool(jid and job_lock_held("ocr", jid))
    inventory_lock = bool(jid and job_lock_held("inventory", jid))
    return {
        "gpu_slots_total": total,
        "gpu_slots_used": used,
        "gpu_slots_free": free,
        "gpu_holders": holders,
        "host_gpu_semaphore": host_gpu,
        "cpu_heavy_reason": (cpu or {}).get("reason") if cpu else None,
        "cpu_slots_total": cpu_total,
        "cpu_slots_used": cpu_used,
        "cpu_slots_free": cpu_free,
        "cpu_holders": cpu_holders,
        "host_cpu_semaphore": host_cpu,
        "extract_lock": extract_lock,
        "parse_lock": parse_lock,
        "ocr_lock": ocr_lock,
        "inventory_lock": inventory_lock,
        "lane_namespace": _service_lane_prefix(),
        "can_start_gpu": free > 0,
        "can_share_gpu": total > 1 and free > 0,
        # Per-job extract_lock is handled by extract_task_in_flight — do not
        # treat it as the global CPU-heavy slot or extract self-blocks.
        "can_start_cpu_heavy": cpu_free > 0,
    }


def _holder_heartbeat_age_sec(holder: dict | None) -> float:
    if not holder:
        return 9999.0
    try:
        hb = float(holder.get("heartbeat") or holder.get("started") or 0.0)
        return time.time() - hb if hb else 9999.0
    except Exception:
        return 9999.0


def _container_boot_id() -> str:
    host = ""
    try:
        import socket

        host = socket.gethostname()
    except Exception:
        host = ""
    try:
        return f"{host}:{int(os.stat('/proc/1').st_ctime)}"
    except Exception:
        return host


def heavy_holder_is_stale(holder: dict | None, *, stale_sec: float = STALE_HEAVY_HEARTBEAT_SEC) -> bool:
    """True when a Redis heavy-slot lock outlived its worker (recreate / crash).

    PID reuse after docker recreate must not keep the lock: a new celery
    process can inherit the same pid number while the heartbeat is frozen.
    """
    if not holder:
        return True
    if _holder_heartbeat_age_sec(holder) > float(stale_sec):
        return True
    boot = str(holder.get("boot_id") or "")
    me = _container_boot_id()
    if boot and me and boot != me and boot.split(":", 1)[0] == me.split(":", 1)[0]:
        return True
    return False


def force_release_cpu_heavy_slot() -> bool:
    """Delete stale CPU-heavy slots so extract can resume after worker restart."""
    try:
        client = _redis_client()
        removed = 0
        for key in _cpu_slot_keys():
            holder = _lock_held(key)
            if holder is None or heavy_holder_is_stale(holder):
                removed += int(bool(client.delete(key)))
        return bool(removed)
    except Exception as exc:
        log.debug("force_release_cpu_heavy_slot failed: %s", exc)
        return False


def _reclaim_stale_heavy_lock(client, key: str, holder: dict | None, *, label: str) -> bool:
    if not heavy_holder_is_stale(holder):
        return False
    age = _holder_heartbeat_age_sec(holder)
    log.warning(
        "Reclaiming stale %s heavy slot (was %s pid=%s, idle %.0fs)",
        label,
        (holder or {}).get("reason") or "?",
        (holder or {}).get("pid") or "?",
        age,
    )
    try:
        client.delete(key)
        return True
    except Exception:
        return False


def _heavy_stack(kind: str) -> list[Any]:
    attr = f"{kind}_heavy_leases"
    stack = getattr(_heavy_tls, attr, None)
    if stack is None:
        stack = []
        setattr(_heavy_tls, attr, stack)
    return stack


def _atomic_refresh_heavy(client, key: str, token: str, ttl: int, heartbeat: float) -> bool:
    script = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, obj = pcall(cjson.decode, raw)
if not ok or tostring(obj['token'] or '') ~= ARGV[1] then return 0 end
obj['heartbeat'] = tonumber(ARGV[3])
redis.call('SET', KEYS[1], cjson.encode(obj), 'EX', tonumber(ARGV[2]))
return 1
"""
    try:
        return bool(client.eval(script, 1, key, token, int(ttl), float(heartbeat)))
    except AttributeError:
        raw = client.get(key)
        if not raw:
            return False
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw)
        if str(data.get("token") or "") != token:
            return False
        data["heartbeat"] = float(heartbeat)
        client.set(key, json.dumps(data), ex=int(ttl))
        return True


def _atomic_release_heavy(client, key: str, token: str) -> bool:
    script = r"""
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local ok, obj = pcall(cjson.decode, raw)
if not ok or tostring(obj['token'] or '') ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"""
    try:
        return bool(client.eval(script, 1, key, token))
    except AttributeError:
        raw = client.get(key)
        if not raw:
            return False
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw)
        if str(data.get("token") or "") != token:
            return False
        return bool(client.delete(key))


class _LocalHeavyLease:
    def __init__(self, *, kind: str, key: str, token: str, reason: str, ttl: int, client: Any):
        self.kind = kind
        self.key = key
        self.token = token
        self.reason = reason
        self.ttl = ttl
        self.client = client
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        self.released = False

    def refresh(self, ttl_sec: int | None = None) -> bool:
        if self.released:
            return False
        ttl = max(int(ttl_sec or self.ttl), 120)
        try:
            return _atomic_refresh_heavy(self.client, self.key, self.token, ttl, time.time())
        except Exception as exc:
            log.warning("refresh_%s_heavy_slot failed: %s", self.kind, exc)
            return False

    def start_heartbeat(self) -> None:
        interval = max(min(self.ttl / 3.0, 60.0), 15.0)
        retry_delay = min(5.0, max(1.0, interval / 3.0))

        def _loop() -> None:
            while not self.stop.wait(interval):
                while not self.stop.is_set():
                    try:
                        if not _atomic_refresh_heavy(
                            self.client, self.key, self.token, self.ttl, time.time()
                        ):
                            return
                        break
                    except Exception as exc:
                        log.warning("%s heavy heartbeat transient failure: %s", self.kind, exc)
                        if self.stop.wait(retry_delay):
                            return

        self.thread = threading.Thread(
            target=_loop, name=f"{self.kind}-heavy-heartbeat", daemon=True
        )
        self.thread.start()

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        self.stop.set()
        last_exc = None
        for attempt in range(3):
            try:
                if _atomic_release_heavy(self.client, self.key, self.token):
                    log.info("Released %s heavy slot %s (was %s)", self.kind.upper(), self.key, self.reason)
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
        if last_exc is not None:
            log.debug("release_%s_heavy_slot failed after retries: %s", self.kind, last_exc)


def _push_heavy_lease(kind: str, lease: _LocalHeavyLease) -> None:
    _heavy_stack(kind).append(lease)


def _remove_heavy_lease(kind: str, lease: _LocalHeavyLease) -> None:
    stack = _heavy_stack(kind)
    try:
        stack.remove(lease)
    except ValueError:
        pass


def _current_heavy_lease(kind: str) -> _LocalHeavyLease | None:
    stack = _heavy_stack(kind)
    return stack[-1] if stack else None


def refresh_gpu_heavy_slot(*, ttl_sec: int | None = None) -> None:
    lease = _current_heavy_lease("gpu")
    if lease is not None:
        lease.refresh(ttl_sec)


def release_gpu_heavy_slot() -> None:
    lease = _current_heavy_lease("gpu")
    if lease is None:
        return
    _remove_heavy_lease("gpu", lease)
    lease.release()


def refresh_cpu_heavy_slot(*, ttl_sec: int | None = None) -> None:
    lease = _current_heavy_lease("cpu")
    if lease is not None:
        lease.refresh(ttl_sec)


def release_cpu_heavy_slot() -> None:
    lease = _current_heavy_lease("cpu")
    if lease is None:
        return
    _remove_heavy_lease("cpu", lease)
    lease.release()


def cpu_heavy_lease_for_job(job_id: str) -> dict | None:
    """V45.5: the live CPU-heavy lease (holder + heartbeat age) copying this job, else None.

    This is the authoritative "is the extract worker alive" signal: the lease
    heartbeat thread refreshes it every 15-60 s from inside the worker process.
    """
    if not job_id:
        return None
    for key in _cpu_slot_keys():
        holder = _lock_held(key)
        if not holder or heavy_holder_is_stale(holder):
            continue
        if str(holder.get("job_id") or "") == str(job_id):
            try:
                hb_age = _holder_heartbeat_age_sec(holder)
            except Exception:
                hb_age = 0.0
            return {
                "key": key,
                "reason": holder.get("reason"),
                "pid": holder.get("pid"),
                "started": holder.get("started"),
                "heartbeat_age_sec": round(float(hb_age), 1),
            }
    return None


def cpu_heavy_slot_owned_by_job(job_id: str) -> bool:
    """True when a live CPU slot is already copying this job."""
    if not job_id:
        return False
    for key in _cpu_slot_keys():
        holder = _lock_held(key)
        if not holder or heavy_holder_is_stale(holder):
            continue
        if str(holder.get("job_id") or "") == str(job_id):
            return True
    return False


def _acquire_local_heavy_lease(
    kind: str,
    reason: str,
    *,
    wait_sec: float,
    ttl: int,
    job_id: str | None = None,
) -> _LocalHeavyLease | None:
    """Acquire only the product-local lane; shared host admission happens later."""
    is_gpu = kind == "gpu"
    keys = _gpu_slot_keys() if is_gpu else _cpu_slot_keys()
    live_cap = _gpu_heavy_max_slots() if is_gpu else _cpu_heavy_max_slots()
    if live_cap <= 0:
        return None
    token = f"{os.getpid()}:{threading.get_ident()}:{uuid.uuid4().hex[:10]}:{reason}"
    payload = json.dumps(
        {
            "token": token,
            "reason": reason,
            "pid": os.getpid(),
            "thread": threading.get_ident(),
            "boot_id": _container_boot_id(),
            "started": time.time(),
            "heartbeat": time.time(),
            "job_id": job_id or "",
        }
    )
    one_shot = wait_sec <= 0
    deadline = time.time() if one_shot else time.time() + wait_sec
    client = _redis_client()
    label = kind.upper()
    while True:
        if job_id and cpu_heavy_slot_owned_by_job(job_id):
            mine = _current_heavy_lease(kind)
            if mine is None or mine.released or getattr(mine, "job_id", None) != job_id:
                raise ExtractSlotAlreadyHeld(job_id)
        if job_id:
            refresh_job_lock("extract", job_id)
        active = 0
        free_keys: list[str] = []
        for index, key in enumerate(keys):
            holder = _lock_held(key)
            if holder and _reclaim_stale_heavy_lock(client, key, holder, label=label):
                holder = None
            if holder:
                active += 1
            elif index < live_cap:
                free_keys.append(key)
        if active < live_cap:
            for key in free_keys:
                if client.set(key, payload, nx=True, ex=ttl):
                    lease = _LocalHeavyLease(
                        kind=kind, key=key, token=token, reason=reason, ttl=ttl, client=client
                    )
                    lease.job_id = job_id or ""
                    lease.start_heartbeat()
                    _push_heavy_lease(kind, lease)
                    return lease
        if one_shot or time.time() >= deadline:
            return None
        time.sleep(1.0 if is_gpu else 1.5)


def _settings_float(name: str, default: float) -> float:
    try:
        from app.config import get_settings

        return float(getattr(get_settings(), name, default) or default)
    except Exception:
        return default


def _settings_int(name: str, default: int) -> int:
    try:
        from app.config import get_settings

        return int(getattr(get_settings(), name, default) or default)
    except Exception:
        return default


def _settings_bool(name: str, default: bool) -> bool:
    try:
        from app.config import get_settings

        value = getattr(get_settings(), name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}
    except Exception:
        return default


@contextmanager
def gpu_heavy_slot(
    reason: str,
    *,
    wait_sec: float | None = None,
    ttl_sec: int | None = None,
    fail_closed: bool = True,
) -> Iterator[bool]:
    """Two-level GPU admission without cross-product hold-and-wait.

    Product-local capacity is reserved first.  Only then is a host-wide permit
    acquired.  A task waiting on its own product can therefore never consume a
    shared Disk/Android/iOS host permit.
    """
    wait_budget = float(
        wait_sec if wait_sec is not None else _settings_float("gpu_heavy_lock_wait_sec", DEFAULT_GPU_HEAVY_WAIT_SEC)
    )
    ttl = max(
        int(ttl_sec if ttl_sec is not None else _settings_int("gpu_heavy_lock_ttl_sec", DEFAULT_GPU_HEAVY_TTL_SEC)),
        120,
    )
    started = time.time()
    local_lease: _LocalHeavyLease | None = None
    adaptive_lease = None
    try:
        try:
            local_lease = _acquire_local_heavy_lease(
                "gpu", reason, wait_sec=wait_budget, ttl=ttl
            )
        except Exception as exc:
            if fail_closed:
                raise GpuHeavySlotTimeout(f"GPU local slot unavailable ({exc})") from exc
            log.warning("GPU local slot unavailable (%s) — thermal guards only", exc)

        if local_lease is None:
            msg = f"GPU local slot wait timed out for {reason} after {wait_budget:.0f}s"
            msg += f" — {describe_gpu_lane_state()}"
            if fail_closed:
                raise GpuHeavySlotTimeout(msg)
            log.warning("%s", msg)
            yield False
            return

        remaining = 0.0 if wait_budget <= 0 else max(wait_budget - (time.time() - started), 0.0)
        try:
            from app.services.adaptive_semaphore import ResourceSemaphoreTimeout, acquire_resource_slot

            adaptive_lease = acquire_resource_slot(
                "gpu",
                reason=reason,
                wait_sec=remaining,
                ttl_sec=ttl,
                fail_closed=fail_closed,
                requested_limit=_gpu_heavy_configured_slots(),
            )
        except ResourceSemaphoreTimeout as exc:
            raise GpuHeavySlotTimeout(str(exc)) from exc
        except Exception as exc:
            if fail_closed:
                raise GpuHeavySlotTimeout(f"Adaptive GPU semaphore unavailable ({exc})") from exc
            log.warning("Adaptive GPU semaphore unavailable (%s) — using local slot only", exc)

        log.info("Acquired GPU heavy local=%s for %s (ttl=%ss)", local_lease.key, reason, ttl)
        yield True
    finally:
        if adaptive_lease is not None:
            adaptive_lease.release()
        if local_lease is not None:
            _remove_heavy_lease("gpu", local_lease)
            local_lease.release()


@contextmanager
def cpu_heavy_slot(
    reason: str,
    *,
    wait_sec: float | None = None,
    ttl_sec: int | None = None,
    fail_closed: bool = True,
    job_id: str | None = None,
) -> Iterator[bool]:
    """Two-level CPU/I/O admission with independent product-local lanes."""
    existing = _current_heavy_lease("cpu")
    if existing is not None and not existing.released and (
        not job_id or getattr(existing, "job_id", None) in (None, "", job_id)
    ):
        yield True
        return
    wait_budget = float(wait_sec if wait_sec is not None else DEFAULT_CPU_HEAVY_WAIT_SEC)
    ttl = max(int(ttl_sec if ttl_sec is not None else DEFAULT_CPU_HEAVY_TTL_SEC), 120)
    started = time.time()
    local_lease: _LocalHeavyLease | None = None
    adaptive_lease = None
    try:
        try:
            local_lease = _acquire_local_heavy_lease(
                "cpu", reason, wait_sec=wait_budget, ttl=ttl, job_id=job_id
            )
        except ExtractSlotAlreadyHeld:
            raise
        except Exception as exc:
            if fail_closed:
                raise CpuHeavySlotTimeout(f"CPU local slot unavailable ({exc})") from exc
            log.warning("CPU local slot unavailable (%s) — local thermal guards only", exc)

        if local_lease is None:
            msg = f"CPU local slot wait timed out for {reason} after {wait_budget:.0f}s"
            if fail_closed:
                raise CpuHeavySlotTimeout(msg)
            log.warning("%s", msg)
            yield False
            return

        remaining = 0.0 if wait_budget <= 0 else max(wait_budget - (time.time() - started), 0.0)
        try:
            from app.services.adaptive_semaphore import ResourceSemaphoreTimeout, acquire_resource_slot

            adaptive_lease = acquire_resource_slot(
                "cpu_heavy",
                reason=reason,
                wait_sec=remaining,
                ttl_sec=ttl,
                fail_closed=fail_closed,
                requested_limit=max(_settings_int("max_concurrent_disk_builds", 2), 1),
                fail_open_if_unavailable=_settings_bool(
                    "resource_governor_fail_open_on_unavailable", True
                ),
            )
        except ResourceSemaphoreTimeout as exc:
            raise CpuHeavySlotTimeout(str(exc)) from exc
        except Exception as exc:
            if fail_closed:
                raise CpuHeavySlotTimeout(f"Adaptive CPU semaphore unavailable ({exc})") from exc
            log.warning("Adaptive CPU semaphore unavailable (%s) — using local slot only", exc)

        log.info("Acquired CPU heavy local=%s for %s (ttl=%ss)", local_lease.key, reason, ttl)
        yield True
    finally:
        if adaptive_lease is not None:
            adaptive_lease.release()
        if local_lease is not None:
            _remove_heavy_lease("cpu", local_lease)
            local_lease.release()


def wait_for_chassis_idle(*, reason: str = "extract", max_wait_sec: float = 0.0) -> float:
    """Pause only when the chassis is thermally hot.

    A held GPU slot must not block extract/parse — GPU and CPU lanes run
    together. max_wait_sec <= 0 waits until temperatures drop.
    Returns seconds waited.
    """
    started = time.time()
    deadline = None if max_wait_sec <= 0 else started + max_wait_sec
    while deadline is None or time.time() < deadline:
        holder = gpu_heavy_slot_held()
        if holder and heavy_holder_is_stale(holder):
            try:
                client = _redis_client()
                for key in _gpu_slot_keys():
                    _reclaim_stale_heavy_lock(client, key, _lock_held(key), label="GPU")
            except Exception:
                pass
            holder = None
        hot = False
        try:
            from app.services.gpu_thermal import _load_settings, get_gpu_stats

            stats = get_gpu_stats()
            settings = _load_settings(gpu_name=stats.name)
            if stats.available and stats.temperature_c is not None:
                if stats.temperature_c >= settings.pause_c:
                    hot = True
        except Exception:
            pass
        try:
            from app.config import get_settings
            from app.services.host_capacity import probe_host

            snap = probe_host()
            cpu_pause = int(getattr(get_settings(), "cpu_thermal_pause_c", 94) or 94)
            # Only pause-level CPU heat must block new work — 86°C under OCR is normal.
            if snap.cpu_temp_c is not None and snap.cpu_temp_c >= cpu_pause:
                hot = True
        except Exception:
            pass

        if not hot:
            break
        log.info(
            "Chassis hot for %s (gpu_slot=%s) — cooling",
            reason,
            (holder or {}).get("reason") or "-",
        )
        time.sleep(5.0)
    return max(0.0, time.time() - started)
