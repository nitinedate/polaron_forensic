"""Adaptive distributed resource semaphores for forensic workloads.

The forensic pipeline has several independent Celery queues, thread pools and
(optionally) separate product stacks.  Queue-level concurrency alone cannot
protect a shared workstation: disk/mobile extraction, parse, OCR and RAG can
all become runnable at the same time.

This module provides two complementary controls:

* ``resource_capacity`` / ``cap_parallelism`` shrink *in-process* fan-out from
  live CPU temperature/load/RAM and GPU temperature/VRAM.
* ``acquire_resource_slot`` is a Redis-backed distributed semaphore with TTL
  heartbeats.  Set ``RESOURCE_GOVERNOR_REDIS_URL`` to the same Redis URL in
  forensic + mobile-extract stacks to coordinate one physical host even when
  each product otherwise has its own Redis container.

The governor never changes evidence selection, parser behaviour or forensic
content.  It only changes how much work may run at once.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("adaptive_semaphore")

DEFAULT_TTL_SEC = 600
DEFAULT_STALE_SEC = 90.0

_probe_lock = threading.Lock()
_probe_at = 0.0
_probe_cache: Any = None


def _truthy(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _resource_enabled() -> bool:
    raw = os.environ.get("RESOURCE_GOVERNOR_ENABLED")
    if raw is not None:
        return _truthy(raw, True)
    try:
        from app.config import get_settings

        return bool(getattr(get_settings(), "resource_governor_enabled", True))
    except Exception:
        return True


def _group() -> str:
    raw = (os.environ.get("RESOURCE_GOVERNOR_GROUP") or "").strip()
    if not raw:
        try:
            from app.config import get_settings

            raw = str(getattr(get_settings(), "resource_governor_group", "aetheris-host") or "aetheris-host").strip()
        except Exception:
            raw = "aetheris-host"
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in raw)
    return safe or "aetheris-host"


def _redis_url() -> str:
    explicit = (os.environ.get("RESOURCE_GOVERNOR_REDIS_URL") or "").strip()
    if explicit:
        return explicit
    try:
        from app.config import get_settings

        s = get_settings()
        configured = str(getattr(s, "resource_governor_redis_url", "") or "").strip()
        if configured:
            return configured
        return str(getattr(s, "redis_url", "") or "").strip()
    except Exception:
        return ""


def _redis_client():
    import redis

    url = _redis_url()
    if not url:
        raise RuntimeError("RESOURCE_GOVERNOR_REDIS_URL/REDIS_URL is empty")
    return redis.Redis.from_url(url, socket_connect_timeout=1.5, socket_timeout=2.0)


def _host_snapshot(*, max_age_sec: float = 2.0):
    global _probe_at, _probe_cache
    now = time.monotonic()
    with _probe_lock:
        if _probe_cache is not None and (now - _probe_at) <= max_age_sec:
            return _probe_cache
        try:
            from app.services.host_capacity import probe_host

            _probe_cache = probe_host()
        except Exception:
            _probe_cache = None
        _probe_at = now
        return _probe_cache


def _settings_value(name: str, default: Any) -> Any:
    try:
        from app.config import get_settings

        return getattr(get_settings(), name, default)
    except Exception:
        return default


def _cpu_pace_from_snapshot(snap) -> float:
    if snap is None:
        return 0.80
    pace = 1.0
    cpus = max(int(getattr(snap, "cpu_logical", 1) or 1), 1)
    load = getattr(snap, "load_1m", None)
    if load is not None:
        ratio = float(load) / cpus
        if ratio >= 1.10:
            pace = min(pace, 0.30)
        elif ratio >= 0.90:
            pace = min(pace, 0.50)
        elif ratio >= 0.72:
            pace = min(pace, 0.75)

    total = max(int(getattr(snap, "mem_total_mb", 0) or 0), 1)
    avail = int(getattr(snap, "mem_available_mb", 0) or 0)
    if avail > 0:
        ratio = avail / total
        if avail < 2048 or ratio < 0.08:
            pace = min(pace, 0.25)
        elif avail < 4096 or ratio < 0.14:
            pace = min(pace, 0.45)
        elif ratio < 0.22:
            pace = min(pace, 0.70)

    temp = getattr(snap, "cpu_temp_c", None)
    throttle = int(_settings_value("cpu_thermal_throttle_c", 86) or 86)
    pause = int(_settings_value("cpu_thermal_pause_c", 94) or 94)
    if temp is not None:
        if int(temp) >= pause:
            pace = min(pace, 0.15)
        elif int(temp) >= throttle:
            pace = min(pace, 0.35)
        elif int(temp) >= throttle - 5:
            pace = min(pace, 0.65)
    return max(0.10, min(1.0, pace))


def _gpu_limit(requested: int, snap) -> int:
    """Safe number of simultaneous CUDA-heavy sessions on one physical GPU.

    12 GB laptop cards run OCR/RAG fastest overall when one heavy model owns the
    card at a time.  Larger desktop/workstation cards can use two sessions while
    cool.  Thermal pause returns zero, which prevents a *new* GPU session from
    starting; the active session's per-batch thermal guard handles cooldown.
    """
    requested = max(int(requested or 1), 1)
    if snap is None or not bool(getattr(snap, "gpu_available", False)):
        return 1
    temp = getattr(snap, "gpu_temp_c", None)
    vram = int(getattr(snap, "gpu_vram_total_mb", 0) or 0)
    free_vram = int(getattr(snap, "gpu_vram_free_mb", 0) or 0)
    profile = str(getattr(snap, "profile", "unknown") or "unknown")
    throttle = int(_settings_value("gpu_thermal_throttle_c", 87) or 87)
    pause = int(_settings_value("gpu_thermal_pause_c", 92) or 92)
    if temp is not None and int(temp) >= pause:
        return 0
    # Laptop/tight or <=12 GB: one resident heavy model at a time.  Extraction
    # and CPU parse still run concurrently, so this does not serialize the case.
    if profile in {"tight", "laptop"} or (0 < vram <= 12_500):
        return 1
    if temp is not None and int(temp) >= throttle - 3:
        return 1
    # Do not admit a second heavy model when the first one (or another local
    # CUDA process) has already consumed most of the card. This keeps the
    # throughput gain of two light models on large cards without VRAM thrash.
    if free_vram and free_vram < 8_192:
        return 1
    if vram >= 20_000:
        return min(requested, 2)
    if vram >= 16_000:
        return min(requested, 2)
    return 1


def resource_capacity(resource: str, *, requested: int | None = None, snapshot=None) -> int:
    """Return the live number of distributed permits for ``resource``."""
    snap = snapshot if snapshot is not None else _host_snapshot()
    resource = str(resource or "cpu_heavy").strip().lower()

    if resource in {"gpu", "gpu_heavy", "cuda"}:
        base = int(requested or _settings_value("gpu_heavy_max_concurrent", 1) or 1)
        return _gpu_limit(base, snap)

    if resource in {"cpu_heavy", "extract_job", "materialize"}:
        base = int(requested or _settings_value("max_concurrent_disk_builds", 2) or 2)
        profile = str(getattr(snap, "profile", "unknown") or "unknown") if snap else "unknown"
        # Laptop (20+ logical CPUs / 12GB+ VRAM) can sustain 3 concurrent CPU-heavy
        # extract lanes; keep thermal fail-closed via pace gates below.
        profile_cap = {"tight": 1, "laptop": 3, "desktop": 4, "workstation": 5}.get(profile, 2)
        cap = min(max(base, 1), profile_cap)
        pace = _cpu_pace_from_snapshot(snap)
        if pace < 0.30:
            return 1
        if pace < 0.60:
            return min(cap, 1)
        if pace < 0.80:
            return min(cap, 2)
        return max(1, cap)

    # Generic distributed resources are bounded by requested and CPU pace.
    base = max(int(requested or 1), 1)
    pace = _cpu_pace_from_snapshot(snap)
    if pace < 0.30:
        return 1
    if pace < 0.60:
        return max(1, min(base, 2))
    return base


def cap_parallelism(kind: str, requested: int, *, min_workers: int = 1, snapshot=None) -> int:
    """Thermal/load/RAM-aware cap for local thread/process fan-out."""
    requested = max(int(requested or 1), 1)
    min_workers = max(int(min_workers or 1), 1)
    snap = snapshot if snapshot is not None else _host_snapshot()
    if snap is None:
        return max(min_workers, min(requested, 4))

    profile = str(getattr(snap, "profile", "unknown") or "unknown")
    kind = str(kind or "cpu").strip().lower()
    if kind in {"mobile", "mobile_readers", "mobile_extract"}:
        profile_cap = {"tight": 3, "laptop": 12, "desktop": 14, "workstation": 16}.get(profile, 8)
    elif kind in {"disk", "disk_readers", "ewf"}:
        profile_cap = {"tight": 2, "laptop": 12, "desktop": 14, "workstation": 16}.get(profile, 8)
    elif kind in {"parse", "parse_workers"}:
        profile_cap = {"tight": 2, "laptop": 8, "desktop": 12, "workstation": 16}.get(profile, 8)
    elif kind in {"inventory", "inventory_workers"}:
        profile_cap = {"tight": 2, "laptop": 6, "desktop": 8, "workstation": 10}.get(profile, 6)
    else:
        profile_cap = max(int(getattr(snap, "cpu_logical", 4) or 4) - 2, 1)

    cap = min(requested, profile_cap)
    pace = _cpu_pace_from_snapshot(snap)
    if pace < 0.30:
        cap = min(cap, 1)
    elif pace < 0.50:
        cap = min(cap, 2)
    elif pace < 0.70:
        cap = min(cap, max(2, int(round(profile_cap * 0.45))))
    elif pace < 0.85:
        cap = min(cap, max(2, int(round(profile_cap * 0.70))))
    return max(min_workers, min(requested, cap))


def cpu_backoff_delay(*, snapshot=None) -> float:
    """Small cooperative delay for already-running CPU/I/O worker loops.

    Admission limits stop *new* work. Long extraction shards also need to react
    when the chassis heats after they started. The cached host probe makes this
    cheap to call from several extraction threads.
    """
    snap = snapshot if snapshot is not None else _host_snapshot()
    pace = _cpu_pace_from_snapshot(snap)
    if pace >= 0.85:
        return 0.0
    if pace >= 0.70:
        return 0.02
    if pace >= 0.50:
        return 0.08
    if pace >= 0.30:
        return 0.30
    return 1.25


def _host_namespace_limit(resource: str, requested_limit: int | None = None) -> int:
    """Stable host-wide slot namespace, independent of product-local tuning.

    Disk/Android/iOS may intentionally have different local worker ceilings.
    The shared coordinator must still inspect the *same* complete namespace or
    a lower-configured product could miss a higher-index lease held by another.
    """
    resource = str(resource or "cpu_heavy").strip().lower()
    if resource in {"gpu", "gpu_heavy", "cuda"}:
        configured = int(os.environ.get("RESOURCE_GOVERNOR_GPU_MAX_SLOTS") or 4)
    elif resource in {"cpu_heavy", "extract_job", "materialize"}:
        configured = int(os.environ.get("RESOURCE_GOVERNOR_CPU_MAX_SLOTS") or 8)
    else:
        configured = int(os.environ.get("RESOURCE_GOVERNOR_GENERIC_MAX_SLOTS") or 16)
    return max(configured, int(requested_limit or 0), 1)


def _lane() -> str:
    """Return the product lane sharing this physical host.

    Product-local Redis remains fully isolated; this value is used only for
    fairness inside the host-capacity coordinator.
    """
    try:
        from app.service_identity import current_service

        lane = str(current_service() or "forensic")
    except Exception:
        lane = str(os.environ.get("AETHERIS_SERVICE") or "forensic").strip().lower()
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in lane)
    return safe or "forensic"


def _demand_key(resource: str, lane: str) -> str:
    return f"aetheris:resource:{_group()}:{resource}:demand:{lane}"


def _known_lanes() -> tuple[str, ...]:
    # Keep this finite so fairness does not depend on Redis SCAN support.
    return ("forensic", "mobile-android", "mobile-ios", "mobile", "mobile-extract", "vuln")


def _touch_demand(client, resource: str, lane: str, *, ttl_sec: int = 30) -> None:
    try:
        client.set(_demand_key(resource, lane), str(time.time()), ex=max(int(ttl_sec), 10))
    except Exception:
        pass


def _other_demand_lanes(client, resource: str, lane: str) -> list[str]:
    out: list[str] = []
    for candidate in _known_lanes():
        if candidate == lane:
            continue
        try:
            if client.get(_demand_key(resource, candidate)):
                out.append(candidate)
        except Exception:
            continue
    return out


def _fair_lane_cap(cap: int, other_demand_count: int) -> int:
    """Soft reservation that prevents one product from monopolising a resource.

    With no competing demand a product can use every host permit.  Once another
    product is waiting, future admissions from the current product leave one
    permit per waiting lane where physical capacity allows.  Running forensic
    work is never pre-empted.
    """
    cap = max(int(cap or 0), 0)
    if cap <= 1 or other_demand_count <= 0:
        return cap
    reserve = min(max(int(other_demand_count), 0), cap - 1)
    return max(1, cap - reserve)


def _atomic_try_acquire(
    client,
    *,
    resource: str,
    slot_keys: list[str],
    cap: int,
    lane: str,
    lane_cap: int,
    payload: str,
    ttl_sec: int,
) -> str | None:
    """Atomically enforce host capacity and per-product fair share."""
    if cap <= 0 or lane_cap <= 0 or not slot_keys:
        return None
    script = r"""
local cap = tonumber(ARGV[1])
local lane = ARGV[2]
local lane_cap = tonumber(ARGV[3])
local payload = ARGV[4]
local ttl = tonumber(ARGV[5])
local active = 0
local lane_active = 0
for i=1,#KEYS do
  local raw = redis.call('GET', KEYS[i])
  if raw then
    active = active + 1
    local ok, obj = pcall(cjson.decode, raw)
    if ok and tostring(obj['lane'] or '') == lane then
      lane_active = lane_active + 1
    end
  end
end
if active >= cap or lane_active >= lane_cap then return '' end
for i=1,math.min(cap,#KEYS) do
  if not redis.call('GET', KEYS[i]) then
    redis.call('SET', KEYS[i], payload, 'EX', ttl)
    return KEYS[i]
  end
end
return ''
"""
    try:
        result = client.eval(
            script, len(slot_keys), *slot_keys, int(cap), lane, int(lane_cap), payload, int(ttl_sec)
        )
        if isinstance(result, bytes):
            result = result.decode('utf-8', errors='replace')
        return str(result) if result else None
    except AttributeError:
        # Unit-test/in-memory clients: preserve semantics as closely as possible.
        active = 0
        lane_active = 0
        for key in slot_keys:
            raw = client.get(key)
            if not raw:
                continue
            active += 1
            if isinstance(raw, bytes):
                raw = raw.decode('utf-8', errors='replace')
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
            if str(data.get('lane') or '') == lane:
                lane_active += 1
        if active >= cap or lane_active >= lane_cap:
            return None
        for key in slot_keys[:cap]:
            if client.set(key, payload, nx=True, ex=ttl_sec):
                return key
        return None


def _key(resource: str, idx: int) -> str:
    return f"aetheris:resource:{_group()}:{resource}:slot:{idx}"




def _compare_token_and_expire(client, key: str, token: str, ttl_sec: int, heartbeat_ts: float) -> bool:
    """Atomically refresh a lease only when ``token`` still owns ``key``.

    Redis GET+SET is unsafe around TTL turnover: an old holder can read its
    token, expire, and then overwrite a new holder.  Lua makes ownership check
    and refresh one operation.  A small fallback keeps unit-test fakes working.
    """
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
        return bool(client.eval(script, 1, key, token, int(ttl_sec), float(heartbeat_ts)))
    except AttributeError:
        raw = client.get(key)
        if not raw:
            return False
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='replace')
        try:
            data = json.loads(raw)
        except Exception:
            return False
        if str(data.get('token') or '') != token:
            return False
        data['heartbeat'] = float(heartbeat_ts)
        client.set(key, json.dumps(data), ex=int(ttl_sec))
        return True


def _compare_token_and_delete(client, key: str, token: str) -> bool:
    """Atomically delete only the lease still owned by ``token``."""
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
            raw = raw.decode('utf-8', errors='replace')
        try:
            data = json.loads(raw)
        except Exception:
            return False
        if str(data.get('token') or '') != token:
            return False
        return bool(client.delete(key))


def _compare_raw_and_delete(client, key: str, raw_value: str | bytes) -> bool:
    """Delete a stale candidate only if Redis still contains the same payload."""
    expected = raw_value.decode('utf-8', errors='replace') if isinstance(raw_value, bytes) else str(raw_value)
    script = r"""
local raw = redis.call('GET', KEYS[1])
if not raw or raw ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
"""
    try:
        return bool(client.eval(script, 1, key, expected))
    except AttributeError:
        current = client.get(key)
        if isinstance(current, bytes):
            current = current.decode('utf-8', errors='replace')
        if current != expected:
            return False
        return bool(client.delete(key))

def _holder_stale(holder: dict[str, Any] | None, *, stale_sec: float = DEFAULT_STALE_SEC) -> bool:
    if not holder:
        return True
    try:
        hb = float(holder.get("heartbeat") or holder.get("started") or 0.0)
        return not hb or (time.time() - hb) > float(stale_sec)
    except Exception:
        return True


@dataclass
class ResourceLease:
    resource: str
    key: str | None
    token: str | None
    ttl_sec: int
    acquired: bool
    _client: Any = None
    _stop: threading.Event | None = None
    _thread: threading.Thread | None = None

    def start_heartbeat(self) -> None:
        if not self.acquired or not self.key or not self.token or self._client is None:
            return
        stop = threading.Event()
        self._stop = stop
        interval = max(min(self.ttl_sec / 3.0, 45.0), 15.0)

        def _beat() -> None:
            # A transient coordinator/network failure must not permanently stop
            # heartbeats.  Otherwise a still-running forensic task can look stale
            # and a second task may be admitted into the same physical resource.
            retry_delay = min(5.0, max(1.0, interval / 3.0))
            while not stop.wait(interval):
                while not stop.is_set():
                    try:
                        owned = _compare_token_and_expire(
                            self._client, self.key, self.token, self.ttl_sec, time.time()
                        )
                        if not owned:
                            return
                        break
                    except Exception as exc:
                        log.warning(
                            "resource heartbeat transient failure resource=%s: %s",
                            self.resource,
                            exc,
                        )
                        if stop.wait(retry_delay):
                            return

        t = threading.Thread(target=_beat, name=f"resource-{self.resource}-heartbeat", daemon=True)
        self._thread = t
        t.start()

    def release(self) -> None:
        if self._stop is not None:
            self._stop.set()
        self._stop = None
        self._thread = None
        if not self.acquired or not self.key or not self.token or self._client is None:
            return
        last_exc = None
        for attempt in range(3):
            try:
                _compare_token_and_delete(self._client, self.key, self.token)
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
        if last_exc is not None:
            log.debug("resource release failed resource=%s after retries: %s", self.resource, last_exc)
        self.acquired = False


class ResourceSemaphoreTimeout(RuntimeError):
    pass


def acquire_resource_slot(
    resource: str,
    *,
    reason: str,
    wait_sec: float = 0.0,
    ttl_sec: int = DEFAULT_TTL_SEC,
    fail_closed: bool = False,
    requested_limit: int | None = None,
    fail_open_if_unavailable: bool = False,
) -> ResourceLease:
    """Acquire one distributed adaptive permit.

    Capacity is re-evaluated while waiting, so a hot GPU naturally stops new
    sessions and resumes them after cooling without restarting workers.
    """
    if not _resource_enabled():
        return ResourceLease(resource, None, None, ttl_sec, False)

    ttl = max(int(ttl_sec or DEFAULT_TTL_SEC), 120)
    one_shot = float(wait_sec or 0.0) <= 0.0
    deadline = time.time() if one_shot else time.time() + float(wait_sec)
    token = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:10]}"
    lane = _lane()
    client = None
    try:
        client = _redis_client()
        client.ping()
    except Exception as exc:
        if fail_open_if_unavailable:
            log.warning(
                "resource governor unavailable for %s (%s) - continuing with local guards only",
                resource,
                exc,
            )
            return ResourceLease(resource, None, None, ttl, False)
        if fail_closed:
            raise ResourceSemaphoreTimeout(f"resource governor unavailable: {exc}") from exc
        log.debug("resource governor unavailable for %s: %s", resource, exc)
        return ResourceLease(resource, None, None, ttl, False)

    # Demand is deliberately short-lived.  A task that cannot enter immediately
    # leaves a brief fairness hint so a busy product cannot instantly reacquire
    # every freed slot before another Disk/Android/iOS product retries.
    _touch_demand(client, resource, lane)

    while True:
        namespace_limit = _host_namespace_limit(resource, requested_limit)
        cap = resource_capacity(resource, requested=namespace_limit)
        other_demand = _other_demand_lanes(client, resource, lane)
        lane_cap = _fair_lane_cap(cap, len(other_demand))
        # Inspect the full configured namespace before admitting against the
        # live capacity.  This is essential when capacity shrinks (for example
        # 2 -> 1 while slot :1 is still active): that higher-index lease must
        # count toward the new limit even though only slot :0 is admissible.
        scan_limit = max(namespace_limit, cap, 1)
        slot_keys = [_key(resource, idx) for idx in range(scan_limit)]
        active = 0
        for key in slot_keys:
            try:
                raw = client.get(key)
                if not raw:
                    continue
                raw_for_compare = raw
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                try:
                    holder = json.loads(raw)
                except Exception:
                    holder = None
                if _holder_stale(holder):
                    # Do not let a stale-reader race delete a lease that has just
                    # been heartbeated/replaced by its rightful owner.
                    _compare_raw_and_delete(client, key, raw_for_compare)
                    continue
                active += 1
            except Exception:
                continue

        if cap > 0 and active < cap:
            payload = json.dumps(
                {
                    "token": token,
                    "resource": resource,
                    "lane": lane,
                    "reason": reason,
                    "pid": os.getpid(),
                    "host": socket.gethostname(),
                    "started": time.time(),
                    "heartbeat": time.time(),
                }
            )
            try:
                key = _atomic_try_acquire(
                    client,
                    resource=resource,
                    slot_keys=slot_keys,
                    cap=cap,
                    lane=lane,
                    lane_cap=lane_cap,
                    payload=payload,
                    ttl_sec=ttl,
                )
            except Exception as exc:
                key = None
                log.debug("atomic resource admission failed resource=%s lane=%s: %s", resource, lane, exc)
            if key:
                lease = ResourceLease(resource, key, token, ttl, True, _client=client)
                lease.start_heartbeat()
                log.info(
                    "Acquired adaptive resource slot %s for %s lane=%s (%s/%s active, lane_cap=%s)",
                    key,
                    reason,
                    lane,
                    active + 1,
                    cap,
                    lane_cap,
                )
                return lease

        if one_shot or time.time() >= deadline:
            msg = (
                f"adaptive resource slot unavailable resource={resource} reason={reason} "
                f"lane={lane} cap={cap} lane_cap={lane_cap}"
            )
            if fail_closed:
                raise ResourceSemaphoreTimeout(msg)
            log.info("%s — proceeding with local guards", msg)
            return ResourceLease(resource, None, None, ttl, False, _client=client)
        _touch_demand(client, resource, lane)
        time.sleep(1.0 if resource in {"gpu", "gpu_heavy", "cuda"} else 1.5)


def semaphore_snapshot(resource: str, *, requested_limit: int | None = None) -> dict[str, Any]:
    """Debug/status view used by the Performance Agent and lane arbitration."""
    namespace_limit = _host_namespace_limit(resource, requested_limit)
    cap = resource_capacity(resource, requested=namespace_limit)
    out: dict[str, Any] = {
        "resource": resource,
        "enabled": _resource_enabled(),
        "capacity": cap,
        "used": 0,
        "holders": [],
    }
    if not out["enabled"]:
        out["free"] = cap
        return out
    try:
        client = _redis_client()
        scan_limit = max(namespace_limit, cap, 1)
        for idx in range(scan_limit):
            raw = client.get(_key(resource, idx))
            if not raw:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            try:
                holder = json.loads(raw)
            except Exception:
                holder = {"raw": str(raw)}
            if _holder_stale(holder):
                _compare_raw_and_delete(client, _key(resource, idx), raw)
                continue
            out["used"] += 1
            out["holders"].append(
                {
                    "lane": holder.get("lane"),
                    "reason": holder.get("reason"),
                    "pid": holder.get("pid"),
                    "host": holder.get("host"),
                }
            )
    except Exception as exc:
        out["error"] = str(exc)[:160]
    out["free"] = max(int(out["capacity"]) - int(out["used"]), 0)
    return out
