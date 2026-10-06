"""Adaptive laptop capacity planner for edge vulnerability scans.

v1.3.5 targets a sustained 15-18 completed IPs/hour on a healthy 8-12+ core
scanner without weakening evidence quality.  Each IP owns one OpenVAS task; the
planner normally admits 5-6 tasks concurrently and reduces admission under
thermal/memory pressure.  Existing tasks are never killed by this planner.
"""

from __future__ import annotations

import logging
import math
import os
import time
from typing import Any

log = logging.getLogger("scanner_agent.capacity")

_last_probe: dict[str, Any] | None = None
_last_probe_mono = 0.0

IP_WORKERS_MIN = 5
IP_WORKERS_MAX_DEFAULT = 6
IP_WORKERS_MAX_HARD = 12


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        value = float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))


def _configured_max() -> int:
    raw = (os.environ.get("SCAN_IP_MAX_PARALLELISM") or str(IP_WORKERS_MAX_DEFAULT)).strip()
    try:
        return max(IP_WORKERS_MIN, min(IP_WORKERS_MAX_HARD, int(raw)))
    except (TypeError, ValueError):
        return IP_WORKERS_MAX_DEFAULT


def throughput_target_hph() -> float:
    return _env_float("SCAN_SLO_HOSTS_PER_HOUR", 18.0, 1.0, 120.0)


def throughput_min_hph() -> float:
    return _env_float("SCAN_SLO_MIN_HOSTS_PER_HOUR", 15.0, 1.0, throughput_target_hph())


def expected_host_minutes() -> float:
    return _env_float("SCAN_EXPECTED_HOST_MINUTES", 20.0, 2.0, 120.0)


def required_workers_for_slo() -> int:
    # Little's-law style sizing: concurrency ~= arrival/completion rate * service time.
    required = math.ceil(throughput_target_hph() * expected_host_minutes() / 60.0)
    return max(IP_WORKERS_MIN, min(_configured_max(), required))


def projected_hosts_per_hour(workers: int) -> float:
    minutes = expected_host_minutes()
    return round(max(1, int(workers)) * 60.0 / minutes, 2)


def _read_loadavg() -> float | None:
    try:
        with open("/proc/loadavg", encoding="utf-8") as fh:
            return float(fh.read().split()[0])
    except Exception:
        return None


def _cpu_count() -> int:
    try:
        return max(1, int(os.cpu_count() or 1))
    except Exception:
        return 1


def _read_cpu_temp_c() -> float | None:
    raw_env = (os.environ.get("SCAN_HOST_TEMP_C") or "").strip()
    if raw_env:
        try:
            return float(raw_env)
        except ValueError:
            pass
    temps: list[float] = []
    for root in ("/sys/class/thermal", "/sys/class/hwmon"):
        if not os.path.isdir(root):
            continue
        try:
            for dirname, _, files in os.walk(root):
                for name in files:
                    if not (name == "temp" or (name.startswith("temp") and name.endswith("_input"))):
                        continue
                    path = os.path.join(dirname, name)
                    try:
                        raw = float(open(path, encoding="utf-8").read().strip())
                        c = raw / 1000.0 if raw > 200 else raw
                        if 20.0 <= c <= 115.0:
                            temps.append(c)
                    except Exception:
                        continue
        except Exception:
            continue
    return max(temps) if temps else None


def _mem_available_gb() -> float | None:
    try:
        avail = None
        total = None
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    avail = int(line.split()[1]) / (1024 * 1024)
                elif line.startswith("MemTotal:"):
                    total = int(line.split()[1]) / (1024 * 1024)
        if avail is not None:
            return float(avail)
        if total is not None:
            return float(total) * 0.4
    except Exception:
        return None
    return None


def _cpu_percent_sample(sample_sec: float = 0.35) -> float | None:
    try:
        def _snap() -> tuple[int, int]:
            with open("/proc/stat", encoding="utf-8") as fh:
                parts = fh.readline().split()
            vals = [int(x) for x in parts[1:8]]
            idle = vals[3] + vals[4]
            total = sum(vals)
            return idle, total

        i1, t1 = _snap()
        time.sleep(max(0.1, sample_sec))
        i2, t2 = _snap()
        di, dt = i2 - i1, t2 - t1
        if dt <= 0:
            return None
        return max(0.0, min(100.0, (1.0 - di / dt) * 100.0))
    except Exception:
        return None


def ip_workers_for_cpu(
    cpus: int,
    *,
    mem_gb: float | None = None,
    explicit: str | None = None,
) -> int:
    """Choose stable one-IP OpenVAS concurrency for the 18 IP/hour SLO.

    Auto CPU envelope:
      <=4 logical CPUs -> 5 tasks (admission pauses under critical pressure)
      5-8             -> 5 tasks
      9+              -> up to the SLO requirement (normally 6)
    """
    ceiling = _configured_max()
    raw = (explicit if explicit is not None else (os.environ.get("SCAN_IP_PARALLELISM") or "auto")).strip().lower()
    if raw.isdigit():
        return max(IP_WORKERS_MIN, min(ceiling, int(raw)))

    n = max(1, int(cpus or 1))
    if n <= 4:
        cpu_cap = IP_WORKERS_MIN
    elif n <= 8:
        cpu_cap = 5
    else:
        cpu_cap = ceiling
    return max(IP_WORKERS_MIN, min(cpu_cap, required_workers_for_slo(), ceiling))


def probe_laptop_capacity(*, force: bool = False) -> dict[str, Any]:
    global _last_probe, _last_probe_mono
    now = time.monotonic()
    if not force and _last_probe is not None and (now - _last_probe_mono) < 5.0:
        return dict(_last_probe)

    cpus = _cpu_count()
    load = _read_loadavg()
    mem_gb = _mem_available_gb()
    cpu_pct = _cpu_percent_sample()
    cpu_temp_c = _read_cpu_temp_c()

    base_workers = ip_workers_for_cpu(cpus, mem_gb=mem_gb)
    ip_workers = base_workers

    configured_jobs = max(1, min(8, int(os.environ.get("MAX_CONCURRENT_SCAN_JOBS") or 1)))
    max_jobs = configured_jobs

    throttle_c = float(os.environ.get("SCAN_CPU_THROTTLE_C") or 84)
    pause_c = float(os.environ.get("SCAN_CPU_PAUSE_C") or 92)
    load_ratio = (float(load) / max(cpus, 1)) if load is not None else 0.0

    critical = bool(
        (cpu_temp_c is not None and cpu_temp_c >= pause_c)
        or (cpu_pct is not None and cpu_pct >= 98)
        or load_ratio >= 1.75
        or (mem_gb is not None and mem_gb < 0.75)
    )
    hot = bool(
        critical
        or (cpu_temp_c is not None and cpu_temp_c >= throttle_c)
        or (cpu_pct is not None and cpu_pct >= 92)
        or load_ratio >= 1.25
        or (mem_gb is not None and mem_gb < 1.5)
    )
    warm = bool(
        hot
        or (cpu_temp_c is not None and cpu_temp_c >= throttle_c - 5)
        or (cpu_pct is not None and cpu_pct >= 84)
        or load_ratio >= 0.95
        or (mem_gb is not None and mem_gb < 2.5)
    )

    admission_paused = False
    if critical:
        ip_workers = IP_WORKERS_MIN
        max_jobs = 1
        admission_paused = True
        thermal_state = "critical"
    elif hot:
        ip_workers = IP_WORKERS_MIN
        max_jobs = 1
        thermal_state = "hot"
    elif warm:
        ip_workers = max(IP_WORKERS_MIN, min(base_workers, 5))
        max_jobs = 1
        thermal_state = "warm"
    else:
        thermal_state = "cool"

    target_hph = throughput_target_hph()
    min_hph = throughput_min_hph()
    required_workers = required_workers_for_slo()
    projected_hph = projected_hosts_per_hour(ip_workers)
    plan = {
        "cpu_count": cpus,
        "load_1m": load,
        "load_ratio": load_ratio,
        "cpu_pct": cpu_pct,
        "cpu_temp_c": cpu_temp_c,
        "mem_available_gb": mem_gb,
        "ip_workers": ip_workers,
        "semaphore_limit": ip_workers,
        "max_concurrent_jobs": max_jobs,
        "chunk_size": 1,
        "thermal_state": thermal_state,
        "hot": hot,
        "admission_paused": admission_paused,
        "operational_floor": IP_WORKERS_MIN,
        "configured_ceiling": _configured_max(),
        "throughput_target_hph": target_hph,
        "throughput_min_hph": min_hph,
        "expected_host_minutes": expected_host_minutes(),
        "required_workers_for_slo": required_workers,
        "projected_hosts_per_hour": projected_hph,
        "slo_at_risk": bool(projected_hph + 0.01 < min_hph),
    }
    _last_probe = dict(plan)
    _last_probe_mono = now
    return plan


def chunk_targets(targets: list[str], chunk_size: int) -> list[list[str]]:
    size = max(1, int(chunk_size))
    return [targets[i : i + size] for i in range(0, len(targets), size)]
