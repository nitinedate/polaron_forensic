"""Capacity-aware parallelism for vulnerability scan jobs.

Premise scans run on worker-nessus (nessus-sync queue) isolated from
disk-build / mobile-build / report-gen / rag-index. Up to 4 scan cases
run at once; OpenVAS prefs stay at full strength so parallel jobs do not
slow each other. ZAP/Trivy sidecars accept concurrent API calls (no wait).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from contextlib import contextmanager
from typing import Any, Iterator

log = logging.getLogger("vuln_capacity")

ZAP_ENGINE_LOCK_KEY = "vuln:engine_lock:zap"
TRIVY_ENGINE_LOCK_KEY = "vuln:engine_lock:trivy"
DEFAULT_ENGINE_LOCK_TTL_SEC = 3600


def _settings():
    from app.config import get_settings

    return get_settings()


def vuln_max_parallel_jobs() -> int:
    try:
        return max(1, min(8, int(getattr(_settings(), "vuln_max_parallel_jobs", 4) or 4)))
    except Exception:
        return 4


def vuln_parallel_min_pace() -> float:
    try:
        return max(0.05, min(1.0, float(getattr(_settings(), "vuln_parallel_min_pace", 0.45) or 0.45)))
    except Exception:
        return 0.45


def count_running_vuln_jobs(db, *, exclude_job_id: str | None = None) -> int:
    from app.db.sql_helpers import fetchone

    # Laptop/edge jobs run on the scanner-agent, not worker-nessus.
    row = fetchone(
        db,
        """SELECT count(*)::int AS c FROM vuln_scan_jobs
           WHERE lower(status) IN ('running', 'syncing')
             AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = false
             AND (:excl IS NULL OR id <> CAST(:excl AS uuid))""",
        {"excl": exclude_job_id},
    )
    return int((row or {}).get("c") or 0)


def allowed_vuln_scan_slots() -> int:
    """How many premise scan jobs may run at once. Shrinks only when RAM is critical."""
    ceiling = vuln_max_parallel_jobs()
    try:
        from app.services.host_capacity import probe_host

        snap = probe_host()
        avail_mb = int(getattr(snap, "mem_available_mb", 0) or 0)
        if avail_mb and avail_mb < 1024:
            return 1
        if avail_mb and avail_mb < 3072:
            return min(ceiling, 2)
    except Exception:
        pass
    return ceiling


def vuln_scan_can_start(db, scan_job_id: str) -> tuple[bool, str]:
    """True when another premise scan may begin without overloading worker-nessus."""
    slots = allowed_vuln_scan_slots()
    running = count_running_vuln_jobs(db, exclude_job_id=scan_job_id)
    if running >= slots:
        return False, f"capacity_wait running={running} slots={slots}"
    return True, f"ok running={running} slots={slots}"


def detect_scan_accel() -> dict[str, Any]:
    """Report GPU presence. OpenVAS/Nmap/ZAP/Trivy host scans are not GPU workloads."""
    gpu_present = False
    detail = (
        "OpenVAS, Nmap, ZAP, and Trivy host scans are CPU and network bound; "
        "they do not run NVTs or port probes on a GPU."
    )
    try:
        if shutil.which("nvidia-smi"):
            proc = subprocess.run(
                ["nvidia-smi", "-L"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0 and (proc.stdout or "").strip():
                gpu_present = True
                detail = (
                    "GPU detected; extra parallel IP workers are enabled. "
                    "OpenVAS and Nmap themselves are not GPU-accelerated."
                )
    except Exception:
        pass
    return {"gpu_present": gpu_present, "used_for_scan": False, "detail": detail}


def vuln_target_workers() -> int:
    """How many IPs aux engines may scan at once inside one job."""
    try:
        base = max(1, int(getattr(_settings(), "vuln_target_workers", 4) or 4))
    except Exception:
        base = 4
    if detect_scan_accel().get("gpu_present"):
        base = min(8, base + 2)
    return max(1, min(8, base))


def vuln_openvas_ip_workers() -> int:
    """How many client IPs OpenVAS may scan as concurrent GMP tasks."""
    try:
        base = max(1, int(getattr(_settings(), "vuln_openvas_ip_workers", 4) or 4))
    except Exception:
        base = 4
    if detect_scan_accel().get("gpu_present"):
        base = min(8, base + 2)
    return max(2, min(8, base))


def adaptive_gvm_max_hosts_checks(*, running_jobs: int | None = None) -> tuple[int, int]:
    """Keep full OpenVAS prefs so parallel cases do not slow each other down."""
    settings = _settings()
    max_checks = max(1, int(getattr(settings, "gvm_max_checks", 20) or 20))
    max_hosts = max(1, int(getattr(settings, "gvm_max_hosts", 8) or 8))
    return max_hosts, max_checks


def _redis():
    from app.services.job_locks import _redis_client

    return _redis_client()


@contextmanager
def scanner_engine_lock(engine: str, *, ttl_sec: int = DEFAULT_ENGINE_LOCK_TTL_SEC) -> Iterator[bool]:
    """Best-effort marker for ZAP/Trivy. Never wait — parallel cases share the sidecar."""
    engine_l = (engine or "").strip().lower()
    if engine_l in {"zap", "owasp_zap"}:
        key = ZAP_ENGINE_LOCK_KEY
    elif engine_l == "trivy":
        key = TRIVY_ENGINE_LOCK_KEY
    else:
        yield True
        return

    acquired = False
    client = None
    token = f"{time.time():.3f}"
    try:
        client = _redis()
        acquired = bool(client.set(key, token, nx=True, ex=max(int(ttl_sec), 60)))
        if not acquired:
            log.info("engine %s already in use — continuing in parallel (no wait)", engine_l)
            client = None
    except Exception as exc:
        log.warning("engine lock unavailable for %s (%s) — proceeding", engine_l, exc)
        acquired = False
        client = None
    try:
        yield True
    finally:
        if client is not None and acquired:
            try:
                raw = client.get(key)
                if raw is not None:
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", errors="replace")
                    if str(raw) == token:
                        client.delete(key)
            except Exception:
                pass


def capacity_snapshot(db=None) -> dict[str, Any]:
    running = 0
    if db is not None:
        try:
            running = count_running_vuln_jobs(db)
        except Exception:
            running = 0
    hosts, checks = adaptive_gvm_max_hosts_checks(running_jobs=max(1, running))
    return {
        "allowed_slots": allowed_vuln_scan_slots(),
        "running_jobs": running,
        "adaptive_max_hosts": hosts,
        "adaptive_max_checks": checks,
        "target_workers": vuln_target_workers(),
        "openvas_ip_workers": vuln_openvas_ip_workers(),
    }
