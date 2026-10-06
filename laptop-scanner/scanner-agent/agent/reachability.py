"""Fast host reachability probes for edge scan target filtering.

Targets are probed concurrently so an unavailable IP cannot hold up the rest of
an authorized subnet.  Quick-probe failures are telemetry by default, not evidence that an authorized
host is dead. Set SKIP_UNREACHABLE_TARGETS=true only when the operator explicitly
accepts that coverage trade-off.
"""

from __future__ import annotations

import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from agent.ip_audit import emit_ip_event

log = logging.getLogger("scanner_agent.reachability")


def _env_bool(name: str, default: bool = True) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _ports() -> list[int]:
    raw = (os.environ.get("REACHABILITY_PORTS") or "22,80,443,445,3389,139,135,8080").strip()
    out: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
            if 1 <= port <= 65535 and port not in out:
                out.append(port)
        except ValueError:
            continue
    return out or [80, 443, 22]


def _timeout_sec() -> float:
    try:
        return max(0.15, min(5.0, float(os.environ.get("REACHABILITY_TIMEOUT_SEC") or 0.5)))
    except (TypeError, ValueError):
        return 0.5


def _workers(target_count: int) -> int:
    try:
        configured = int(os.environ.get("REACHABILITY_WORKERS") or 10)
    except (TypeError, ValueError):
        configured = 10
    # Keep the same requested five-thread floor when enough targets exist, but
    # never create more workers than targets or an excessive unbounded pool.
    return max(1, min(target_count or 1, max(5, min(32, configured))))


def probe_host(
    host: str,
    *,
    ports: list[int] | None = None,
    timeout: float | None = None,
    job_id: str | None = None,
) -> dict[str, Any]:
    h = (host or "").strip()
    if not h:
        return {"host": h, "reachable": False, "open_port": None, "attempted_ports": [], "errors": []}

    try:
        import ipaddress
        ipaddress.ip_address(h)
    except ValueError:
        # CIDR/range/hostname expressions stay delegated to OpenVAS.
        return {"host": h, "reachable": True, "open_port": None, "attempted_ports": [], "errors": []}

    port_list = ports if ports is not None else _ports()
    to = timeout if timeout is not None else _timeout_sec()
    attempted: list[int] = []
    errors: list[dict[str, Any]] = []
    for port in port_list:
        attempted.append(int(port))
        try:
            with socket.create_connection((h, int(port)), timeout=to):
                if job_id:
                    emit_ip_event(job_id, h, "reachable", open_port=int(port), attempted_ports=attempted)
                return {
                    "host": h,
                    "reachable": True,
                    "open_port": int(port),
                    "attempted_ports": attempted,
                    "errors": errors,
                }
        except OSError as exc:
            errors.append({"port": int(port), "error": exc.__class__.__name__})
            if job_id:
                emit_ip_event(job_id, h, "port_unavailable", port=int(port), error=exc.__class__.__name__)
            continue

    if job_id:
        emit_ip_event(job_id, h, "unreachable", attempted_ports=attempted, reason="no_quick_probe_port_available")
    return {
        "host": h,
        "reachable": False,
        "open_port": None,
        "attempted_ports": attempted,
        "errors": errors,
    }


def host_reachable(host: str, *, ports: list[int] | None = None, timeout: float | None = None) -> bool:
    return bool(probe_host(host, ports=ports, timeout=timeout).get("reachable"))


def partition_targets(targets: list[str], *, job_id: str | None = None) -> dict[str, Any]:
    """Split targets concurrently into reachable and unreachable sets."""
    enabled = _env_bool("SKIP_UNREACHABLE_TARGETS", False)
    clean = [str(t).strip() for t in targets if str(t).strip()]
    if not enabled:
        for host in clean:
            if job_id:
                emit_ip_event(job_id, host, "queued", reachability_filter=False)
        return {"enabled": False, "reachable": clean, "unreachable": [], "skipped_hosts": []}

    reachable: list[str] = []
    unreachable: list[str] = []
    results: dict[str, dict[str, Any]] = {}
    max_workers = _workers(len(clean))

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="aetheris-reach") as pool:
        future_map = {pool.submit(probe_host, host, job_id=job_id): host for host in clean}
        for fut in as_completed(future_map):
            host = future_map[fut]
            try:
                result = fut.result()
            except Exception as exc:
                result = {"host": host, "reachable": False, "open_port": None, "attempted_ports": [], "errors": [{"error": exc.__class__.__name__}]}
                if job_id:
                    emit_ip_event(job_id, host, "unreachable", error=exc.__class__.__name__, reason="probe_error")
            results[host] = result

    # Preserve user-selected order for deterministic reports/UI.
    for host in clean:
        result = results.get(host) or {"reachable": False}
        if result.get("reachable"):
            reachable.append(host)
        else:
            unreachable.append(host)
            log.info("Eliminating unreachable target %s from OpenVAS scan set", host)

    skipped = [{"host": h, "reason": "unreachable"} for h in unreachable]
    return {
        "enabled": True,
        "reachable": reachable,
        "unreachable": unreachable,
        "skipped_hosts": skipped,
        "probe_results": results,
        "probe_workers": max_workers,
    }
