"""Fast pre-scan TCP discovery for the portable Greenbone scanner.

The purpose is not to decide whether an authorized host is alive.  It records
which candidate service ports answer so the scan log can show them.  The
OpenVAS task still scans the Nessus-style catalog in vuln_ports.json, using
SYN inside OpenVAS.  A short connect probe that only sees 135/139/445, or
that sees nothing, must not drop SSH, TLS, SMB, or the rest of that catalog.
"""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

DEFAULT_FAST_RANGE = (
    "T:21-23,T:25,T:53,T:80,T:81,T:88,T:110,T:111,T:135,T:139,T:143,T:389,"
    "T:443,T:445,T:465,T:587,T:631,T:993,T:995,T:1433,T:1521,T:1723,T:2049,"
    "T:3000,T:3306,T:3389,T:5432,T:5672,T:5900,T:5985,T:6379,T:6443,"
    "T:8080,T:8443,T:9000,T:9418,T:27017"
)


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def enabled() -> bool:
    return _env_bool("PORT_DISCOVERY_ENABLED", True)


def parse_tcp_ports(spec: str) -> list[int]:
    raw = (spec or "").strip()
    if raw.upper().startswith("T:"):
        raw = raw[2:]
    out: list[int] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        if token.upper().startswith("T:"):
            token = token[2:]
        if "-" in token:
            left, right = token.split("-", 1)
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            out.extend(range(max(1, lo), min(65535, hi) + 1))
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            out.append(port)
    return sorted(set(out))


def ports_to_gvm_range(ports: list[int]) -> str:
    clean = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    if not clean:
        return DEFAULT_FAST_RANGE
    return ",".join(f"T:{p}" for p in clean)


def _timeout_sec() -> float:
    try:
        return max(0.05, min(2.0, float(os.environ.get("PORT_DISCOVERY_TIMEOUT_SEC") or 1.0)))
    except (TypeError, ValueError):
        return 1.0


def _workers(total_probes: int) -> int:
    try:
        configured = int(os.environ.get("PORT_DISCOVERY_WORKERS") or 32)
    except (TypeError, ValueError):
        configured = 32
    return max(1, min(max(8, configured), max(1, total_probes), 96))


def candidate_range() -> str:
    profile = (os.environ.get("PORT_PROFILE") or "").strip().lower()
    if profile in {"vuln", "nexus", "nessus"}:
        from agent.vuln_ports import tcp_gmp_range

        return tcp_gmp_range()
    return (os.environ.get("PORT_DISCOVERY_RANGE") or DEFAULT_FAST_RANGE).strip() or DEFAULT_FAST_RANGE


def probe_open_tcp_ports(
    hosts: list[str],
    *,
    port_range: str | None = None,
    timeout: float | None = None,
) -> dict[str, list[int]]:
    """Return observed open candidate TCP ports for each host.

    A refused/filtered/timeout result is not treated as proof that the host is
    dead.  Callers must use the fast fallback range when this returns no ports.
    """
    clean_hosts = [str(h).strip() for h in hosts if str(h).strip()]
    ports = parse_tcp_ports(port_range or candidate_range())
    result: dict[str, list[int]] = {host: [] for host in clean_hosts}
    if not clean_hosts or not ports:
        return result

    to = _timeout_sec() if timeout is None else max(0.05, float(timeout))

    def _one(host: str, port: int) -> tuple[str, int, bool]:
        try:
            with socket.create_connection((host, int(port)), timeout=to):
                return host, int(port), True
        except OSError:
            return host, int(port), False

    total = len(clean_hosts) * len(ports)
    with ThreadPoolExecutor(max_workers=_workers(total), thread_name_prefix="aetheris-port") as pool:
        futs = [pool.submit(_one, host, port) for host in clean_hosts for port in ports]
        for fut in as_completed(futs):
            host, port, is_open = fut.result()
            if is_open:
                result[host].append(port)

    for host in result:
        result[host] = sorted(set(result[host]))
    return result


def discovery_plan(hosts: list[str]) -> dict[str, Any]:
    """Build a Greenbone port-range plan without reducing fast-profile coverage."""
    fallback = candidate_range()
    if not enabled():
        return {
            "enabled": False,
            "port_range": fallback,
            "open_ports": {},
            "open_port_count": 0,
            "fallback": True,
        }

    observed = probe_open_tcp_ports(hosts, port_range=fallback)
    union = sorted({p for vals in observed.values() for p in vals})
    if not union:
        return {
            "enabled": True,
            "port_range": fallback,
            "open_ports": observed,
            "open_port_count": 0,
            "fallback": True,
        }
    return {
        "enabled": True,
        "port_range": ports_to_gvm_range(union),
        "open_ports": observed,
        "open_port_count": len(union),
        "fallback": False,
    }
