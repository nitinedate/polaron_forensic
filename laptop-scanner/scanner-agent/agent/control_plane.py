"""Skip OpenVAS web NVTs against the Aetheris API/UI on a scan target."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

from agent.port_range import exclude_tcp_ports_from_range

log = logging.getLogger("scanner_agent.control_plane")

AETHERIS_HTTP_PORTS = (8080, 8081, 8082, 3001, 3002, 3003)


def _body_is_aetheris(payload: str) -> bool:
    try:
        data = json.loads(payload)
    except (TypeError, ValueError):
        lowered = (payload or "").lower()
        return "aetheris" in lowered and ("-api" in lowered or "central-api" in lowered)
    if not isinstance(data, dict):
        return False
    service = str(data.get("service") or "").strip().lower()
    role = str(data.get("role") or "").strip().lower()
    return service == "aetheris" and (
        role in {"central-api", "forensic-api", "mobile-extract-api", "vuln-api"}
        or role.endswith("-api")
    )


def _probe_health(host: str, port: int, *, timeout: float = 0.6) -> bool:
    url = f"http://{host}:{port}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(512).decode("utf-8", errors="replace")
            return _body_is_aetheris(body)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def _central_api_host_port() -> tuple[str | None, int | None]:
    raw = (os.environ.get("CENTRAL_API_URL") or "").strip()
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        return None, None
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


def control_plane_ports_for_hosts(hosts: list[str]) -> set[int]:
    found: set[int] = set()
    api_host, api_port = _central_api_host_port()
    for host in hosts:
        h = (host or "").strip()
        if not h:
            continue
        if api_host and h.casefold() == api_host.casefold() and api_port:
            found.add(int(api_port))
        for port in AETHERIS_HTTP_PORTS:
            if _probe_health(h, port):
                found.add(port)
                log.info("Excluding Aetheris control-plane port %s on %s from OpenVAS", port, h)
    return found


def port_range_without_control_plane(port_range: str, hosts: list[str]) -> str:
    skip = control_plane_ports_for_hosts(hosts)
    if not skip:
        return port_range
    return exclude_tcp_ports_from_range(port_range, skip)
