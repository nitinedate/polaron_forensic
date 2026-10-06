"""LAN fingerprint for portable scanners.

Detects when the laptop left the network where a job started. OpenVAS tasks
keep a fixed IP list; roaming would otherwise scan the wrong site (especially
when two offices share the same RFC1918 /24).

Docker Desktop NAT hides the host default route, so the host-side
``.lan-fingerprint`` file (written by Write-LanFingerprint.ps1) is preferred.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("scanner_agent.lan")

FINGERPRINT_PATHS = (
    Path(os.environ.get("LAN_FINGERPRINT_FILE") or "/app/.lan-fingerprint"),
    Path("/run/aetheris/lan-fingerprint.json"),
)

_DOCKER_NETS = (
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.65.0/24"),
    ipaddress.ip_network("10.0.2.0/24"),
)


def _ip(value: str) -> ipaddress.IPv4Address | None:
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return parsed if isinstance(parsed, ipaddress.IPv4Address) else None


def is_docker_nat_fingerprint(fp: dict[str, Any] | None) -> bool:
    if not fp:
        return False
    gw = _ip(str(fp.get("gateway") or ""))
    if gw is None:
        return True
    return any(gw in net for net in _DOCKER_NETS)


def _normalize(fp: dict[str, Any]) -> dict[str, str]:
    gateway = str(fp.get("gateway") or "").strip()
    subnet = str(fp.get("subnet") or "").strip()
    if gateway and not subnet:
        ip = _ip(gateway)
        if ip is not None:
            subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return {
        "gateway": gateway,
        "subnet": subnet,
        "source": str(fp.get("source") or "").strip(),
    }


def _from_file() -> dict[str, str] | None:
    for path in FINGERPRINT_PATHS:
        try:
            if not path.is_file():
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            fp = _normalize(raw)
            if not fp["gateway"]:
                continue
            age = time.time() - path.stat().st_mtime
            fp["source"] = fp["source"] or f"file:{path.name}"
            fp["age_sec"] = str(int(age))
            return fp
        except Exception:
            continue
    return None


def _from_proc_route() -> dict[str, str] | None:
    route = Path("/proc/net/route")
    try:
        if not route.is_file():
            return None
        for line in route.read_text(encoding="utf-8").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            dest, gateway_hex = parts[1], parts[2]
            if dest != "00000000":
                continue
            gw_int = int(gateway_hex, 16)
            gateway = ".".join(str((gw_int >> shift) & 0xFF) for shift in (0, 8, 16, 24))
            return _normalize({"gateway": gateway, "source": "proc"})
    except Exception:
        return None
    return None


def _from_env() -> dict[str, str] | None:
    gw = (os.environ.get("SCANNER_LAN_GATEWAY") or "").strip()
    subnet = (os.environ.get("SCANNER_LAN_SUBNET") or "").strip()
    if not gw:
        return None
    return _normalize({"gateway": gw, "subnet": subnet, "source": "env"})


def should_watch_lan(scanner_role: str | None) -> bool:
    """LAN-change abort is Portable-only. Persistent Edge must not roam-abort."""
    return str(scanner_role or "").strip().lower() == "portable"


def capture_lan_fingerprint() -> dict[str, str]:
    file_fp = _from_file()
    if file_fp and not is_docker_nat_fingerprint(file_fp):
        return file_fp
    proc_fp = _from_proc_route()
    if proc_fp and not is_docker_nat_fingerprint(proc_fp):
        return proc_fp
    env_fp = _from_env()
    if env_fp:
        return env_fp
    return file_fp or proc_fp or {}


def lan_changed(origin: dict[str, str] | None, current: dict[str, str] | None) -> bool:
    """True when the host default gateway or /24 changed.

    Missing fingerprints are not treated as a change (avoids aborting inside
    Docker NAT when the host file has not been written yet).
    """
    if not origin or not current:
        return False
    og = str(origin.get("gateway") or "").strip()
    cg = str(current.get("gateway") or "").strip()
    if not og or not cg:
        return False
    if is_docker_nat_fingerprint(origin) and is_docker_nat_fingerprint(current):
        return False
    if og != cg:
        return True
    osn = str(origin.get("subnet") or "").strip()
    csn = str(current.get("subnet") or "").strip()
    return bool(osn and csn and osn != csn)
