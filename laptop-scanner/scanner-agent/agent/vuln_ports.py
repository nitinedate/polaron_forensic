"""Nessus-style service catalog loaded from vuln_ports.json.

The list is the Aetheris scanning-service specification: core and platform
services, plus the other ports that can produce a vulnerability severity.
UDP entries are that specification's targeted probes, not a full UDP sweep.
A pre-probe that sees nothing does not shrink this catalog.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_PATH = Path(__file__).with_name("vuln_ports.json")


@lru_cache(maxsize=1)
def port_document() -> dict[str, list[dict[str, str]]]:
    raw = json.loads(_PATH.read_text(encoding="utf-8"))
    tcp = [dict(item) for item in raw.get("tcp") or []]
    udp = [dict(item) for item in raw.get("udp") or []]
    return {"tcp": tcp, "udp": udp}


def _gmp_side(items: list[dict[str, Any]], prefix: str) -> str:
    parts: list[str] = []
    for item in items:
        spec = str(item.get("ports") or "").strip()
        if spec:
            parts.append(f"{prefix}:{spec}")
    return ",".join(parts)


def tcp_gmp_range() -> str:
    return _gmp_side(port_document()["tcp"], "T")


def gmp_range() -> str:
    doc = port_document()
    tcp = _gmp_side(doc["tcp"], "T")
    udp = _gmp_side(doc["udp"], "U")
    return f"{tcp},{udp}" if udp else tcp
