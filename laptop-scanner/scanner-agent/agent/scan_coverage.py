"""Scan coverage verdict (V45.4).

A Greenbone task reaches ``Done`` even when its port-scanner NVT was killed by
``scanner_plugins_timeout``: no open ports -> no service NVTs -> three
informational results -> ``errors/count = 1`` -> reported as *completed*.
Three IPs in ~390 s each with ``severity={'info': 3}`` is that signature.

This module turns the report into an explicit verdict so the agent can retry
once and the central/UI can show **incomplete** instead of a green row.

Signals (all from the report XML, no network calls):

* ``port_scanner_errors`` — ``<errors><error>`` rows whose NVT is a scanner
  (Nmap / Ping Host / Services) or whose text says timeout/killed/exceeded;
* ``nvts_launched`` — distinct NVT OIDs that produced a result or an
  ``EXIT_CODE`` host detail (a full "Full and fast" run is thousands; a
  truncated one is < 30);
* ``open_tcp_ports`` — host details ``ports``/``tcp_ports``/``Open TCP Port``
  plus result ports of the form ``N/tcp``.

Verdict:
  ``full``                      scanner ran, ports were enumerated
  ``degraded_port_scan_failed`` scanner NVT error/timeout (retry-able)
  ``degraded_no_ports``         zero ports and very few NVTs on an alive host
"""

from __future__ import annotations

import re
from typing import Any

# Greenbone scanner NVT OIDs (stable across feeds).
SCANNER_NVT_OIDS: frozenset[str] = frozenset({
    "1.3.6.1.4.1.25623.1.0.14259",   # Nmap (NASL wrapper)
    "1.3.6.1.4.1.25623.1.0.100315",  # Ping Host
    "1.3.6.1.4.1.25623.1.0.10330",   # Services
    "1.3.6.1.4.1.25623.1.0.900239",  # Open TCP Port (legacy)
    "1.3.6.1.4.1.25623.1.0.108521",  # Nmap UDP
    "1.3.6.1.4.1.25623.1.0.11219",   # Nmap (NASL wrapper, alt)
})
_SCANNER_NAME_RE = re.compile(r"nmap|ping host|port ?scan|^services$|open tcp port|openvasd port", re.I)
_TIMEOUT_RE = re.compile(r"time ?out|timed out|killed|exceeded|took too long|was interrupted", re.I)
_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)$", re.I)
_PORT_DETAIL_NAMES = {"ports", "tcp_ports", "udp_ports", "open ports", "open_ports", "tcp ports"}

MIN_NVTS_FOR_FULL = 30


def _text(node: Any, path: str) -> str:
    try:
        return (node.findtext(path) or "").strip()
    except Exception:
        return ""


def _host_matches(node_host: str, host: str | None) -> bool:
    if not host:
        return True
    return (node_host or "").strip() == host.strip()


def coverage_from_report(report: Any, *, host: str | None = None, errors: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return the coverage verdict for one host (or the whole report when host is None)."""
    out: dict[str, Any] = {
        "host": host,
        "nvts_launched": 0,
        "open_tcp_ports": [],
        "open_udp_ports": [],
        "port_scanner_errors": [],
        "other_errors": 0,
        "verdict": "full",
        "reason": "",
    }
    if report is None:
        out["verdict"] = "unknown"
        out["reason"] = "no report"
        return out

    # ---- errors ------------------------------------------------------------
    errs = errors if errors is not None else []
    if errors is None:
        try:
            for e in report.xpath("./errors/error") or report.xpath(".//errors/error"):
                nvt = e.find("nvt")
                errs.append({
                    "host": _text(e, "host"),
                    "nvt_oid": (nvt.get("oid") or "").strip() if nvt is not None else "",
                    "nvt_name": (_text(nvt, "name") if nvt is not None else "") or _text(e, "name"),
                    "description": _text(e, "description"),
                })
        except Exception:
            pass
    for e in errs:
        if not _host_matches(str(e.get("host") or ""), host):
            continue
        oid = str(e.get("nvt_oid") or "")
        name = str(e.get("nvt_name") or "")
        desc = str(e.get("description") or "")
        if oid in SCANNER_NVT_OIDS or _SCANNER_NAME_RE.search(name) or (
            _TIMEOUT_RE.search(desc) and _SCANNER_NAME_RE.search(desc)
        ):
            out["port_scanner_errors"].append({"nvt_oid": oid or None, "nvt_name": name or None, "description": desc[:300]})
        else:
            out["other_errors"] += 1

    # ---- NVTs launched + ports --------------------------------------------
    oids: set[str] = set()
    tcp: set[int] = set()
    udp: set[int] = set()
    try:
        for r in report.xpath(".//results/result"):
            if not _host_matches(_text(r, "host"), host):
                continue
            nvt = r.find("nvt")
            if nvt is not None and nvt.get("oid"):
                oids.add(nvt.get("oid"))
            m = _PORT_RE.match(_text(r, "port"))
            if m:
                (tcp if m.group(2).lower() == "tcp" else udp).add(int(m.group(1)))
    except Exception:
        pass
    try:
        for h in report.xpath(".//host"):
            if not _host_matches(_text(h, "ip") or (h.get("ip") or ""), host):
                continue
            for d in h.findall("detail"):
                name = _text(d, "name")
                value = _text(d, "value")
                if name == "EXIT_CODE":
                    src = d.find("source")
                    src_name = _text(src, "name") if src is not None else ""
                    if src_name:
                        oids.add(src_name)
                elif name.lower() in _PORT_DETAIL_NAMES or name.lower().startswith("open tcp port") or name.lower().startswith("open udp port"):
                    for tok in re.split(r"[,\s]+", value):
                        m = _PORT_RE.match(tok.strip())
                        if m:
                            (tcp if m.group(2).lower() == "tcp" else udp).add(int(m.group(1)))
                        elif tok.strip().isdigit():
                            tcp.add(int(tok))
    except Exception:
        pass
    out["nvts_launched"] = len(oids)
    out["open_tcp_ports"] = sorted(tcp)[:512]
    out["open_udp_ports"] = sorted(udp)[:128]

    # ---- verdict -----------------------------------------------------------
    if out["port_scanner_errors"]:
        first = out["port_scanner_errors"][0]
        out["verdict"] = "degraded_port_scan_failed"
        out["reason"] = (
            f"port scanner NVT failed ({first.get('nvt_name') or first.get('nvt_oid') or 'scanner'}: "
            f"{(first.get('description') or 'error')[:120]}) — service NVTs never ran"
        )
    elif not tcp and not udp and out["nvts_launched"] < MIN_NVTS_FOR_FULL:
        out["verdict"] = "degraded_no_ports"
        out["reason"] = (
            f"no open ports enumerated and only {out['nvts_launched']} NVT(s) ran — "
            "host filtered, scanner timed out, or feed not loaded"
        )
    else:
        out["reason"] = f"{len(tcp)} TCP / {len(udp)} UDP port(s), {out['nvts_launched']} NVT(s) ran"
    return out


def is_degraded(coverage: dict[str, Any] | None) -> bool:
    return str((coverage or {}).get("verdict") or "").startswith("degraded")
