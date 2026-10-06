"""Tenable Nessus report normalization.

This module does not ship or emulate Tenable's proprietary NASL plugin feed.
It normalizes *results produced by a licensed Nessus scanner* so the platform
can ingest every finding row with Tenable-compatible CVSS severity semantics.
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _first(row: dict[str, Any], *names: str) -> str:
    lowered = {str(k).strip().lower(): k for k in row.keys() if k is not None}
    for name in names:
        key = lowered.get(name.strip().lower())
        if key is None:
            continue
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _float(value: Any) -> float | None:
    try:
        text = str(value).strip()
        return float(text) if text else None
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    text = str(value or "").strip()
    if "/" in text:
        text = text.split("/", 1)[0]
    try:
        return int(text)
    except ValueError:
        return None


def _cves(*values: Any) -> list[str]:
    out: list[str] = []
    for value in values:
        for match in _CVE_RE.findall(str(value or "")):
            item = match.upper()
            if item not in out:
                out.append(item)
    return out


def parse_nessus_csv_findings(csv_text: str) -> list[dict[str, Any]]:
    """Return one normalized scanner row for every Nessus CSV finding.

    Column aliases cover common Nessus Professional/Expert exports across
    versions.  The ingest layer chooses the configured CVSS severity basis.
    """
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        raise ValueError("Nessus CSV has no header row")

    findings: list[dict[str, Any]] = []
    for raw in reader:
        host = _first(raw, "Host", "IP Address", "IP", "Hostname")
        plugin_name = _first(raw, "Name", "Plugin Name", "Synopsis")
        if not host or not plugin_name:
            continue

        cvss2 = _float(_first(raw, "CVSS Base Score", "CVSS v2.0 Base Score", "CVSS V2 Base Score", "CVSS"))
        cvss3 = _float(_first(raw, "CVSS v3.1 Base Score", "CVSS v3.0 Base Score", "CVSS V3 Base Score", "CVSS3 Base Score"))
        cvss4 = _float(_first(raw, "CVSS v4.0 Base Score", "CVSS V4 Base Score", "CVSS4 Base Score"))
        vpr = _float(_first(raw, "VPR Score", "VPR"))
        epss = _float(_first(raw, "EPSS Score", "EPSS"))
        cves = _cves(_first(raw, "CVE", "CVEs", "CVE ID"), _first(raw, "Description"))

        refs: list[str] = []
        for col in ("See Also", "References", "Reference"):
            text = _first(raw, col)
            if text:
                refs.extend([x.strip() for x in re.split(r"[\r\n,]+", text) if x.strip()])

        findings.append(
            {
                "plugin_id": _first(raw, "Plugin ID", "PluginID", "Plugin"),
                "plugin_family": _first(raw, "Plugin Family", "Family"),
                "plugin_name": plugin_name,
                "synopsis": _first(raw, "Synopsis") or plugin_name,
                "description": _first(raw, "Description", "Plugin Output"),
                "solution": _first(raw, "Solution", "Remediation"),
                "host": host,
                "port": _int(_first(raw, "Port")),
                "protocol": _first(raw, "Protocol").lower() or None,
                "service": _first(raw, "Service", "Svc Name") or None,
                "cve": cves[0] if cves else None,
                "cves": cves,
                "cwe": _first(raw, "CWE") or None,
                "severity": _first(raw, "Risk", "Severity", "Risk Factor").lower() or "info",
                "scanner_threat": _first(raw, "Risk", "Severity", "Risk Factor") or None,
                "cvss2": cvss2,
                "cvss_v2": cvss2,
                "cvss3": cvss3,
                "cvss_v3": cvss3,
                "cvss4": cvss4,
                "cvss_v4": cvss4,
                "cvss_vector": _first(raw, "CVSS v4.0 Vector", "CVSS v3.0 Vector", "CVSS Vector") or None,
                "vpr_score": vpr,
                "epss_percentile": epss,
                "exploit_maturity": _first(raw, "Exploit Code Maturity", "Exploit Maturity") or None,
                "references": refs[:50],
                "plugin_output": _first(raw, "Plugin Output") or None,
                "scan_engine": "nessus",
                "source_result_id": _first(raw, "Vuln UUID", "Finding ID") or None,
            }
        )
    return findings
