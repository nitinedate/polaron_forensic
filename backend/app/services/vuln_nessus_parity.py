"""Nessus-to-Aetheris parity comparison without mutating findings.

The comparator is intentionally read-only. It accepts a Nessus CSV export and
compares it with the normalized Aetheris findings already stored for a case.
Critical/High coverage is the primary gate, while all severities are reported.
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from app.db.sql_helpers import fetchall

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_WORD_RE = re.compile(r"[a-z0-9]+")


def _first(row: dict[str, Any], *names: str) -> str:
    lowered = {str(k).strip().lower(): k for k in row.keys() if k is not None}
    for name in names:
        key = lowered.get(name.strip().lower())
        if key is not None:
            value = row.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()
    return ""


def _float(value: Any) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _severity(raw: Any, cvss: float) -> str:
    val = str(raw or "").strip().lower()
    aliases = {
        "informational": "info",
        "none": "info",
        "log": "info",
        "moderate": "medium",
    }
    val = aliases.get(val, val)
    scanner = val if val in _SEV_RANK else "info"
    numeric = _severity_from_cvss(cvss)
    return scanner if _SEV_RANK[scanner] >= _SEV_RANK[numeric] else numeric


def _port(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    if "/" in text:
        text = text.split("/", 1)[0]
    try:
        return int(text)
    except ValueError:
        return None


def _cves(value: Any) -> list[str]:
    found = {m.group(0).upper() for m in _CVE_RE.finditer(str(value or ""))}
    return sorted(found)


def _tokens(value: Any) -> set[str]:
    return set(_WORD_RE.findall(str(value or "").lower()))


def _name_similarity(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / max(1, len(ta | tb))


def parse_nessus_csv(csv_text: str) -> list[dict[str, Any]]:
    """Parse common Tenable/Nessus CSV column variants into a neutral shape."""
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        raise ValueError("Nessus CSV has no header row")

    rows: list[dict[str, Any]] = []
    for raw in reader:
        host = _first(raw, "Host", "IP Address", "IP", "Hostname")
        name = _first(raw, "Name", "Plugin Name", "Synopsis")
        if not host or not name:
            continue
        cvss_candidates = [
            _float(_first(raw, "CVSS v4.0 Base Score", "CVSS V4 Base Score", "CVSS4 Base Score")),
            _float(_first(raw, "CVSS v3.1 Base Score", "CVSS v3.0 Base Score", "CVSS V3 Base Score", "CVSS3 Base Score")),
            _float(_first(raw, "CVSS v2.0 Base Score", "CVSS Base Score", "CVSS")),
        ]
        cvss = max(cvss_candidates, default=0.0)
        cve_text = _first(raw, "CVE", "CVEs", "CVE ID")
        rows.append(
            {
                "host": host.strip().lower(),
                "port": _port(_first(raw, "Port")),
                "protocol": _first(raw, "Protocol").strip().lower() or None,
                "plugin_id": _first(raw, "Plugin ID", "PluginID", "Plugin").strip(),
                "plugin_family": _first(raw, "Plugin Family", "Family"),
                "name": name,
                "cves": _cves(cve_text),
                "cvss": cvss,
                "severity": _severity(_first(raw, "Risk", "Severity"), cvss),
                "description": _first(raw, "Description"),
                "solution": _first(raw, "Solution", "Remediation"),
            }
        )
    return rows


def _aetheris_rows(db, case_id: str) -> list[dict[str, Any]]:
    rows = fetchall(
        db,
        """SELECT f.id, f.plugin_id, f.plugin_family, f.cve, f.cvss, f.severity,
                  f.port, f.protocol, f.synopsis, f.description, f.remediation,
                  COALESCE(NULLIF(trim(a.primary_ip), ''), NULLIF(trim(a.hostname), '')) AS host
             FROM vuln_findings f
             LEFT JOIN vuln_assets a ON a.id = f.asset_id
            WHERE f.case_id = CAST(:cid AS uuid)
              AND f.status IN ('open', 'exception')
            ORDER BY f.created_at DESC""",
        {"cid": case_id},
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "id": str(r.get("id") or ""),
                "host": str(r.get("host") or "").strip().lower(),
                "port": _port(r.get("port")),
                "protocol": str(r.get("protocol") or "").strip().lower() or None,
                "plugin_id": str(r.get("plugin_id") or "").strip(),
                "plugin_family": str(r.get("plugin_family") or "").strip(),
                "name": str(r.get("synopsis") or "").strip(),
                "cves": _cves(r.get("cve")),
                "cvss": _float(r.get("cvss")),
                "severity": _severity(r.get("severity"), _float(r.get("cvss"))),
            }
        )
    return out


def _match_score(ref: dict[str, Any], got: dict[str, Any]) -> int:
    # Host identity is mandatory for parity. A cross-host name match is not evidence.
    if ref.get("host") != got.get("host"):
        return -1
    score = 40

    rp, gp = ref.get("port"), got.get("port")
    if rp is not None and gp is not None:
        if rp != gp:
            return -1
        score += 20
    elif rp == gp:
        score += 8

    rc, gc = set(ref.get("cves") or []), set(got.get("cves") or [])
    if rc and gc:
        if rc & gc:
            score += 100
        else:
            # Different explicit CVEs on same host/port are not equivalent.
            return -1

    rpid, gpid = str(ref.get("plugin_id") or ""), str(got.get("plugin_id") or "")
    if rpid and gpid and rpid == gpid:
        score += 80

    sim = _name_similarity(str(ref.get("name") or ""), str(got.get("name") or ""))
    if sim >= 0.90:
        score += 60
    elif sim >= 0.65:
        score += 35
    elif sim >= 0.45:
        score += 15

    if ref.get("protocol") and got.get("protocol") and ref.get("protocol") == got.get("protocol"):
        score += 5
    return score


def compare_rows(reference: list[dict[str, Any]], observed: list[dict[str, Any]]) -> dict[str, Any]:
    used: set[int] = set()
    matched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    severity_mismatches: list[dict[str, Any]] = []

    # High-impact rows first so a weak generic match cannot consume a better candidate.
    ordered = sorted(reference, key=lambda r: (_SEV_RANK.get(str(r.get("severity")), 0), r.get("cvss") or 0), reverse=True)
    for ref in ordered:
        best_idx = None
        best_score = -1
        for idx, got in enumerate(observed):
            if idx in used:
                continue
            score = _match_score(ref, got)
            if score > best_score:
                best_idx, best_score = idx, score
        # 95 means host+port plus either strong name similarity or a stronger identity signal.
        if best_idx is None or best_score < 95:
            missing.append(ref)
            continue
        got = observed[best_idx]
        used.add(best_idx)
        item = {"nessus": ref, "aetheris": got, "match_score": best_score}
        matched.append(item)
        if _SEV_RANK.get(str(got.get("severity")), 0) < _SEV_RANK.get(str(ref.get("severity")), 0):
            severity_mismatches.append(item)

    extra = [row for idx, row in enumerate(observed) if idx not in used]
    ref_ch = [r for r in reference if _SEV_RANK.get(str(r.get("severity")), 0) >= _SEV_RANK["high"]]
    missing_ch = [r for r in missing if _SEV_RANK.get(str(r.get("severity")), 0) >= _SEV_RANK["high"]]
    sev_ch = [m for m in severity_mismatches if _SEV_RANK.get(str(m["nessus"].get("severity")), 0) >= _SEV_RANK["high"]]
    matched_ch = max(0, len(ref_ch) - len(missing_ch))
    coverage = round((matched_ch / len(ref_ch)) * 100.0, 1) if ref_ch else 100.0

    return {
        "reference_total": len(reference),
        "aetheris_total": len(observed),
        "matched_total": len(matched),
        "missing_total": len(missing),
        "severity_mismatch_total": len(severity_mismatches),
        "critical_high_reference": len(ref_ch),
        "critical_high_matched": matched_ch,
        "critical_high_missing": len(missing_ch),
        "critical_high_severity_mismatches": len(sev_ch),
        "critical_high_coverage_pct": coverage,
        "critical_high_gate_pass": len(missing_ch) == 0 and len(sev_ch) == 0,
        "missing_critical_high": missing_ch,
        "severity_mismatches": severity_mismatches,
        "missing_all": missing,
        "extra_aetheris": extra,
    }


def compare_nessus_csv(db, *, case_id: str, csv_text: str) -> dict[str, Any]:
    reference = parse_nessus_csv(csv_text)
    if not reference:
        raise ValueError("No usable Nessus rows were found (Host and Name are required)")
    observed = _aetheris_rows(db, case_id)
    result = compare_rows(reference, observed)
    result["case_id"] = case_id
    result["mode"] = "read_only_nessus_parity"
    return result
