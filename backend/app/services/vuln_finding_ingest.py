"""Normalize and upsert vuln findings with KEV enrichment, dedup, and BRD §9 scoring."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from app.db.sql_helpers import execute, fetchone
from app.services.aetheris_severity import SEVERITY_RANK, choose_cvss_score, classify_severity, severity_basis, severity_from_cvss
from app.services.vuln_kev_feed import is_kev_cve
from app.services.vuln_risk import score_finding

log = logging.getLogger("vuln_finding_ingest")

# Back-compat aliases used by older tests / callers.
_severity_from_cvss = severity_from_cvss


def _canonical_severity(raw_severity: Any, cvss: float) -> str:
    sev, _ = classify_severity(cvss=cvss, raw_severity=raw_severity)
    return sev


def normalize_raw_vuln(v: dict[str, Any]) -> dict[str, Any]:
    # Preserve version-specific scores; select the configured basis, with explicit
    # fallback provenance. Generic Greenbone signals use the strongest valid value.
    cvss, score_source, score_candidates = choose_cvss_score(v)
    basis = score_source if score_source in {"cvss_v2", "cvss_v3", "cvss_v4"} else severity_basis()
    synopsis = v.get("plugin_name") or v.get("synopsis") or v.get("name") or ""
    sev, policy_rule = classify_severity(cvss=cvss, synopsis=str(synopsis), raw_severity=v.get("severity"), basis=basis)
    raw_scanner = str(v.get("severity") or "info").strip().lower()
    if raw_scanner in {"log", "debug"}:
        raw_scanner = "info"
    scanner_sev = raw_scanner if raw_scanner in SEVERITY_RANK else "info"
    cves: list[str] = []
    for source in (v.get("cves"), v.get("cve")):
        values = source if isinstance(source, list) else [source]
        for value in values:
            if value is None:
                continue
            for match in re.findall(r"CVE-\d{4}-\d{4,}", str(value), flags=re.I):
                item = match.upper()
                if item not in cves:
                    cves.append(item)
    cve = cves[0] if cves else None
    cwe = str(v.get("cwe") or v.get("cwe_id") or "").strip().upper() or None
    cvss_vector = str(v.get("cvss_vector") or v.get("cvss3_vector") or v.get("cvss_v3_vector") or v.get("cvss4_vector") or v.get("cvss_v4_vector") or "").strip() or None
    references = v.get("references") or v.get("refs") or []
    if isinstance(references, str):
        references = [references]
    if not isinstance(references, list):
        references = []
    return {
        "plugin_id": str(v.get("plugin_id") or v.get("pluginID") or v.get("nvt_oid") or ""),
        "plugin_family": v.get("plugin_family") or v.get("family"),
        "cve": cve,
        "cves": cves,
        "cwe": cwe,
        "cvss": cvss,
        "severity_basis": basis,
        "severity_score_source": score_source,
        "cvss_candidates": score_candidates,
        "score_available": bool(score_candidates) and v.get("score_available") is not False,
        "vpr_score": v.get("vpr_score"),
        "epss_score": v.get("epss_score"),
        "cvss_vector": cvss_vector,
        "references": [str(x) for x in references if str(x).strip()][:50],
        "severity": sev,
        "scanner_severity": scanner_sev,
        "severity_policy_rule": policy_rule,
        "source_result_id": str(v.get("source_result_id") or v.get("result_id") or "").strip() or None,
        "synopsis": synopsis,
        "description": v.get("description") or "",
        "remediation": v.get("solution") or v.get("remediation") or "",
        "port": v.get("port"),
        "protocol": v.get("protocol"),
        "service": v.get("service"),
        "endpoint_context": {key: str(v[key])[:1000] for key in ("service", "product", "cpe", "version") if v.get(key)},
        "pci_requirement_tag": v.get("pci_requirement_tag"),
        "scan_engine": v.get("scan_engine"),
        "qod": v.get("qod") if v.get("qod") is not None else v.get("quality_of_detection"),
        "qod_type": v.get("qod_type") or v.get("quality_of_detection_type"),
    }


def upsert_finding(
    db,
    *,
    case_id: str,
    scan_job_id: str | None,
    asset_id: str,
    vuln: dict[str, Any],
    asset_meta: dict[str, Any] | None = None,
    credentialed: bool = False,
    source: str = "scan",
) -> str | None:
    """Insert or update finding; returns finding id."""
    norm = normalize_raw_vuln(vuln)
    meta = asset_meta or {}
    kev = is_kev_cve(db, norm["cve"])
    days_open = 0
    # A finding occurrence belongs to one immutable scan report.  Reusing a
    # row from an older job and changing scan_job_id makes the finding vanish
    # from the older report and appear in the newer one.  Deduplicate retries
    # only inside the same scan job.
    existing = fetchone(
        db,
        """SELECT id, first_seen_at, status FROM vuln_findings
           WHERE asset_id = CAST(:aid AS uuid)
             AND scan_job_id IS NOT DISTINCT FROM CAST(:jid AS uuid)
             AND COALESCE(risk_factors_json->>'source_result_id', '') = COALESCE(:rid, '')
             AND COALESCE(plugin_id, '') = COALESCE(:pid, '')
             AND COALESCE(cve, '') = COALESCE(:cve, '')
             AND COALESCE(port, -1) = COALESCE(:port, -1)
             AND LOWER(COALESCE(protocol, '')) = LOWER(COALESCE(:proto, ''))
           ORDER BY created_at DESC LIMIT 1""",
        {
            "aid": asset_id,
            "jid": scan_job_id,
            "rid": norm.get("source_result_id"),
            "pid": norm["plugin_id"] or None,
            "cve": norm["cve"],
            "port": norm.get("port"),
            "proto": norm.get("protocol"),
        },
    )
    if existing and existing.get("first_seen_at"):
        try:
            fs = existing["first_seen_at"]
            if hasattr(fs, "timestamp"):
                days_open = max(0, int((datetime.now(timezone.utc) - fs.replace(tzinfo=timezone.utc)).days))
        except Exception:
            days_open = 0

    scored = score_finding(
        cvss=norm["cvss"],
        is_kev=kev,
        external_exposure=meta.get("external_exposure") or "internal",
        asset_criticality=meta.get("criticality") or "tier2",
        days_open=days_open,
        credentialed=credentialed,
        qod=norm.get("qod"),
        vpr_score=norm.get("vpr_score"),
        epss_score=norm.get("epss_score"),
    )
    factors = dict(scored["risk_factors_json"])
    factors["source"] = source
    factors["scanner_severity"] = norm["scanner_severity"]
    factors["severity_basis"] = norm["severity_basis"]
    factors["severity_score_source"] = norm["severity_score_source"]
    factors["cvss_candidates"] = norm["cvss_candidates"]
    factors["score_available"] = norm["score_available"]
    if norm["endpoint_context"]:
        factors["endpoint_context"] = norm["endpoint_context"]
    if norm.get("severity_policy_rule"):
        factors["severity_profile"] = "aetheris"
        factors["severity_policy_rule"] = norm["severity_policy_rule"]
    if norm.get("source_result_id"):
        factors["source_result_id"] = norm["source_result_id"]
    if norm.get("scan_engine"):
        factors["scan_engine"] = norm["scan_engine"]
    if norm.get("qod") is not None:
        try:
            factors["quality_of_detection"] = float(norm["qod"])
        except (TypeError, ValueError):
            factors["quality_of_detection"] = norm["qod"]
    if norm.get("qod_type"):
        factors["quality_of_detection_type"] = str(norm["qod_type"])
    if norm.get("cves"):
        factors["cves"] = list(norm["cves"])
    if norm.get("cwe"):
        factors["cwe"] = norm["cwe"]
    if norm.get("cvss_vector"):
        factors["cvss_vector"] = norm["cvss_vector"]
    if norm.get("references"):
        factors["references"] = list(norm["references"])

    if existing and existing.get("status") not in ("resolved",):
        fid = str(existing["id"])
        execute(
            db,
            """UPDATE vuln_findings SET
                 scan_job_id = CAST(:jid AS uuid),
                 cvss = :cvss, severity = :sev, synopsis = :syn, remediation = :rem,
                 description = COALESCE(:desc, description),
                 scan_engine = COALESCE(:engine, scan_engine),
                 port = :port, protocol = :proto, service = :svc,
                 is_kev = :kev, enterprise_risk_score = :ers, risk_band = :band,
                 risk_factors_json = CAST(:rf AS jsonb),
                 pci_requirement_tag = COALESCE(:pci, pci_requirement_tag),
                 last_seen_at = NOW(), updated_at = NOW()
               WHERE id = CAST(:id AS uuid)""",
            {
                "jid": scan_job_id,
                "cvss": norm["cvss"],
                "sev": norm["severity"],
                "syn": norm["synopsis"],
                "rem": norm["remediation"],
                "desc": norm.get("description") or None,
                "engine": norm.get("scan_engine"),
                "port": norm.get("port"),
                "proto": norm.get("protocol"),
                "svc": norm.get("service"),
                "kev": kev,
                "ers": scored["enterprise_risk_score"],
                "band": scored["risk_band"],
                "rf": json.dumps(factors),
                "pci": norm.get("pci_requirement_tag"),
                "id": fid,
            },
        )
        return fid

    row = fetchone(
        db,
        """INSERT INTO vuln_findings
           (case_id, scan_job_id, asset_id, plugin_id, plugin_family, cve, cvss, severity,
            port, protocol, service, synopsis, description, remediation, status,
            enterprise_risk_score, risk_band, risk_factors_json, is_kev, pci_requirement_tag, scan_engine)
           VALUES (CAST(:cid AS uuid), CAST(:jid AS uuid), CAST(:aid AS uuid),
                   :pid, :pfam, :cve, :cvss, :sev, :port, :proto, :svc, :syn, :desc, :rem, 'open',
                   :ers, :band, CAST(:rf AS jsonb), :kev, :pci, :engine)
           RETURNING id""",
        {
            "cid": case_id,
            "jid": scan_job_id,
            "aid": asset_id,
            "pid": norm["plugin_id"] or None,
            "pfam": norm["plugin_family"],
            "cve": norm["cve"],
            "cvss": norm["cvss"],
            "sev": norm["severity"],
            "port": norm.get("port"),
            "proto": norm.get("protocol"),
            "svc": norm.get("service"),
            "syn": norm["synopsis"],
            "desc": norm.get("description") or None,
            "rem": norm["remediation"],
            "ers": scored["enterprise_risk_score"],
            "band": scored["risk_band"],
            "rf": json.dumps(factors),
            "kev": kev,
            "pci": norm.get("pci_requirement_tag"),
            "engine": norm.get("scan_engine") or source,
        },
    )
    return str(row["id"]) if row else None


def refresh_asset_risk(db, asset_id: str) -> None:
    risk = fetchone(
        db,
        """SELECT COALESCE(AVG(enterprise_risk_score), 0)::float AS avg_risk
           FROM vuln_findings WHERE asset_id = CAST(:aid AS uuid) AND status = 'open'""",
        {"aid": asset_id},
    )
    execute(
        db,
        "UPDATE vuln_assets SET risk_score = :r, updated_at = NOW() WHERE id = CAST(:aid AS uuid)",
        {"r": float((risk or {}).get("avg_risk") or 0), "aid": asset_id},
    )
