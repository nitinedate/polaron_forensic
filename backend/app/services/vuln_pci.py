"""PCI-readiness pre-scan evidence (FR-17) — not an ASV attestation."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

PCI_DISCLAIMER = (
    "READINESS ONLY — NOT AN ASV ATTESTATION. "
    "This package maps internal scan findings to PCI-DSS requirement references for remediation planning. "
    "The attested external PCI scan must be performed by a PCI SSC-accredited ASV."
)

# Map common finding patterns to PCI-DSS v4 requirement references (readiness mapping only).
PCI_REQUIREMENT_HINTS: dict[str, str] = {
    "tls": "PCI-DSS 4.2.1",
    "ssl": "PCI-DSS 4.2.1",
    "certificate": "PCI-DSS 4.2.1",
    "log4j": "PCI-DSS 6.3.3",
    "patch": "PCI-DSS 6.3.3",
    "openssl": "PCI-DSS 6.3.3",
    "ssh": "PCI-DSS 2.2.7",
    "default password": "PCI-DSS 2.2.2",
    "firewall": "PCI-DSS 1.3.1",
}


def infer_pci_requirement(synopsis: str | None, cve: str | None, explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    text = f"{synopsis or ''} {cve or ''}".lower()
    for hint, req in PCI_REQUIREMENT_HINTS.items():
        if hint in text:
            return req
    return None


def tag_findings_pci_readiness(db, case_id: str) -> int:
    """Tag open findings with PCI requirement references where inferable."""
    rows = fetchall(
        db,
        """SELECT id, synopsis, cve, pci_requirement_tag FROM vuln_findings
           WHERE case_id = CAST(:cid AS uuid) AND status = 'open'""",
        {"cid": case_id},
    )
    tagged = 0
    for r in rows:
        if r.get("pci_requirement_tag"):
            continue
        req = infer_pci_requirement(r.get("synopsis"), r.get("cve"), None)
        if not req:
            continue
        execute(
            db,
            "UPDATE vuln_findings SET pci_requirement_tag = :req, updated_at = NOW() WHERE id = CAST(:id AS uuid)",
            {"req": req, "id": str(r["id"])},
        )
        tagged += 1
    return tagged


def build_pci_readiness_package(
    db,
    *,
    case_id: str,
    created_by: str | None,
    period_start: str | None = None,
    period_end: str | None = None,
) -> dict[str, Any]:
    tagged = tag_findings_pci_readiness(db, case_id)
    findings = fetchall(
        db,
        """SELECT id, cve, severity, synopsis, pci_requirement_tag, enterprise_risk_score, risk_band
           FROM vuln_findings
           WHERE case_id = CAST(:cid AS uuid) AND status = 'open'
             AND pci_requirement_tag IS NOT NULL
           ORDER BY enterprise_risk_score DESC NULLS LAST""",
        {"cid": case_id},
    )
    payload = {
        "framework": "PCI-DSS",
        "disclaimer": PCI_DISCLAIMER,
        "readiness_only": True,
        "not_asv_attestation": True,
        "case_id": case_id,
        "findings_mapped": len(findings),
        "findings_tagged_this_run": tagged,
        "findings": [
            {
                "id": str(f["id"]),
                "cve": f.get("cve"),
                "severity": f.get("severity"),
                "pci_requirement": f.get("pci_requirement_tag"),
                "risk_band": f.get("risk_band"),
                "synopsis": (f.get("synopsis") or "")[:200],
            }
            for f in findings
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    raw = json.dumps(payload, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    row = fetchone(
        db,
        """INSERT INTO vuln_evidence_packages
           (case_id, framework, control_id, title, metadata_json, integrity_hash, period_start, period_end, created_by)
           VALUES (CAST(:cid AS uuid), 'PCI-DSS', 'readiness', :title, CAST(:meta AS jsonb), :hash,
                   CAST(:ps AS timestamptz), CAST(:pe AS timestamptz),
                   CASE WHEN :uid IS NULL THEN NULL ELSE CAST(:uid AS uuid) END)
           RETURNING id, created_at""",
        {
            "cid": case_id,
            "title": "PCI-DSS Readiness Pre-Scan (Not ASV Attestation)",
            "meta": json.dumps(payload),
            "hash": digest,
            "ps": period_start,
            "pe": period_end,
            "uid": created_by,
        },
    )
    return {
        "id": str(row["id"]),
        "integrity_hash": digest,
        "disclaimer": PCI_DISCLAIMER,
        "findings_mapped": len(findings),
        "classification": "Confidential — Internal Use Only",
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "payload": payload,
    }
