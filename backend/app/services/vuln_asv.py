"""PCI ASV external attestation workflow (FR-17 companion).

Platform prepares submission packs and records attestations returned by
accredited ASV vendors — it does NOT self-attest PCI compliance.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

ASV_DISCLAIMER = (
    "This submission package is for an accredited PCI SSC Approved Scanning Vendor (ASV). "
    "The platform does NOT perform ASV attestation or claim PCI compliance. "
    "Only an accredited ASV may issue the attested external scan report."
)


def row_asv_provider(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(r["id"]),
        "name": r["name"],
        "accreditation_id": r.get("accreditation_id"),
        "contact_email": r.get("contact_email"),
        "api_endpoint": r.get("api_endpoint"),
        "status": r.get("status"),
    }


def create_asv_provider(db, *, name: str, accreditation_id: str | None = None, contact_email: str | None = None) -> dict[str, Any]:
    row = fetchone(
        db,
        """INSERT INTO vuln_asv_providers (name, accreditation_id, contact_email)
           VALUES (:name, :acc, :email) RETURNING *""",
        {"name": name, "acc": accreditation_id, "email": contact_email},
    )
    return row_asv_provider(row)


def build_asv_submission_package(
    db,
    *,
    case_id: str,
    provider_id: str | None,
    target_scope: str,
    created_by: str | None,
) -> dict[str, Any]:
    findings = fetchall(
        db,
        """SELECT id, cve, severity, synopsis, pci_requirement_tag, enterprise_risk_score, risk_band, port, protocol
           FROM vuln_findings
           WHERE case_id = CAST(:cid AS uuid) AND status = 'open'
           ORDER BY enterprise_risk_score DESC NULLS LAST""",
        {"cid": case_id},
    )
    assets = fetchall(
        db,
        "SELECT id, hostname, primary_ip, external_exposure, criticality FROM vuln_assets WHERE case_id = CAST(:cid AS uuid)",
        {"cid": case_id},
    )
    package = {
        "framework": "PCI-DSS",
        "disclaimer": ASV_DISCLAIMER,
        "not_self_attestation": True,
        "requires_accredited_asv": True,
        "case_id": case_id,
        "target_scope": target_scope,
        "assets": [
            {
                "id": str(a["id"]),
                "hostname": a.get("hostname"),
                "primary_ip": a.get("primary_ip"),
                "external_exposure": a.get("external_exposure"),
                "criticality": a.get("criticality"),
            }
            for a in assets
        ],
        "findings": [
            {
                "id": str(f["id"]),
                "cve": f.get("cve"),
                "severity": f.get("severity"),
                "pci_requirement": f.get("pci_requirement_tag"),
                "risk_band": f.get("risk_band"),
                "port": f.get("port"),
                "protocol": f.get("protocol"),
                "synopsis": (f.get("synopsis") or "")[:300],
            }
            for f in findings
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    raw = json.dumps(package, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    row = fetchone(
        db,
        """INSERT INTO vuln_asv_submissions
           (case_id, provider_id, target_scope, submission_hash, status, disclaimer, package_json, created_by)
           VALUES (CAST(:cid AS uuid),
                   CASE WHEN :pid IS NULL THEN NULL ELSE CAST(:pid AS uuid) END,
                   :scope, :hash, 'ready', :disc, CAST(:pkg AS jsonb),
                   CASE WHEN :uid IS NULL THEN NULL ELSE CAST(:uid AS uuid) END)
           RETURNING id, created_at""",
        {
            "cid": case_id,
            "pid": provider_id,
            "scope": target_scope,
            "hash": digest,
            "disc": ASV_DISCLAIMER,
            "pkg": raw,
            "uid": created_by,
        },
    )
    return {
        "id": str(row["id"]),
        "submission_hash": digest,
        "disclaimer": ASV_DISCLAIMER,
        "status": "ready",
        "findings_count": len(findings),
        "assets_count": len(assets),
        "package": package,
    }


def record_asv_attestation(
    db,
    *,
    submission_id: str,
    attestation_ref: str,
    attestation_date: str | None,
    result_status: str,
    document_ref: str | None,
    notes: str | None,
    recorded_by: str | None,
) -> dict[str, Any]:
    row = fetchone(
        db,
        """INSERT INTO vuln_asv_attestations
           (submission_id, attestation_ref, attestation_date, result_status, attestation_document_ref, notes, recorded_by)
           VALUES (CAST(:sid AS uuid), :ref, CAST(:ad AS date), :st, :doc, :notes,
                   CASE WHEN :uid IS NULL THEN NULL ELSE CAST(:uid AS uuid) END)
           RETURNING id, created_at""",
        {
            "sid": submission_id,
            "ref": attestation_ref,
            "ad": attestation_date,
            "st": result_status,
            "doc": document_ref,
            "notes": notes,
            "uid": recorded_by,
        },
    )
    execute(
        db,
        """UPDATE vuln_asv_submissions SET status = 'attested', submitted_at = NOW(), updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {"id": submission_id},
    )
    return {
        "id": str(row["id"]),
        "submission_id": submission_id,
        "attestation_ref": attestation_ref,
        "result_status": result_status,
        "disclaimer": "Attestation recorded from external accredited ASV — not platform-generated",
    }
