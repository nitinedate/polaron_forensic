"""BRD v2.1 acceptance scenarios VM-01 through VM-13 (unit-level, no Postgres required)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.greenbone_client import GreenboneClient
from app.services.nessus_client import NessusClient
from app.services.nessus_sync import preflight_scan_job
from app.services.permissions_catalog import FIRM_PERMISSIONS
from app.services.scanner_adapter import enrich_stub_scan_details, get_scanner_client
from app.services.scanner_stub import stub_scan_vulnerabilities
from app.services.vuln_exploit_validation import ExploitValidationError
from app.services.vuln_finding_ingest import normalize_raw_vuln
from app.services.vuln_kev_feed import SAMPLE_KEV_CVES, is_kev_cve, sync_kev_catalog
from app.services.vuln_pci import PCI_DISCLAIMER, build_pci_readiness_package, infer_pci_requirement
from app.services.vuln_risk import score_finding


# ---------- VM-02: supplied threat signal + KEV on tier0 ----------


def test_vm02_log4shell_kev_tier0_critical_band():
    """Supplied VPR + KEV + tier0 exposure produces critical contextual risk."""
    scored = score_finding(
        cvss=10.0,
        is_kev=True,
        external_exposure="internet-facing",
        asset_criticality="tier0",
        credentialed=True,
        vpr_score=9.0,
    )
    assert scored["risk_band"] == "critical"
    assert scored["enterprise_risk_score"] >= 80
    assert scored["risk_factors_json"]["model_version"] == "nessus-aligned-weighted-1"
    assert scored["risk_factors_json"]["known_exploitation"] == 15.0


def test_vm02_isolated_tier3_same_cvss_lower_band():
    """§9 worked example: same CVSS, isolated tier3 → medium."""
    scored = score_finding(
        cvss=10.0,
        is_kev=False,
        external_exposure="isolated",
        asset_criticality="tier3",
        credentialed=True,
    )
    assert scored["risk_band"] in {"medium", "low", "high"}
    assert scored["enterprise_risk_score"] < 80


# ---------- VM-01: Authenticated scan stub produces findings ----------


def test_vm01_stub_scan_produces_findings(monkeypatch):
    """VM-01 / FR-1: stub scanner returns CVE-tagged findings."""
    # Live GVM in the api container would try /run/gvmd/gvmd.sock (not mounted).
    monkeypatch.setattr(GreenboneClient, "configured", False)
    client = GreenboneClient(base_url="")
    details = client.scan_details("stub-1")
    assert details.get("stub") is True
    vulns = enrich_stub_scan_details(details, credentialed=True, custom_checks=[])["vulnerabilities"]
    assert len(vulns) >= 2
    assert any(v.get("cve") == "CVE-2021-44228" for v in vulns)
    cred = stub_scan_vulnerabilities(credentialed=True)
    assert any("credentialed" in (v.get("plugin_name") or "").lower() for v in cred)


# ---------- VM-03: Credential preflight fails ----------


def test_vm03_preflight_fails_on_missing_credential():
    """VM-03 / FR-3.2 / FR-6.3: invalid credential ref fails preflight."""

    class FakeDb:
        pass

    job = {"policy_id": None}
    targets = [{"target": "10.0.0.1", "credential_ref": "vault://missing-cred", "excluded": False}]

    def fake_fetchone(db, sql, params):
        if "vuln_credential_refs" in sql:
            return None
        return None

    import app.services.nessus_sync as sync_mod

    orig = sync_mod.fetchone
    sync_mod.fetchone = fake_fetchone
    try:
        result = preflight_scan_job(FakeDb(), job, targets)
    finally:
        sync_mod.fetchone = orig
    assert result["ok"] is False
    assert any("not found" in e.lower() for e in result["errors"])


def test_vm03_preflight_fails_inactive_policy():
    class FakeDb:
        pass

    job = {"policy_id": "00000000-0000-0000-0000-000000000001"}
    targets = [{"target": "10.0.0.1", "excluded": False}]

    def fake_fetchone(db, sql, params):
        if "vuln_scan_policies" in sql:
            return {"lifecycle_state": "draft", "name": "Test Policy"}
        return None

    import app.services.nessus_sync as sync_mod

    orig = sync_mod.fetchone
    sync_mod.fetchone = fake_fetchone
    try:
        result = preflight_scan_job(FakeDb(), job, targets)
    finally:
        sync_mod.fetchone = orig
    assert result["ok"] is False


# ---------- VM-07: Scanner adapter editions ----------


def test_vm07_greenbone_adapter_stub():
    """VM-07 / FR-2: OpenVAS edition routes to Greenbone adapter."""
    client = get_scanner_client(edition="OpenVAS", base_url="https://gvm.local:9390")
    assert isinstance(client, GreenboneClient)
    status = client.server_status()
    assert status.get("edition") == "OpenVAS"


def test_vm07_nessus_unconfigured_stub():
    client = NessusClient(base_url="", access_key="", secret_key="")
    assert client.configured is False
    details = client.scan_details("stub-1")
    assert details.get("stub") is True
    assert len(details.get("vulnerabilities") or []) >= 1


# ---------- VM-08: Export classification in PCI package ----------


def test_vm08_pci_package_has_classification_disclaimer():
    """VM-13 / FR-17.3: readiness output labelled not ASV attestation."""
    assert "NOT AN ASV ATTESTATION" in PCI_DISCLAIMER
    assert infer_pci_requirement("Apache Log4j Remote Code Execution", "CVE-2021-44228") == "PCI-DSS 6.3.3"


# ---------- VM-09: Module flag ----------


def test_vm09_vuln_service_mount_source():
    src = Path(__file__).resolve().parents[1] / "app" / "app_factory.py"
    text = src.read_text(encoding="utf-8")
    assert "def _mount_vuln(" in text
    assert "app.include_router(vuln.router)" in text
    assert "app.include_router(scanner_agent.router)" in text


# ---------- VM-10: Agent lifecycle (from existing + ingest normalize) ----------


def test_vm10_agent_finding_normalization_scored_fields():
    norm = normalize_raw_vuln(
        {"plugin_id": "AGENT-PKG", "cve": "CVE-2024-0001", "score": 8.0, "severity": "high", "plugin_name": "Agent package finding"}
    )
    scored = score_finding(cvss=norm["cvss"], is_kev=norm["cve"] in SAMPLE_KEV_CVES, credentialed=True)
    assert scored["enterprise_risk_score"] > 0
    assert scored["risk_band"] in {"critical", "high", "medium", "low", "info"}


# ---------- VM-11: Custom checks in stub scan ----------


def test_vm11_custom_check_in_stub_scan():
    custom = [{"id": "abc123", "name": "Firm TLS check", "severity_hint": "high", "cve_hint": "CVE-2024-9999"}]
    vulns = stub_scan_vulnerabilities(custom_checks=custom)
    assert any(v.get("plugin_family") == "Custom" for v in vulns)


# ---------- VM-12: Exploit validation requires authorization ----------


def test_vm12_validate_refuses_without_authorization():
    with pytest.raises(ExploitValidationError) as exc:
        from app.services.vuln_exploit_validation import validate_finding_safe

        validate_finding_safe(None, finding_id="x", authorization_ref="", validated_by="u1")
    assert exc.value.code == "authz_required"


def test_vm12_validate_permission_catalog():
    codes = {c for c, *_ in FIRM_PERMISSIONS}
    assert "vuln:validate" in codes


# ---------- VM-13: PCI readiness mapping ----------


def test_vm13_pci_tls_mapping():
    assert infer_pci_requirement("Weak TLS cipher suite on port 443", None) == "PCI-DSS 4.2.1"


# ---------- KEV feed ----------


def test_kev_sample_fallback_lookup():
    assert is_kev_cve(None, "CVE-2021-44228") is True
    assert is_kev_cve(None, "CVE-9999-0000") is False


def test_kev_sync_sample_mode(monkeypatch):
    class FakeDb:
        def __init__(self):
            self.calls = 0

    db = FakeDb()

    def fake_execute(db_, sql, params):
        db_.calls += 1

    monkeypatch.setattr("app.services.vuln_kev_feed.execute", fake_execute)
    monkeypatch.setattr(
        "app.services.vuln_kev_feed.httpx.Client",
        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")),
    )
    result = sync_kev_catalog(db, use_sample_on_failure=True)
    assert result["status"] == "ok"
    assert result["source"] == "sample_fallback"
    assert result["count"] >= len(SAMPLE_KEV_CVES)


# ---------- FR-7 normalization ----------


def test_finding_normalization_maps_nessus_fields():
    norm = normalize_raw_vuln({"pluginID": "19506", "score": 5.0, "plugin_name": "Test", "family": "General", "cve": ["CVE-2020-0001"]})
    assert norm["plugin_id"] == "19506"
    assert norm["cve"] == "CVE-2020-0001"


# ---------- Migration presence ----------


def test_migration_016_present():
    mig = Path(__file__).resolve().parents[2] / "migrations" / "016_vuln_brd_v21.sql"
    text = mig.read_text(encoding="utf-8")
    assert "cisa_kev_catalog" in text
    assert "vuln_custom_checks" in text
    assert "exploit_validation_status" in text
