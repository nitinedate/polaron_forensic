"""Tests for Gap Assessment LLM enrichment."""

from app.services.gap_report_llm import _clean_scanner_text, _fallback_enrich, _merge_llm_row, enrich_gap_findings


def test_clean_scanner_text_strips_stub_markers():
    raw = "Nuclei stub: rapid CVE/misconfiguration template match."
    cleaned = _clean_scanner_text(raw)
    assert "stub" not in cleaned.lower()
    assert "nuclei" not in cleaned.lower()


def test_fallback_enrich_produces_client_fields():
    finding = {
        "name": "SSL/TLS weak protocol (stub)",
        "risk": "Critical",
        "description": "Nuclei stub: weak TLS enabled.",
        "remediation": "Disable weak TLS; enforce TLS 1.2+.",
        "hosts": ["192.168.1.7"],
    }
    out = _fallback_enrich(finding)
    assert out["client_observation"]
    assert out["client_impact"]
    assert out["client_description"]
    assert len(out["client_mitigation"]) >= 1
    assert len(out["client_mitigation_paragraph"]) >= 100
    assert "enforce tls 1.2" not in out["client_mitigation_paragraph"].lower()
    assert out["client_recommendation"]
    assert len(out["client_recommendation"]) >= 80
    assert "stub" not in out["client_observation"].lower()


def test_merge_llm_row_preserves_llm_text():
    finding = {"name": "BlueKeep", "risk": "Critical", "description": "raw", "remediation": "patch"}
    row = {
        "name": "BlueKeep",
        "observation": "The system is vulnerable to BlueKeep.",
        "impact": "An attacker could take over the system.",
        "description": "BlueKeep is a serious Remote Desktop weakness.",
        "mitigation": (
            "Work with your IT team to install the latest security update on all affected computers. "
            "Turn off remote access if it is not needed for daily work, and confirm the fix with a follow-up review."
        ),
        "recommendation": (
            "Apply the official Microsoft security patch for BlueKeep on all affected systems immediately. "
            "Disable Remote Desktop where it is not required and restrict RDP access to trusted networks only."
        ),
    }
    out = _merge_llm_row(finding, row)
    assert out["client_observation"] == row["observation"].rstrip(".")
    assert out["client_mitigation_paragraph"].rstrip(".") == row["mitigation"].rstrip(".")
    assert out["client_recommendation"].rstrip(".") == row["recommendation"].rstrip(".")
    assert len(out["client_recommendation"]) >= 80


def test_fallback_enrich_keeps_vendor_solution():
    from app.services.gap_report_llm import _fallback_enrich

    solution = (
        "Disable SSLv2 and SSLv3 on all servers and network devices. Configure the "
        "server to use only TLS 1.2 and TLS 1.3 with strong cipher suites."
    )
    out = _fallback_enrich(
        {
            "name": "SSL Version 2 and 3 Protocol Detection",
            "risk": "Critical",
            "description": "The server supports outdated SSLv2/SSLv3.",
            "remediation": solution,
            "nvt_impact": "An attacker may use POODLE to intercept encrypted traffic.",
            "hosts": ["192.168.0.1"],
        }
    )
    assert "Disable SSLv2" in out["client_mitigation_paragraph"]
    assert "POODLE" in out["client_impact"]


def test_build_mitigation_text_is_plain_language():
    from app.services.gap_report_llm import _build_mitigation_text

    text = _build_mitigation_text(
        "SSL/TLS weak protocol (stub)",
        "Critical",
        ["Disable weak TLS", "Enforce TLS 1.2+"],
    )
    assert len(text) >= 100
    assert "enforce tls 1.2" not in text.lower()
    assert "it team" in text.lower()


def test_finding_mitigation_paragraph_uses_plain_language():
    from app.services.gap_assessment_report import _finding_mitigation_paragraph

    finding = {
        "name": "SSL/TLS weak protocol (stub)",
        "risk": "Critical",
        "remediation": "Disable weak TLS; enforce TLS 1.2+.",
    }
    text = _finding_mitigation_paragraph(finding)
    assert len(text) >= 100
    assert "enforce tls 1.2" not in text.lower()


def test_finding_mitigation_uses_vendor_solution_text():
    from app.services.gap_assessment_report import _finding_mitigation_paragraph, _finding_impact

    solution = (
        "Disable SSLv2 and SSLv3 on all servers and network devices. Configure the server "
        "to use only secure protocols such as TLS 1.2 and TLS 1.3, and ensure strong cipher "
        "suites are enabled. Verify the configuration through regular security scans."
    )
    finding = {
        "name": "SSL Version 2 and 3 Protocol Detection",
        "risk": "Critical",
        "description": "The server supports outdated SSLv2 and/or SSLv3 protocols.",
        "remediation": solution,
        "nvt_impact": (
            "An attacker may exploit SSLv2/SSLv3 (such as POODLE) to intercept or "
            "manipulate sensitive communications."
        ),
    }
    assert "Disable SSLv2" in _finding_mitigation_paragraph(finding)
    assert "POODLE" in _finding_impact(finding)


def test_build_recommendation_text_is_human_readable():
    from app.services.gap_report_llm import _build_recommendation_text

    rec = _build_recommendation_text(
        "SSL/TLS weak protocol (stub)",
        "Critical",
        ["Disable weak TLS", "Enforce TLS 1.2+"],
    )
    assert len(rec) >= 80
    assert "TLS" in rec
    assert "stub" not in rec.lower()


def test_enrich_gap_findings_without_llm(monkeypatch):
    monkeypatch.setattr(
        "app.services.gap_report_llm.get_settings",
        lambda: type("S", (), {"gap_report_llm_enabled": False, "gap_report_llm_model": "", "llm_fast_model": "x"})(),
    )
    findings = [{"name": "Test gap", "risk": "High", "description": "Scanner output.", "remediation": "Fix it."}]
    out = enrich_gap_findings(findings, client="Demo", enabled=False)
    assert out[0]["client_observation"]
