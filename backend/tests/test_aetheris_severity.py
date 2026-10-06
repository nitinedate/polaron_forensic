from app.services.aetheris_severity import (
    aetheris_severity_sql,
    classify_severity,
    severity_from_cvss,
)


def test_aetheris_cvss_bands():
    assert severity_from_cvss(9.0) == "critical"
    assert severity_from_cvss(8.9) == "high"
    assert severity_from_cvss(7.0) == "high"
    assert severity_from_cvss(6.9) == "medium"
    assert severity_from_cvss(4.0) == "medium"
    assert severity_from_cvss(3.9) == "low"
    assert severity_from_cvss(0.1) == "low"
    assert severity_from_cvss(0.0) == "info"


def test_classify_ignores_scanner_threat_labels():
    sev, rule = classify_severity(cvss=5.0, synopsis="OpenSSL", raw_severity="High")
    assert sev == "medium"
    assert rule is None
    sev, _ = classify_severity(cvss=9.8, synopsis="RCE", raw_severity="Log")
    assert sev == "critical"


def test_descriptions_do_not_override_cvss_severity(monkeypatch):
    monkeypatch.delenv("VULN_SEVERITY_PROFILE", raising=False)
    sev, rule = classify_severity(
        cvss=5.0,
        synopsis="SSL Version 2 and 3 Protocol Detection",
        raw_severity="medium",
    )
    assert sev == "medium"
    assert rule is None


def test_aetheris_severity_sql_uses_cvss_not_stored_label():
    sql = aetheris_severity_sql("f")
    assert "f.cvss" in sql
    assert "f.severity" not in sql
    assert "critical" in sql
    assert "high" in sql
