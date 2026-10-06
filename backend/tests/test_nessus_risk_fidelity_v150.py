from app.services.aetheris_severity import aetheris_severity_sql, classify_severity, severity_from_cvss
from app.services.vuln_risk import MODEL_VERSION, risk_band_from_number, score_finding
from app.services.vuln_finding_ingest import normalize_raw_vuln


def test_nessus_cvss_bands_are_exact():
    assert severity_from_cvss(10.0) == "critical"
    assert severity_from_cvss(9.0) == "critical"
    assert severity_from_cvss(8.9) == "high"
    assert severity_from_cvss(7.0) == "high"
    assert severity_from_cvss(6.9) == "medium"
    assert severity_from_cvss(4.0) == "medium"
    assert severity_from_cvss(3.9) == "low"
    assert severity_from_cvss(0.1) == "low"
    assert severity_from_cvss(0.0) == "info"


def test_greenbone_label_and_local_policy_do_not_override_nessus_severity():
    assert classify_severity(cvss=5.0, raw_severity="High", synopsis="SSL Version 2 and 3 Protocol Detection")[0] == "medium"
    assert classify_severity(cvss=9.8, raw_severity="Log", synopsis="anything")[0] == "critical"
    sql = aetheris_severity_sql("f")
    assert "f.cvss" in sql
    assert "f.severity" not in sql
    assert "synopsis" not in sql


def test_normalizer_takes_highest_valid_numeric_cvss_signal():
    row = normalize_raw_vuln({
        "plugin_id": "1",
        "score": "0.0",
        "cvss": "0.0",
        "greenbone_result_severity": "9.8",
        "severity": "medium",
        "plugin_name": "RCE",
    })
    assert row["cvss"] == 9.8
    assert row["severity"] == "critical"


def test_weighted_risk_model_uses_documented_bands_and_no_fake_threat():
    assert MODEL_VERSION == "nessus-aligned-weighted-1"
    assert risk_band_from_number(80) == "critical"
    assert risk_band_from_number(60) == "high"
    assert risk_band_from_number(35) == "medium"
    assert risk_band_from_number(1) == "low"
    assert risk_band_from_number(0) == "info"

    scored = score_finding(
        cvss=9.8,
        is_kev=False,
        external_exposure="internal",
        asset_criticality="tier2",
        credentialed=False,
    )
    assert scored["risk_factors_json"]["threat"] == 0
    assert scored["risk_factors_json"]["threat_source"] == "unavailable"


def test_weighted_risk_prefers_explicit_vpr_and_keeps_risk_separate_from_severity():
    scored = score_finding(
        cvss=5.0,
        is_kev=True,
        external_exposure="internet-facing",
        asset_criticality="tier0",
        credentialed=True,
        qod=95,
        vpr_score=9.0,
        days_open=45,
    )
    assert scored["risk_factors_json"]["threat_source"] == "vpr"
    assert scored["risk_factors_json"]["threat"] == 18.0
    assert scored["enterprise_risk_score"] >= 80
    assert scored["risk_band"] == "critical"
    # Technical severity still remains Medium because CVSS is 5.0.
    assert severity_from_cvss(5.0) == "medium"
