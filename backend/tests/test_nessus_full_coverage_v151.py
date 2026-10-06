from app.services.aetheris_severity import choose_cvss_score, severity_from_cvss
from app.services.nessus_report import parse_nessus_csv_findings


def test_nessus_cvss_v2_and_v3_critical_bands_differ():
    assert severity_from_cvss(9.0, "cvss_v3") == "critical"
    assert severity_from_cvss(9.0, "cvss_v2") == "high"
    assert severity_from_cvss(10.0, "cvss_v2") == "critical"


def test_configured_basis_is_not_max_across_cvss_versions():
    row = {"cvss_v2": 10.0, "cvss_v3": 8.8, "cvss_v4": 8.5}
    score, source, candidates = choose_cvss_score(row, "cvss_v3")
    assert score == 8.8
    assert source == "cvss_v3"
    assert candidates["cvss_v2"] == 10.0


def test_generic_greenbone_signals_keep_strongest_numeric_value():
    score, source, _ = choose_cvss_score(
        {"score": "0.0", "cvss": "0.0", "greenbone_result_severity": "9.8"},
        "cvss_v3",
    )
    assert score == 9.8
    assert source == "greenbone_result_severity"


def test_nessus_csv_parser_keeps_each_finding_and_all_scoring_signals():
    csv_text = '''Plugin ID,CVE,CVSS v2.0 Base Score,CVSS v3.0 Base Score,CVSS v4.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,Plugin Family,VPR Score,EPSS Score,Exploit Code Maturity\n1001,CVE-2026-12345,10.0,8.8,8.6,High,192.0.2.10,tcp,443,TLS issue,TLS issue,desc,fix,General,9.1,0.82,Functional\n1002,,0,0,0,Info,192.0.2.10,tcp,22,SSH service,SSH detected,desc,,Service detection,,,\n'''
    rows = parse_nessus_csv_findings(csv_text)
    assert len(rows) == 2
    assert rows[0]["plugin_id"] == "1001"
    assert rows[0]["cves"] == ["CVE-2026-12345"]
    assert rows[0]["cvss_v2"] == 10.0
    assert rows[0]["cvss_v3"] == 8.8
    assert rows[0]["cvss_v4"] == 8.6
    assert rows[0]["vpr_score"] == 9.1
    assert rows[0]["scan_engine"] == "nessus"
    assert rows[1]["severity"] == "info"
