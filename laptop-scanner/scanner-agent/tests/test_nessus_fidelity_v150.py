from lxml import etree

from agent.gmp_local import _best_cvss, _canonical_severity, _severity_from_cvss, _vulnerabilities_from_report


def test_nonfinite_result_score_cannot_hide_valid_nvt_score():
    for bad in ("NaN", "Infinity", "-Infinity"):
        result = etree.fromstring(f"<result><severity>{bad}</severity></result>")
        nvt = etree.fromstring("<nvt><cvss_base>7.5</cvss_base></nvt>")
        score, source, candidates = _best_cvss(nvt, result, {})
        assert score == 7.5
        assert source == "nvt.cvss_base"
        assert "result.severity" not in candidates


def test_nessus_severity_ignores_greenbone_threat_label():
    assert _canonical_severity("High", 5.0) == "medium"
    assert _canonical_severity("Log", 9.8) == "critical"
    assert _severity_from_cvss(0.0) == "info"


def test_best_cvss_does_not_let_string_zero_hide_result_severity():
    nvt = etree.fromstring(b"<nvt><cvss_base>0.0</cvss_base></nvt>")
    result = etree.fromstring(b"<result><severity>9.8</severity></result>")
    score, source, candidates = _best_cvss(nvt, result, {})
    assert score == 9.8
    assert source == "result.severity"
    assert candidates["nvt.cvss_base"] == 0.0


def test_report_parser_preserves_host_all_cves_raw_signals_and_critical_score():
    xml = etree.fromstring(b"""
    <get_reports_response><report><results><result id='res-1'>
      <host>192.168.0.195</host><port>443/tcp</port><severity>9.8</severity><threat>High</threat>
      <qod><value>95</value><type>remote_vul</type></qod>
      <nvt oid='1.3.6.1.4.1.25623.1.0.999999'>
        <name>Critical remote issue</name><family>General</family><cvss_base>0.0</cvss_base>
        <refs><ref type='cve' id='CVE-2026-1111'/><ref type='cve' id='CVE-2026-2222'/></refs>
        <tags>summary=Critical remote issue|solution=Patch now</tags>
      </nvt>
    </result></results></report></get_reports_response>
    """)
    rows = _vulnerabilities_from_report(xml)
    assert len(rows) == 1
    row = rows[0]
    assert row["host"] == "192.168.0.195"
    assert row["cvss"] == 9.8
    assert row["severity"] == "critical"
    assert row["cves"] == ["CVE-2026-1111", "CVE-2026-2222"]
    assert row["greenbone_result_severity"] == "9.8"
    assert row["scanner_threat"] == "High"
    assert row["qod"] == 95.0
