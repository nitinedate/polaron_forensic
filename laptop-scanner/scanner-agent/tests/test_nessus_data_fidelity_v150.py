from lxml import etree

from agent.gmp_local import _canonical_severity, _vulnerabilities_from_report


def _parse(result_xml: str):
    xml = etree.fromstring(
        f"<get_reports_response><report><results>{result_xml}</results></report></get_reports_response>".encode()
    )
    return _vulnerabilities_from_report(xml)[0]


def test_zero_string_cvss_base_does_not_hide_critical_result_score():
    row = _parse(
        """<result id='r-critical'>
        <host>192.168.0.195</host><port>443/tcp</port><severity>9.8</severity><threat>High</threat>
        <nvt oid='1.3.6.1.4.1.test.critical'><name>Critical RCE</name><family>General</family><cvss_base>0.0</cvss_base>
          <refs><ref type='cve' id='CVE-2026-12345'/><ref type='cve' id='CVE-2026-12346'/></refs>
        </nvt></result>"""
    )
    assert row["cvss"] == 9.8
    assert row["severity"] == "critical"
    assert row["cvss_source"] == "result.severity"
    assert row["cvss_candidates"]["nvt.cvss_base"] == 0.0
    assert row["cvss_candidates"]["result.severity"] == 9.8
    assert row["cves"] == ["CVE-2026-12345", "CVE-2026-12346"]
    assert row["host"] == "192.168.0.195"


def test_greenbone_threat_label_does_not_override_nessus_cvss_band():
    row = _parse(
        """<result id='r-medium'>
        <host>192.168.0.163</host><port>80/tcp</port><severity>5.0</severity><threat>Critical</threat>
        <nvt oid='1.3.6.1.4.1.test.medium'><name>Medium technical severity</name><family>General</family><cvss_base>5.0</cvss_base></nvt>
        </result>"""
    )
    assert row["cvss"] == 5.0
    assert row["severity"] == "medium"
    assert row["scanner_threat"] == "Critical"
    assert _canonical_severity("Critical", 5.0) == "medium"


def test_info_result_is_preserved_instead_of_disappearing_from_host_data():
    row = _parse(
        """<result id='r-info'>
        <host>192.168.0.195</host><port>general/tcp</port><severity>0.0</severity><threat>Log</threat>
        <nvt oid='1.3.6.1.4.1.test.info'><name>Host information</name><family>General</family><cvss_base>0.0</cvss_base></nvt>
        </result>"""
    )
    assert row["severity"] == "info"
    assert row["host"] == "192.168.0.195"
