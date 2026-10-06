from lxml import etree

from agent.gmp_local import (
    LocalOpenVAS,
    _default_scan_port_range,
    _versioned_cvss_scores,
    _vulnerabilities_from_report,
)
from agent.port_range import exclude_tcp_ports_from_range


def test_full_tcp_and_priority_udp_is_default(monkeypatch):
    monkeypatch.delenv("PORT_PROFILE", raising=False)
    monkeypatch.delenv("UDP_PROFILE", raising=False)
    monkeypatch.delenv("UDP_PORT_RANGE", raising=False)
    scanner = LocalOpenVAS()
    assert scanner.port_profile == "full"
    assert scanner.udp_profile == "priority"
    port_range = _default_scan_port_range(scanner.port_profile, scanner.udp_profile)
    assert port_range.startswith("T:1-65535,U:")
    assert "161" in port_range
    assert "4500" in port_range


def test_full_udp_is_available(monkeypatch):
    monkeypatch.delenv("UDP_PORT_RANGE", raising=False)
    port_range = _default_scan_port_range("full", "full")
    assert port_range == "T:1-65535,U:1-65535"


def test_control_plane_exclusion_never_removes_udp_ports():
    value = exclude_tcp_ports_from_range("T:1-10,T:80,T:443,U:53,U:80,U:161", {5, 80})
    assert value == "T:1-4,T:6-10,T:443,U:53,U:80,U:161"


def test_explicit_versioned_cvss_is_preserved_for_central_policy():
    xml = etree.fromstring(
        b"""
        <get_reports_response><report><results><result id='r-151'>
          <host>192.168.0.10</host><port>443/tcp</port><severity>10.0</severity><threat>High</threat>
          <nvt oid='1.3.6.1.4.1.test.151'>
            <name>Versioned CVSS example</name><family>General</family>
            <cvss_base>10.0</cvss_base><cvss2_base>10.0</cvss2_base>
            <cvss3_base>8.8</cvss3_base><cvss4_base>8.6</cvss4_base>
            <refs><ref type='cve' id='CVE-2026-1510'/><ref type='cwe' id='78'/></refs>
            <tags>cvss_v3_vector=CVSS:3.1/AV:N/AC:L|cvss_v4_vector=CVSS:4.0/AV:N/AC:L</tags>
          </nvt>
        </result></results></report></get_reports_response>
        """
    )
    row = _vulnerabilities_from_report(xml)[0]
    assert row["cvss"] == 10.0
    assert row["cvss_v2"] == 10.0
    assert row["cvss_v3"] == 8.8
    assert row["cvss_v4"] == 8.6
    assert row["cwe"] == "CWE-78"
    assert row["scan_engine"] == "openvas"
    assert row["cvss_v3_vector"].startswith("CVSS:3.1")


def test_generic_greenbone_score_is_not_mislabeled_as_cvss_version():
    scores = _versioned_cvss_scores({"result.severity": 9.8, "nvt.cvss_base": 9.8})
    assert scores == {"cvss_v2": None, "cvss_v3": None, "cvss_v4": None}


def test_generated_port_ranges_match_gmp_protocol_prefix_format(monkeypatch):
    import re
    monkeypatch.delenv("UDP_PORT_RANGE", raising=False)
    port_range = _default_scan_port_range("full", "priority")
    assert all(re.fullmatch(r"[TU]:\d{1,5}(?:-\d{1,5})?", token) for token in port_range.split(","))
