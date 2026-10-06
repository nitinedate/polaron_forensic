from lxml import etree

from agent.gmp_local import _report_evidence_from_xml, _report_payload, _vulnerabilities_from_report


def _report_xml(host_ip: str) -> etree._Element:
    return etree.fromstring(
        f"""
        <get_reports_response>
          <report id="r1">
            <scan_run_status>Done</scan_run_status>
            <scan_start>2026-08-26T11:54:08Z</scan_start>
            <scan_end>2026-08-26T13:00:54Z</scan_end>
            <hosts><count>1</count></hosts>
            <host><ip>{host_ip}</ip></host>
            <result_count>12</result_count>
          </report>
        </get_reports_response>
        """.strip()
    )


def test_done_report_one_alive_of_two_is_complete():
    evidence = _report_evidence_from_xml(
        _report_xml("192.168.0.163"),
        report_id="r1",
        task_status="done",
        progress=100.0,
        expected_targets=["192.168.0.163", "192.168.0.103"],
        alive_test="Consider Alive",
    )
    assert evidence["assessment_complete"] is True
    assert evidence["missing_ip_targets"] == ["192.168.0.103"]
    assert evidence["assessment_verdict"] == "assessed_with_unreachable_skips"
    assert "192.168.0.163" in evidence["assessed_hosts"]


def test_done_report_wrong_host_is_not_complete():
    evidence = _report_evidence_from_xml(
        _report_xml("10.10.80.1"),
        report_id="r1",
        task_status="done",
        progress=100.0,
        expected_targets=["192.168.0.163"],
        alive_test="Consider Alive",
    )
    assert evidence["assessment_complete"] is False
    assert evidence["missing_ip_targets"] == ["192.168.0.163"]


def test_merge_promotes_skipped_gap_to_complete():
    from agent.main import _merge_chunk_details

    merged = _merge_chunk_details(
        [
            (
                ["192.168.0.163", "192.168.0.103"],
                {
                    "status": "completed",
                    "gmp_status": "done",
                    "progress": 100,
                    "vulnerabilities": [],
                    "evidence": {
                        "report_id": "r1",
                        "task_status": "done",
                        "assessed_hosts": ["192.168.0.163"],
                        "hosts_attempted": 2,
                        "hosts_assessed": 1,
                        "assessment_complete": False,
                        "assessment_verdict": "target_not_in_report",
                        "scan_start": "2026-08-26T11:54:08Z",
                        "scan_end": "2026-08-26T13:00:54Z",
                        "report_result_count": 12,
                    },
                },
            )
        ],
        all_targets=["192.168.0.163", "192.168.0.103"],
        skipped_hosts=[{"host": "192.168.0.103", "reason": "unreachable"}],
    )
    assert merged["status"] == "completed"
    assert merged["evidence"]["assessment_complete"] is True
    assert merged["evidence"]["missing_ip_targets"] == []


def test_merge_preserves_distinct_rows_with_the_same_summary_key():
    from agent.main import _merge_chunk_details

    rows = [
        {
            "plugin_id": f"oid-{i}",
            "host": "192.168.0.1",
            "port": 443,
            "plugin_name": f"finding {i}",
            "severity": "info",
        }
        for i in range(49)
    ]
    # Greenbone may emit multiple distinct result records that share the fields
    # used by the old semantic dedupe key. Total=53, unique old keys=49.
    rows.extend(dict(rows[0]) for _ in range(4))
    details = {
        "status": "completed",
        "gmp_status": "done",
        "progress": 100,
        "vulnerabilities": rows,
        "evidence": {
            "report_id": "report-53",
            "task_status": "done",
            "assessed_hosts": ["192.168.0.1"],
            "report_result_count": 53,
            "assessment_complete": True,
            "scan_start": "2026-09-01T00:00:00Z",
            "scan_end": "2026-09-01T01:00:00Z",
        },
    }

    merged = _merge_chunk_details(
        [(["192.168.0.1"], details)],
        all_targets=["192.168.0.1"],
    )
    assert len(merged["vulnerabilities"]) == 53
    assert merged["evidence"]["report_result_count"] == 53
    assert merged["evidence"]["assessment_complete"] is True

    # If the same report is accidentally supplied twice during resume, count
    # and upload it once rather than duplicating all rows.
    repeated = _merge_chunk_details(
        [(["192.168.0.1"], details), (["192.168.0.1"], details)],
        all_targets=["192.168.0.1"],
    )
    assert len(repeated["vulnerabilities"]) == 53
    assert repeated["evidence"]["report_result_count"] == 53


def test_report_filter_requests_low_qod_results(monkeypatch):
    from agent.gmp_local import _report_filter_string

    monkeypatch.delenv("GVM_REPORT_MIN_QOD", raising=False)
    assert _report_filter_string() == "rows=-1 min_qod=0"


def test_vulnerability_parser_preserves_qod():
    from agent.gmp_local import _vulnerabilities_from_report

    xml = etree.fromstring(
        b"""<get_reports_response><report><results><result id='greenbone-result-1'>
        <host>192.168.0.1</host><port>443/tcp</port><severity>9.8</severity><threat>High</threat>
        <qod><value>35</value><type>remote_banner</type></qod>
        <nvt oid='1.3.6.1.4.1.test'><name>Low-QoD critical candidate</name><family>SSL</family><cvss_base>9.8</cvss_base></nvt>
        </result></results></report></get_reports_response>"""
    )
    rows = _vulnerabilities_from_report(xml)
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"
    assert rows[0]["qod"] == 35.0
    assert rows[0]["qod_type"] == "remote_banner"
    assert rows[0]["source_result_id"] == "greenbone-result-1"


def test_canonical_severity_uses_nessus_cvss_bands_only():
    from agent.gmp_local import _canonical_severity

    assert _canonical_severity("Info", 9.8) == "critical"
    assert _canonical_severity("High", 9.8) == "critical"
    assert _canonical_severity("Critical", 5.0) == "medium"
    assert _canonical_severity("Medium", 7.5) == "high"


def test_report_result_count_falls_back_to_materialized_rows():
    xml = etree.fromstring(
        b"""<get_reports_response><report id='r1'>
        <scan_run_status>Done</scan_run_status>
        <scan_start>2026-08-31T10:00:00Z</scan_start><scan_end>2026-08-31T10:10:00Z</scan_end>
        <host><ip>192.168.0.1</ip></host>
        <results>
          <result><host>192.168.0.1</host><nvt oid='1'><name>a</name></nvt></result>
          <result><host>192.168.0.1</host><nvt oid='2'><name>b</name></nvt></result>
        </results>
        </report></get_reports_response>"""
    )
    evidence = _report_evidence_from_xml(
        xml,
        report_id="r1",
        task_status="done",
        progress=100.0,
        expected_targets=["192.168.0.1"],
        alive_test="Consider Alive",
    )
    assert evidence["report_result_count"] == 2


def test_filtered_count_not_full_count_is_upload_integrity_boundary():
    results = "".join(
        f"<result><host>192.168.0.1</host><nvt oid='{i}'><name>finding {i}</name></nvt></result>"
        for i in range(35)
    )
    xml = etree.fromstring(
        f"""<get_reports_response><report id='r1'>
        <scan_run_status>Done</scan_run_status>
        <scan_start>2026-08-31T10:00:00Z</scan_start><scan_end>2026-08-31T10:10:00Z</scan_end>
        <host><ip>192.168.0.1</ip></host>
        <result_count><full>36</full><filtered>35</filtered></result_count>
        <results>{results}</results>
        </report></get_reports_response>""".encode()
    )
    evidence = _report_evidence_from_xml(
        xml,
        report_id="r1",
        task_status="done",
        progress=100.0,
        expected_targets=["192.168.0.1"],
        alive_test="Consider Alive",
    )
    rows = _vulnerabilities_from_report(xml)
    assert evidence["report_result_count_full"] == 36
    assert evidence["report_result_count_filtered"] == 35
    assert evidence["report_materialized_result_count"] == 35
    assert evidence["report_result_count"] == len(rows) == 35

    class FakeGmp:
        def get_task(self, task_id):
            return etree.fromstring(
                b"<get_tasks_response><task><status>Done</status><progress>100</progress>"
                b"<current_report><report id='r1'/></current_report></task></get_tasks_response>"
            )

        def get_report(self, **kwargs):
            return xml

    uploaded, payload_evidence = _report_payload(
        FakeGmp(),
        "task-1",
        expected_targets=["192.168.0.1"],
        alive_test="Consider Alive",
        task_status="done",
        progress=100.0,
    )
    assert len(uploaded) == 35
    assert payload_evidence["assessment_complete"] is True
    assert payload_evidence.get("report_read_error") in {None, ""}


def test_harvest_survives_when_full_report_closes_the_socket():
    results = "".join(
        f"<result><host>192.168.1.11</host><nvt oid='{i}'><name>finding {i}</name></nvt></result>"
        for i in range(12)
    )
    xml = etree.fromstring(
        f"""<get_reports_response><report id='r-page'>
        <scan_run_status>Done</scan_run_status>
        <scan_start>2026-09-02T08:00:00Z</scan_start><scan_end>2026-09-02T08:50:00Z</scan_end>
        <host><ip>192.168.1.11</ip></host>
        <host><ip>192.168.1.12</ip></host>
        <result_count><full>12</full><filtered>12</filtered></result_count>
        <results>{results}</results>
        </report></get_reports_response>""".encode()
    )

    class FakeGmp:
        def get_task(self, task_id):
            return etree.fromstring(
                b"<get_tasks_response><task><status>Done</status><progress>100</progress>"
                b"<current_report><report id='r-page'/></current_report></task></get_tasks_response>"
            )

        def get_report(self, **kwargs):
            filt = str(kwargs.get("filter_string") or "")
            if kwargs.get("ignore_pagination") or "rows=-1" in filt:
                raise ConnectionError("Remote closed the connection")
            return xml

    uploaded, evidence = _report_payload(
        FakeGmp(),
        "task-page",
        expected_targets=["192.168.1.11", "192.168.1.12"],
        alive_test="Consider Alive",
        task_status="done",
        progress=100.0,
    )
    assert len(uploaded) == 12
    assert evidence["assessment_complete"] is True
    assert evidence.get("report_read_error") in {None, ""}
    assert "192.168.1.11" in evidence["assessed_hosts"]
    assert "192.168.1.12" in evidence["assessed_hosts"]
    assert evidence["scan_start"]
    assert evidence["scan_end"]


def test_start_scan_never_silently_downgrades_to_bare_task(monkeypatch):
    from contextlib import contextmanager
    from agent import gmp_local as mod

    monkeypatch.setenv("GVM_ALLOW_BARE_TASK_FALLBACK", "false")
    monkeypatch.setenv("PORT_PROFILE", "full")

    class FakeGmp:
        def __init__(self):
            self.calls = []
        def create_target(self, **kwargs):
            return {"id": "target-1"}
        def create_task(self, **kwargs):
            self.calls.append(kwargs)
            raise RuntimeError("preferences rejected")
        def delete_target(self, target_id):
            self.deleted = target_id

    fake = FakeGmp()

    @contextmanager
    def fake_session(**kwargs):
        yield fake

    monkeypatch.setattr(mod, "_session", fake_session)
    monkeypatch.setattr(mod, "_find_config_id", lambda gmp, name: "config-1")
    monkeypatch.setattr(mod, "_assert_feed_quality", lambda gmp, config_id: None)
    monkeypatch.setattr(mod, "_find_scanner_id", lambda gmp: "scanner-1")

    scanner = mod.LocalOpenVAS()
    try:
        scanner.start_scan(name="quality-test", targets=["192.168.0.1"])
        assert False, "expected degraded scan refusal"
    except RuntimeError as exc:
        assert "refusing a bare/degraded scan" in str(exc)

    assert len(fake.calls) == 2
    assert "preferences" in fake.calls[0]
    assert "thorough_tests" not in fake.calls[0]["preferences"]
    assert fake.calls[0]["preferences"]["checks_read_timeout"] == "10"
    assert fake.calls[0]["preferences"]["timeout_retry"] == "3"
    assert fake.calls[0]["preferences"]["open_sock_max_attempts"] == "5"
    assert "preferences" in fake.calls[1]
