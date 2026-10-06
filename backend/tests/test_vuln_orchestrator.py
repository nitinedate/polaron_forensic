"""Tests for multi-scanner orchestrator and solution-set CSV export."""

from __future__ import annotations

import csv
import io
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.services.scan_orchestrator import (
    DEFAULT_PIPELINE,
    _wait_for_openvas,
    adaptive_openvas_timeout_sec,
    resolve_pipeline,
    scan_job_progress,
    scan_job_target_rows,
)
from app.services.vuln_correlation import correlation_key_for
from app.services.vuln_report_export import CSV_COLUMNS, XLSX_COLUMNS, export_case_xlsx


def test_default_pipeline_has_six_engines():
    engines = [s["engine"] for s in DEFAULT_PIPELINE]
    assert engines == ["nmap", "openvas", "nuclei", "zap", "wazuh", "trivy"]


def test_fast_port_range_is_much_smaller_than_full_tcp():
    from app.services.greenbone_gmp import DEFAULT_TARGET_PORT_RANGE, FAST_TARGET_PORT_RANGE

    assert "1-65535" in DEFAULT_TARGET_PORT_RANGE
    assert "1-65535" not in FAST_TARGET_PORT_RANGE
    assert "443" in FAST_TARGET_PORT_RANGE
    assert "8080" in FAST_TARGET_PORT_RANGE
    assert "8888" not in FAST_TARGET_PORT_RANGE


def test_resolve_pipeline_from_job_json():
    job = {"orchestration_json": {"pipeline": [{"engine": "nmap", "role": "discovery"}]}}
    assert resolve_pipeline(job) == [{"engine": "nmap", "role": "discovery"}]


def test_correlation_key_prefers_cve():
    key = correlation_key_for("192.168.1.1", 443, "SSL weak", "CVE-2014-3566")
    assert "cve:CVE-2014-3566" in key


def test_csv_columns_match_solution_set():
    assert CSV_COLUMNS == ("Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Description", "Solution")


def test_xlsx_matches_solution_set_five_columns(monkeypatch):
    from io import BytesIO

    from openpyxl import load_workbook

    import app.services.vuln_report_export as export_mod

    monkeypatch.setattr(
        export_mod,
        "_open_finding_rows",
        lambda db, *, case_id: [
            {
                "severity": "critical",
                "cvss": 9.8,
                "synopsis": "Microsoft DNS Server Remote Code Execution (SIGRed)",
                "description": "",
                "remediation": "",
                "port": 53,
                "protocol": "tcp",
                "cve": None,
                "host": "172.16.0.1",
            },
            {
                "severity": "medium",
                "cvss": 5.0,
                "synopsis": "Terminal Services Encryption Level is Medium or Low",
                "description": "",
                "remediation": "",
                "port": None,
                "protocol": "tcp",
                "cve": None,
                "host": "172.16.2.173",
            },
        ],
    )
    data = export_case_xlsx(object(), case_id="00000000-0000-0000-0000-000000000001")
    wb = load_workbook(BytesIO(data))
    ws = wb.active
    assert XLSX_COLUMNS == (
        "Risk", "Host", "Protocol", "Port", "Name", "Synopsis", "Description", "Solution"
    )
    assert [c.value for c in ws[1][:8]] == list(XLSX_COLUMNS)
    assert [c.value for c in ws[2][:5]] == [
        "Critical",
        "172.16.0.1",
        "tcp",
        53,
        "Microsoft DNS Server Remote Code Execution (SIGRed)",
    ]
    assert ws.cell(row=2, column=6).value == "Microsoft DNS Server Remote Code Execution (SIGRed)"
    assert ws.cell(row=3, column=4).value == 0
    assert ws.column_dimensions["B"].width == 15.88671875
    assert ws.column_dimensions["E"].width == 60.6640625
    assert ws["A1"].font.bold is False
    assert ws["A1"].font.name == "Aptos Narrow"
    assert str(ws["A2"].fill.fgColor.rgb).endswith("C00000")
    assert str(ws["A3"].fill.fgColor.rgb).endswith("FFC000")
    assert ws["A2"].border.left.style == "thin"


@pytest.mark.parametrize("engine", ["nmap", "nuclei", "zap", "wazuh", "trivy"])
def test_aux_scanner_stub_returns_vulnerabilities(engine):
    from app.services.multi_scanner_clients import BaseAuxScanner, get_aux_scanner

    client = get_aux_scanner(engine)
    # Call the stub path directly so a live ZAP/nmap/trivy in compose cannot
    # return an empty findings list and fail this unit test.
    result = BaseAuxScanner.run_scan(client, targets="192.168.1.246", name="test")
    assert result.get("stub") is True
    assert result["info"]["status"] == "completed"
    assert len(result["vulnerabilities"]) >= 1


def test_import_solution_csv_parsing_logic():
    """Validate CSV column mapping without DB."""
    csv_text = io.StringIO()
    writer = csv.DictWriter(csv_text, fieldnames=list(CSV_COLUMNS))
    writer.writeheader()
    writer.writerow(
        {
            "Risk": "Critical",
            "Host": "192.168.1.246",
            "Protocol": "tcp",
            "Port": "443",
            "Name": "SSL Version 2 and 3 Protocol Detection",
            "Synopsis": "Weak SSL",
            "Description": "SSL 3.0 flaws",
            "Solution": "Disable SSL 3.0",
        }
    )
    reader = csv.DictReader(io.StringIO(csv_text.getvalue()))
    row = next(reader)
    assert row["Host"] == "192.168.1.246"
    assert row["Risk"] == "Critical"


def test_wait_for_openvas_returns_partial_near_complete_timeout():
    client = MagicMock()
    client.scan_details.return_value = {
        "info": {"status": "running", "progress": 96},
        "vulnerabilities": [{"plugin_name": "x", "host": "1.2.3.4", "severity": 5}],
    }
    settings = MagicMock()
    settings.gvm_scan_poll_interval_sec = 1
    settings.gvm_scan_timeout_sec = 1
    settings.gvm_scan_near_complete_grace_sec = 0
    settings.gvm_scan_near_complete_progress_pct = 85
    mono = [0.0, 2.0, 2.5, 3.0]

    def _mono() -> float:
        return mono.pop(0) if mono else 99.0

    with patch("app.services.scan_orchestrator.get_settings", return_value=settings):
        with patch("app.services.scan_orchestrator.time.sleep", return_value=None):
            with patch("app.services.scan_orchestrator.time.monotonic", side_effect=_mono):
                out = _wait_for_openvas(client, "task-1")
    assert out["partial"] is True
    assert len(out["vulnerabilities"]) == 1


def test_wait_for_openvas_harvests_on_high_progress_stall():
    client = MagicMock()
    client.scan_details.return_value = {
        "info": {"status": "running", "progress": 98},
        "vulnerabilities": [{"plugin_name": "x", "host": "1.2.3.4", "severity": 5}],
    }
    settings = MagicMock()
    settings.gvm_scan_poll_interval_sec = 1
    settings.gvm_scan_timeout_sec = 3600
    settings.gvm_scan_near_complete_grace_sec = 3600
    settings.gvm_scan_near_complete_progress_pct = 85
    settings.gvm_scan_stall_progress_pct = 95
    settings.gvm_scan_stall_sec = 2
    # t0 init last_progress_change; then polls with same 98% until stall window passes
    ticks = [0.0, 0.5, 1.0, 2.5, 3.0]

    def _mono() -> float:
        return ticks.pop(0) if ticks else 10.0

    with patch("app.services.scan_orchestrator.get_settings", return_value=settings):
        with patch("app.services.scan_orchestrator.time.sleep", return_value=None):
            with patch("app.services.scan_orchestrator.time.monotonic", side_effect=_mono):
                out = _wait_for_openvas(client, "task-stall")
    assert out["partial"] is True
    assert "stalled" in (out.get("partial_reason") or "")
    client.stop_scan.assert_called()


def test_wait_for_openvas_extends_grace_when_near_complete():
    client = MagicMock()
    client.scan_details.side_effect = [
        {"info": {"status": "running", "progress": 90}, "vulnerabilities": []},
        {"info": {"status": "running", "progress": 95}, "vulnerabilities": []},
        {"info": {"status": "completed", "progress": 100}, "vulnerabilities": [{"plugin_name": "ok"}]},
    ]
    settings = MagicMock()
    settings.gvm_scan_poll_interval_sec = 1
    settings.gvm_scan_timeout_sec = 1
    settings.gvm_scan_near_complete_grace_sec = 60
    settings.gvm_scan_near_complete_progress_pct = 85
    # deadline starts at t0+1; first check at 2.0 triggers grace → deadline 62; then complete
    ticks = [0.0, 2.0, 3.0, 4.0]

    def _mono() -> float:
        return ticks.pop(0) if ticks else 100.0

    with patch("app.services.scan_orchestrator.get_settings", return_value=settings):
        with patch("app.services.scan_orchestrator.time.sleep", return_value=None):
            with patch("app.services.scan_orchestrator.time.monotonic", side_effect=_mono):
                out = _wait_for_openvas(client, "task-2")
    assert out["info"]["status"] == "completed"
    assert not out.get("partial")


def test_wait_for_openvas_timeout_zero_uses_adaptive_cap_and_completes():
    client = MagicMock()
    client.scan_details.side_effect = [
        {"info": {"status": "running", "progress": 40}, "vulnerabilities": []},
        {"info": {"status": "completed", "progress": 100}, "vulnerabilities": [{"plugin_name": "x"}]},
    ]
    settings = MagicMock()
    settings.gvm_scan_poll_interval_sec = 1
    settings.gvm_scan_timeout_sec = 0
    settings.gvm_port_profile = "fast"
    settings.gvm_scan_near_complete_grace_sec = 0
    settings.gvm_scan_near_complete_progress_pct = 85
    settings.gvm_scan_stall_sec = 0
    settings.gvm_scan_stall_progress_pct = 95

    with patch("app.services.scan_orchestrator.get_settings", return_value=settings):
        with patch("app.services.scan_orchestrator.time.sleep", return_value=None):
            with patch("app.services.scan_orchestrator.time.monotonic", side_effect=[0.0, 10.0, 20.0]):
                out = _wait_for_openvas(client, "task-unlimited")
    assert out["info"]["status"] == "completed"
    assert not out.get("partial")
    client.stop_scan.assert_not_called()


def test_adaptive_openvas_timeout_scales_with_profile_and_hosts():
    fast = adaptive_openvas_timeout_sec(1, SimpleNamespace(gvm_scan_timeout_sec=0, gvm_port_profile="fast"))
    full = adaptive_openvas_timeout_sec(1, SimpleNamespace(gvm_scan_timeout_sec=0, gvm_port_profile="full"))
    assert 1200 <= fast <= 14_400
    assert full > fast
    assert adaptive_openvas_timeout_sec(1, SimpleNamespace(gvm_scan_timeout_sec=900, gvm_port_profile="fast")) == 900


def test_wait_for_openvas_stall_sec_zero_does_not_force_early_harvest():
    client = MagicMock()
    client.scan_details.side_effect = [
        {"info": {"status": "running", "progress": 98}, "vulnerabilities": []},
        {"info": {"status": "completed", "progress": 100}, "vulnerabilities": [{"plugin_name": "real"}]},
    ]
    settings = MagicMock()
    settings.gvm_scan_poll_interval_sec = 1
    settings.gvm_scan_timeout_sec = 3600
    settings.gvm_scan_near_complete_grace_sec = 0
    settings.gvm_scan_near_complete_progress_pct = 85
    settings.gvm_scan_stall_progress_pct = 95
    settings.gvm_scan_stall_sec = 0
    ticks = [0.0, 100.0, 200.0]

    def _mono() -> float:
        return ticks.pop(0) if ticks else 300.0

    with patch("app.services.scan_orchestrator.get_settings", return_value=settings):
        with patch("app.services.scan_orchestrator.time.sleep", return_value=None):
            with patch("app.services.scan_orchestrator.time.monotonic", side_effect=_mono):
                out = _wait_for_openvas(client, "task-no-stall")
    assert out["info"]["status"] == "completed"
    assert not out.get("partial")
    client.stop_scan.assert_not_called()


def test_scan_job_progress_names_running_openvas_not_trivy():
    job = {"id": "11111111-1111-1111-1111-111111111111", "status": "running", "orchestration_json": {}}
    runs = [
        {"engine": "openvas", "status": "running"},
        {"engine": "nmap", "status": "completed"},
        {"engine": "nuclei", "status": "completed"},
        {"engine": "zap", "status": "completed"},
        {"engine": "wazuh", "status": "skipped"},
        {"engine": "trivy", "status": "skipped"},
    ]
    with patch("app.services.scan_orchestrator.fetchall", return_value=runs):
        out = scan_job_progress(object(), job)
    assert "openvas" in out["progress_label"].lower()
    assert "trivy" not in out["progress_label"].lower()


def test_scan_job_target_rows_show_live_activity_and_counts():
    job = {
        "id": "jid",
        "status": "running",
        "orchestration_json": {
            "target_progress": {
                "10.0.0.1": {"status": "scanning", "activity": "OpenVAS 72%", "engines": {"openvas": "running"}},
                "10.0.0.2": {"status": "completed", "activity": "Completed", "engines": {"openvas": "completed"}},
            }
        },
    }

    def _fetchall(db, sql, params=None):
        if "vuln_scan_targets" in sql:
            return [{"target": "10.0.0.1", "excluded": False}, {"target": "10.0.0.2", "excluded": False}]
        return [
            {"host": "10.0.0.2", "severity": "critical", "count": 2},
            {"host": "10.0.0.2", "severity": "high", "count": 4},
            {"host": "10.0.0.2", "severity": "low", "count": 1},
        ]

    with patch("app.services.scan_orchestrator.fetchall", side_effect=_fetchall):
        rows = {r["ip"]: r for r in scan_job_target_rows(object(), job)}
    assert rows["10.0.0.1"]["status"] == "scanning"
    assert "OpenVAS" in rows["10.0.0.1"]["activity"]
    assert rows["10.0.0.2"]["status"] == "completed"
    assert rows["10.0.0.2"]["activity"] == "Completed"
    assert rows["10.0.0.2"]["critical"] == 2
    assert rows["10.0.0.2"]["high"] == 4
    assert rows["10.0.0.2"]["low"] == 1


def test_trivy_skips_ip_targets():
    from app.services.multi_scanner_clients import TrivyScanner, _is_container_image

    assert _is_container_image("192.168.1.10") is False
    assert _is_container_image("nginx:1.25") is True
    result = TrivyScanner().run_scan(targets="10.0.0.5", name="t")
    assert result["stub"] is False
    assert result["info"]["status"] == "skipped"
    assert result["vulnerabilities"] == []


def test_terminate_scan_job_processes_stops_openvas_and_revokes_celery():
    from app.services.scan_orchestrator import terminate_scan_job_processes

    client = MagicMock()
    client.find_tasks.return_value = [{"id": "gvm-1", "name": "orch-11111111-openvas", "status": "running"}]
    celery = MagicMock()
    celery.control.inspect.return_value.active.return_value = {
        "w1": [{"id": "celery-1", "args": ["firm_aetheris", "11111111-1111-1111-1111-111111111111"]}]
    }
    celery.control.inspect.return_value.reserved.return_value = {}
    celery.control.inspect.return_value.scheduled.return_value = {}

    import sys
    import types

    fake_module = types.ModuleType("app.celery_vuln")
    fake_module.celery = celery
    with patch("app.services.scan_orchestrator.get_scanner_client", return_value=client), patch.dict(
        sys.modules, {"app.celery_vuln": fake_module}
    ):
        out = terminate_scan_job_processes(
            {"id": "11111111-1111-1111-1111-111111111111", "external_scan_id": "gvm-ext"}
        )
    assert "gvm-ext" in out["stopped_openvas"]
    assert "gvm-1" in out["stopped_openvas"]
    client.stop_scan.assert_any_call("gvm-ext")
    celery.control.revoke.assert_called()


def test_parse_gvm_port_range_and_probe_helpers():
    from app.services.greenbone_gmp import parse_tcp_ports_from_range, ports_to_gvm_range

    assert parse_tcp_ports_from_range("T:21-23,80,443") == [21, 22, 23, 80, 443]
    assert ports_to_gvm_range([443, 80]) == "T:80,443"


def test_nmap_parse_xml_keeps_per_host_address():
    from app.services.multi_scanner_clients import NmapScanner

    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host><address addr="10.0.0.1"/><ports>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      </ports></host>
      <host><address addr="10.0.0.2"/><ports>
        <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      </ports></host>
    </nmaprun>"""
    vulns = NmapScanner()._parse_nmap_xml(xml, "fallback")
    assert {v["host"] for v in vulns} == {"10.0.0.1", "10.0.0.2"}


def test_ingest_engine_results_does_not_truncate_after_500(monkeypatch):
    import app.services.scan_orchestrator as mod

    inserted = []
    monkeypatch.setattr(mod, "_ensure_asset", lambda db, *, case_id, target: "asset-1")
    monkeypatch.setattr(mod, "refresh_asset_risk", lambda db, asset_id: None)

    def _upsert(db, **kwargs):
        inserted.append(kwargs["vuln"]["plugin_id"])
        return f"finding-{len(inserted)}"

    monkeypatch.setattr(mod, "upsert_finding", _upsert)
    vulns = [
        {"plugin_id": f"vt-{i}", "host": "192.168.0.1", "severity": "info"}
        for i in range(750)
    ]
    count = mod.ingest_engine_results(
        object(),
        case_id="case-1",
        scan_job_id="scan-1",
        engine="openvas",
        targets=["192.168.0.1"],
        vulnerabilities=vulns,
        credentialed=False,
    )
    assert count == 750
    assert inserted[-1] == "vt-749"


def test_ingest_engine_results_maps_each_multi_host_row_once(monkeypatch):
    import app.services.scan_orchestrator as mod

    ensured = []
    inserted = []
    refreshed = []

    def _ensure(db, *, case_id, target):
        ensured.append(target)
        return f"asset-{target}"

    def _upsert(db, **kwargs):
        inserted.append((kwargs["asset_id"], kwargs["vuln"]["plugin_id"]))
        return f"finding-{len(inserted)}"

    monkeypatch.setattr(mod, "_ensure_asset", _ensure)
    monkeypatch.setattr(mod, "upsert_finding", _upsert)
    monkeypatch.setattr(mod, "refresh_asset_risk", lambda db, asset_id: refreshed.append(asset_id))

    count = mod.ingest_engine_results(
        object(),
        case_id="case-1",
        scan_job_id="scan-1",
        engine="openvas",
        targets=["192.168.0.1", "192.168.0.2"],
        vulnerabilities=[
            {"plugin_id": "router-vt", "host": "192.168.0.1"},
            {"plugin_id": "host-vt", "host": "192.168.0.2"},
        ],
        credentialed=False,
    )

    assert count == 2
    assert inserted == [
        ("asset-192.168.0.1", "router-vt"),
        ("asset-192.168.0.2", "host-vt"),
    ]
    assert ensured == ["192.168.0.1", "192.168.0.2"]
    assert set(refreshed) == {"asset-192.168.0.1", "asset-192.168.0.2"}


def test_ingest_engine_results_stores_scanner_wide_row_only_once(monkeypatch):
    import app.services.scan_orchestrator as mod

    inserted = []
    monkeypatch.setattr(
        mod,
        "_ensure_asset",
        lambda db, *, case_id, target: f"asset-{target}",
    )
    monkeypatch.setattr(mod, "refresh_asset_risk", lambda db, asset_id: None)
    monkeypatch.setattr(
        mod,
        "upsert_finding",
        lambda db, **kwargs: inserted.append(kwargs["asset_id"]) or "finding-1",
    )

    count = mod.ingest_engine_results(
        object(),
        case_id="case-1",
        scan_job_id="scan-1",
        engine="openvas",
        targets=["192.168.0.1", "192.168.0.2"],
        vulnerabilities=[{"plugin_id": "scanner-wide", "host": "*"}],
        credentialed=False,
    )

    assert count == 1
    assert inserted == ["asset-192.168.0.1"]


def test_finding_dedup_is_scoped_to_the_scan_job(monkeypatch):
    import app.services.vuln_finding_ingest as mod

    queries = []

    def _fetchone(db, sql, params):
        queries.append((sql, params))
        return {"id": "finding-1", "status": "open", "first_seen_at": None}

    monkeypatch.setattr(mod, "fetchone", _fetchone)
    monkeypatch.setattr(mod, "execute", lambda *args, **kwargs: None)
    monkeypatch.setattr(mod, "is_kev_cve", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        mod,
        "score_finding",
        lambda **kwargs: {
            "enterprise_risk_score": 0.0,
            "risk_band": "informational",
            "risk_factors_json": {},
        },
    )

    finding_id = mod.upsert_finding(
        object(),
        case_id="00000000-0000-0000-0000-000000000001",
        scan_job_id="00000000-0000-0000-0000-000000000002",
        asset_id="00000000-0000-0000-0000-000000000003",
        vuln={"plugin_id": "vt-1", "host": "192.168.0.1"},
    )

    assert finding_id == "finding-1"
    assert "scan_job_id IS NOT DISTINCT FROM CAST(:jid AS uuid)" in queries[0][0]
    assert queries[0][1]["jid"] == "00000000-0000-0000-0000-000000000002"


def test_tls_descriptions_preserve_cvss_severity(monkeypatch):
    from app.services.vuln_finding_ingest import normalize_raw_vuln

    monkeypatch.setenv("VULN_SEVERITY_PROFILE", "aetheris")
    sslv3 = normalize_raw_vuln(
        {"plugin_name": "SSL Version 2 and 3 Protocol Detection", "severity": "medium", "cvss": 5.0}
    )
    sweet32 = normalize_raw_vuln(
        {"plugin_name": "SSL Medium Strength Cipher Suites Supported (SWEET32)", "severity": "medium", "cvss": 5.0}
    )

    assert sslv3["severity"] == "medium"
    assert sslv3["severity_policy_rule"] is None
    assert sslv3["cvss"] == 5.0
    assert sweet32["severity"] == "medium"
    assert sweet32["severity_policy_rule"] is None


def test_source_result_id_participates_in_retry_dedup(monkeypatch):
    import app.services.vuln_finding_ingest as mod

    queries = []
    monkeypatch.setattr(
        mod,
        "fetchone",
        lambda db, sql, params: queries.append((sql, params)) or {"id": "finding-1", "status": "open"},
    )
    monkeypatch.setattr(mod, "execute", lambda *args, **kwargs: None)
    monkeypatch.setattr(mod, "is_kev_cve", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        mod,
        "score_finding",
        lambda **kwargs: {"enterprise_risk_score": 0, "risk_band": "info", "risk_factors_json": {}},
    )

    mod.upsert_finding(
        object(),
        case_id="00000000-0000-0000-0000-000000000001",
        scan_job_id="00000000-0000-0000-0000-000000000002",
        asset_id="00000000-0000-0000-0000-000000000003",
        vuln={"plugin_id": "vt-1", "source_result_id": "result-abc"},
    )

    assert "risk_factors_json->>'source_result_id'" in queries[0][0]
    assert queries[0][1]["rid"] == "result-abc"


def test_normalize_raw_vuln_preserves_qod_metadata():
    from app.services.vuln_finding_ingest import normalize_raw_vuln

    norm = normalize_raw_vuln(
        {
            "plugin_id": "oid-1",
            "severity": "critical",
            "cvss": 9.8,
            "qod": 35,
            "qod_type": "remote_banner",
        }
    )
    assert norm["qod"] == 35
    assert norm["qod_type"] == "remote_banner"
