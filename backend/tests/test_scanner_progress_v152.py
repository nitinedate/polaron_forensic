import json
from unittest.mock import patch

import pytest

from app.services.scanner_agent_jobs import _merge_edge_target_progress, _target_event_state, update_job_progress, ingest_agent_results
from app.services.scan_orchestrator import scan_job_target_rows


@pytest.mark.parametrize("value", [float("nan"), float("inf"), "bad", None])
def test_invalid_percent_is_safe_and_running_never_complete(value):
    assert _target_event_state("running", progress_pct=value)["progress_pct"] == 0
    assert _target_event_state("running", progress_pct=1000)["progress_pct"] == 99


def test_merge_clips_scope_ports_and_preserves_coverage_terminal():
    old = {"10.0.0.1": {"status": "incomplete", "progress_pct": 100, "task_id": "t1", "coverage": {"verdict": "degraded_ports"}}}
    incoming = {"10.0.0.1": {"status": "running", "progress_pct": 55, "task_id": "t1"},
                "10.0.0.2": {"status": "scanning", "progress_pct": 43, "open_ports": [22, 22, "443", -1, 99999, "bad", True]},
                "10.0.0.99": {"status": "completed"}}
    got = _merge_edge_target_progress(old, incoming, ["10.0.0.1", "10.0.0.2"])
    assert got["10.0.0.1"] == old["10.0.0.1"]
    assert got["10.0.0.2"]["open_ports"] == [22, 443]
    assert "10.0.0.99" not in got


def test_new_task_can_restart_percent_but_delayed_poll_cannot_regress_same_task():
    old = {"host": {"status": "scanning", "progress_pct": 61, "task_id": "old"}}
    assert _merge_edge_target_progress(old, {"host": {"status": "scanning", "progress_pct": 40, "task_id": "old"}}, ["host"])["host"]["progress_pct"] == 61
    got = _merge_edge_target_progress(old, {"host": {"status": "scanning", "progress_pct": 4, "task_id": "new"}}, ["host"])
    assert got["host"]["progress_pct"] == 4


def _job(owner="agent-1", status="running"):
    return {"id": "00000000-0000-0000-0000-000000000001", "scanner_id": "00000000-0000-0000-0000-000000000002",
            "status": status, "orchestration_json": {"edge_agent": True, "edge_owner_instance": owner}}


def test_snapshot_patch_is_locked_scoped_and_persisted():
    job = _job()
    writes = []
    reads = []
    def one(db, sql, params=None):
        reads.append(sql)
        return {"version": "1.5.2"} if "vuln_scanners" in sql else job
    with patch("app.services.scanner_agent_jobs.fetchone", side_effect=one), \
         patch("app.services.scanner_agent_jobs.fetchall", return_value=[{"target": "10.0.0.1"}, {"target": "10.0.0.2"}]), \
         patch("app.services.scanner_agent_jobs.execute", side_effect=lambda db, sql, params=None: writes.append(params)):
        result = update_job_progress(object(), scanner_id=job["scanner_id"], job_id=job["id"],
            agent_instance_id="agent-1", target_progress={"10.0.0.1": {"status": "scanning", "progress_pct": 44},
            "10.0.0.2": {"status": "pending"}, "10.0.0.99": {"status": "completed"}})
    assert result["status"] == "running"
    assert "FOR UPDATE" in reads[0]
    stored = json.loads(writes[-1]["orch"])["target_progress"]
    assert set(stored) == {"10.0.0.1", "10.0.0.2"}
    assert stored["10.0.0.1"]["progress_pct"] == 44
    assert stored["10.0.0.2"]["status"] == "pending"


def test_non_owner_cannot_write_progress():
    job = _job()
    with patch("app.services.scanner_agent_jobs.fetchone", return_value=job), patch("app.services.scanner_agent_jobs.execute") as write:
        result = update_job_progress(object(), scanner_id=job["scanner_id"], job_id=job["id"],
            agent_instance_id="other", target_progress={"10.0.0.1": {"status": "completed"}})
    assert result["owner_mismatch"] is True
    write.assert_not_called()


def test_completed_job_cannot_reopen_from_late_snapshot():
    job = _job(owner="", status="completed")
    with patch("app.services.scanner_agent_jobs.fetchone", return_value=job), \
         patch("app.services.scanner_agent_jobs.fetchall", return_value=[]), \
         patch("app.services.scanner_agent_jobs._job_payload", return_value={"status": "completed"}), \
         patch("app.services.scanner_agent_jobs.execute") as write:
        assert update_job_progress(object(), scanner_id=job["scanner_id"], job_id=job["id"], status="running",
            target_progress={"10.0.0.1": {"status": "scanning"}})["status"] == "completed"
    write.assert_not_called()


def test_ui_summary_keeps_waiting_running_and_incomplete_separate():
    job = _job(owner="")
    job["orchestration_json"]["target_progress"] = {
        "10.0.0.1": {"status": "scanning", "progress_pct": 44},
        "10.0.0.2": {"status": "incomplete", "progress_pct": 100},
    }
    with patch("app.services.scan_orchestrator.fetchall", side_effect=[
        [{"target": f"10.0.0.{i}"} for i in range(1, 4)], []]):
        rows = scan_job_target_rows(object(), job)
    assert [(r["status"], r["progress_pct"]) for r in rows] == [("scanning", 44), ("incomplete", 100), ("pending", 0)]


def test_finished_task_with_degraded_port_scan_cannot_claim_clean_result():
    job = _job()
    job["case_id"] = "00000000-0000-0000-0000-000000000003"
    writes = []
    with patch("app.services.scanner_agent_jobs.fetchone", return_value=job), \
         patch("app.services.scanner_agent_jobs.fetchall", return_value=[{"target": "10.0.0.1", "excluded": False}]), \
         patch("app.services.scanner_agent_jobs.ingest_engine_results", return_value=1), \
         patch("app.services.scanner_agent_jobs.execute", side_effect=lambda db, sql, params=None: writes.append(params)), \
         patch("app.services.vuln_brd.record_scan_result") as record, \
         patch("app.services.scanner_agent_jobs.timeline"):
        result = ingest_agent_results(object(), scanner_id=job["scanner_id"], job_id=job["id"],
            agent_instance_id="agent-1", vulnerabilities=[{"severity": "info"}],
            external_scan_id="task-1", report_id="report-1", task_status="Done", partial=False,
            hosts_attempted=1, hosts_assessed=1, assessed_hosts=["10.0.0.1"], report_result_count=1,
            scan_start="2026-10-06T10:00:00Z", scan_end="2026-10-06T10:20:00Z", assessment_complete=True,
            host_coverage={"10.0.0.1": {"verdict": "degraded_ports", "reason": "SYN scanner interrupted"}})
    stored = json.loads(next(p["orch"] for p in writes if p and "orch" in p))
    evidence = record.call_args.kwargs["result_json"]
    for view in (result, stored, evidence):
        assert view["partial"] is True
        assert view["clean_eligible"] is False
        assert view["completed_with_warnings"] is True
    assert stored["target_progress"]["10.0.0.1"]["status"] == "incomplete"
    assert evidence["degraded_hosts"] == ["10.0.0.1"]
