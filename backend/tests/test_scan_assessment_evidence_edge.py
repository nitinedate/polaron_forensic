import json

import app.services.scan_assessment_evidence as sae


def _run(monkeypatch, *, job, result):
    calls = iter([job, result])
    monkeypatch.setattr(sae, "fetchone", lambda *a, **k: next(calls))
    return sae.load_case_scan_assessment(object(), "00000000-0000-0000-0000-000000000001")


def test_completed_central_job_infers_verified_from_engines(monkeypatch):
    job = {
        "id": "j-central",
        "status": "completed",
        "target_count": 1,
        "active_target_count": 1,
        "orchestration_json": {"enabled": True},
        "error": None,
    }

    def _fetchall(db, sql, params=None):
        if "vuln_scan_targets" in sql:
            return [{"target": "192.168.0.164", "excluded": False}]
        if "vuln_scan_engine_runs" in sql:
            return [{"engine": "openvas", "status": "completed"}, {"engine": "nuclei", "status": "completed"}]
        return [{"host": "192.168.0.164"}]

    monkeypatch.setattr(sae, "fetchone", lambda *a, **k: job if "vuln_scan_jobs" in (a[1] if len(a) > 1 else "") else None)
    # load_case: first fetchone is job, second is result
    calls = iter([job, None])
    monkeypatch.setattr(sae, "fetchone", lambda *a, **k: next(calls))
    monkeypatch.setattr(sae, "fetchall", _fetchall)
    out = sae.load_case_scan_assessment(object(), "00000000-0000-0000-0000-000000000001")
    assert out["verified"] is True
    assert out["hosts_assessed"] == 1
    assert out["state"] == "verified"


def test_completed_without_result_is_unverified(monkeypatch):
    job = {
        "id": "j1", "status": "completed", "target_count": 2, "active_target_count": 2,
        "orchestration_json": {"edge_agent": True}, "external_scan_id": "task1", "error": None,
    }
    out = _run(monkeypatch, job=job, result=None)
    assert out["verified"] is False
    assert out["state"] == "unverified"
    assert "no durable" in out["message"].lower()


def test_one_assessed_one_skipped_is_verified_not_clean(monkeypatch):
    job = {
        "id": "j1", "status": "completed", "target_count": 2, "active_target_count": 1,
        "orchestration_json": {"edge_agent": True}, "external_scan_id": "task1", "error": None,
    }
    result = {
        "hosts_attempted": 1,
        "hosts_assessed": 1,
        "plugin_error_count": 0,
        "result_json": {
            "edge_agent": True,
            "assessment_complete": True,
            "assessment_verdict": "assessed_with_unreachable_skips",
            "report_id": "r1",
            "task_id": "task1",
            "assessed_hosts": ["192.168.0.10"],
            "skipped_hosts": [{"host": "192.168.0.11", "reason": "unreachable"}],
        },
    }
    out = _run(monkeypatch, job=job, result=result)
    assert out["verified"] is True
    assert out["clean_eligible"] is False
    assert out["state"] == "verified_with_skips"
    assert out["hosts_assessed"] == 1
    assert out["target_count"] == 2


def test_all_targets_assessed_is_verified_clean(monkeypatch):
    job = {
        "id": "j1", "status": "completed", "target_count": 2, "active_target_count": 2,
        "orchestration_json": {"edge_agent": True}, "external_scan_id": "task1", "error": None,
    }
    result = {
        "hosts_attempted": 2,
        "hosts_assessed": 2,
        "plugin_error_count": 0,
        "result_json": {
            "edge_agent": True, "assessment_complete": True, "report_id": "r1", "task_id": "task1",
            "assessed_hosts": ["192.168.0.10", "192.168.0.11"], "skipped_hosts": [],
        },
    }
    out = _run(monkeypatch, job=job, result=result)
    assert out["verified"] is True
    assert out["clean_eligible"] is True
    assert out["state"] == "verified"
