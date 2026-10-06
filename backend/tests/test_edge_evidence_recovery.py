import app.services.scanner_agent_jobs as saj


def test_completed_edge_job_without_result_is_reopened_for_evidence(monkeypatch):
    recoverable = {
        "id": "00000000-0000-0000-0000-000000000011",
        "case_id": "00000000-0000-0000-0000-000000000012",
        "external_scan_id": "task-123",
        "status": "completed",
        "orchestration_json": {"edge_agent": True},
    }
    reopened = dict(recoverable, status="running", completed_at=None)
    calls = {"n": 0}

    def fake_fetchone(db, sql, params=None):
        calls["n"] += 1
        if calls["n"] == 1:
            assert "NOT EXISTS" in sql
            assert "vuln_scan_results" in sql
            return recoverable
        if calls["n"] == 2:
            assert "SET status = 'running'" in sql
            return reopened
        raise AssertionError(f"unexpected fetchone call {calls['n']}")

    monkeypatch.setattr(saj, "fetchone", fake_fetchone)
    monkeypatch.setattr(saj, "_agent_supports_parallel", lambda db, sid: True)
    monkeypatch.setattr(saj, "_agent_supports_resume", lambda db, sid: True)
    monkeypatch.setattr(saj, "timeline", lambda *a, **k: None)
    monkeypatch.setattr(saj, "_job_payload", lambda db, row, resumed: {"id": row["id"], "status": row["status"], "resume": resumed})

    out = saj.claim_next_job(object(), "00000000-0000-0000-0000-000000000099", active_job_ids=[])
    assert out["status"] == "running"
    assert out["resume"] is True
