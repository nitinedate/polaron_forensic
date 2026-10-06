import json
from unittest.mock import patch

from app.services.scanner_agent_jobs import _target_event_state, update_target_progress


def test_target_event_state_maps_requested_ui_statuses():
    assert _target_event_state("queued")["status"] == "pending"
    assert _target_event_state("started")["status"] == "scanning"
    assert _target_event_state("progress", progress_pct=61)["activity"].endswith("(61%)")
    assert _target_event_state("completed")["status"] == "completed"
    assert _target_event_state("scan_failed", error="boom")["status"] == "failed"


def test_update_target_progress_persists_into_existing_orchestration_json():
    job = {
        "id": "00000000-0000-0000-0000-000000000001",
        "scanner_id": "00000000-0000-0000-0000-000000000002",
        "status": "running",
        "orchestration_json": {"edge_agent": True, "target_progress": {}},
    }
    executed = []

    with patch("app.services.scanner_agent_jobs.fetchone", return_value=job), patch(
        "app.services.scanner_agent_jobs.fetchall",
        return_value=[{"target": "10.0.0.7"}],
    ), patch(
        "app.services.scanner_agent_jobs.execute",
        side_effect=lambda db, sql, params=None: executed.append((sql, params)),
    ):
        out = update_target_progress(
            object(),
            scanner_id=job["scanner_id"],
            job_id=job["id"],
            target="10.0.0.7",
            event="progress",
            status="running",
            progress_pct=44,
            open_ports=[22, 443],
            task_id="task-7",
        )

    assert out["status"] == "ok"
    assert out["target_progress"]["status"] == "scanning"
    assert out["target_progress"]["progress_pct"] == 44
    assert out["target_progress"]["open_ports"] == [22, 443]
    assert executed
    payload = json.loads(executed[-1][1]["orch"])
    state = payload["target_progress"]["10.0.0.7"]
    assert state["status"] == "scanning"
    assert state["task_id"] == "task-7"


def test_update_target_progress_rejects_target_outside_job():
    job = {
        "id": "00000000-0000-0000-0000-000000000001",
        "scanner_id": "00000000-0000-0000-0000-000000000002",
        "status": "running",
        "orchestration_json": {"edge_agent": True},
    }
    with patch("app.services.scanner_agent_jobs.fetchone", return_value=job), patch(
        "app.services.scanner_agent_jobs.fetchall",
        return_value=[{"target": "10.0.0.7"}],
    ):
        out = update_target_progress(
            object(),
            scanner_id=job["scanner_id"],
            job_id=job["id"],
            target="10.0.0.99",
            event="queued",
        )
    assert out["status"] == "invalid_target"
