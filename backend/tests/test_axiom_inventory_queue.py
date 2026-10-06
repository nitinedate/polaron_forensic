"""Artifact inventory must queue async — parse drain must not block on full-disk counts."""

from unittest.mock import MagicMock, patch

from app.services.axiom_artifact_runner import (
    finalize_job_after_pipeline,
    inventory_task_in_flight,
    queue_axiom_artifact_inventory,
)


def test_finalize_queues_inventory_task() -> None:
    db = MagicMock()
    inv = {"platform": "Windows", "total": 614, "completed": 0, "done": False}

    with patch("app.services.axiom_artifact_runner.parse_pending_count", return_value=0), patch(
        "app.services.axiom_artifact_runner.axiom_inventory_progress",
        return_value=inv,
    ), patch("app.services.axiom_artifact_runner.inventory_task_in_flight", return_value=False), patch(
        "app.services.axiom_artifact_runner._apply_inventory_progress",
    ), patch("app.services.axiom_artifact_runner.write_disk_log"), patch(
        "app.services.axiom_artifact_runner.resolve_job_axiom_platform",
        return_value="Windows",
    ), patch("app.tasks.axiom_artifact_inventory_task") as task:
        task.delay = MagicMock()
        result = finalize_job_after_pipeline(db, "job-1", schema_name="firm_aetheris")

    assert result["queued_axiom_inventory"] is True
    task.delay.assert_called_once_with("firm_aetheris", "job-1")


def test_finalize_skips_when_parse_pending() -> None:
    db = MagicMock()
    with patch("app.services.axiom_artifact_runner.parse_pending_count", return_value=12), patch(
        "app.services.axiom_artifact_runner.axiom_inventory_progress",
        return_value={"total": 614, "completed": 0, "done": False},
    ):
        result = finalize_job_after_pipeline(db, "job-1", schema_name="firm_aetheris")
    assert result["queued_axiom_inventory"] is False
    assert result["reason"] == "parse_pending"


def test_queue_skips_when_already_running() -> None:
    db = MagicMock()
    inv = {"platform": "Windows", "total": 614, "completed": 3, "done": False}
    with patch("app.services.axiom_artifact_runner.parse_pending_count", return_value=0), patch(
        "app.services.axiom_artifact_runner.axiom_inventory_progress",
        return_value=inv,
    ), patch("app.services.axiom_artifact_runner.inventory_task_in_flight", return_value=True), patch(
        "app.tasks.axiom_artifact_inventory_task"
    ) as task:
        task.delay = MagicMock()
        result = queue_axiom_artifact_inventory(db, "job-1", schema_name="firm_aetheris")
    assert result["queued_axiom_inventory"] is True
    assert result["reason"] == "already_running"
    task.delay.assert_not_called()


def test_queue_stays_quiet_while_disk_has_no_artifacts() -> None:
    db = MagicMock()
    with patch(
        "app.services.catalog_artifact_runner.artifacts_ready_for_inventory",
        return_value=(False, "waiting_for_artifacts (0 < 500)"),
    ), patch(
        "app.services.catalog_artifact_runner.axiom_inventory_progress",
        return_value={"platform": "Windows", "total": 614, "completed": 0, "done": False},
    ), patch(
        "app.services.catalog_artifact_runner.write_disk_log",
    ) as disk_log, patch(
        "app.services.catalog_artifact_runner.ensure_job_axiom_results_schema",
    ), patch(
        "app.services.artifact_selection_catalog.persist_job_axiom_platform",
    ):
        result = queue_axiom_artifact_inventory(db, "job-1", schema_name="firm_aetheris")
    assert result["queued_axiom_inventory"] is False
    assert result["reason"].startswith("waiting_for_artifacts")
    disk_log.assert_not_called()


def test_zero_artifacts_during_extract_is_a_wait_not_a_failure() -> None:
    from app.services.catalog_artifact_runner import artifacts_ready_for_inventory

    with patch(
        "app.services.catalog_artifact_runner.materialized_artifact_count",
        return_value=0,
    ), patch(
        "app.services.catalog_artifact_runner._min_artifacts_for_inventory",
        return_value=500,
    ), patch(
        "app.services.catalog_artifact_runner._job_pipeline_state",
        return_value=("processing", "extract"),
    ):
        ready, reason = artifacts_ready_for_inventory(MagicMock(), "job-1")
    assert ready is False
    assert reason == "waiting_for_artifacts (0 < 500)"


def test_small_image_is_ready_after_materialize() -> None:
    from app.services.catalog_artifact_runner import artifacts_ready_for_inventory

    with patch(
        "app.services.catalog_artifact_runner.materialized_artifact_count",
        return_value=120,
    ), patch(
        "app.services.catalog_artifact_runner._min_artifacts_for_inventory",
        return_value=500,
    ), patch(
        "app.services.catalog_artifact_runner._job_pipeline_state",
        return_value=("indexing", "parse"),
    ):
        ready, reason = artifacts_ready_for_inventory(MagicMock(), "job-1")
    assert ready is True
    assert "120" in reason


def test_inventory_in_flight_detects_axiom_pass_log() -> None:
    from datetime import datetime, timezone

    db = MagicMock()
    start_ts = datetime.now(timezone.utc)
    with patch("app.services.axiom_artifact_runner.axiom_inventory_progress", return_value={
        "total": 614,
        "completed": 0,
        "done": False,
    }), patch("app.services.axiom_artifact_runner.fetchone") as fetchone:
        fetchone.side_effect = [
            {"timestamp": start_ts},
            None,
        ]
        assert inventory_task_in_flight(db, "job-1") is True
