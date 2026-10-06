"""Queued legacy huddles must never start another monitoring process."""

from unittest.mock import MagicMock, patch

from app.services.agent_huddle import run_agent_huddle


def test_retired_huddle_never_reads_or_dispatches():
    db = MagicMock()
    with (
        patch("app.services.progress_agent.monitor_job") as monitor,
        patch("app.services.pipeline_supervisor.dispatch_stage_agent") as dispatch,
    ):
        result = run_agent_huddle(db, "job-1", schema_name="firm_test")
    assert result["status"] == "retired"
    assert result["coordinator"] == "progressAgent"
    monitor.assert_not_called()
    dispatch.assert_not_called()
    assert not db.mock_calls


def test_old_supervisor_delivery_does_not_start_progress_agent():
    from app.tasks import pipeline_supervisor_task

    with patch("app.tasks.progress_agent_task") as progress:
        result = pipeline_supervisor_task.run(schema_name="firm_test")
    assert result["status"] == "retired"
    progress.assert_not_called()
