"""Remove only the named legacy huddle chatter, while retaining process evidence."""

from unittest.mock import MagicMock, patch

import pytest

from app.services.disk_build_log import write_disk_log, write_disk_logs_batch
from app.services.retired_agents import (
    is_retired_huddle_message,
    visible_pipeline_logs_sql,
)


@pytest.mark.parametrize(
    "message",
    [
        "[Agent huddle] Observe: polling",
        " [Agent huddle] Performance — tune",
        "[agent HUDDLE] Repair: retry",
        "[Agent huddle] Observe Agent started",
    ],
)
def test_retired_console_messages_are_dropped(message):
    assert is_retired_huddle_message(message)
    db = MagicMock()
    with patch("app.services.disk_build_log.execute") as insert:
        write_disk_log(db, "job", message)
    insert.assert_not_called()
    assert not db.mock_calls


@pytest.mark.parametrize(
    "message",
    [
        "progressAgent: valid thermal pause",
        "Repairing corrupt SQLite source",
        "Performance measurements: 250 files/sec",
        "Observe attached evidence",
        "[Agent huddle] OCR: source page failed",
        "Suspicious app named Repair",
    ],
)
def test_process_and_evidence_messages_are_kept(message):
    assert not is_retired_huddle_message(message)


def test_batch_preserves_processing_logs_only():
    db = MagicMock()
    write_disk_logs_batch(
        db,
        "job",
        [
            {"message": "[Agent huddle] Repair: retry"},
            {"message": "progressAgent: progress resumed"},
        ],
    )
    payload = db.execute.call_args.args[1]
    assert (
        len(payload) == 1 and payload[0]["message"] == "progressAgent: progress resumed"
    )


def test_log_filter_uses_only_known_columns():
    assert "l.message" in visible_pipeline_logs_sql("l.message")
    with pytest.raises(ValueError):
        visible_pipeline_logs_sql("user text")
