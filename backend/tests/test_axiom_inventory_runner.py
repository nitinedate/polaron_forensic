"""Tests for AXIOM artifact inventory batching and progress."""

import json

from app.services.axiom_artifact_runner import (
    INVENTORY_PHASE,
    PIPELINE_PROGRESS_CAP,
    _progress_pct,
    inventory_ui_pct_for,
    pending_inventory_rows,
    should_skip_pipeline_sync_on_read,
)


def test_should_skip_pipeline_sync_when_inventory_done_and_orchestration_complete():
    inv = {"done": True, "completed": 634, "total": 634, "platform": "Windows"}

    class FakeDb:
        pass

    db = FakeDb()
    row = {
        "status": "indexed",
        "pipeline_progress": {
            "phase": INVENTORY_PHASE,
            "completed": 634,
            "total": 634,
            "orchestration": {
                "overall_pct": 100,
                "agents": {"artifacts_agent": {"state": "done", "pct": 100}},
            },
        },
    }

    from app.services import axiom_artifact_runner as mod

    original = mod.axiom_inventory_progress
    mod.axiom_inventory_progress = lambda _db, _jid: inv
    try:
        assert should_skip_pipeline_sync_on_read(db, "job", row=row) is True
    finally:
        mod.axiom_inventory_progress = original


def test_should_skip_pipeline_sync_when_inventory_incomplete_and_indexing():
    inv = {"done": False, "completed": 10, "total": 634, "platform": "Windows"}

    class FakeDb:
        pass

    db = FakeDb()
    row = {"status": "indexing", "pipeline_progress": {"phase": INVENTORY_PHASE, "completed": 10, "total": 634}}

    from app.services import axiom_artifact_runner as mod

    original = mod.axiom_inventory_progress
    original_parse = mod.parse_pending_count
    mod.axiom_inventory_progress = lambda _db, _jid: inv
    mod.parse_pending_count = lambda _db, _jid: 0
    try:
        assert should_skip_pipeline_sync_on_read(db, "job", row=row) is True
    finally:
        mod.axiom_inventory_progress = original
        mod.parse_pending_count = original_parse


def test_should_skip_pipeline_sync_with_string_pipeline_progress():
    inv = {"done": True, "completed": 100, "total": 100, "platform": "Windows"}
    pp = {
        "phase": INVENTORY_PHASE,
        "completed": 100,
        "total": 100,
        "orchestration": {
            "overall_pct": 100,
            "agents": {"artifacts_agent": {"state": "done", "pct": 100}},
        },
    }
    row = {"status": "indexed", "pipeline_progress": json.dumps(pp)}

    class FakeDb:
        pass

    db = FakeDb()

    from app.services import axiom_artifact_runner as mod

    original = mod.axiom_inventory_progress
    mod.axiom_inventory_progress = lambda _db, _jid: inv
    try:
        assert should_skip_pipeline_sync_on_read(db, "job", row=row) is True
    finally:
        mod.axiom_inventory_progress = original


def test_load_stored_axiom_counts_reads_db_only():
    class FakeDb:
        pass

    db = FakeDb()
    from app.services import axiom_artifact_runner as mod

    original = mod.fetchall
    mod.fetchall = lambda _db, sql, _params: (
        [{"artifact_id": "a1", "artifact_count": 5}]
        if "status='done'" in sql
        else []
    )
    try:
        counts = mod.load_stored_axiom_counts(db, "job")
    finally:
        mod.fetchall = original
    assert counts == {"a1": 5}


def test_load_job_axiom_counts_never_recomputes():
    class FakeDb:
        pass

    db = FakeDb()
    from app.services import axiom_artifact_runner as mod

    original_fetch = mod.fetchall
    mod.fetchall = lambda _db, _sql, _params: []
    try:
        assert mod.load_job_axiom_counts(db, "job", "Windows") == {}
    finally:
        mod.fetchall = original_fetch


def test_progress_pct_caps_at_pipeline_cap_until_complete():
    assert _progress_pct(0, 623) == PIPELINE_PROGRESS_CAP
    mid = _progress_pct(100, 623)
    assert PIPELINE_PROGRESS_CAP < mid < 100
    assert _progress_pct(623, 623) == 100


def test_inventory_ui_pct_prewarm_and_counting_ranges():
    assert inventory_ui_pct_for(stage="start") == 1
    assert inventory_ui_pct_for(stage="path_index") == 12
    assert inventory_ui_pct_for(stage="carve") == 15
    assert inventory_ui_pct_for(stage="prewarm_done") == 18
    assert inventory_ui_pct_for(stage="counting", count_idx=0, count_total=635) == 18
    mid = inventory_ui_pct_for(stage="counting", count_idx=318, count_total=635)
    assert 18 < mid < 99
    assert inventory_ui_pct_for(stage="counting", count_idx=635, count_total=635) == 99
    assert inventory_ui_pct_for(stage="done") == 100


def test_inventory_not_in_flight_after_crash_with_zero_counts():
    from datetime import datetime, timedelta, timezone

    from app.services.axiom_artifact_runner import inventory_task_in_flight

    start_ts = datetime.now(timezone.utc) - timedelta(minutes=10)

    class FakeDb:
        pass

    db = FakeDb()

    from app.services import axiom_artifact_runner as mod

    original_progress = mod.axiom_inventory_progress
    original_fetchone = mod.fetchone

    def fake_fetchone(_db, sql, params=None):
        s = (sql or "").lower()
        if "inventory batch%" in s and "order by timestamp desc" in s:
            return None
        if "inventory failed%" in s:
            return None
        if (
            "inventory batch started%" in s
            or "axiom-aligned pass%" in s
            or "artifact inventory queued%" in s
        ) and "order by timestamp desc" in s:
            return {"timestamp": start_ts}
        if "inventory batch complete%" in s or "artifact inventory complete" in s:
            return None
        if "from jobs where id=:id" in s:
            return {"updated_at": start_ts}
        return None

    mod.axiom_inventory_progress = lambda _db, _jid: {
        "done": False,
        "completed": 0,
        "total": 634,
        "platform": "Windows",
    }
    mod.fetchone = fake_fetchone
    try:
        assert inventory_task_in_flight(db, "job") is False
    finally:
        mod.axiom_inventory_progress = original_progress
        mod.fetchone = original_fetchone


def test_pending_inventory_rows_skips_done():
    rows = [
        {"artifact_id": "a1"},
        {"artifact_id": "a2"},
        {"artifact_id": "a3"},
    ]

    class FakeDb:
        pass

    db = FakeDb()

    from app.services import axiom_artifact_runner as mod

    original = mod.fetchall
    mod.fetchall = lambda _db, _sql, _params: [{"artifact_id": "a1"}]
    try:
        pending = pending_inventory_rows(db, "job", rows)
    finally:
        mod.fetchall = original

    assert [r["artifact_id"] for r in pending] == ["a2", "a3"]
