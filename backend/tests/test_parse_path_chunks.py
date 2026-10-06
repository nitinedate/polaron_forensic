from unittest.mock import Mock

from app.db.sql_helpers import is_retryable_db_error, retry_on_deadlock
from app.services.artifact_parse import (
    PATH_ANY_CHUNK,
    _claim_pending_rows,
    _exec_locked,
    iter_path_chunks,
    recover_stale_parsing_claims,
)


def test_iter_path_chunks_keeps_any_bind_small():
    paths = [f"Windows/WinSxS/file_{i}.dll" for i in range(1_003)]
    chunks = list(iter_path_chunks(paths))
    assert PATH_ANY_CHUNK == 250
    assert len(chunks) == 5
    assert all(len(chunk) <= PATH_ANY_CHUNK for chunk in chunks)
    assert sum(len(chunk) for chunk in chunks) == 1_003
    assert chunks[0][0] == "Windows/WinSxS/file_0.dll"


def test_iter_path_chunks_skips_empty():
    assert list(iter_path_chunks(["", "a", ""])) == [["a"]]


def test_retryable_db_errors():
    assert is_retryable_db_error(RuntimeError("server closed the connection unexpectedly"))
    assert is_retryable_db_error(RuntimeError("deadlock detected"))
    assert not is_retryable_db_error(ValueError("path not found"))


def test_retry_on_deadlock_recovers_then_succeeds():
    db = Mock()
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("deadlock detected DETAIL: Process 1 waits for ShareLock")
        return "ok"

    assert retry_on_deadlock(db, flaky, attempts=5) == "ok"
    assert calls["n"] == 3
    assert db.rollback.called


def test_retry_on_deadlock_gives_up():
    db = Mock()

    def always():
        raise RuntimeError("deadlock detected")

    try:
        retry_on_deadlock(db, always, attempts=3)
        assert False, "expected deadlock to propagate"
    except RuntimeError as exc:
        assert "deadlock" in str(exc)


def test_claim_sql_orders_and_skips_locked(monkeypatch):
    captured = {}

    def fake_fetchall(_db, sql, params):
        captured["sql"] = sql
        captured["params"] = params
        return [{"id": "1"}]

    monkeypatch.setattr("app.services.artifact_parse.fetchall", fake_fetchall)
    monkeypatch.setattr("app.services.artifact_parse.retry_on_deadlock", lambda db, fn, **kw: fn())
    rows = _claim_pending_rows(Mock(), "job-1", extra_sql="", limit=10)
    assert rows == [{"id": "1"}]
    assert "FOR UPDATE SKIP LOCKED" in captured["sql"]
    assert "ORDER BY id" in captured["sql"]
    assert "parse_status='parsing'" in captured["sql"]


def test_recover_stale_claims_orders_by_id(monkeypatch):
    captured = {}

    def fake_fetchall(_db, sql, params):
        captured["sql"] = sql
        captured["params"] = params
        return [{"id": "a"}, {"id": "b"}]

    monkeypatch.setattr("app.services.artifact_parse.fetchall", fake_fetchall)
    monkeypatch.setattr("app.services.artifact_parse.retry_on_deadlock", lambda db, fn, **kw: fn())
    assert recover_stale_parsing_claims(Mock(), "job-1") == 2
    assert "FOR UPDATE SKIP LOCKED" in captured["sql"]
    assert "ORDER BY id" in captured["sql"]
    assert captured["params"]["sec"] >= 60


def test_exec_locked_retries_deadlock(monkeypatch):
    calls = {"n": 0}

    def fake_execute(_db, _sql, _params):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("deadlock detected")

    monkeypatch.setattr("app.services.artifact_parse.execute", fake_execute)
    db = Mock()
    _exec_locked(db, "UPDATE job_artifacts SET parse_status='skipped' WHERE id=:id", {"id": "x"})
    assert calls["n"] == 2
