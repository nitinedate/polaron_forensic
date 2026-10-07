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


def test_parse_commits_once_per_batch_not_per_file(monkeypatch):
    from types import SimpleNamespace

    from app.services import artifact_parse

    commits: list[int] = []
    db = SimpleNamespace(commit=lambda: commits.append(1))
    monkeypatch.setattr(
        artifact_parse,
        "get_settings",
        lambda: SimpleNamespace(parse_parallel_enabled=True),
    )
    monkeypatch.setattr(
        artifact_parse,
        "_parse_work_item",
        lambda item, timeout: {
            "artifact": item[0],
            "path": item[1],
            "kind": "parsed",
            "parser_name": "text",
            "records": [{"ok": True}],
        },
    )
    monkeypatch.setattr(artifact_parse, "_apply_parse_outcome", lambda *args, **kwargs: (True, "parsed"))
    work = [({"id": str(i)}, f"f{i}.txt", b"abc") for i in range(10)]
    stats = {"parsed": 0, "skipped": 0}
    artifact_parse._process_parse_work_parallel(
        db,
        "job",
        work,
        parse_workers=2,
        timeout_sec=0,
        commit_batch=4,
        stats=stats,
        heartbeat_fn=lambda: None,
        backoff_fn=lambda: None,
        heartbeat_due_fn=lambda: False,
    )
    assert stats["parsed"] == 10
    assert len(commits) == 3


def test_disk_priority_does_not_revisit_every_picture():
    from types import SimpleNamespace

    from app.services.forensic_priority_evidence import (
        disk_priority_parsers,
        disk_priority_web_document,
    )

    picture = SimpleNamespace(name="files_media_parser")
    source = SimpleNamespace(name="communication_evidence")
    logs = SimpleNamespace(name="system_network_parser")
    browser = SimpleNamespace(name="browser_parser")
    history = "Users/a/AppData/Local/Google/Chrome/User Data/Default/History"
    assert disk_priority_parsers([picture, source, logs, browser], history) == [browser]
    assert disk_priority_parsers([source], "Users/a/Mail/note.eml") == [source]
    assert disk_priority_parsers(
        [source],
        "Program Files/Microsoft Office/root/Office16/FPEXT.MSG",
    ) == []
    assert disk_priority_parsers([source], "ProgramData/HP/Logs/service.log") == []
    assert not disk_priority_web_document(
        "new data/IITB/Bloomscope/build/static/media/logo.png"
    )
    assert disk_priority_web_document("Users/a/Documents/invoice.html")
    assert disk_priority_web_document("Users/a/Desktop/link.url")
    contacts = SimpleNamespace(name="contacts_parser")
    assert disk_priority_parsers(
        [contacts],
        "Program Files/Adobe/Acrobat DC/WebResources/images/AddressBook2x.png",
    ) == []
    assert disk_priority_parsers(
        [browser],
        "Users/a/AppData/Local/Google/Chrome/User Data/Default/History",
    ) == [browser]
    assert disk_priority_parsers(
        [browser],
        "Users/a/AppData/Local/Google/Chrome/User Data/GPUPersistentCache/cache.db",
    ) == []
    assert disk_priority_parsers(
        [browser],
        "Users/a/AppData/Local/Google/Chrome/User Data/Snapshots/127.0/Default/History",
    ) == []
    from app.services.forensic_priority_evidence import disk_priority_database

    assert not disk_priority_database(
        "Program Files (x86)/Xiph.Org/Open Codecs/HISTORY"
    )


def test_priority_json_keeps_browser_titles_postgres_safe():
    import json

    from app.services.mobile_forensic.storage import _dumps

    text = _dumps({"title": "a\x00b\ud800c"})
    assert "\\u0000" not in text
    assert json.loads(text)["title"] == "ab?c"
    from app.services.artifact_parse import _parse_work_item

    artifact = {"id": "1", "size_bytes": 0}
    assert _parse_work_item((artifact, "Chrome/LOCK", b""), 0)["kind"] == "empty"
    assert _parse_work_item((artifact, "Chrome/LOCK", None), 0)["kind"] == "no_data"
