import json
from typing import Any
from unittest.mock import MagicMock

from app.services.rag_enrich import (
    ENRICH_BATCH,
    NIL_PARSE_ID,
    extract_entities_from_normalized,
    parse_result_cursor,
    persist_enrichment_stats,
    read_enrichment_stats,
)


def test_parse_result_cursor_never_sends_integer_to_uuid_column():
    assert parse_result_cursor(None) == NIL_PARSE_ID
    assert parse_result_cursor(0) == NIL_PARSE_ID
    assert parse_result_cursor("0") == NIL_PARSE_ID
    uid = "8c8e85cb-20ca-4521-9db1-b327b9759cc5"
    assert parse_result_cursor(uid) == uid


def test_extract_entities_from_prefetch_and_email():
    payload = [
        {
            "executable": "chrome.exe",
            "user_profile": "LENOVO",
            "registry_key": r"HKCU\\Software\\Foo",
            "text": "Contact admin@example.com at 10.0.0.8",
        }
    ]
    counts = extract_entities_from_normalized(payload)
    assert counts["process"] >= 1
    assert counts["user"] >= 1
    assert counts["registry"] >= 1
    assert counts["email"] >= 1
    assert counts["ip"] >= 1


def test_read_enrichment_stats_requires_complete_flag():
    assert read_enrichment_stats({}) == {}
    assert read_enrichment_stats({"enrichment_stats": {"scanned": 10}})["scanned"] == 10
    assert not read_enrichment_stats({"enrichment_stats": {"scanned": 10}}).get("complete")


def test_run_rag_enrichment_until_complete_loops_without_celery_hops():
    from app.services import rag_enrich as enrich_mod

    calls = {"n": 0}

    def fake_batch(db, job_id, *, batch_size=ENRICH_BATCH, on_progress=None, current=None):
        calls["n"] += 1
        return {
            "scanned": calls["n"] * 80,
            "parse_total": 240,
            "complete": calls["n"] >= 3,
            "entity_mentions": calls["n"],
        }

    orig = enrich_mod.run_rag_enrichment_batch
    enrich_mod.run_rag_enrichment_batch = fake_batch  # type: ignore[assignment]
    try:
        heartbeats: list[dict] = []
        stats = enrich_mod.run_rag_enrichment_until_complete(
            MagicMock(),
            "job-1",
            on_batch=heartbeats.append,
        )
        assert calls["n"] == 3
        assert len(heartbeats) == 3
        assert stats["complete"] is True
        assert stats["scanned"] == 240
    finally:
        enrich_mod.run_rag_enrichment_batch = orig


def test_extract_entities_caps_huge_payload():
    payload = {
        "user": "alice",
        "executable": "chrome.exe",
        "text": "x" * 80_000,
        "nested": [{"k": i, "v": "y" * 200} for i in range(8_000)],
    }
    counts = extract_entities_from_normalized(payload)
    assert counts["user"] >= 1
    assert counts["process"] >= 1
    raw = json.dumps(payload)
    counts_raw = extract_entities_from_normalized(raw)
    assert isinstance(counts_raw, dict)


def test_persist_enrichment_stats_uses_jsonb_set(monkeypatch):
    from app.services import rag_enrich as enrich_mod

    captured: dict[str, Any] = {}

    def fake_execute(db, sql, params=None):
        captured["sql"] = sql
        captured["params"] = params

    monkeypatch.setattr(enrich_mod, "execute", fake_execute)
    persist_enrichment_stats(MagicMock(), "job-1", {"scanned": 10, "complete": False})
    assert "jsonb_set" in captured["sql"]
    assert captured["params"]["id"] == "job-1"
    assert '"scanned": 10' in captured["params"]["stats"]


def test_batch_sql_aggregates_without_shipping_json(monkeypatch):
    from app.services import rag_enrich as enrich_mod

    captured: dict[str, Any] = {}

    monkeypatch.setattr(enrich_mod, "load_enrichment_stats", lambda db, job_id: {"last_parse_id": 0})
    monkeypatch.setattr(enrich_mod, "count_parse_results", lambda db, job_id: 2500)
    monkeypatch.setattr(enrich_mod, "persist_enrichment_stats", lambda db, job_id, stats: None)

    def fake_fetchone(db, sql, params=None):
        captured["sql"] = sql
        captured["params"] = params
        if "regexp_count" in sql:
            return {
                "last_id": "8c8e85cb-20ca-4521-9db1-b327b9759cc5",
                "scanned": 2500,
                "user_n": 12,
                "process_n": 4,
                "registry_n": 0,
                "host_n": 0,
                "event_n": 0,
                "database_n": 0,
                "email_n": 3,
                "ip_n": 2,
            }
        return {"c": 0}

    monkeypatch.setattr(enrich_mod, "fetchone", fake_fetchone)
    stats = enrich_mod.run_rag_enrichment_batch(MagicMock(), "job-1")
    assert "regexp_count" in captured["sql"]
    assert "CAST(:last AS uuid)" in captured["sql"]
    assert captured["params"]["last"] == NIL_PARSE_ID
    assert stats["scanned"] == 2500
    assert stats["entity_mentions"] == 21
    assert stats["entity_by_type"]["user"] == 12
    assert stats["last_parse_id"] == "8c8e85cb-20ca-4521-9db1-b327b9759cc5"


def test_run_batch_keeps_cursor_in_memory(monkeypatch):
    from app.services import rag_enrich as enrich_mod

    persisted: list[dict] = []
    monkeypatch.setattr(enrich_mod, "count_parse_results", lambda db, job_id: 5000)
    monkeypatch.setattr(enrich_mod, "persist_enrichment_stats", lambda db, job_id, stats: persisted.append(dict(stats)))
    monkeypatch.setattr(
        enrich_mod,
        "_sql_aggregate_batch",
        lambda db, job_id, last_id, batch_size: {
            "last_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "scanned": 2500,
            "user_n": 5,
            "process_n": 0,
            "registry_n": 0,
            "host_n": 0,
            "event_n": 0,
            "database_n": 0,
            "email_n": 0,
            "ip_n": 0,
        },
    )
    current = {"scanned": 2500, "parse_total": 5000, "entity_mentions": 5, "entity_by_type": {"user": 5}}
    heartbeats: list[dict] = []
    stats = enrich_mod.run_rag_enrichment_batch(
        MagicMock(),
        "job-1",
        current=current,
        on_progress=heartbeats.append,
    )
    assert stats["scanned"] == 5000
    assert stats["entity_mentions"] == 10
    assert len(heartbeats) == 1
    assert persisted[-1]["scanned"] == 5000
