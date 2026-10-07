"""Behavioral checks for serial ordering, evidence completeness and concurrency."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from app.services import forensic_serial_pipeline as pipeline
from app.services import forensic_serial_policy as policy
from app.services import forensic_serial_stages as stages
from app.services.forensic_serial_mobile import evidence_bundles
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.parsers._sqlite_util import (
    SqliteEvidenceBytes,
    open_sqlite_bytes,
)


def rows_at(stage, status="running"):
    before = True
    rows = []
    for index, (name, _, _) in enumerate(pipeline.STAGES):
        if name == stage:
            before = False
        rows.append(
            {
                "id": str(index),
                "stage": name,
                "sequence_no": index + 1,
                "status": "done" if before else status if name == stage else "pending",
                "task_id": "current-delivery",
                "total_items": 0,
                "completed_items": 0,
                "failed_items": 0,
                "skipped_items": 0,
            }
        )
    return rows


@pytest.mark.parametrize(
    "requested,expected", [(1, 1), (2, 2), (4, 4), (16, 4), (64, 4), (0, 1)]
)
def test_parallelism_is_hard_capped(requested, expected):
    assert policy.parallelism(requested) == expected


def test_work_is_bounded_and_all_items_are_processed():
    barrier = threading.Barrier(4, timeout=5)
    guard = threading.Lock()
    active = peak = 0

    def work(item):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        barrier.wait()
        with guard:
            active -= 1
        return item

    assert sorted(policy.bounded_map(work, range(12), workers=32)) == list(range(12))
    assert peak == 4
    assert active == 0


def test_stage_context_resets_after_failure():
    with pytest.raises(RuntimeError), policy.stage_context("parse"):
        assert policy.current_stage() == "parse"
        raise RuntimeError("parser failed")
    assert policy.current_stage() is None


def test_scanner_is_excluded_from_serial_policy(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "vuln")
    assert not policy.serial_enabled()
    assert (
        pipeline.run_serial_stage("firm_test", "job", "parse")["reason"]
        == "other_product"
    )


def test_stage_order_and_ui_do_not_start_downstream_work():
    names = [stage[0] for stage in pipeline.STAGES]
    required = [
        "parse",
        "recovery",
        "ocr",
        "media_review",
        "inventory",
        "chunk",
        "enrichment",
        "graph",
        "validation",
    ]
    assert sorted(required, key=names.index) == required
    snapshot = pipeline.snapshot_from_rows(
        rows_at("ocr"), {"phase": "ocr", "total": 10, "completed": 3}
    )
    assert snapshot["current_stage"] == "ocr"
    assert not snapshot["complete"]
    assert snapshot["overall_pct"] < 100
    assert [s["id"] for s in snapshot["stages"] if s["status"] == "running"] == ["ocr"]
    assert all(
        s["status"] == "pending" for s in snapshot["stages"] if s["id"] in required[3:]
    )


def test_failed_stage_cannot_be_bypassed():
    rows = rows_at("recovery", "failed")
    assert pipeline.first_open_stage(rows)["stage"] == "recovery"
    assert pipeline.snapshot_from_rows(rows)["current_stage"] == "recovery"


def test_completion_requires_final_validation():
    rows = rows_at("validation", "pending")
    assert not pipeline.snapshot_from_rows(rows)["complete"]
    rows[-1]["status"] = "done"
    assert pipeline.snapshot_from_rows(rows)["complete"]
    assert pipeline.snapshot_from_rows(rows)["overall_pct"] == 100


@pytest.mark.parametrize(
    "change",
    [
        {"extracted_disk_uri": None},
        {"files_total": 3, "files_extracted": 1},
        {"extraction_checkpoint": {"next_entry": 12}},
    ],
)
def test_unfinished_extraction_blocks_the_pipeline(change):
    row = {
        "extracted_disk_uri": "s3://derived/manifest",
        "files_total": 1,
        "files_extracted": 1,
        **change,
    }
    assert not pipeline.extraction_barrier(row)[0]


def test_policy_filter_skips_are_not_extractor_exceptions():
    source = {"files_skipped": 347438, "filter_stats": {"filtered_out": 347438}}
    assert pipeline.extraction_skip_split(source) == (0, 347438)
    skipped, details = pipeline.extraction_stage_seed(source, completed_before_controller=True)
    assert skipped == 0
    assert "skip_reason" not in details
    assert details["policy_skipped"] == 347438
    row = {
        "stage": "extraction",
        "skipped_items": 347438,
        "details": {"skip_reason": "Explicit extractor exceptions"},
    }
    assert pipeline.apply_extraction_skip_accounting(row, source)
    assert row["skipped_items"] == 0
    assert "skip_reason" not in row["details"]


def test_unreadable_files_remain_extractor_exceptions():
    source = {"files_skipped": 10, "filter_stats": {"filtered_out": 7}}
    assert pipeline.extraction_skip_split(source) == (3, 7)
    skipped, details = pipeline.extraction_stage_seed(source, completed_before_controller=True)
    assert skipped == 3
    assert details["skip_reason"] == "Unreadable files"


def test_unique_extract_nodes_keeps_one_copy_of_a_repeated_path():
    from app.services.extracted_disk import _unique_extract_nodes

    nodes, duplicates = _unique_extract_nodes(
        [
            {"path": "Windows\\System32\\ntdll.dll"},
            {"path": "Windows/System32/ntdll.dll"},
            {"path": "Users/Alice/notes.txt"},
        ]
    )
    assert duplicates == 1
    assert [node["path"] for node in nodes] == [
        "Windows\\System32\\ntdll.dll",
        "Users/Alice/notes.txt",
    ]


def test_serial_parse_uses_the_parse_worker_cpus(monkeypatch):
    monkeypatch.setattr("os.cpu_count", lambda: 16)
    from app.services.artifact_parse import serial_parse_workers

    assert serial_parse_workers() == 8


def test_cool_or_busy_parse_keeps_its_cores(monkeypatch):
    from app.services.artifact_parse import parse_thermal_backoff
    from app.services.host_capacity import HostSnapshot

    monkeypatch.setattr(
        "app.services.host_capacity.probe_host",
        lambda: HostSnapshot(cpu_logical=12, load_1m=20, cpu_temp_c=60, gpu_temp_c=46),
    )
    cap, sleep_s, reason = parse_thermal_backoff(8, busy_seconds=30)
    assert cap == 8
    assert sleep_s == 0
    assert reason == ""


def test_hot_chassis_rests_before_a_laptop_shutdown(monkeypatch):
    from app.services.artifact_parse import parse_thermal_backoff
    from app.services.host_capacity import HostSnapshot

    monkeypatch.setattr(
        "app.services.host_capacity.probe_host",
        lambda: HostSnapshot(cpu_logical=12, load_1m=4, cpu_temp_c=None, gpu_temp_c=91),
    )
    cap, sleep_s, reason = parse_thermal_backoff(8, busy_seconds=1)
    assert cap == 1
    assert sleep_s >= 8
    assert "shut down" in reason


def test_hidden_cpu_temperature_rests_only_after_a_sustained_run(monkeypatch):
    from app.services.artifact_parse import parse_thermal_backoff
    from app.services.host_capacity import HostSnapshot

    monkeypatch.setattr(
        "app.services.host_capacity.probe_host",
        lambda: HostSnapshot(cpu_logical=12, load_1m=11, cpu_temp_c=None, gpu_temp_c=None),
    )
    cap, sleep_s, _reason = parse_thermal_backoff(8, busy_seconds=10)
    assert cap == 8 and sleep_s == 0
    cap, sleep_s, reason = parse_thermal_backoff(8, busy_seconds=80)
    assert cap == 8 and sleep_s == 4
    assert "not visible" in reason


def test_full_shard_claims_every_pending_file_on_one_part(monkeypatch):
    claimed = []
    monkeypatch.setattr(
        "app.services.artifact_parse.fetchone",
        lambda *args, **kwargs: {"part": "s3://parts/part-00011.tar.zst"},
    )
    monkeypatch.setattr(
        "app.services.artifact_parse.fetchall",
        lambda *args, **kwargs: [{"id": "a"}, {"id": "b"}, {"id": "c"}],
    )
    monkeypatch.setattr(
        "app.services.artifact_parse._claim_artifacts_by_id",
        lambda db, ids: claimed.append(list(ids)) or [{"id": item} for item in ids],
    )
    from app.services.artifact_parse import _claim_full_shard

    rows = _claim_full_shard(object(), "job", "")
    assert claimed == [["a", "b", "c"]]
    assert [row["id"] for row in rows] == ["a", "b", "c"]


def test_parse_stage_deadline_advances_during_a_long_batch(monkeypatch):
    notes = []
    monkeypatch.setattr(
        "app.services.progress_agent.note_operation",
        lambda *args, **kwargs: notes.append(kwargs),
    )
    from app.services.artifact_parse import _advance_parse_stage

    _advance_parse_stage(object(), "job", "Streaming extract shard")
    assert notes[0]["timeout_seconds"] == 900
    assert notes[0]["advanced"] is True


def test_materialize_progress_extends_the_stage_deadline(monkeypatch):
    published = {}

    def report(db, job_id, stage, *, total, completed, label):
        published.update(stage=stage, total=total, completed=completed, label=label)

    monkeypatch.setattr("app.services.forensic_serial_stages.report_progress", report)
    monkeypatch.setattr(
        "app.services.pipeline_progress.write_merged_pipeline_progress",
        lambda *args, **kwargs: None,
    )
    from app.services.artifact_materialize import _publish_materialize_progress

    _publish_materialize_progress(
        object(),
        "job",
        completed=60000,
        total=378805,
        label="Registering artifacts",
        activity={"entries_inspected": 60000},
        status_sql="status='indexing'",
    )
    assert published == {
        "stage": "materialize",
        "total": 378805,
        "completed": 60000,
        "label": "Registering artifacts",
    }


def test_explicit_extraction_exceptions_are_accounted_for():
    row = {
        "extracted_disk_uri": "s3://derived/manifest",
        "files_total": 3,
        "files_extracted": 1,
        "disk_source": {"files_skipped": 2},
    }
    assert pipeline.extraction_barrier(row)[0]


def test_sqlite_database_and_sidecars_share_one_work_unit():
    paths = [
        "app/chat.db-wal",
        "app/chat.db-shm",
        "app/chat.db",
        "app/chat.db-journal",
        "photo.jpg",
    ]
    bundles = evidence_bundles(
        [InventoryItem(path=p, size=1, extension="") for p in paths]
    )
    assert len(bundles) == 2
    database = next(b for b in bundles if len(b) > 1)
    assert database[0].path == "app/chat.db"
    assert {item.path for item in database} == set(paths[:-1])


def test_sqlite_wal_is_applied_to_disposable_readonly_copy(tmp_path):
    source = tmp_path / "chat.db"
    conn = sqlite3.connect(source)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE messages(body TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("INSERT INTO messages VALUES ('committed in WAL')")
        conn.commit()
        data = source.read_bytes()
        wal_path = source.with_name("chat.db-wal")
        wal = wal_path.read_bytes()
        hashes = [hashlib.sha256(value).hexdigest() for value in (data, wal)]
        with open_sqlite_bytes(data) as base:
            assert base.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
        with open_sqlite_bytes(SqliteEvidenceBytes(data, {"-wal": wal})) as working:
            assert (
                working.execute("SELECT body FROM messages").fetchone()[0]
                == "committed in WAL"
            )
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                working.execute("INSERT INTO messages VALUES ('altered')")
        assert [
            hashlib.sha256(path.read_bytes()).hexdigest() for path in (source, wal_path)
        ] == hashes
    finally:
        conn.close()


def test_chunking_preserves_all_parser_outputs_and_ocr_tail():
    rows = [
        {
            "id": "evidence-id",
            "file_path": "app/chat.db",
            "normalized": [{"text": "A" * 9000}, {"body": "NATIVE_LAST_RECORD"}],
            "ocr_text": "B" * 9000 + "OCR_LAST_PAGE",
        }
    ]
    chunks = stages._full_text_chunks(rows)
    contents = "\n".join(chunk[3] for chunk in chunks)
    assert "NATIVE_LAST_RECORD" in contents
    assert "OCR_LAST_PAGE" in contents
    assert all(
        chunk[0] == "evidence-id" and chunk[1] == "app/chat.db" for chunk in chunks
    )


@pytest.mark.parametrize("stage", ["parse", "chunk", "media_review"])
def test_pending_evidence_blocks_stage_completion(monkeypatch, stage):
    monkeypatch.setattr(stages, "fetchone", lambda *args, **kwargs: {"c": 1})
    with pytest.raises(pipeline.StageWaiting):
        stages.validate_stage_barrier(
            object(), "job", stage, {"status": "ok"}, stage_run_id="run"
        )


def test_failed_materialization_is_a_failure_not_an_endless_wait():
    with pytest.raises(RuntimeError, match="materialize failed") as raised:
        stages.validate_stage_barrier(
            object(),
            "job",
            "materialize",
            {"status": "failed", "error": "missing manifest"},
            stage_run_id="run",
        )
    assert not isinstance(raised.value, pipeline.StageWaiting)


def test_unfinished_inventory_blocks_later_stages():
    with pytest.raises(pipeline.StageWaiting, match="inventory"):
        stages.validate_stage_barrier(
            object(),
            "job",
            "inventory",
            {"status": "ok", "done": False},
            stage_run_id="run",
        )


@contextmanager
def acquired_lock(*args, **kwargs):
    yield True


def mock_stage_environment(monkeypatch):
    @contextmanager
    def session(schema):
        yield SimpleNamespace(commit=lambda: None, rollback=lambda: None)

    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    monkeypatch.setattr("app.db.session.firm_session", session)
    monkeypatch.setattr(
        "app.services.mobile_platform_agents.current_service_owns_job",
        lambda *args: True,
    )
    monkeypatch.setattr(pipeline, "pipeline_execution_lock", acquired_lock)
    monkeypatch.setattr(pipeline, "stage_rows", lambda *args: rows_at("ocr"))


@pytest.mark.parametrize(
    "stage,delivery,reason",
    [
        ("graph", "current-delivery", "out_of_order"),
        ("ocr", "obsolete-delivery", "superseded_delivery"),
    ],
)
def test_out_of_order_and_old_deliveries_never_run(
    monkeypatch, stage, delivery, reason
):
    mock_stage_environment(monkeypatch)
    monkeypatch.setattr(
        stages,
        "execute_stage",
        lambda *args, **kwargs: pytest.fail("stage must not execute"),
    )
    assert (
        pipeline.run_serial_stage("firm_test", "job", stage, task_id=delivery)["reason"]
        == reason
    )


def test_duplicate_delivery_cannot_acquire_running_job(monkeypatch):
    mock_stage_environment(monkeypatch)

    @contextmanager
    def busy(*args):
        yield False

    monkeypatch.setattr(pipeline, "pipeline_execution_lock", busy)
    assert pipeline.run_serial_stage("firm_test", "job", "ocr")["status"] == "busy"


def test_dispatch_publishes_only_the_first_unfinished_stage(monkeypatch):
    calls = []
    writes = []
    monkeypatch.setattr(
        "app.services.mobile_platform_agents.current_service_owns_job",
        lambda *args: True,
    )
    monkeypatch.setitem(
        sys.modules,
        "app.tasks",
        SimpleNamespace(
            forensic_serial_stage_task=SimpleNamespace(
                apply_async=lambda **kw: calls.append(kw)
            )
        ),
    )
    monkeypatch.setattr(pipeline, "fetchone", lambda *args: {"id": "job"})
    monkeypatch.setattr(
        pipeline, "stage_rows", lambda *args: rows_at("media_review", "pending")
    )
    monkeypatch.setattr(
        pipeline, "execute", lambda db, sql, params: writes.append((sql, params))
    )
    monkeypatch.setattr(pipeline, "persist_snapshot", lambda *args: None)
    monkeypatch.setattr(pipeline, "queue_for_stage", lambda stage: "rag-index")
    result = pipeline.dispatch_current_stage(
        SimpleNamespace(commit=lambda: None), "job", schema_name="firm_test"
    )
    assert result["status"] == "queued"
    assert len(calls) == 1
    assert calls[0]["args"] == ("firm_test", "job", "media_review")
    assert calls[0]["queue"] == "rag-index"
    assert calls[0]["task_id"] == result["task_id"]
    assert any("status='queued'" in sql for sql, _ in writes)


def test_obsolete_embedding_delivery_does_not_load_a_model(monkeypatch):
    monkeypatch.setattr("app.services.embedding_gpu.embed_texts", lambda *args, **kwargs: pytest.fail("Embedding forbidden"))
    result = pipeline.run_serial_stage("firm_test", "job", "embedding")
    assert result["reason"] == "obsolete_stage"
    assert "embedding" not in {name for name, _, _ in pipeline.STAGES}


def test_ocr_cpu_workers_are_capped_even_with_old_settings(monkeypatch):
    from app.services import ocr_gpu

    monkeypatch.setattr(
        ocr_gpu, "get_settings", lambda: SimpleNamespace(ocr_cpu_workers=32)
    )
    assert ocr_gpu._ocr_cpu_worker_count(gpu=True, n_items=100) == 4
    assert ocr_gpu._ocr_cpu_worker_count(gpu=True, n_items=2) == 2


def test_serial_pdf_preparation_keeps_pages_after_the_legacy_limit():
    import fitz
    from app.services.ocr_gpu import cpu_prepare_ocr_item

    with fitz.open() as document:
        for index in range(55):
            page = document.new_page()
            page.insert_text(
                (50, 50),
                f"Evidence page {index + 1}, FULL_PDF_TAIL"
                if index == 54
                else f"Evidence page {index + 1}",
            )
        pdf = document.tobytes()
    result = cpu_prepare_ocr_item(pdf, path="long-evidence.pdf", max_pages=0)
    assert result["status"] == "cpu_done"
    assert "FULL_PDF_TAIL" in result["text"]


def test_serial_enrichment_reads_records_after_legacy_sample_cap():
    from app.services.rag_enrich import extract_entities_from_normalized

    normalized = [{"padding": "x" * 500} for _ in range(100)] + [
        {"username": "final-account"}
    ]
    with policy.stage_context("enrichment"):
        assert extract_entities_from_normalized(normalized)["user"] == 1


def test_serial_graph_reads_every_parsed_record():
    from app.services.neo4j_sync import _sync_parsed_edges

    calls = []
    session = SimpleNamespace(run=lambda *args, **kwargs: calls.append((args, kwargs)))
    normalized = [{"event_id": index + 1} for index in range(50)]
    assert (
        _sync_parsed_edges(
            session,
            "job",
            [{"file_path": "events", "normalized": normalized}],
            max_records=None,
        )
        == 50
    )
    assert sum("CONTAINS_EVENT" in args[0] for args, kwargs in calls) == 50


def test_missing_registered_file_blocks_materialization(monkeypatch):
    monkeypatch.setattr(stages, "fetchone", lambda *args: {"c": 0})
    with pytest.raises(pipeline.StageWaiting, match="unregistered"):
        stages.validate_stage_barrier(
            object(),
            "job",
            "materialize",
            {"status": "ok", "expected_files": 1},
            stage_run_id="run",
        )


def test_dispatch_cannot_cross_product_boundaries(monkeypatch):
    monkeypatch.setattr(
        "app.services.mobile_platform_agents.current_service_owns_job",
        lambda *args: False,
    )
    assert (
        pipeline.dispatch_current_stage(object(), "job", schema_name="firm_test")[
            "reason"
        ]
        == "other_product"
    )


def test_watchdog_releases_lock_before_publishing(monkeypatch):
    from app.services import progress_agent as progress
    held = False

    @contextmanager
    def lease(*args):
        nonlocal held
        held = True
        try:
            yield True
        finally:
            held = False

    def dispatch(*args, **kwargs):
        assert not held
        return {"status": "queued", "stage": "ocr"}

    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    monkeypatch.setattr(
        "app.services.mobile_platform_agents.current_service_owns_job",
        lambda *args: True,
    )
    monkeypatch.setattr(pipeline, "stage_rows", lambda *args: rows_at("ocr", "waiting"))
    monkeypatch.setattr(
        progress,
        "fetchone",
        lambda *args: {"status": "indexing", "stop_requested": False},
    )
    monkeypatch.setattr(progress, "execute", lambda *args: None)
    monkeypatch.setattr(pipeline, "pipeline_execution_lock", lease)
    monkeypatch.setattr(pipeline, "dispatch_current_stage", dispatch)
    monkeypatch.setattr(progress, "_monitor_report", lambda *a, **kw: None)
    monkeypatch.setattr(progress, "_event", lambda *a, **kw: None)
    assert (
        progress.monitor_job(
            SimpleNamespace(commit=lambda: None), "job", schema_name="firm_test"
        )["status"]
        == "queued"
    )


@pytest.mark.parametrize("second_path", ["unhashed.db", "data/data/com.whatsapp/files/key"])
def test_materialization_reads_unhashed_entries_and_disables_path_filter(monkeypatch, second_path):
    captured = {}
    manifest = {"index_uri": "s3://derived/index", "parts": ["s3://derived/part"]}
    entries = [
        {"path": "hashed.db", "sha256": "digest", "part_id": 0},
        {"path": second_path, "part_id": 0},
    ]
    monkeypatch.setattr(
        stages,
        "fetchone",
        lambda *args: {"disk_source": manifest, "files_extracted": 2},
    )
    monkeypatch.setattr(
        "app.services.disk_manifest.load_index_entries", lambda *args: entries
    )

    def materialize(db, job_id, rows, **kwargs):
        captured.update({"rows": rows, **kwargs})
        return {"status": "ok"}

    monkeypatch.setattr(
        "app.services.artifact_materialize.materialize_index_entries", materialize
    )
    monkeypatch.setattr(stages, "report_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(stages, "_extend_materialize_deadline", lambda *args, **kwargs: None)
    monkeypatch.setattr("psycopg2.extras.execute_values", lambda *args, **kwargs: None)
    captured_keys = []
    monkeypatch.setattr("app.services.mobile_forensic.key_intake.capture_registered_keys", lambda _db, jid: captured_keys.append(jid))

    @contextmanager
    def cursor():
        yield object()

    db = SimpleNamespace(
        commit=lambda: None,
        connection=lambda: SimpleNamespace(connection=SimpleNamespace(cursor=cursor)),
    )
    result = stages._materialize_full(db, "00000000-0000-0000-0000-000000000001")
    assert result["expected_files"] == 2
    assert {row["path"] for row in captured["rows"]} == {"hashed.db", second_path}
    assert captured["phase1_filter"] is False
    assert bool(captured_keys) == (second_path.endswith("/files/key"))


def test_materialize_collapses_duplicate_paths_instead_of_failing(monkeypatch):
    captured = {}
    manifest = {"index_uri": "s3://derived/index", "parts": ["s3://derived/part"]}
    entries = [
        {"path": "Windows/System32/ntdll.dll", "sha256": "abc", "part_id": 0},
        {"path": "Windows\\System32\\ntdll.dll", "sha256": "abc", "part_id": 0},
        {"path": "Users/Alice/notes.txt", "part_id": 0},
    ]
    monkeypatch.setattr(
        stages,
        "fetchone",
        lambda *args: {"disk_source": manifest, "files_extracted": 3},
    )
    monkeypatch.setattr("app.services.disk_manifest.load_index_entries", lambda *args: entries)
    monkeypatch.setattr(
        "app.services.artifact_materialize.materialize_index_entries",
        lambda db, job_id, rows, **kwargs: captured.update({"rows": rows}) or {"status": "ok"},
    )
    monkeypatch.setattr(stages, "report_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(stages, "_extend_materialize_deadline", lambda *args, **kwargs: None)
    monkeypatch.setattr("psycopg2.extras.execute_values", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.services.disk_build_log.write_disk_log", lambda *args, **kwargs: None)

    @contextmanager
    def cursor():
        yield object()

    db = SimpleNamespace(
        commit=lambda: None,
        connection=lambda: SimpleNamespace(connection=SimpleNamespace(cursor=cursor)),
    )
    result = stages._materialize_full(db, "00000000-0000-0000-0000-000000000001")
    assert result["expected_files"] == 2
    assert {row["path"] for row in captured["rows"]} == {
        "Windows/System32/ntdll.dll",
        "Users/Alice/notes.txt",
    }


def test_combined_index_is_not_merged_with_shard_copies(monkeypatch):
    import zstandard as zstd

    from app.services import disk_manifest

    def fake_get(uri):
        if uri.endswith("/index"):
            body = b'{"path":"a.dll","part_id":0}\n'
            return zstd.ZstdCompressor().compress(body)
        raise AssertionError(f"shard index should not be read: {uri}")

    monkeypatch.setattr(disk_manifest, "get_bytes", fake_get)
    rows = disk_manifest.load_index_entries(
        {"index_uri": "s3://disk/index", "shard_indexes": {"0": "s3://disk/shard-0"}}
    )
    assert [row["path"] for row in rows] == ["a.dll"]


def test_materialize_still_fails_when_index_is_short(monkeypatch):
    manifest = {"index_uri": "s3://derived/index", "parts": ["s3://derived/part"]}
    monkeypatch.setattr(
        stages,
        "fetchone",
        lambda *args: {"disk_source": manifest, "files_extracted": 2},
    )
    monkeypatch.setattr(
        "app.services.disk_manifest.load_index_entries",
        lambda *args: [{"path": "only.db", "part_id": 0}],
    )
    monkeypatch.setattr(stages, "_extend_materialize_deadline", lambda *args, **kwargs: None)
    db = SimpleNamespace(commit=lambda: None)
    with pytest.raises(RuntimeError, match="accounts for 1 / 2"):
        stages._materialize_full(db, "00000000-0000-0000-0000-000000000001")


@pytest.mark.parametrize(
    "part,expected", [("s3://derived/part", b"evidence"), (None, None)]
)
def test_mobile_reads_finalized_extracted_parts_without_reopening_originals(
    monkeypatch, part, expected
):
    from app.services.mobile_forensic import sqlite_counts

    artifact = {
        "id": "artifact",
        "file_path": "app/messages.db",
        "size_bytes": 8,
        "metadata": {"extracted_part_uri": part} if part else {},
    }
    source = {"extracted_disk_uri": "s3://derived/manifest", "disk_source": {}}
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-android")
    monkeypatch.setattr(
        sqlite_counts,
        "fetchone",
        lambda db, sql, params: source if "FROM jobs" in sql else artifact,
    )
    monkeypatch.setattr("app.services.disk_manifest.build_index_map", lambda *args: {})
    monkeypatch.setattr(
        "app.services.tar_cache.read_file_from_part",
        lambda *args, **kwargs: b"evidence",
    )
    monkeypatch.setattr(
        "app.services.virtual_disk.open_virtual_disk",
        lambda *args, **kwargs: pytest.fail("Original evidence must not reopen"),
    )
    assert (
        sqlite_counts._read_artifact_bytes(
            SimpleNamespace(info={}), "job", "app/messages.db"
        )
        == expected
    )


def test_oversized_mobile_database_is_an_explicit_exception(monkeypatch):
    from app.services.mobile_forensic import sqlite_counts

    artifact = {
        "id": "artifact",
        "file_path": "large.db",
        "size_bytes": 900_000_000,
        "metadata": {},
    }
    source = {"extracted_disk_uri": "s3://derived/manifest", "disk_source": {}}
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-android")
    monkeypatch.setattr(
        sqlite_counts,
        "fetchone",
        lambda db, sql, params: source if "FROM jobs" in sql else artifact,
    )
    with pytest.raises(ValueError, match="read ceiling"):
        sqlite_counts._read_artifact_bytes(SimpleNamespace(info={}), "job", "large.db")


def test_recovery_uses_the_idle_disk_pool(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    assert pipeline.queue_for_stage("recovery") == "disk-build"
    assert pipeline.queue_for_stage("parse") == "disk-parse"
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-android")
    assert pipeline.queue_for_stage("recovery") != "disk-build"


def test_deleted_path_hint_does_not_replace_parser_metadata():
    from app.services.deleted_evidence import MERGE_DELETED_PATH_HINT_SQL

    assert "? e.key" in MERGE_DELETED_PATH_HINT_SQL
    assert "CAST(:hint AS jsonb) || COALESCE(metadata" not in MERGE_DELETED_PATH_HINT_SQL


def test_recovery_overlap_queues_only_a_pending_stage(monkeypatch):
    from app.services import disk_build_log

    calls = {"queued": 0}
    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")

    def fake_fetchone(_db, sql, params=None):
        if "status='pending'" in sql:
            calls["queued"] += 1
            return {"id": "recovery-stage"}
        return None

    monkeypatch.setattr(pipeline, "ensure_serial_schema", lambda db: None)
    monkeypatch.setattr(pipeline, "fetchone", fake_fetchone)
    monkeypatch.setattr(disk_build_log, "write_disk_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        pipeline,
        "_enqueue_recovery_overlap",
        lambda schema, job, task_id: calls.update(queue="disk-build", task_id=task_id),
    )
    db = SimpleNamespace(commit=lambda: None)
    result = pipeline.start_recovery_overlap(db, "job", schema_name="firm_p")
    assert result["status"] == "queued"
    assert calls["queue"] == "disk-build"
    assert calls["queued"] == 1

    def already_started(_db, sql, params=None):
        return None

    monkeypatch.setattr(pipeline, "fetchone", already_started)
    held = pipeline.start_recovery_overlap(db, "job", schema_name="firm_p")
    assert held["status"] == "held"
    assert calls["queued"] == 1
