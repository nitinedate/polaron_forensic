from pathlib import Path


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def test_parse_drain_uses_queue_helper_not_local_self_import() -> None:
    src = (_repo() / "backend" / "app" / "tasks.py").read_text(encoding="utf-8")
    body = src.split("def parse_drain_sync", 1)[1].split("def parse_shard_sync", 1)[0]
    assert "_queue_parse_drain(" in body
    assert "from app.tasks import parse_drain_task" not in body


def test_parse_progress_uses_nonblocking_advisory_lock() -> None:
    src = (_repo() / "backend" / "app" / "tasks.py").read_text(encoding="utf-8")
    body = src.split("def _write_parse_progress", 1)[1].split("def parse_drain_sync", 1)[0]
    assert "pg_try_advisory_xact_lock" in body


def test_parse_shard_has_single_flight_lock_and_divided_thread_budget() -> None:
    src = (_repo() / "backend" / "app" / "tasks.py").read_text(encoding="utf-8")
    body = src.split("def parse_shard_sync", 1)[1].split("def parse_bucket_sync", 1)[0]
    assert 'job_lock("parse_shard"' in body
    assert "parse_shard_in_flight" in body
    assert "parse_buckets=shard_fanout" in body
    assert "db.commit()\n                    _write_parse_progress" in body


def test_parse_drain_waits_for_streamed_shards() -> None:
    src = (_repo() / "backend" / "app" / "tasks.py").read_text(encoding="utf-8")
    body = src.split("def parse_drain_sync", 1)[1].split("def parse_shard_sync", 1)[0]
    assert 'job_lock_prefix_held("parse_shard"' in body
    assert "parse_shards_active" in body


def test_phase3_shard_has_single_flight_lock() -> None:
    src = (_repo() / "backend" / "app" / "tasks.py").read_text(encoding="utf-8")
    body = src.split("def phase3_shard_sync", 1)[1].split("@celery.task(name=\"app.tasks.phase3_shard_task\")", 1)[0]
    assert 'job_lock("phase3_shard"' in body
    assert "phase3_shard_in_flight" in body


def test_disk_log_commits_are_serialized_inside_threaded_extract() -> None:
    src = (_repo() / "backend" / "app" / "services" / "disk_build_log.py").read_text(encoding="utf-8")
    assert "_COMMITTED_LOG_LOCK = threading.Lock()" in src
    body = src.split("def write_disk_log_committed", 1)[1].split("@contextmanager", 1)[0]
    assert "with _COMMITTED_LOG_LOCK:" in body


def test_disk_and_parse_workers_have_service_specific_db_pools() -> None:
    for name in ("docker-compose.yml", "docker-compose.https.yml"):
        src = (_repo() / name).read_text(encoding="utf-8")
        assert "DISK_WORKER_DB_POOL_SIZE:-8" in src
        assert "DISK_WORKER_DB_MAX_OVERFLOW:-4" in src
        assert "PARSE_WORKER_DB_POOL_SIZE:-4" in src
        assert "PARSE_WORKER_DB_MAX_OVERFLOW:-4" in src


def test_carve_rebuild_is_background_and_single_flight() -> None:
    tasks = (_repo() / "backend" / "app" / "tasks.py").read_text(encoding="utf-8")
    routes = (_repo() / "backend" / "app" / "celery_factory.py").read_text(encoding="utf-8")
    assert "def signature_carve_rebuild_task" in tasks
    assert 'job_lock("carve_rebuild"' in tasks
    assert '"app.tasks.signature_carve_rebuild_task": {"queue": "disk-parse"}' in routes


def test_artifact_router_reports_browse_repair_instead_of_false_empty_count() -> None:
    src = (_repo() / "backend" / "app" / "routers" / "artifacts.py").read_text(encoding="utf-8")
    assert "evidence_rebuild_queued" in src
    assert "expected_total" in src
    assert "signature_carve_rebuild_task" in src
