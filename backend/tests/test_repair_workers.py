"""Repair must fan work across multiple Celery workers when capacity allows."""

from unittest.mock import MagicMock, patch

from app.services.action_agents import collect_action_votes


def test_queue_parallel_parse_buckets_starts_multiple(monkeypatch):
    delayed: list[tuple] = []

    class _Sess:
        def __enter__(self):
            return MagicMock()

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("app.db.session.firm_session", lambda _schema: _Sess())
    monkeypatch.setattr("app.forensic_common.job_types.is_mobile_job", lambda _db, _jid: False)

    def _delay(*args):
        delayed.append(args)
        return MagicMock()

    with patch("app.tasks.parse_bucket_task.delay", _delay):
        from app.services.artifact_parse import queue_parallel_parse_buckets

        n = queue_parallel_parse_buckets("firm_aetheris", "job-1", num_buckets=4)
    assert n == 4
    assert len(delayed) == 4
    assert delayed[0][:2] == ("firm_aetheris", "job-1")
    assert delayed[-1][2] == 3


def test_queue_parallel_ocr_buckets_starts_multiple():
    delayed: list[tuple] = []

    def _delay(*args):
        delayed.append(args)
        return MagicMock()

    with patch("app.tasks.ocr_bucket_task.delay", _delay):
        from app.services.ocr_gpu import queue_parallel_ocr_buckets

        n = queue_parallel_ocr_buckets("firm_aetheris", "job-1", num_buckets=4)
    assert n == 4
    assert len(delayed) == 4


def test_ocr_votes_gpu_when_drain_already_running():
    snap = {
        "row": {"disk_source": {}, "extracted_disk_uri": "s3://x"},
        "status": "indexing",
        "files_total": 10,
        "files_done": 10,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {},
        "chunk_n": 0,
        "artifact_n": 100,
        "parse_pending": 0,
        "ocr_pending": 80,
        "ocr_done": 12,
        "ocr_eligible": 92,
        "rag_remaining": 0,
        "graph_status": "",
        "extract_live": False,
        "lanes": {"ocr_lock": True, "gpu_slots_free": 1},
    }
    vote = next(v for v in collect_action_votes(snap) if v["id"] == "ocr_agent")
    assert vote["want"] == "run"
    reason = vote["reason"].lower()
    assert "ocr" in reason
    assert "gpu" in reason or "glm" in reason
    assert "cpu text-layer in parallel" not in reason


def test_dispatch_ocr_agent_starts_gpu_drain_only():
    delayed: list[tuple] = []

    def _delay(*args, **kwargs):
        delayed.append(args)
        return MagicMock()

    with patch("app.tasks.ocr_drain_task.delay", _delay):
        from app.services.ocr_gpu import dispatch_ocr_agent

        n = dispatch_ocr_agent("firm_aetheris", "job-1")
    assert n == 1
    assert delayed == [("firm_aetheris", "job-1")]


def test_queue_parallel_ocr_buckets_noop_when_gpu_only(monkeypatch):
    from app.services import ocr_gpu

    monkeypatch.setattr(ocr_gpu, "ocr_is_gpu_only", lambda: True)
    assert ocr_gpu.queue_parallel_ocr_buckets("firm_aetheris", "job-1", num_buckets=4) == 0


def test_cpu_bucket_does_not_requeue_when_only_glm_left():
    from app.tasks import should_requeue_ocr_drain

    assert should_requeue_ocr_drain(pending_left=12, gpu_deferred=True, is_cpu_bucket=True) is False
    assert should_requeue_ocr_drain(pending_left=12, gpu_deferred=True, is_cpu_bucket=False) is True
    assert should_requeue_ocr_drain(pending_left=12, gpu_deferred=False, is_cpu_bucket=True) is True
    assert should_requeue_ocr_drain(pending_left=0, gpu_deferred=True, is_cpu_bucket=False) is False


def test_reclaim_stale_ocr_lock_when_no_celery_task(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, job_id: True)
    monkeypatch.setattr(job_locks, "ocr_celery_work_active", lambda *a, **k: False)
    monkeypatch.setattr(job_locks, "force_release_job_lock", lambda kind, job_id: True)
    assert job_locks.reclaim_stale_ocr_lock("job-1") is True
    monkeypatch.setattr(job_locks, "ocr_celery_work_active", lambda *a, **k: True)
    assert job_locks.reclaim_stale_ocr_lock("job-1") is False


def test_reclaim_stale_enrich_lock_when_no_celery_task(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, job_id: True)
    monkeypatch.setattr(job_locks, "ocr_celery_work_active", lambda *a, **k: False)
    monkeypatch.setattr(job_locks, "force_release_job_lock", lambda kind, job_id: True)
    assert job_locks.reclaim_stale_enrich_lock("job-1") is True
    monkeypatch.setattr(job_locks, "ocr_celery_work_active", lambda *a, **k: True)
    assert job_locks.reclaim_stale_enrich_lock("job-1") is False


def test_rewrite_ocr_queue_concurrency(monkeypatch):
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "scripts" / "dynamic_perf_entrypoint.py"
    spec = importlib.util.spec_from_file_location("dynamic_perf_entrypoint", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    monkeypatch.setenv("OCR_CELERY_CONCURRENCY", "4")
    argv = [
        "celery",
        "-A",
        "app.celery_app.celery",
        "worker",
        "--concurrency=1",
        "-Q",
        "ocr",
    ]
    out = mod._rewrite_celery_concurrency(argv)
    joined = " ".join(out)
    assert "--concurrency=4" in joined or (
        "--concurrency" in out and out[out.index("--concurrency") + 1] == "4"
    )
