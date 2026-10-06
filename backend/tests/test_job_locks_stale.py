import time

from app.services.job_locks import extract_task_in_flight, heavy_holder_is_stale


def test_fresh_heartbeat_is_not_stale():
    holder = {"reason": "extract", "pid": 19, "heartbeat": time.time(), "started": time.time()}
    assert heavy_holder_is_stale(holder) is False


def test_frozen_heartbeat_after_worker_death_is_stale():
    holder = {
        "reason": "extract",
        "pid": 19,
        "heartbeat": time.time() - 221,
        "started": time.time() - 8800,
    }
    assert heavy_holder_is_stale(holder) is True


def test_same_host_old_boot_id_is_stale(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "_container_boot_id", lambda: "worker-mobile:200")
    holder = {
        "reason": "extract",
        "pid": 19,
        "boot_id": "worker-mobile:100",
        "heartbeat": time.time(),
        "started": time.time(),
    }
    assert heavy_holder_is_stale(holder) is True


def test_empty_holder_is_stale():
    assert heavy_holder_is_stale(None) is True
    assert heavy_holder_is_stale({}) is True


def test_extract_lock_without_celery_task_is_released(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, job_id: kind == "extract")
    monkeypatch.setattr(job_locks, "extract_celery_work_active", lambda job_id, timeout=1.5: False)
    monkeypatch.setattr(job_locks, "job_lock_age_sec", lambda kind, job_id: 400.0)
    monkeypatch.setattr(job_locks, "_extract_heartbeat_age_sec", lambda db, job_id: 400.0)
    released = []
    monkeypatch.setattr(job_locks, "force_release_job_lock", lambda kind, job_id: released.append((kind, job_id)) or True)
    assert extract_task_in_flight(None, "job-hung") is False
    assert released == [("extract", "job-hung")]


def test_extract_lock_keeps_live_heartbeat_when_inspect_is_empty(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, job_id: True)
    monkeypatch.setattr(job_locks, "extract_celery_work_active", lambda job_id, timeout=1.5: False)
    monkeypatch.setattr(job_locks, "job_lock_age_sec", lambda kind, job_id: 400.0)
    monkeypatch.setattr(job_locks, "_extract_heartbeat_age_sec", lambda db, job_id: 12.0)
    released = []
    monkeypatch.setattr(job_locks, "force_release_job_lock", lambda kind, job_id: released.append(job_id) or True)
    assert extract_task_in_flight(None, "job-copying") is True
    assert released == []


def test_extract_lock_just_queued_without_heartbeat_is_live(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, job_id: True)
    monkeypatch.setattr(job_locks, "extract_celery_work_active", lambda job_id, timeout=1.5: False)
    monkeypatch.setattr(job_locks, "job_lock_age_sec", lambda kind, job_id: 12.0)
    monkeypatch.setattr(job_locks, "_extract_heartbeat_age_sec", lambda db, job_id: None)
    monkeypatch.setattr(job_locks, "force_release_job_lock", lambda kind, job_id: True)
    assert extract_task_in_flight(None, "job-new") is True


def test_huddle_updated_at_does_not_keep_dead_extract_lock(monkeypatch):
    """jobs.updated_at is stamped every 30s by huddle — must not keep a dead lock."""
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, job_id: True)
    monkeypatch.setattr(job_locks, "extract_celery_work_active", lambda job_id, timeout=1.5: False)
    monkeypatch.setattr(job_locks, "job_lock_age_sec", lambda kind, job_id: 900.0)
    monkeypatch.setattr(job_locks, "_extract_heartbeat_age_sec", lambda db, job_id: None)
    released = []
    monkeypatch.setattr(job_locks, "force_release_job_lock", lambda kind, job_id: released.append(job_id) or True)
    assert extract_task_in_flight(None, "job-dead") is False
    assert released == ["job-dead"]
