import threading

import pytest


class FakeRedis:
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()

    def ping(self):
        return True

    def get(self, key):
        with self.lock:
            return self.data.get(key)

    def set(self, key, value, nx=False, ex=None):
        with self.lock:
            if nx and key in self.data:
                return False
            self.data[key] = value
            return True

    def delete(self, key):
        with self.lock:
            return int(self.data.pop(key, None) is not None)


class DummyAdaptiveLease:
    def __init__(self):
        self.acquired = True
        self.released = False

    def release(self):
        self.released = True


def test_two_threads_keep_independent_local_gpu_lease_ownership(monkeypatch):
    from app.services import adaptive_semaphore as adaptive
    from app.services import job_locks

    fake = FakeRedis()
    monkeypatch.setattr(job_locks, "_redis_client", lambda: fake)
    monkeypatch.setattr(job_locks, "_gpu_slot_keys", lambda: ["gpu:test:0", "gpu:test:1"])
    monkeypatch.setattr(job_locks, "_gpu_heavy_max_slots", lambda: 2)
    monkeypatch.setattr(adaptive, "acquire_resource_slot", lambda *a, **k: DummyAdaptiveLease())

    entered = threading.Barrier(3)
    release_one = threading.Event()
    release_two = threading.Event()
    keys = {}
    errors = []

    def runner(name, release_event):
        try:
            with job_locks.gpu_heavy_slot(name, fail_closed=True):
                lease = job_locks._current_heavy_lease("gpu")
                assert lease is not None
                keys[name] = lease.key
                entered.wait(timeout=3)
                release_event.wait(timeout=3)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    t1 = threading.Thread(target=runner, args=("one", release_one))
    t2 = threading.Thread(target=runner, args=("two", release_two))
    t1.start(); t2.start()
    entered.wait(timeout=3)
    assert not errors
    assert len(set(keys.values())) == 2
    assert len(fake.data) == 2

    release_one.set(); t1.join(timeout=3)
    assert not errors
    # Releasing thread one must leave thread two's token/slot untouched.
    assert len(fake.data) == 1
    assert keys["two"] in fake.data

    release_two.set(); t2.join(timeout=3)
    assert not errors
    assert fake.data == {}


def test_shared_host_permit_is_not_requested_when_local_lane_is_full(monkeypatch):
    from app.services import adaptive_semaphore as adaptive
    from app.services import job_locks

    called = {"host": 0}
    monkeypatch.setattr(job_locks, "_acquire_local_heavy_lease", lambda *a, **k: None)

    def host(*args, **kwargs):
        called["host"] += 1
        return DummyAdaptiveLease()

    monkeypatch.setattr(adaptive, "acquire_resource_slot", host)
    with pytest.raises(job_locks.CpuHeavySlotTimeout):
        with job_locks.cpu_heavy_slot("extract", wait_sec=0, fail_closed=True):
            pass
    assert called["host"] == 0


def test_cpu_and_gpu_lanes_are_independent(monkeypatch):
    from app.services import adaptive_semaphore as adaptive
    from app.services import job_locks

    fake = FakeRedis()
    monkeypatch.setattr(job_locks, "_redis_client", lambda: fake)
    monkeypatch.setattr(job_locks, "_gpu_slot_keys", lambda: ["gpu:test:0"])
    monkeypatch.setattr(job_locks, "_cpu_slot_keys", lambda: ["cpu:test:0"])
    monkeypatch.setattr(job_locks, "_gpu_heavy_max_slots", lambda: 1)
    monkeypatch.setattr(job_locks, "_cpu_heavy_max_slots", lambda: 1)

    host_calls = []
    def host(resource, **kwargs):
        host_calls.append(resource)
        return DummyAdaptiveLease()
    monkeypatch.setattr(adaptive, "acquire_resource_slot", host)

    with job_locks.cpu_heavy_slot("extract", fail_closed=True):
        with job_locks.gpu_heavy_slot("ocr", fail_closed=True):
            assert "cpu:test:0" in fake.data
            assert "gpu:test:0" in fake.data
    assert host_calls == ["cpu_heavy", "gpu"]


def test_extract_and_parse_queues_are_separate_for_every_forensic_product():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    routes = (root / "backend/app/celery_factory.py").read_text()
    assert '"app.tasks.build_extracted_disk_task": {"queue": "disk-build"}' in routes
    assert '"app.tasks.parse_drain_task": {"queue": "disk-parse"}' in routes
    assert 'parse = f"{prefix}-parse"' in routes
    for service, prefix in (("mobile-android", "android"), ("mobile-ios", "ios")):
        compose = (root / f"services/{service}/docker-compose.yml").read_text()
        assert f"{prefix}-build" in compose
        assert f"{prefix}-parse" in compose
        assert "worker-parse:" in compose
    disk = (root / "docker-compose.yml").read_text()
    assert "worker-parse:" in disk
    assert "disk-parse" in disk


def test_shared_host_gpu_workers_release_resident_models_by_default(monkeypatch):
    from app.services.gpu_thermal import release_gpu_model_after_task_enabled

    monkeypatch.delenv("GPU_RELEASE_MODEL_AFTER_TASK", raising=False)
    monkeypatch.setenv("AETHERIS_SHARE_HOST", "true")
    assert release_gpu_model_after_task_enabled() is True
    monkeypatch.setenv("GPU_RELEASE_MODEL_AFTER_TASK", "false")
    assert release_gpu_model_after_task_enabled() is False


def test_rag_and_ocr_register_model_unload_before_gpu_lease_release():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    rag = (root / "backend/app/services/dual_rag_index.py").read_text()
    ocr = (root / "backend/app/services/ocr_gpu.py").read_text()
    assert "stack.callback(unload_embedder)" in rag
    assert "gpu_stack.callback(unload_glm_ocr)" in ocr
    thermal = (root / "backend/app/services/gpu_thermal.py").read_text()
    assert "unload_clip_model" in thermal
