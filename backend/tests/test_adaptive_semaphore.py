from types import SimpleNamespace

from app.services.adaptive_semaphore import cap_parallelism, resource_capacity


def snap(
    *,
    profile="laptop",
    cpus=16,
    mem_total=64 * 1024,
    mem_avail=32 * 1024,
    load=4.0,
    cpu_temp=55,
    gpu=True,
    vram=12_288,
    free_vram=None,
    gpu_temp=55,
):
    return SimpleNamespace(
        profile=profile,
        cpu_logical=cpus,
        mem_total_mb=mem_total,
        mem_available_mb=mem_avail,
        load_1m=load,
        cpu_temp_c=cpu_temp,
        gpu_available=gpu,
        gpu_vram_total_mb=vram,
        gpu_vram_free_mb=vram if free_vram is None else free_vram,
        gpu_temp_c=gpu_temp,
    )


def test_12gb_laptop_runs_one_heavy_gpu_session():
    assert resource_capacity("gpu", requested=2, snapshot=snap()) == 1


def test_large_cool_workstation_can_run_two_gpu_sessions():
    s = snap(profile="workstation", vram=24_576, gpu_temp=50)
    assert resource_capacity("gpu", requested=2, snapshot=s) == 2


def test_large_gpu_needs_vram_headroom_for_second_model():
    s = snap(profile="workstation", vram=24_576, free_vram=6_000, gpu_temp=50)
    assert resource_capacity("gpu", requested=2, snapshot=s) == 1


def test_gpu_pause_temperature_stops_new_gpu_admission():
    s = snap(profile="workstation", vram=24_576, gpu_temp=99)
    assert resource_capacity("gpu", requested=2, snapshot=s) == 0


def test_laptop_cpu_heavy_jobs_use_current_three_lane_tuning_when_cool():
    assert resource_capacity("cpu_heavy", requested=6, snapshot=snap()) == 3


def test_hot_cpu_reduces_cpu_heavy_admission_to_one():
    s = snap(cpu_temp=95)
    assert resource_capacity("cpu_heavy", requested=4, snapshot=s) == 1


def test_mobile_reader_fanout_uses_current_headroom_but_is_bounded():
    assert cap_parallelism("mobile_readers", 16, snapshot=snap()) == 12


def test_parse_fanout_reduces_under_high_load():
    s = snap(load=18.0)  # > 1.10 load/cpu on a 16-thread host
    assert cap_parallelism("parse_workers", 16, snapshot=s) == 2


def test_capacity_shrink_counts_higher_slot_before_admission(monkeypatch):
    import json
    import time
    from app.services import adaptive_semaphore as sem

    class FakeRedis:
        def __init__(self):
            self.data = {}
            self.set_calls = []

        def ping(self):
            return True

        def get(self, key):
            return self.data.get(key)

        def delete(self, key):
            return int(self.data.pop(key, None) is not None)

        def set(self, key, value, nx=False, ex=None):
            self.set_calls.append(key)
            if nx and key in self.data:
                return False
            self.data[key] = value
            return True

    fake = FakeRedis()
    monkeypatch.setenv("RESOURCE_GOVERNOR_GROUP", "test-host")
    # Slot :1 was admitted while capacity was 2; now thermal policy shrank to 1.
    fake.data[sem._key("gpu", 1)] = json.dumps(
        {"token": "old", "reason": "rag", "heartbeat": time.time(), "started": time.time()}
    )
    monkeypatch.setattr(sem, "_redis_client", lambda: fake)
    monkeypatch.setattr(sem, "resource_capacity", lambda *args, **kwargs: 1)

    lease = sem.acquire_resource_slot(
        "gpu", reason="ocr", requested_limit=2, wait_sec=0, fail_closed=False
    )
    assert lease.acquired is False
    # Fairness may publish a short-lived demand marker, but no resource slot may
    # be attempted while the higher-index in-flight lease already consumes the
    # shrunken capacity.
    assert not [key for key in fake.set_calls if ":slot:" in key]

    view = sem.semaphore_snapshot("gpu", requested_limit=2)
    assert view["capacity"] == 1
    assert view["used"] == 1
    assert view["free"] == 0


def test_running_worker_backoff_increases_with_pressure():
    from app.services.adaptive_semaphore import cpu_backoff_delay

    cool = snap(load=1.0, cpu_temp=50)
    hot = snap(load=20.0, cpu_temp=95)
    assert cpu_backoff_delay(snapshot=cool) == 0.0
    assert cpu_backoff_delay(snapshot=hot) >= 1.0


def test_host_namespace_sees_higher_slots_from_differently_tuned_product(monkeypatch):
    import json
    import time
    from app.services import adaptive_semaphore as sem

    class FakeRedis:
        def __init__(self):
            self.data = {}
        def ping(self): return True
        def get(self, key): return self.data.get(key)
        def delete(self, key): return int(self.data.pop(key, None) is not None)
        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.data:
                return False
            self.data[key] = value
            return True

    fake = FakeRedis()
    monkeypatch.setenv("RESOURCE_GOVERNOR_GROUP", "namespace-test")
    monkeypatch.setenv("RESOURCE_GOVERNOR_CPU_MAX_SLOTS", "8")
    fake.data[sem._key("cpu_heavy", 3)] = json.dumps({
        "token": "disk-high-slot", "lane": "forensic", "reason": "extract",
        "heartbeat": time.time(), "started": time.time(),
    })
    monkeypatch.setattr(sem, "_redis_client", lambda: fake)
    # Simulate a workstation host capacity of 4 even though this caller's local
    # product is configured for only two workers.
    monkeypatch.setattr(sem, "resource_capacity", lambda *args, **kwargs: 4)
    view = sem.semaphore_snapshot("cpu_heavy", requested_limit=2)
    assert view["capacity"] == 4
    assert view["used"] == 1
    assert view["holders"][0]["lane"] == "forensic"


def test_competing_product_demand_prevents_reacquire_monopoly(monkeypatch):
    import json
    from app.services import adaptive_semaphore as sem

    class FakeRedis:
        def __init__(self):
            self.data = {}
        def ping(self): return True
        def get(self, key): return self.data.get(key)
        def delete(self, key): return int(self.data.pop(key, None) is not None)
        def set(self, key, value, nx=False, ex=None):
            if nx and key in self.data:
                return False
            self.data[key] = value
            return True

    fake = FakeRedis()
    monkeypatch.setenv("RESOURCE_GOVERNOR_GROUP", "fairness-test")
    monkeypatch.setenv("RESOURCE_GOVERNOR_CPU_MAX_SLOTS", "3")
    monkeypatch.setattr(sem, "_redis_client", lambda: fake)
    monkeypatch.setattr(sem, "resource_capacity", lambda *args, **kwargs: 3)

    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    disk = [
        sem.acquire_resource_slot("cpu_heavy", reason=f"disk-{i}", requested_limit=3)
        for i in range(3)
    ]
    assert all(x.acquired for x in disk)

    # Android cannot preempt running work, but its failed attempt leaves a short
    # demand marker. Once one Disk lease finishes, Disk may not immediately take
    # the freed slot again ahead of the waiting Android product.
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-android")
    waiting = sem.acquire_resource_slot(
        "cpu_heavy", reason="android-wait", requested_limit=2, fail_closed=False
    )
    assert not waiting.acquired

    disk[0].release()
    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    disk_reacquire = sem.acquire_resource_slot(
        "cpu_heavy", reason="disk-reacquire", requested_limit=3, fail_closed=False
    )
    assert not disk_reacquire.acquired

    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-android")
    android = sem.acquire_resource_slot(
        "cpu_heavy", reason="android", requested_limit=2, fail_closed=False
    )
    assert android.acquired

    for lease in disk[1:]:
        lease.release()
    android.release()


def test_shared_governor_transport_outage_can_fail_open_to_local_guards(monkeypatch):
    from app.services import adaptive_semaphore as sem

    class DownRedis:
        def ping(self):
            raise OSError("redis-capacity:6379 name or service not known")

    monkeypatch.setattr(sem, "_redis_client", lambda: DownRedis())
    lease = sem.acquire_resource_slot(
        "cpu_heavy",
        reason="extract",
        requested_limit=2,
        fail_closed=True,
        fail_open_if_unavailable=True,
    )
    assert lease.acquired is False
    assert lease.key is None


def test_shared_governor_transport_outage_still_fails_closed_without_fallback(monkeypatch):
    import pytest
    from app.services import adaptive_semaphore as sem

    class DownRedis:
        def ping(self):
            raise OSError("redis-capacity:6379 name or service not known")

    monkeypatch.setattr(sem, "_redis_client", lambda: DownRedis())
    with pytest.raises(sem.ResourceSemaphoreTimeout, match="resource governor unavailable"):
        sem.acquire_resource_slot(
            "cpu_heavy",
            reason="extract",
            requested_limit=2,
            fail_closed=True,
            fail_open_if_unavailable=False,
        )


def test_fail_open_transport_policy_does_not_override_real_capacity_exhaustion(monkeypatch):
    import pytest
    from app.services import adaptive_semaphore as sem

    class FakeRedis:
        def ping(self): return True
        def get(self, key): return None
        def set(self, key, value, nx=False, ex=None): return True
        def delete(self, key): return 0

    monkeypatch.setattr(sem, "_redis_client", lambda: FakeRedis())
    monkeypatch.setattr(sem, "resource_capacity", lambda *args, **kwargs: 0)
    with pytest.raises(sem.ResourceSemaphoreTimeout, match="adaptive resource slot unavailable"):
        sem.acquire_resource_slot(
            "cpu_heavy",
            reason="extract",
            requested_limit=2,
            fail_closed=True,
            fail_open_if_unavailable=True,
        )
