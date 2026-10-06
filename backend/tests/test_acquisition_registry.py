from __future__ import annotations

import threading

from app.services.mobile_acquire.run_registry import (
    TERMINAL_STATES,
    AcquisitionRegistry,
    AcquisitionRun,
)


def _run(device_id: str = "UDID-1", status: str = "running", run_id: str = "dead1") -> AcquisitionRun:
    run = AcquisitionRun(
        run_id=run_id,
        case_id="CASE-1",
        evidence_id="E01",
        adapter="ios_lockdown",
        device_id=device_id,
        examiner="tester",
    )
    run.status = status
    return run


def _device_blocked(registry: AcquisitionRegistry, device_id: str) -> bool:
    with registry._lock:
        registry._reap_abandoned_runs_locked()
        return any(
            existing.status not in TERMINAL_STATES and existing.device_id == device_id
            for existing in registry._runs.values()
        )


def test_reap_abandoned_frees_same_device():
    registry = AcquisitionRegistry()
    run = _run()
    registry._runs[run.run_id] = run
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    registry._threads[run.run_id] = dead

    assert _device_blocked(registry, "UDID-1") is False
    assert run.status == "failed"
    assert run.error
    assert "free" in (run.error or "").lower()


def test_failed_run_does_not_block_same_device():
    registry = AcquisitionRegistry()
    registry._runs["done"] = _run(status="failed", run_id="done")
    assert _device_blocked(registry, "UDID-1") is False


def test_in_flight_run_still_blocks_same_device():
    registry = AcquisitionRegistry()
    live = _run(status="running", run_id="live")
    registry._runs[live.run_id] = live
    thread = threading.Thread(target=lambda: threading.Event().wait(30), daemon=True)
    thread.start()
    registry._threads[live.run_id] = thread
    try:
        assert _device_blocked(registry, "UDID-1") is True
    finally:
        # Thread is daemon + Event wait; process exit will reap it.
        pass
