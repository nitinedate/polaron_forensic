#!/usr/bin/env python3
"""Proof of the background acquisition lifecycle: progress, cancel, recovery.

Exercises the registry with a simulated slow device so the behaviours that only
appear on a long collection can be tested without hardware:

  * the API returns immediately and the collection continues in the background
  * progress snapshots update while the run is in flight
  * a second run against the same device is refused, not queued
  * cancellation stops at a safe boundary and still seals what was collected
  * a completed run is recoverable from disk after the process forgets it

Run:  python scripts/acquisition_progress_test.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.mobile_acquire import (  # noqa: E402
    AcquisitionRegistry,
    AcquisitionRequest,
    CollectionMethod,
    DeviceDetector,
    DeviceProfile,
)
from app.services.mobile_acquire.adapters.base import AcquisitionOutcome  # noqa: E402
from app.services.mobile_acquire.device_profile import ConnectionMode, LockState  # noqa: E402


class SlowAndroidAdapter:
    """A device that takes its time, so progress and cancellation are observable."""

    name = "android_adb"
    os_family = "android"

    def __init__(self, items: int = 40, delay: float = 0.05) -> None:
        self.items = items
        self.delay = delay

    def tool_available(self) -> bool:
        return True

    def detect(self) -> list[str]:
        return ["SLOWDEVICE01"]

    def identify(self, device_id: str) -> DeviceProfile:
        return DeviceProfile(
            os_family="android", manufacturer="Google", model="Pixel 8",
            serial=device_id, imei="356938035643809", os_version="15",
            security_patch_level="2026-06-05",
            lock_state=LockState.LOCKED_AFU, encryption_state="fbe",
            connection_mode=ConnectionMode.ADB, usb_debugging_authorized=True,
            rooted_or_jailbroken=True, battery_percent=90, network_isolated=True,
        )

    def supported_methods(self, profile):
        return [CollectionMethod.LOGICAL, CollectionMethod.FILE_SYSTEM,
                CollectionMethod.FULL_FILE_SYSTEM]

    def preflight(self, profile, method) -> list[str]:
        return []

    def acquire(self, *, profile, method, destination, progress=None, cancel=None):
        outcome = AcquisitionOutcome(ok=True, adapter=self.name, method=method)
        for i in range(self.items):
            if cancel and cancel():
                outcome.interrupted = True
                outcome.errors.append(
                    f"Cancelled by examiner after {i} of {self.items} items."
                )
                break
            target = Path(destination) / "data" / f"artifact_{i:03d}.db"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"SQLite format 3\x00 record {i}", encoding="latin-1")
            outcome.files_written.append(str(target))
            outcome.bytes_written += target.stat().st_size
            if progress:
                progress(target.name, outcome.bytes_written, None)
            time.sleep(self.delay)
        outcome.device_metadata = profile.as_dict()
        return outcome


def make_request(workspace: Path, evidence_id: str = "E01") -> AcquisitionRequest:
    return AcquisitionRequest(
        case_id="CASE-2026-777",
        evidence_id=evidence_id,
        examiner="A. Examiner",
        legal_authority="Warrant 2026/SW/9001",
        case_root=str(workspace),
        adapter_name="android_adb",
        device_id="SLOWDEVICE01",
        objective_methods=[CollectionMethod.FILE_SYSTEM],
        network_isolated=True,
    )


def wait_until(predicate, timeout: float = 30.0, interval: float = 0.05) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="acq-progress-"))
    checks: list[tuple[str, bool]] = []
    try:
        detector = DeviceDetector(adapters=[SlowAndroidAdapter()])
        registry = AcquisitionRegistry()

        # --- 1. start returns immediately -----------------------------------
        t0 = time.time()
        run = registry.start(make_request(workspace), detector=detector)
        elapsed = time.time() - t0
        checks.append(("start returns immediately (<1s)", elapsed < 1.0))
        checks.append(("run is queued or running", run.status in ("queued", "running")))
        print(f"start returned in {elapsed * 1000:.0f} ms as run {run.run_id}")

        # --- 2. progress advances while in flight ---------------------------
        saw_progress = wait_until(lambda: run.progress.bytes_done > 0, timeout=10)
        checks.append(("progress snapshot advances during collection", saw_progress))
        mid = run.summary()
        print(f"mid-run: stage={mid['progress']['stage']} "
              f"bytes={mid['progress']['bytes_done']} files={mid['progress']['files_seen']}")

        # --- 3. same device cannot be acquired twice ------------------------
        conflict = False
        try:
            registry.start(make_request(workspace, "E02"), detector=detector)
        except RuntimeError as exc:
            conflict = "already being acquired" in str(exc)
        checks.append(("second run on the same device is refused", conflict))

        # --- 4. completion --------------------------------------------------
        done = wait_until(lambda: run.status in ("completed", "failed", "cancelled"), timeout=60)
        checks.append(("run reaches a terminal state", done))
        checks.append(("run completed successfully", run.status == "completed"))
        checks.append(("result attached to run", bool(run.result)))
        checks.append(("run name assigned", bool(run.run_name)))
        if run.result:
            checks.append(("working copy verified",
                           (run.result.get("verification") or {}).get("ok") is True))
            file_count = len((run.result.get("evidence_package") or {}).get("extraction_data") or [])
            checks.append(("all 40 artifacts collected", file_count == 40))
            print(f"completed: {run.run_name} ({file_count} files)")

        # --- 5. cancellation seals a partial extraction ---------------------
        registry2 = AcquisitionRegistry()
        detector2 = DeviceDetector(adapters=[SlowAndroidAdapter(items=200, delay=0.02)])
        run2 = registry2.start(make_request(workspace, "E03"), detector=detector2)
        wait_until(lambda: run2.progress.bytes_done > 0, timeout=10)
        accepted = registry2.cancel(run2.run_id)
        checks.append(("cancellation accepted", accepted))
        cancelled = wait_until(
            lambda: run2.status in ("cancelled", "failed", "completed"), timeout=60)
        checks.append(("cancelled run reaches a terminal state", cancelled))
        checks.append(("run reports cancelled", run2.status == "cancelled"))
        if run2.result:
            partial = (run2.result.get("evidence_package") or {}).get("extraction_data") or []
            checks.append(("partial extraction still hashed and sealed", len(partial) > 0))
            checks.append(("interruption recorded as a limitation",
                           any("Cancelled" in e for e in run2.result.get("errors") or [])))
            manifest = (run2.result.get("evidence_package") or {}).get("hash_manifest")
            checks.append(("hash manifest exists for partial run",
                           bool(manifest) and Path(manifest).is_file()))
            print(f"cancelled after {len(partial)} files, manifest written")

        # --- 6. cancelling a finished run is a no-op ------------------------
        checks.append(("cancelling a finished run is refused",
                       registry2.cancel(run2.run_id) is False))

        # --- 7. recovery from disk after the process forgets the run --------
        fresh = AcquisitionRegistry()
        recovered = fresh.recover(str(workspace), "CASE-2026-777")
        checks.append(("completed runs recoverable from disk", len(recovered) >= 1))
        checks.append(("recovered entries flagged as such",
                       all(r.get("recovered") for r in recovered)))
        print(f"recovered {len(recovered)} run(s) from the case folder")

        # --- 8. listing and pruning ----------------------------------------
        checks.append(("registry lists the run", len(registry.list()) == 1))
        checks.append(("no active runs remain", registry.active_count() == 0))

        print("\nchecks:")
        failed = 0
        for label, passed in checks:
            print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
            failed += 0 if passed else 1
        print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
        return 1 if failed else 0
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
