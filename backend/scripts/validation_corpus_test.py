#!/usr/bin/env python3
"""Acceptance-testing and version-ledger proof (Architecture sections 22 and 15).

Runs the acceptance harness against a simulated corpus device and exercises the
version ledger, including the two conditions that matter most in practice:

  * a NEW TOOL VERSION invalidates every previously validated device family
  * a validation record that has aged past its validity period blocks reuse

Run:  python scripts/validation_corpus_test.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.mobile_acquire import (  # noqa: E402
    CollectionMethod,
    CollectionOrchestrator,
    DeviceDetector,
)
from app.services.mobile_acquire.validation import (  # noqa: E402
    ACCEPTANCE_AREAS,
    CRITICAL_DEVICE_FAMILIES,
    AcceptanceHarness,
    CorpusDevice,
    ToolVersionLedger,
    device_family_for,
    preflight_validation_gate,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acquisition_smoke_test import SimulatedAndroidAdapter  # noqa: E402


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="validation-"))
    checks: list[tuple[str, bool]] = []
    try:
        detector = DeviceDetector(adapters=[SimulatedAndroidAdapter()])

        device = CorpusDevice(
            device_family="android_modern",
            label="Google Pixel 8 (corpus)",
            adapter="android_adb",
            device_id="SIMULATED0001",
            expected_methods=[CollectionMethod.LOGICAL, CollectionMethod.FILE_SYSTEM],
            expected_artifacts=["msgstore.db", "msgstore.db-wal", "getprop.txt"],
            min_expected_files=5,
            notes="Reference handset: work profile and WAL sidecar must both appear.",
        )

        # --- acceptance run -------------------------------------------------
        harness = AcceptanceHarness("aetheris-acquire/1.0", examiner="QA Examiner")
        run = harness.run(
            device,
            detector=detector,
            orchestrator_factory=lambda: CollectionOrchestrator(detector),
            case_root=str(workspace),
        )
        summary = run.as_dict()
        print(f"acceptance run: {summary['coverage']} areas evaluated, passed={run.passed}")
        for check in run.checks:
            mark = "SKIP" if check.skipped else ("PASS" if check.passed else "FAIL")
            print(f"  [{mark}] {check.area}: {check.detail[:76]}")

        checks.append(("acceptance run passes", run.passed))
        checks.append(("every section 22 area accounted for",
                       {c.area for c in run.checks} == set(ACCEPTANCE_AREAS)))
        checks.append(("human-only areas recorded as skipped, not passed silently",
                       "peer_review" in run.skipped_areas
                       and "network_controls" in run.skipped_areas))
        checks.append(("expected artifacts verified present",
                       any(c.area == "filesystem_collection" and c.passed for c in run.checks)))
        checks.append(("integrity verified", any(c.area == "integrity" and c.passed
                                                 for c in run.checks)))
        checks.append(("sealed original re-verifies",
                       any(c.area == "recovery" and c.passed for c in run.checks)))

        # --- ledger ---------------------------------------------------------
        ledger_path = workspace / "validation_ledger.json"
        ledger = ToolVersionLedger(ledger_path, validity_days=180)

        blocked, reason = ledger.requires_revalidation("aetheris-acquire/1.0", "android_modern")
        checks.append(("unvalidated family is blocked before any record exists", blocked))
        print(f"\nbefore validation: blocked={blocked} — {reason[:88]}")

        ledger.record(run, approver="Lab Manager", notes="Initial acceptance.")
        blocked, reason = ledger.requires_revalidation("aetheris-acquire/1.0", "android_modern")
        checks.append(("validated family clears after recording", not blocked))
        print(f"after validation : blocked={blocked} — {reason}")

        # --- version drift ---------------------------------------------------
        blocked_new, reason_new = ledger.requires_revalidation(
            "aetheris-acquire/1.1", "android_modern")
        checks.append(("a new tool version invalidates prior validation", blocked_new))
        checks.append(("drift reason names the previously validated version",
                       "aetheris-acquire/1.0" in reason_new))
        print(f"new version 1.1  : blocked={blocked_new} — {reason_new[:100]}")

        drift = ledger.drift_from("aetheris-acquire/1.1")
        checks.append(("drift report lists the unvalidated family",
                       "android_modern" in drift))

        # --- staleness --------------------------------------------------------
        stale = ToolVersionLedger(workspace / "stale_ledger.json", validity_days=0)
        stale.record_manual(tool_version="aetheris-acquire/1.0",
                            device_family="ios_modern", examiner="QA", passed=True)
        blocked_stale, reason_stale = stale.requires_revalidation(
            "aetheris-acquire/1.0", "ios_modern")
        checks.append(("validation past its validity period is blocked", blocked_stale))
        print(f"stale record     : blocked={blocked_stale} — {reason_stale[:88]}")

        # --- failed validation is not a pass ---------------------------------
        failing = ToolVersionLedger(workspace / "failed_ledger.json")
        failing.record_manual(tool_version="aetheris-acquire/1.0",
                              device_family="sim", examiner="QA", passed=False)
        blocked_fail, _ = failing.requires_revalidation("aetheris-acquire/1.0", "sim")
        checks.append(("a failed validation blocks production use", blocked_fail))

        # --- production readiness --------------------------------------------
        status = ledger.status("aetheris-acquire/1.0")
        checks.append(("status covers every critical family",
                       len(status["families"]) == len(CRITICAL_DEVICE_FAMILIES)))
        checks.append(("not production ready while other families are unvalidated",
                       status["production_ready"] is False))
        unvalidated = [f["device_family"] for f in status["families"] if f["blocked"]]
        print(f"\nproduction ready : {status['production_ready']}")
        print(f"still to validate: {', '.join(unvalidated)}")

        # --- family mapping ---------------------------------------------------
        checks.append(("Android 15 maps to android_modern",
                       device_family_for("android", "15") == "android_modern"))
        checks.append(("Android 9 maps to android_legacy",
                       device_family_for("android", "9") == "android_legacy"))
        checks.append(("iOS 17 maps to ios_modern",
                       device_family_for("ios", "17.4") == "ios_modern"))
        checks.append(("iOS 14 maps to ios_legacy",
                       device_family_for("ios", "14.8") == "ios_legacy"))

        # --- preflight gate is advisory, never blocking ----------------------
        gate = preflight_validation_gate(
            ledger, tool_version="aetheris-acquire/1.1",
            os_family="android", os_version="15")
        checks.append(("preflight gate warns on an unvalidated version",
                       bool(gate["warning"]) and gate["validated"] is False))
        checks.append(("preflight gate never blocks the acquisition",
                       gate["blocking"] is False))

        no_ledger = preflight_validation_gate(
            None, tool_version="x", os_family="ios", os_version="17")
        checks.append(("absent ledger produces a warning, not a crash",
                       bool(no_ledger["warning"])))

        # --- persistence ------------------------------------------------------
        reopened = ToolVersionLedger(ledger_path)
        checks.append(("ledger persists across restarts",
                       reopened.latest("aetheris-acquire/1.0", "android_modern") is not None))
        checks.append(("approver retained in the record",
                       (reopened.latest("aetheris-acquire/1.0", "android_modern") or
                        type("x", (), {"approver": ""})()).approver == "Lab Manager"))

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
