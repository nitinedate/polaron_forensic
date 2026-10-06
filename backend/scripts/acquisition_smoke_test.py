#!/usr/bin/env python3
"""End-to-end proof of the acquisition orchestrator against a simulated device.

Runs the full §7 ten-step sequence with a fake adapter so the case layout,
integrity manifest, sealing, verified working copy, audit trail and acquisition
record can be exercised without hardware.

Run:  python scripts/acquisition_smoke_test.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.mobile_acquire import (  # noqa: E402
    AcquisitionRequest,
    CollectionMethod,
    CollectionOrchestrator,
    DeviceDetector,
    DeviceProfile,
)
from app.services.mobile_acquire.adapters.base import AcquisitionOutcome  # noqa: E402
from app.services.mobile_acquire.device_profile import ConnectionMode, LockState  # noqa: E402


class SimulatedAndroidAdapter:
    """Stands in for a rooted Android handset on the bench."""

    name = "android_adb"
    os_family = "android"

    def tool_available(self) -> bool:
        return True

    def detect(self) -> list[str]:
        return ["SIMULATED0001"]

    def identify(self, device_id: str) -> DeviceProfile:
        return DeviceProfile(
            os_family="android",
            manufacturer="Google",
            model="Pixel 8",
            chipset="zuma",
            serial=device_id,
            imei="356938035643809",
            os_version="15",
            security_patch_level="2026-06-05",
            build_id="google/shiba/shiba:15/AP4A.260605.001/12345:user/release-keys",
            lock_state=LockState.LOCKED_AFU,
            encryption_state="fbe",
            connection_mode=ConnectionMode.ADB,
            usb_debugging_authorized=True,
            rooted_or_jailbroken=True,
            battery_percent=87,
            network_isolated=True,
            sim_present=True,
            iccid="8991101200003204514",
            sd_card_present=False,
            required_cable="USB-C validated data cable",
        )

    def supported_methods(self, profile):
        return [
            CollectionMethod.LOGICAL,
            CollectionMethod.BACKUP,
            CollectionMethod.ADVANCED_LOGICAL,
            CollectionMethod.FILE_SYSTEM,
            CollectionMethod.FULL_FILE_SYSTEM,
            CollectionMethod.PHYSICAL,
        ]

    def preflight(self, profile, method) -> list[str]:
        return []

    def acquire(self, *, profile, method, destination, progress=None, cancel=None):
        outcome = AcquisitionOutcome(ok=True, adapter=self.name, method=method)
        fixtures = {
            "device_state/getprop.txt": "[ro.product.model]: [Pixel 8]\n",
            "device_state/packages_all.txt": "package:/data/app/com.whatsapp\n",
            "data/data_data/com.whatsapp/databases/msgstore.db": "SQLite format 3\x00",
            "data/data_data/com.whatsapp/databases/msgstore.db-wal": "WAL\x00",
            "data/data_data/com.whatsapp/files/key": "\x00keymaterial",
            "data/data_user/10/com.whatsapp/databases/msgstore.db": "SQLite format 3\x00",
            "data/data_system/dropbox/system_server_crash@1719830400000.txt": "crash\n",
            "shared_storage/sdcard_DCIM/IMG_0001.jpg": "\xff\xd8\xff\xe0JFIF",
        }
        for rel, content in fixtures.items():
            target = Path(destination) / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="latin-1")
            outcome.files_written.append(str(target))
            outcome.bytes_written += target.stat().st_size
            if progress:
                progress(rel, outcome.bytes_written, None)

        outcome.warnings.append("Two application containers were locked and skipped.")
        outcome.coverage_gaps.append(
            "Keystore-backed app data could not be decrypted on-device."
        )
        outcome.device_metadata = profile.as_dict()
        return outcome


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="acq-smoke-"))
    try:
        detector = DeviceDetector(adapters=[SimulatedAndroidAdapter()])
        events: list[str] = []
        orch = CollectionOrchestrator(
            detector, progress=lambda e: events.append(e.get("stage", "")))

        devices, warnings = detector.scan()
        print(f"detected: {[d.as_dict() for d in devices]}")
        assert devices, "simulated device was not detected"

        preview = orch.preview("android_adb", devices[0].device_id)
        print(f"capability: {preview['capability']['capability_label']}")
        print(f"supported:  {preview['capability']['supported_methods']}")

        result = orch.run(AcquisitionRequest(
            case_id="CASE-2026-001",
            evidence_id="E01",
            examiner="A. Examiner",
            legal_authority="Warrant 2026/SW/4471",
            case_root=str(workspace),
            adapter_name="android_adb",
            device_id=devices[0].device_id,
            objective_methods=[CollectionMethod.FILE_SYSTEM,
                               CollectionMethod.FULL_FILE_SYSTEM],
            cable_adapter_asset_id="CBL-USBC-014",
            device_condition="Powered on, AFU, screen intact",
            network_isolated=True,
            examiner_notes="Airplane mode engaged at intake.",
        ))

        print(f"\nrun:      {result.run_name}")
        print(f"stage:    {result.stage_reached}")
        print(f"ok:       {result.ok}")
        print(f"method:   {result.method_decision['selected']}")
        print(f"rationale:{result.method_decision['rationale'][:100]}...")
        print(f"files:    {len(result.package['extraction_data'])}")
        print(f"verified: {result.verification.get('verified')} "
              f"(ok={result.verification.get('ok')})")

        print("\nlimitations recorded:")
        for lim in result.limitations:
            print(f"  - {lim[:110]}")

        checks: list[tuple[str, bool]] = []
        run_root = Path(result.paths["case_root"])
        checks.append(("case skeleton created", (run_root / "01_Authority").is_dir()))
        checks.append(("original written", Path(result.paths["original"]).is_dir()))
        checks.append(("hash manifest written",
                       Path(result.paths["hashes"], "manifest.json").is_file()))
        checks.append(("audit log written",
                       Path(result.paths["logs"], "audit.jsonl").is_file()))
        checks.append(("acquisition record written",
                       Path(result.paths["logs"], "acquisition_record.json").is_file()))
        checks.append(("collection summary written",
                       Path(result.paths["logs"], "collection_summary.json").is_file()))
        checks.append(("working copy verified", result.verification.get("ok") is True))
        checks.append(("least-intrusive sufficient method chosen",
                       result.method_decision["selected"] == "file_system"))
        checks.append(("deeper method recorded as available",
                       "full_file_system" in result.method_decision["deeper_available"]))
        checks.append(("coverage gap carried to limitations",
                       any("Keystore" in l for l in result.limitations)))
        checks.append(("mandatory caveat present",
                       any("does not establish" in l for l in result.limitations)))
        checks.append(("chain of custody built", len(result.custody) >= 4))

        manifest = json.loads(Path(result.paths["hashes"], "manifest.json").read_text())
        checks.append(("every file hashed twice",
                       all(len(f["digests"]) == 2 for f in manifest["files"])))
        checks.append(("WAL sidecar collected",
                       any(f["path"].endswith("msgstore.db-wal") for f in manifest["files"])))
        checks.append(("work-profile copy collected",
                       any("data_user/10" in f["path"] for f in manifest["files"])))

        original = Path(result.paths["original"])
        sealed = not (original / "device_state" / "getprop.txt").stat().st_mode & 0o200
        checks.append(("original sealed read-only", sealed))

        # A second run with the same inputs must not be able to overwrite the first.
        clash = orch.run(AcquisitionRequest(
            case_id="CASE-2026-001", evidence_id="E01", examiner="A. Examiner",
            legal_authority="Warrant 2026/SW/4471", case_root=str(workspace),
            adapter_name="android_adb", device_id=devices[0].device_id,
            objective_methods=[CollectionMethod.FILE_SYSTEM],
        ))
        checks.append(("second run does not overwrite the first",
                       clash.run_name != result.run_name or not clash.ok))

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
