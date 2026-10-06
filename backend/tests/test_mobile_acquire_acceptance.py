"""§22 acceptance tests — UFED 4PC architecture compliance (simulated corpus)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.services.mobile_acquire import (
    AcceptanceHarness,
    AcquisitionRequest,
    CollectionMethod,
    CollectionOrchestrator,
    CorpusDevice,
    DeviceDetector,
    DeviceProfile,
    OPEN_INTERFACE_ENTITLEMENTS,
    Entitlement,
    LicenceProfile,
    resolve_capability,
)
from app.services.mobile_acquire.adapters.base import AcquisitionOutcome
from app.services.mobile_acquire.device_profile import ConnectionMode, LockState
from app.services.mobile_acquire.entitlements import NOT_IMPLEMENTED_HERE
from app.services.mobile_acquire.orchestrator import TOOL_VERSION


class _SimAndroid:
    """Rooted Android stand-in for §22 harness (no USB hardware)."""

    name = "android_adb"
    os_family = "android"

    def __init__(self, *, rooted: bool = True) -> None:
        self._rooted = rooted

    def tool_available(self) -> bool:
        return True

    def detect(self) -> list[str]:
        return ["SIM-ACCEPT-001"]

    def identify(self, device_id: str) -> DeviceProfile:
        return DeviceProfile(
            os_family="android",
            manufacturer="Google",
            model="Pixel Validation",
            chipset="test",
            serial=device_id,
            imei="356938035643809",
            os_version="15",
            security_patch_level="2026-06-05",
            lock_state=LockState.LOCKED_AFU,
            encryption_state="fbe",
            connection_mode=ConnectionMode.ADB,
            usb_debugging_authorized=True,
            rooted_or_jailbroken=self._rooted,
            battery_percent=80,
            network_isolated=True,
            tool_version=TOOL_VERSION,
        )

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]:
        methods = [
            CollectionMethod.LOGICAL,
            CollectionMethod.BACKUP,
            CollectionMethod.ADVANCED_LOGICAL,
        ]
        if profile.rooted_or_jailbroken:
            methods += [
                CollectionMethod.FILE_SYSTEM,
                CollectionMethod.FULL_FILE_SYSTEM,
                CollectionMethod.PHYSICAL,
            ]
        return methods

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        return []

    def acquire(
        self,
        *,
        profile: DeviceProfile,
        method: CollectionMethod,
        destination: Path,
        progress=None,
        cancel=None,
    ) -> AcquisitionOutcome:
        outcome = AcquisitionOutcome(ok=True, adapter=self.name, method=method)
        destination.mkdir(parents=True, exist_ok=True)
        state = destination / "device_state"
        state.mkdir(parents=True, exist_ok=True)
        prop = state / "getprop.txt"
        prop.write_text("ro.build.version.release=15\n", encoding="utf-8")
        outcome.files_written.append(str(prop))
        outcome.bytes_written += prop.stat().st_size

        if method == CollectionMethod.LOGICAL:
            shared = destination / "shared_storage" / "DCIM"
            shared.mkdir(parents=True, exist_ok=True)
            img = shared / "IMG_0001.jpg"
            img.write_bytes(b"\xff\xd8\xff\xd9")
            outcome.files_written.append(str(img))
            outcome.bytes_written += img.stat().st_size
            outcome.coverage_gaps.append("Logical only — no /data/data.")
        elif method in (CollectionMethod.FILE_SYSTEM, CollectionMethod.FULL_FILE_SYSTEM):
            data = destination / "data" / "data" / "com.whatsapp" / "databases"
            data.mkdir(parents=True, exist_ok=True)
            db = data / "msgstore.db"
            db.write_bytes(b"SQLite format 3\x00")
            outcome.files_written.append(str(db))
            outcome.bytes_written += db.stat().st_size
        elif method == CollectionMethod.PHYSICAL:
            images = destination / "physical_images"
            images.mkdir(parents=True, exist_ok=True)
            raw = images / "userdata.raw"
            raw.write_bytes(b"RAWUSERDATA" + b"\x00" * 1024)
            outcome.files_written.append(str(raw))
            outcome.bytes_written += raw.stat().st_size
            outcome.coverage_gaps.append("Simulated userdata partition image only.")
        else:
            outcome.ok = False
            outcome.errors.append(f"unsupported {method}")
        outcome.device_metadata = profile.as_dict()
        return outcome


def test_physical_entitlement_is_implemented():
    assert Entitlement.PHYSICAL in OPEN_INTERFACE_ENTITLEMENTS
    assert Entitlement.PHYSICAL not in NOT_IMPLEMENTED_HERE
    assert Entitlement.ADVANCED_ACCESS in NOT_IMPLEMENTED_HERE
    licence = LicenceProfile()
    assert licence.implemented(CollectionMethod.PHYSICAL)
    assert licence.permits(CollectionMethod.PHYSICAL)


def test_capability_offers_physical_only_when_rooted():
    rooted = _SimAndroid(rooted=True).identify("SIM-ACCEPT-001")
    unrooted = _SimAndroid(rooted=False).identify("SIM-ACCEPT-001")
    rooted.rooted_or_jailbroken = True
    unrooted.rooted_or_jailbroken = False
    cap_r = resolve_capability(rooted)
    cap_u = resolve_capability(unrooted)
    assert CollectionMethod.PHYSICAL in cap_r.supported_methods
    assert CollectionMethod.PHYSICAL not in cap_u.supported_methods
    assert CollectionMethod.PHYSICAL.value in cap_u.blocked_methods


def test_acceptance_harness_logical_and_physical():
    workspace = Path(tempfile.mkdtemp(prefix="acq-accept-"))
    adapter = _SimAndroid(rooted=True)
    detector = DeviceDetector(adapters=[adapter])
    harness = AcceptanceHarness(tool_version=TOOL_VERSION, examiner="pytest")
    device = CorpusDevice(
        device_family="android_pixel_rooted",
        label="Simulated rooted Pixel",
        adapter="android_adb",
        device_id="SIM-ACCEPT-001",
        expected_methods=[CollectionMethod.LOGICAL, CollectionMethod.PHYSICAL],
        expected_artifacts=["getprop.txt"],
        min_expected_files=1,
    )
    run = harness.run(
        device,
        detector=detector,
        orchestrator_factory=lambda: CollectionOrchestrator(detector),
        case_root=str(workspace),
    )
    assert run.passed, [c.as_dict() for c in run.checks if not c.passed and not c.skipped]
    areas = {c.area for c in run.checks if not c.skipped}
    assert "logical_collection" in areas
    assert "integrity" in areas
    assert "audit_trail" in areas
    assert "peer_review" in {c.area for c in run.checks if c.skipped}


def test_physical_orchestrator_run_seals_package():
    workspace = Path(tempfile.mkdtemp(prefix="acq-phys-"))
    adapter = _SimAndroid(rooted=True)
    detector = DeviceDetector(adapters=[adapter])
    orch = CollectionOrchestrator(detector)
    result = orch.run(
        AcquisitionRequest(
            case_id="CASE-PHYS-001",
            evidence_id="E01",
            examiner="pytest",
            legal_authority="VALIDATION",
            case_root=str(workspace),
            adapter_name="android_adb",
            device_id="SIM-ACCEPT-001",
            examiner_method_override=CollectionMethod.PHYSICAL,
            network_isolated=True,
        )
    )
    assert result.ok
    assert result.method_decision["selected"] == "physical"
    assert result.verification.get("ok") is True
    files = result.package.get("extraction_data") or []
    assert any("userdata.raw" in p.replace("\\", "/") for p in files)
    assert any("does not establish" in lim or "partition" in lim.lower() for lim in result.limitations)


def test_cli_module_importable():
    from app.services.mobile_acquire import cli

    assert callable(cli.main)
    assert callable(cli.run_acquire)
