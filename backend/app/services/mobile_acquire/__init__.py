"""Live mobile acquisition — UFED 4PC reference architecture (v1.0, July 2026).

    from app.services.mobile_acquire import (
        CollectionOrchestrator, DeviceDetector, AcquisitionRequest, CollectionMethod,
    )

    detector = DeviceDetector()
    devices, warnings = detector.scan()
    preview = CollectionOrchestrator(detector).preview("android_adb", devices[0].device_id)
    result  = CollectionOrchestrator(detector).run(AcquisitionRequest(...))

Scope note: this package implements the documented, lawful device interfaces
(ADB, lockdownd/AFC, PC/SC, block-device imaging). Lock bypass, bootloader or
chipset exploitation and vendor advanced-access workflows are NOT implemented;
where they would be required the capability model reports a gap so the report
states a limitation rather than an empty result (§20).
"""

from app.services.mobile_acquire.audit import (
    AcquisitionRecord,
    AuditLog,
    custody_entry,
)
from app.services.mobile_acquire.case_layout import (
    CASE_SUBDIRS,
    EvidencePackage,
    RunPaths,
    build_run_name,
    ensure_case,
    new_run,
    seal_original,
)
from app.services.mobile_acquire.device_profile import (
    Capability,
    ConnectionMode,
    DeviceProfile,
    LockState,
    resolve_capability,
)
from app.services.mobile_acquire.integrity import (
    HashingWriter,
    IntegrityManifest,
    build_manifest,
    copy_verified,
    hash_file,
    verify_against_manifest,
)
from app.services.mobile_acquire.methods import (
    METHOD_PROFILES,
    CollectionMethod,
    MethodDecision,
    coverage_statement,
    select_method,
)
from app.services.mobile_acquire.entitlements import (
    OPEN_INTERFACE_ENTITLEMENTS,
    Entitlement,
    LicenceProfile,
    load_profile,
)
from app.services.mobile_acquire.validation import (
    ACCEPTANCE_AREAS,
    CRITICAL_DEVICE_FAMILIES,
    AcceptanceHarness,
    CorpusDevice,
    ToolVersionLedger,
    ValidationRun,
    device_family_for,
    preflight_validation_gate,
)
from app.services.mobile_acquire.run_registry import (
    TERMINAL_STATES,
    AcquisitionRegistry,
    AcquisitionRun,
    ProgressSnapshot,
    get_registry,
)
from app.services.mobile_acquire.orchestrator import (
    AcquisitionRequest,
    AcquisitionResult,
    CollectionOrchestrator,
    DetectedDevice,
    DeviceDetector,
)

__all__ = [
    "ACCEPTANCE_AREAS", "CRITICAL_DEVICE_FAMILIES", "OPEN_INTERFACE_ENTITLEMENTS",
    "AcceptanceHarness", "CorpusDevice", "Entitlement", "LicenceProfile",
    "ToolVersionLedger", "ValidationRun", "device_family_for", "load_profile",
    "preflight_validation_gate",
    "AcquisitionRegistry", "AcquisitionRun", "ProgressSnapshot", "TERMINAL_STATES",
    "get_registry",
    "AcquisitionRecord", "AcquisitionRequest", "AcquisitionResult", "AuditLog",
    "CASE_SUBDIRS", "Capability", "CollectionMethod", "CollectionOrchestrator",
    "ConnectionMode", "DetectedDevice", "DeviceDetector", "DeviceProfile",
    "EvidencePackage", "HashingWriter", "IntegrityManifest", "LockState",
    "METHOD_PROFILES", "MethodDecision", "RunPaths", "build_manifest",
    "build_run_name", "copy_verified", "coverage_statement", "custody_entry",
    "ensure_case", "hash_file", "new_run", "resolve_capability", "seal_original",
    "select_method", "verify_against_manifest",
]
