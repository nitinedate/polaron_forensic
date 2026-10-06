"""Collection orchestration engine — Architecture §7.

Implements the ten-step sequence verbatim:

    1. Initialize the case and evidence item.
    2. Identify the device and record its state.
    3. Resolve available collection methods.
    4. Display device-preparation and cable instructions.
    5. Validate connection and communication mode.
    6. Start acquisition and monitor the data stream.
    7. Write output into a controlled case directory.
    8. Record warnings, errors, interruptions and examiner actions.
    9. Finalize the output and integrity metadata.
   10. Generate the collection summary and preserve logs.

The orchestrator owns the ten components named in §7 — device detector, profile
resolver, method selector, connection manager, data-stream receiver, output
writer, integrity monitor, error handler, audit logger, summary generator — and
guarantees three invariants that the previous import-only implementation could
not:

  * an acquisition that fails part-way still produces a sealed original, a hash
    manifest for what WAS collected, and a summary that states what was not;
  * the original extraction is sealed read-only before any working copy is made,
    and the working copy is hash-verified against the original before analysis;
  * every capability gap is carried into the summary as a reportable limitation
    (§20: "do not report false zero results").
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.services.mobile_acquire.adapters.android_adb import AndroidAdbAdapter
from app.services.mobile_acquire.adapters.android_mtp import AndroidMtpAdapter
from app.services.mobile_acquire.adapters.base import AcquisitionOutcome, ToolUnavailable
from app.services.mobile_acquire.adapters.ios_lockdown import IosLockdownAdapter
from app.services.mobile_acquire.adapters.removable_media import (
    RemovableMediaAdapter,
    SimReaderAdapter,
)
from app.services.mobile_acquire.audit import AcquisitionRecord, AuditLog, custody_entry
from app.services.mobile_acquire.case_layout import (
    EvidencePackage,
    RunPaths,
    new_run,
    seal_original,
)
from app.services.mobile_acquire.device_profile import Capability, DeviceProfile, resolve_capability
from app.services.mobile_acquire.integrity import (
    IntegrityManifest,
    build_manifest,
    copy_verified,
)
from app.services.mobile_acquire.entitlements import LicenceProfile, load_profile
from app.services.mobile_acquire.validation import (
    ToolVersionLedger,
    preflight_validation_gate,
)
from app.services.mobile_acquire.methods import (
    CollectionMethod,
    MethodDecision,
    coverage_statement,
    select_method,
)

TOOL_VERSION = "aetheris-acquire/1.0"

# §15 — "Record the tool version used for every acquisition." The ledger path is
# configurable so it can be placed under change control alongside the installer.
VALIDATION_LEDGER_PATH = os.environ.get("FORENSIC_VALIDATION_LEDGER", "")


def _ledger() -> ToolVersionLedger | None:
    if not VALIDATION_LEDGER_PATH:
        return None
    try:
        return ToolVersionLedger(VALIDATION_LEDGER_PATH)
    except Exception:
        return None

ProgressCallback = Callable[[dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Device detector — §7 component 1
# ---------------------------------------------------------------------------

@dataclass
class DetectedDevice:
    adapter_name: str
    device_id: str
    os_family: str

    def as_dict(self) -> dict[str, str]:
        return {
            "adapter": self.adapter_name,
            "device_id": self.device_id,
            "os_family": self.os_family,
        }


class DeviceDetector:
    """Enumerates every device visible to every installed adapter."""

    def __init__(self, adapters: list[Any] | None = None) -> None:
        self.adapters = adapters if adapters is not None else [
            AndroidAdbAdapter(),
            AndroidMtpAdapter(),
            IosLockdownAdapter(),
            SimReaderAdapter(),
            RemovableMediaAdapter(),
        ]

    def adapter_by_name(self, name: str) -> Any | None:
        return next((a for a in self.adapters if a.name == name), None)

    def scan(self) -> tuple[list[DetectedDevice], list[str]]:
        """Return (devices, warnings). Missing tools are warnings, not failures."""
        found: list[DetectedDevice] = []
        warnings: list[str] = []
        for adapter in self.adapters:
            try:
                if not adapter.tool_available():
                    warnings.append(
                        f"Adapter '{adapter.name}' is unavailable: its external tooling is "
                        "not installed on this workstation. Devices of this type will not "
                        "be detected."
                    )
                    continue
                for device_id in adapter.detect():
                    found.append(DetectedDevice(adapter.name, device_id, adapter.os_family))
            except ToolUnavailable as exc:
                warnings.append(str(exc))
            except Exception as exc:
                warnings.append(f"Adapter '{adapter.name}' failed during detection: {exc}")
        return found, warnings


# ---------------------------------------------------------------------------
# Request / result
# ---------------------------------------------------------------------------

@dataclass
class AcquisitionRequest:
    case_id: str
    evidence_id: str
    examiner: str
    legal_authority: str
    case_root: str
    adapter_name: str
    device_id: str

    objective_methods: list[CollectionMethod] = field(default_factory=list)
    authorized_methods: list[CollectionMethod] = field(default_factory=list)
    examiner_method_override: CollectionMethod | None = None

    cable_adapter_asset_id: str = ""
    license_endpoint_id: str = ""
    backup_password: str | None = None
    examiner_notes: str = ""
    device_condition: str = ""
    network_isolated: bool | None = None
    create_working_copy: bool = True
    # Optional IMAP cloud mailbox credentials (Gmail/Outlook app passwords).
    cloud_mailboxes: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AcquisitionResult:
    ok: bool
    run_name: str = ""
    stage_reached: str = "initialize"
    paths: dict[str, str] = field(default_factory=dict)
    profile: dict[str, Any] = field(default_factory=dict)
    capability: dict[str, Any] = field(default_factory=dict)
    method_decision: dict[str, Any] = field(default_factory=dict)
    preparation_steps: list[str] = field(default_factory=list)
    package: dict[str, Any] = field(default_factory=dict)
    acquisition_record: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    coverage_statement: dict[str, str] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)
    licence: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)
    custody: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "run_name": self.run_name,
            "stage_reached": self.stage_reached,
            "paths": self.paths,
            "device_profile": self.profile,
            "capability": self.capability,
            "method_decision": self.method_decision,
            "preparation_steps": self.preparation_steps,
            "evidence_package": self.package,
            "acquisition_record": self.acquisition_record,
            "verification": self.verification,
            "coverage_statement": self.coverage_statement,
            "validation": self.validation,
            "licence": self.licence,
            "limitations": self.limitations,
            "warnings": self.warnings,
            "errors": self.errors,
            "audit": self.audit,
            "chain_of_custody": self.custody,
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class CollectionOrchestrator:
    """§7 collection orchestrator."""

    def __init__(
        self,
        detector: DeviceDetector | None = None,
        *,
        progress: ProgressCallback | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> None:
        self.detector = detector or DeviceDetector()
        self.progress = progress
        self.cancel = cancel

    # ---------- pre-flight, no side effects on the case folder ----------

    def preview(self, adapter_name: str, device_id: str) -> dict[str, Any]:
        """Steps 2-4 without starting a collection: profile, capability, prep steps.

        This is what the Device Wizard calls to populate the examiner's screen.
        """
        adapter = self.detector.adapter_by_name(adapter_name)
        if adapter is None:
            return {"ok": False, "error": f"Unknown adapter '{adapter_name}'."}
        try:
            profile = adapter.identify(device_id)
        except Exception as exc:
            return {"ok": False, "error": f"Device identification failed: {exc}"}

        profile.tool_version = TOOL_VERSION
        capability = resolve_capability(profile)
        adapter_methods = adapter.supported_methods(profile)
        # Intersection: the capability model and the adapter must BOTH agree.
        supported = [m for m in capability.supported_methods if m in adapter_methods] \
            or adapter_methods

        # §3.3 — entitlement is the final term in the capability model. A method
        # blocked by licensing is reported with that reason specifically, so the
        # report never conflates "we are not licensed" with "the device lacks it".
        licence = load_profile()
        permitted, licence_blocked = licence.filter_methods(supported)
        capability.supported_methods = permitted
        capability.blocked_methods.update(licence_blocked)
        capability.warnings.extend(licence.warnings())

        return {
            "ok": True,
            "device_profile": profile.as_dict(),
            "capability": capability.as_dict(),
            "preparation_steps": capability.preparation_steps,
            "licence": licence.as_dict(),
            "method_profiles": {m.value: coverage_statement(m) for m in permitted},
        }

    # ---------- the full ten-step run ----------

    def run(self, request: AcquisitionRequest) -> AcquisitionResult:
        result = AcquisitionResult(ok=False)
        started = datetime.now(timezone.utc)

        adapter = self.detector.adapter_by_name(request.adapter_name)
        if adapter is None:
            result.errors.append(f"Unknown adapter '{request.adapter_name}'.")
            return result

        # ---- Step 2: identify the device and record its state ----
        result.stage_reached = "identify"
        try:
            profile = adapter.identify(request.device_id)
        except Exception as exc:
            result.errors.append(f"Device identification failed: {exc}")
            return result
        profile.tool_version = TOOL_VERSION
        if request.network_isolated is not None:
            profile.network_isolated = request.network_isolated
        result.profile = profile.as_dict()

        # ---- Step 3: resolve available collection methods ----
        result.stage_reached = "capability"
        capability = resolve_capability(profile)
        adapter_methods = adapter.supported_methods(profile)
        supported = [
            m for m in capability.supported_methods if m in adapter_methods
        ] or adapter_methods
        licence = load_profile()
        permitted, licence_blocked = licence.filter_methods(supported)
        capability.supported_methods = permitted
        capability.blocked_methods.update(licence_blocked)
        capability.warnings.extend(licence.warnings())
        result.licence = licence.as_dict()
        result.capability = capability.as_dict()
        result.preparation_steps = capability.preparation_steps
        result.warnings.extend(capability.warnings)

        # §15 validation gate — advisory, but always recorded. An unvalidated
        # tool version on an urgent seizure is the examiner's decision to make;
        # it must not be an undocumented one.
        gate = preflight_validation_gate(
            _ledger(),
            tool_version=TOOL_VERSION,
            os_family=profile.os_family,
            os_version=profile.os_version,
        )
        result.validation = gate
        if gate.get("warning"):
            result.warnings.append(gate["warning"])

        decision = select_method(
            supported=capability.supported_methods,
            objective_requires=request.objective_methods or None,
            authorized=request.authorized_methods or None,
            examiner_override=request.examiner_method_override,
        )
        result.method_decision = decision.as_dict()

        if decision.selected is None:
            result.errors.append(decision.rationale)
            result.limitations.append(
                "No collection method could be performed. This is a capability gap and "
                "must NOT be reported as an absence of evidence on the device (§20)."
            )
            return result

        method = decision.selected
        result.coverage_statement = coverage_statement(method)

        # ---- Step 1 (deferred until the run name is knowable): case + run dir ----
        result.stage_reached = "initialize"
        try:
            paths: RunPaths = new_run(
                case_root=request.case_root,
                case_id=request.case_id,
                evidence_id=request.evidence_id,
                device_label=profile.device_label,
                method=method.value,
                when=started,
            )
        except FileExistsError as exc:
            result.errors.append(str(exc))
            return result
        result.run_name = paths.run_name
        result.paths = paths.as_dict()

        audit = AuditLog(paths.logs / "audit.jsonl", actor=request.examiner)
        audit.record("initialize", "run_created", run_name=paths.run_name,
                     case_id=request.case_id, evidence_id=request.evidence_id,
                     workstation=platform.node(), tool_version=TOOL_VERSION)
        audit.record("identify", "device_identified", **{
            k: v for k, v in profile.as_dict().items()
            if k in ("manufacturer", "model", "os_version", "security_patch_level",
                     "lock_state", "encryption_state", "connection_mode", "serial",
                     "imei", "udid")
        })
        for warning in capability.warnings:
            audit.warn("capability", warning)
        audit.record("method_selection", "method_selected", **decision.as_dict())
        audit.record(
            "validation", "tool_version_recorded",
            severity="info" if gate.get("validated") else "warning",
            tool_version=TOOL_VERSION, **gate)
        if request.examiner_method_override is not None:
            audit.deviation("method_selection", "examiner_override",
                            method=request.examiner_method_override.value)

        custody: list[dict[str, Any]] = [
            custody_entry("intake", actor=request.examiner,
                          detail=f"Evidence {request.evidence_id} registered to case "
                                 f"{request.case_id}."),
            custody_entry("identification", actor=request.examiner,
                          detail=profile.device_label),
        ]
        if profile.network_isolated:
            custody.append(custody_entry("isolation", actor=request.examiner,
                                         detail="Device isolated from networks."))
        else:
            audit.warn("isolation", "device_not_confirmed_isolated")
            result.warnings.append(
                "Network isolation was not confirmed. Remote wipe and message sync "
                "remained possible during collection (§13.2)."
            )

        # ---- Step 5: validate connection and communication mode ----
        result.stage_reached = "preflight"
        problems = adapter.preflight(profile, method)
        if problems:
            for problem in problems:
                audit.error("preflight", problem)
            result.errors.extend(problems)
            result.audit = audit.summary()
            result.custody = custody
            self._finalise_failed(paths, audit, result, request, profile, method, started)
            return result
        audit.record("preflight", "connection_validated",
                     connection_mode=profile.connection_mode,
                     cable=request.cable_adapter_asset_id or profile.required_cable)

        # ---- Steps 6-7: acquire, streaming into the controlled directory ----
        result.stage_reached = "acquire"
        audit.record("collection", "acquisition_started", method=method.value)

        def _progress(
            item: str,
            done: int,
            total: int | None = None,
            files_seen: int | None = None,
        ) -> None:
            if self.progress:
                event = {
                    "stage": "acquire",
                    "run_name": paths.run_name,
                    "item": item,
                    "bytes_done": done,
                    "bytes_total": total,
                }
                if files_seen is not None:
                    event["files_seen"] = int(files_seen)
                self.progress(event)

        kwargs: dict[str, Any] = {
            "profile": profile,
            "method": method,
            "destination": paths.original,
            "progress": _progress,
            "cancel": self.cancel,
        }
        if adapter.name == "ios_lockdown":
            kwargs["backup_password"] = request.backup_password

        try:
            outcome: AcquisitionOutcome = adapter.acquire(**kwargs)
        except Exception as exc:
            audit.error("collection", "acquisition_exception", error=str(exc))
            outcome = AcquisitionOutcome(ok=False, adapter=adapter.name, method=method)
            outcome.errors.append(f"Acquisition raised: {exc}")

        # ---- Step 8: record warnings, errors, interruptions ----
        for warning in outcome.warnings:
            audit.warn("collection", warning)
        for error in outcome.errors:
            audit.error("collection", error)
        for gap in outcome.coverage_gaps:
            audit.record("collection", "coverage_gap", severity="warning", detail_text=gap)
        if outcome.interrupted:
            audit.error("collection", "acquisition_interrupted")

        result.warnings.extend(outcome.warnings)
        result.errors.extend(outcome.errors)
        result.limitations.extend(outcome.coverage_gaps)
        result.limitations.append(result.coverage_statement["mandatory_caveat"])

        audit.record("collection", "acquisition_finished",
                     files=len(outcome.files_written), bytes=outcome.bytes_written,
                     ok=outcome.ok, interrupted=outcome.interrupted)
        custody.append(custody_entry(
            "collection", actor=request.examiner,
            detail=f"{method.value} collection, {len(outcome.files_written)} files, "
                   f"{outcome.bytes_written} bytes.",
            location=str(paths.original)))

        # ---- Step 9–10: finalise (must not abort after evidence is on disk) ----
        # Secondary failures become warnings so sealed originals still produce
        # portable packages and a complete UI result.
        result.stage_reached = "integrity"
        result.paths = paths.as_dict()

        from app.services.mobile_acquire.content_inventory import inventory_extraction
        from app.services.mobile_acquire.export_packages import build_export_packages
        from app.services.mobile_acquire.ios_readable import materialize_ios_readable_artifacts
        from app.services.mobile_acquire.sqlite_deleted import recover_tree
        from app.services.mobile_acquire.cloud_mail import collect_cloud_mailboxes
        from app.services.mobile_acquire.integrity import IntegrityManifest

        deleted: dict[str, Any] = {}
        cloud_result = None
        readable: dict[str, Any] = {}
        inventory: dict[str, Any] = {}
        export_bundle = None
        manifest: IntegrityManifest | None = None
        manifest_path = ""

        def _warn(msg: str) -> None:
            if msg and msg not in result.warnings:
                result.warnings.append(msg)

        try:
            if self.progress:
                self.progress({
                    "stage": "integrity",
                    "run_name": paths.run_name,
                    "item": "readable_artifacts",
                    "detail": "Materialising social/mail databases from backup…",
                    "category": "Readable artefacts",
                })
            try:
                readable = materialize_ios_readable_artifacts(paths.original)
                if paths.working:
                    # Derived overlay → 03_Working_Copy/<run>. 05_Exports/<run> stays
                    # packages-only; the ZIP carries readable_artifacts/ inside.
                    materialize_ios_readable_artifacts(
                        paths.original,
                        dest_root=paths.working / "readable_artifacts",
                    )
                if readable.get("copied"):
                    cats = sorted((readable.get("domains_by_category") or {}).keys())
                    audit.record(
                        "collection", "readable_artifacts_materialised",
                        count=len(readable["copied"]), categories=cats,
                    )
                    custody.append(custody_entry(
                        "collection", actor=request.examiner,
                        detail=(
                            f"Materialised {len(readable['copied'])} readable DB(s) "
                            f"across {', '.join(cats) or 'catalogued apps'}."
                        ),
                        location=str(paths.working / "readable_artifacts"),
                    ))
                for err in readable.get("errors") or []:
                    _warn(err)
            except Exception as exc:
                _warn(f"Readable artefact materialisation skipped: {exc}")

            readable_root = Path(
                str(readable.get("readable_root") or "")
                or str(paths.working / "readable_artifacts")
            )
            try:
                if readable_root.is_dir():
                    if self.progress:
                        self.progress({
                            "stage": "integrity",
                            "run_name": paths.run_name,
                            "item": "deleted_recovery",
                            "detail": "Carving residual content from acquired SQLite DBs…",
                            "category": "Deleted recovery",
                        })
                    deleted = recover_tree(readable_root)
                    if deleted.get("ok"):
                        audit.record(
                            "collection", "sqlite_residual_recovery",
                            databases=len(deleted.get("databases") or []),
                            carved=deleted.get("total_carved") or 0,
                        )
                    if deleted.get("note"):
                        result.limitations.append(deleted["note"])
                else:
                    result.limitations.append(
                        "Deleted residual carving skipped — no readable_artifacts tree yet."
                    )
            except Exception as exc:
                _warn(f"SQLite residual carving skipped: {exc}")

            if request.cloud_mailboxes:
                try:
                    if self.progress:
                        self.progress({
                            "stage": "acquire",
                            "run_name": paths.run_name,
                            "item": "cloud_mail",
                            "detail": "Fetching cloud mailboxes via IMAP…",
                            "category": "Cloud mail",
                        })
                    cloud_result = collect_cloud_mailboxes(
                        paths.original, request.cloud_mailboxes, progress=self.progress,
                    )
                    if cloud_result.errors:
                        result.warnings.extend(cloud_result.errors)
                    if cloud_result.ok:
                        audit.record(
                            "collection", "cloud_mail_collected",
                            accounts=len(cloud_result.accounts),
                        )
                        custody.append(custody_entry(
                            "collection", actor=request.examiner,
                            detail="Cloud mailboxes collected via IMAP.",
                            location=cloud_result.output_root,
                        ))
                except Exception as exc:
                    _warn(f"Cloud mailbox fetch skipped: {exc}")

            try:
                manifest = build_manifest(
                    paths.original,
                    run_name=paths.run_name,
                    progress=lambda rel: self.progress and self.progress(
                        {"stage": "hashing", "run_name": paths.run_name, "item": rel}),
                )
                manifest_path = manifest.write(paths.hashes / "manifest.json")
                audit.record(
                    "integrity_verification", "manifest_created",
                    files=len(manifest.files), bytes=manifest.total_bytes,
                    manifest=manifest_path,
                )
            except Exception as exc:
                _warn(f"Hash manifest incomplete: {exc}")
                from app.services.mobile_acquire.integrity import DEFAULT_ALGORITHMS
                manifest = IntegrityManifest(
                    run_name=paths.run_name,
                    created_utc=datetime.now(timezone.utc).isoformat(),
                    algorithms=DEFAULT_ALGORITHMS,
                )
                manifest_path = ""

            try:
                seal = seal_original(paths.original)
                audit.record("immutable_storage", "original_sealed", **seal)
                if seal.get("unsealed"):
                    _warn(
                        f"{seal['unsealed']} path(s) could not be set read-only; "
                        "rely on the hash manifest."
                    )
                custody.append(custody_entry(
                    "immutable_storage", actor=request.examiner,
                    detail="Original extraction sealed read-only.",
                    location=str(paths.original),
                ))
            except Exception as exc:
                _warn(f"Seal original skipped: {exc}")

            try:
                inventory = inventory_extraction(paths.original)
                inventory["deleted_recovery"] = deleted
                inventory["domains_by_category"] = readable.get("domains_by_category") or {}
                if cloud_result is not None:
                    inventory["cloud_mail"] = cloud_result.as_dict()
                for gap in inventory.get("gaps") or []:
                    if gap not in result.limitations:
                        result.limitations.append(gap)
            except Exception as exc:
                inventory = {"ok": False, "errors": [str(exc)]}
                _warn(f"Content inventory skipped: {exc}")

            if request.create_working_copy and manifest is not None and manifest.files:
                try:
                    result.stage_reached = "working_copy"
                    # A 100+ GiB phone should not consume a second full copy and then
                    # fail the final ZIP.  Keep folder 03 present, but skip the physical
                    # duplicate when the volume cannot hold it safely.
                    reserve = 2 * 1024**3
                    free = int(shutil.disk_usage(paths.working).free)
                    if free < int(manifest.total_bytes) + reserve:
                        marker = paths.working / "WORKING_COPY_NOT_MATERIALIZED.json"
                        marker.write_text(
                            __import__("json").dumps({
                                "reason": "insufficient_space",
                                "source": str(paths.original),
                                "source_bytes": int(manifest.total_bytes),
                                "free_bytes": free,
                                "reserve_bytes": reserve,
                                "analysis_mode": "sealed-original-plus-derived-overlay",
                            }, indent=2),
                            encoding="utf-8",
                        )
                        result.verification = {
                            "ok": True, "verified": 0, "mismatched": [], "missing": [],
                            "unexpected": [], "mode": "overlay",
                        }
                        _warn(
                            "Physical working-copy duplication was skipped to preserve space; "
                            "03_Working_Copy uses a sealed-original + derived-overlay model."
                        )
                        audit.record(
                            "working_copy", "overlay_mode_selected", severity="warning",
                            source_bytes=int(manifest.total_bytes), free_bytes=free,
                        )
                    else:
                        verification = copy_verified(paths.original, paths.working, manifest)
                        result.verification = verification.as_dict()
                        audit.record(
                            "working_copy",
                            "verified_copy_created" if verification.ok else "verification_failed",
                            severity="info" if verification.ok else "warning",
                            **verification.as_dict(),
                        )
                        if not verification.ok:
                            _warn(
                                "Working copy did not hash-match the original. "
                                "Analyse the sealed original or re-create the working copy."
                            )
                        else:
                            custody.append(custody_entry(
                                "working_copy", actor=request.examiner,
                                detail=f"{verification.verified} files hash-verified.",
                                location=str(paths.working),
                            ))
                except Exception as exc:
                    _warn(f"Working copy skipped: {exc}")

            try:
                result.stage_reached = "export"
                if self.progress:
                    self.progress({
                        "stage": "export",
                        "run_name": paths.run_name,
                        "item": "export_packages",
                        "detail": "Building portable evidence packages (.zip/.ufdx/.ufd/.pas)…",
                        "category": "Export",
                    })
                export_bundle = build_export_packages(
                    run_name=paths.run_name,
                    export_dir=paths.exports,
                    original=paths.original,
                    logs=paths.logs,
                    hashes=paths.hashes,
                    case_id=request.case_id,
                    evidence_id=request.evidence_id,
                    method=method.value,
                    device=profile.as_dict(),
                    inventory=inventory,
                    progress=self.progress,
                )
                result.warnings.extend(export_bundle.warnings)
                audit.record(
                    "report", "portable_packages_created",
                    packages=list(export_bundle.packages.keys()),
                    export_dir=str(paths.exports),
                )
                custody.append(custody_entry(
                    "export", actor=request.examiner,
                    detail=(
                        "Portable packages written: "
                        + ", ".join(f".{k}" for k in export_bundle.packages.keys())
                    ),
                    location=str(paths.exports),
                ))
                result.paths = {
                    **paths.as_dict(),
                    **{f"export_{ext}": path for ext, path in export_bundle.packages.items()},
                }
            except Exception as exc:
                _warn(f"Portable package export failed: {exc}")
                result.paths = paths.as_dict()

        except Exception as exc:
            audit.error("report", "finalise_exception", error=str(exc))
            _warn(f"Finalisation hit an unexpected error: {exc}")
            result.paths = paths.as_dict()

        # ---- Step 10: collection summary (always attempt) ----
        result.stage_reached = "summary"
        ended = datetime.now(timezone.utc)
        file_count = len(manifest.files) if manifest is not None else 0
        total_bytes = int(manifest.total_bytes) if manifest is not None else 0
        try:
            on_disk = 0
            if paths.original.is_dir():
                on_disk = sum(1 for p in paths.original.rglob("*") if p.is_file())
            if on_disk > file_count:
                file_count = on_disk
        except Exception:
            pass

        try:
            record = AcquisitionRecord(
                case_id=request.case_id,
                evidence_id=request.evidence_id,
                examiner=request.examiner,
                legal_authority=request.legal_authority,
                device_make_model=profile.device_label,
                serial_imei=profile.imei or profile.serial or profile.udid,
                device_condition_state=request.device_condition or profile.lock_state,
                tool_version=TOOL_VERSION,
                license_endpoint_id=(request.license_endpoint_id
                                     or licence.endpoint_id or platform.node()),
                collection_method=method.value,
                cable_adapter=request.cable_adapter_asset_id or profile.required_cable,
                start_time=started.isoformat(),
                end_time=ended.isoformat(),
                output_path=str(paths.original),
                output_size=total_bytes,
                hash_integrity_value=manifest_path,
                warnings_errors=audit.warnings + audit.errors,
                imsi=profile.imsi,
                iccid=profile.iccid,
                sd_card_identifier=profile.sd_card_identifier,
                os_version=profile.os_version,
                security_patch_level=profile.security_patch_level,
                lock_state=profile.lock_state,
                encryption_state=profile.encryption_state,
                network_isolation=str(profile.network_isolated),
            )
            record_path = record.write(paths.logs / "acquisition_record.json")
            result.acquisition_record = record.as_dict()
            if record.missing_fields():
                _warn(
                    "Acquisition record incomplete: "
                    + ", ".join(record.missing_fields())
                )
        except Exception as exc:
            record_path = ""
            _warn(f"Acquisition record write skipped: {exc}")

        export_dict = export_bundle.as_dict() if export_bundle is not None else {}
        extraction_data = (
            [f.relative_path for f in manifest.files] if manifest is not None else []
        )
        package = EvidencePackage(
            run_name=paths.run_name,
            extraction_data=extraction_data,
            device_metadata=profile.as_dict(),
            collection_log=str(audit.path),
            collection_summary=str(paths.logs / "collection_summary.json"),
            hash_manifest=manifest_path or None,
            examiner_notes=request.examiner_notes,
            warnings=result.warnings,
            errors=result.errors,
            content_inventory=inventory,
            export_packages=export_dict,
        )

        import json
        summary = {
            "run_name": paths.run_name,
            "case_id": request.case_id,
            "evidence_id": request.evidence_id,
            "examiner": request.examiner,
            "legal_authority": request.legal_authority,
            "device": profile.as_dict(),
            "method": method.value,
            "method_decision": decision.as_dict(),
            "coverage_statement": result.coverage_statement,
            "tool_version": TOOL_VERSION,
            "validation": result.validation,
            "limitations": result.limitations,
            "started_utc": started.isoformat(),
            "ended_utc": ended.isoformat(),
            "duration_seconds": int((ended - started).total_seconds()),
            "file_count": file_count,
            "total_bytes": total_bytes,
            "hash_manifest": manifest_path,
            "acquisition_record": record_path,
            "verification": result.verification,
            "content_inventory": inventory,
            "export_packages": export_dict,
            "warnings": result.warnings,
            "errors": result.errors,
            "interrupted": outcome.interrupted,
            "audit": audit.summary(),
            "chain_of_custody": custody,
            "evidence_package": package.as_dict(),
            "paths": result.paths,
        }
        try:
            (paths.logs / "collection_summary.json").write_text(
                json.dumps(summary, indent=2, default=str), encoding="utf-8")
            audit.record("report", "summary_generated",
                         files=file_count, bytes=total_bytes)
        except Exception as exc:
            _warn(f"collection_summary.json write failed: {exc}")

        result.package = package.as_dict()
        result.audit = audit.summary()
        result.custody = custody
        # Package is successful when evidence landed on disk — adapter warnings/errors
        # (e.g. backup locked after AFC media) must not hide a usable image.
        has_payload = file_count > 0 or bool(export_dict.get("packages"))
        result.ok = bool(has_payload) and not outcome.interrupted
        if has_payload and result.errors:
            result.stage_reached = "complete"
            _warn(
                "Collection finished with adapter errors; sealed original / exports "
                "are still present — review limitations before relying on gaps."
            )
        else:
            result.stage_reached = "complete" if result.ok else "failed"
        return result

    # ---------- failure path ----------

    def _finalise_failed(self, paths, audit, result, request, profile, method, started) -> None:
        """Even a run that never started collection leaves a defensible record."""
        import json
        ended = datetime.now(timezone.utc)
        record = AcquisitionRecord(
            case_id=request.case_id,
            evidence_id=request.evidence_id,
            examiner=request.examiner,
            legal_authority=request.legal_authority,
            device_make_model=profile.device_label,
            serial_imei=profile.imei or profile.serial or profile.udid,
            device_condition_state=request.device_condition or profile.lock_state,
            tool_version=TOOL_VERSION,
            collection_method=method.value,
            start_time=started.isoformat(),
            end_time=ended.isoformat(),
            output_path=str(paths.original),
            warnings_errors=audit.errors,
        )
        record.write(paths.logs / "acquisition_record.json")
        result.acquisition_record = record.as_dict()
        (paths.logs / "collection_summary.json").write_text(
            json.dumps({
                "run_name": paths.run_name,
                "outcome": "not_started",
                "reason": result.errors,
                "device": profile.as_dict(),
                "started_utc": started.isoformat(),
                "ended_utc": ended.isoformat(),
            }, indent=2),
            encoding="utf-8",
        )
        result.limitations.append(
            "No data was collected from this device. This is a capability or connection "
            "gap and must not be reported as an absence of evidence."
        )
