"""Validation, acceptance testing and version control — Architecture §15 and §22.

Two obligations that are easy to skip and expensive to have skipped:

  §22  Acceptance testing. Before production use the platform must demonstrate,
       against a KNOWN-DEVICE CORPUS, that it detects devices, collects what it
       claims to collect, verifies integrity, retains an audit trail and
       reproduces findings under peer review.

  §15  Update and validation architecture. "Record the UFED version used for
       every acquisition" and "revalidate critical device families after major
       updates". A tool version is part of the evidence: an examiner asked in
       two years which build produced an extraction must be able to answer.

The design point worth stating: a validation record is scoped to a
(tool version, device family) pair. Validating an iPhone 15 does not validate a
Pixel, and validating build 1.0 does not validate build 1.1. `requires_revalidation`
enforces both axes, so version drift surfaces as a blocking condition rather
than as a quiet assumption that last quarter's testing still applies.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from app.services.mobile_acquire.methods import CollectionMethod

# §22 acceptance test areas, with the acceptance evidence each must produce.
ACCEPTANCE_AREAS: dict[str, str] = {
    "installation": "Application starts, licence validates, required tooling present.",
    "device_detection": "Known supported test devices are detected correctly.",
    "logical_collection": "Expected contacts, calls, messages and media collected.",
    "filesystem_collection": "Expected application databases and metadata present.",
    "integrity": "Hashes verify after copy and archive.",
    "audit_trail": "Case metadata, timestamps, logs and examiner actions retained.",
    "analysis_import": "Extraction loads successfully into the authorised analysis tool.",
    "report_generation": "Bookmarks and reports reproduce expected findings.",
    "network_controls": "Only approved destinations reachable from the examiner zone.",
    "recovery": "Backup restore and case recovery tested.",
    "peer_review": "A second examiner reproduces key findings from retained evidence.",
}

# Device families whose validation must not be allowed to go stale. A regression
# in any of these silently breaks the majority of casework.
CRITICAL_DEVICE_FAMILIES: tuple[str, ...] = (
    "android_modern",       # Android 12+, FBE, scoped storage
    "android_legacy",       # Android 8-11
    "ios_modern",           # iOS 16+
    "ios_legacy",           # iOS 12-15
    "sim",
    "removable_media",
)

DEFAULT_VALIDITY_DAYS = 180


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Acceptance testing (§22)
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    area: str
    passed: bool
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    skipped: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "area": self.area,
            "acceptance_evidence_required": ACCEPTANCE_AREAS.get(self.area, ""),
            "passed": self.passed,
            "skipped": self.skipped,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class CorpusDevice:
    """One known device in the validation corpus, with its expected outcome."""

    device_family: str
    label: str
    adapter: str
    device_id: str
    expected_methods: list[CollectionMethod] = field(default_factory=list)
    expected_artifacts: list[str] = field(default_factory=list)
    min_expected_files: int = 1
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_family": self.device_family,
            "label": self.label,
            "adapter": self.adapter,
            "device_id": self.device_id,
            "expected_methods": [m.value for m in self.expected_methods],
            "expected_artifacts": self.expected_artifacts,
            "min_expected_files": self.min_expected_files,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "CorpusDevice":
        return CorpusDevice(
            device_family=data["device_family"],
            label=data.get("label", data["device_family"]),
            adapter=data["adapter"],
            device_id=data["device_id"],
            expected_methods=[CollectionMethod(m) for m in data.get("expected_methods", [])],
            expected_artifacts=list(data.get("expected_artifacts", [])),
            min_expected_files=int(data.get("min_expected_files", 1)),
            notes=data.get("notes", ""),
        )


@dataclass
class ValidationRun:
    tool_version: str
    device_family: str
    device_label: str
    examiner: str
    started_utc: str
    ended_utc: str | None = None
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks if not c.skipped) and bool(self.checks)

    @property
    def skipped_areas(self) -> list[str]:
        return [c.area for c in self.checks if c.skipped]

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "device_family": self.device_family,
            "device_label": self.device_label,
            "examiner": self.examiner,
            "started_utc": self.started_utc,
            "ended_utc": self.ended_utc,
            "passed": self.passed,
            "checks": [c.as_dict() for c in self.checks],
            "areas_tested": [c.area for c in self.checks if not c.skipped],
            "areas_skipped": self.skipped_areas,
            "coverage": (
                f"{len([c for c in self.checks if not c.skipped])}/{len(ACCEPTANCE_AREAS)}"
            ),
        }


class AcceptanceHarness:
    """Runs the §22 acceptance areas against a corpus device.

    Areas that cannot be evaluated automatically (peer review, network controls)
    are recorded as SKIPPED with the evidence still required, rather than being
    silently omitted or — worse — marked as passed.
    """

    def __init__(self, tool_version: str, examiner: str = "validation") -> None:
        self.tool_version = tool_version
        self.examiner = examiner

    def run(
        self,
        device: CorpusDevice,
        *,
        detector,
        orchestrator_factory: Callable[[], Any],
        case_root: str,
        legal_authority: str = "VALIDATION — no live evidence",
    ) -> ValidationRun:
        from app.services.mobile_acquire.orchestrator import AcquisitionRequest

        run = ValidationRun(
            tool_version=self.tool_version,
            device_family=device.device_family,
            device_label=device.label,
            examiner=self.examiner,
            started_utc=_now().isoformat(),
        )

        # --- installation ---------------------------------------------------
        adapter = detector.adapter_by_name(device.adapter)
        if adapter is None:
            run.checks.append(CheckResult(
                "installation", False,
                f"Adapter '{device.adapter}' is not registered on this workstation."))
            run.ended_utc = _now().isoformat()
            return run
        available = adapter.tool_available()
        run.checks.append(CheckResult(
            "installation", available,
            "Adapter tooling present." if available else
            "Adapter tooling is missing; install it before production use.",
            {"adapter": device.adapter}))

        # --- device detection -----------------------------------------------
        detected, warnings = detector.scan()
        seen = any(d.device_id == device.device_id for d in detected)
        run.checks.append(CheckResult(
            "device_detection", seen,
            "Corpus device detected." if seen else
            f"Corpus device '{device.device_id}' was NOT detected.",
            {"detected": [d.as_dict() for d in detected], "warnings": warnings}))
        if not seen:
            run.ended_utc = _now().isoformat()
            return run

        # --- collection: every method the corpus device claims to support ----
        # Each method gets its own acceptance area. The shared areas (integrity,
        # audit trail, recovery) are evaluated once, against the DEEPEST method
        # that ran — that is the extraction the lab will actually rely on, and
        # verifying only the shallowest would understate what is being certified.
        deepest: Any = None
        for method, area in (
            (CollectionMethod.LOGICAL, "logical_collection"),
            (CollectionMethod.FILE_SYSTEM, "filesystem_collection"),
            (CollectionMethod.PHYSICAL, "filesystem_collection"),  # §22 FS area covers physical image presence
        ):
            if method not in device.expected_methods:
                # Skip duplicate filesystem_collection skip when physical absent
                if method == CollectionMethod.PHYSICAL:
                    continue
                run.checks.append(CheckResult(
                    area, True, f"{method.value} not expected for this device family.",
                    skipped=True))
                continue

            # Avoid double-running filesystem_collection when both FS and PHYSICAL expected —
            # prefer the deepest method for the shared acceptance area.
            if method == CollectionMethod.FILE_SYSTEM and CollectionMethod.PHYSICAL in device.expected_methods:
                run.checks.append(CheckResult(
                    area, True,
                    "filesystem_collection evaluated via physical run (deeper method).",
                    skipped=True))
                continue
            if method == CollectionMethod.PHYSICAL:
                # Use a dedicated check area label in detail; acceptance area key stays filesystem_collection
                # only if we haven't already recorded one — write as filesystem_collection with method=physical.
                pass

            orchestrator = orchestrator_factory()
            result = orchestrator.run(AcquisitionRequest(
                case_id=f"VALIDATION-{self.tool_version}",
                evidence_id=f"{device.device_family}-{method.value}",
                examiner=self.examiner,
                legal_authority=legal_authority,
                case_root=case_root,
                adapter_name=device.adapter,
                device_id=device.device_id,
                examiner_method_override=method,
                network_isolated=True,
            ))

            collected = (result.package or {}).get("extraction_data") or []
            enough = len(collected) >= device.min_expected_files
            missing = [
                pattern for pattern in device.expected_artifacts
                if not any(pattern.lower() in p.lower() for p in collected)
            ]
            passed = result.ok and enough and not missing
            detail_area = area
            run.checks.append(CheckResult(
                detail_area, passed,
                f"{method.value}: {len(collected)} files collected; expected artifacts present."
                if passed else
                f"{method.value}: collected {len(collected)} files (expected at least "
                f"{device.min_expected_files}); missing expected artifacts: "
                f"{', '.join(missing) or 'none'}.",
                {"run_name": result.run_name, "method": method.value,
                 "file_count": len(collected), "missing_artifacts": missing,
                 "errors": result.errors}))
            if result.ok:
                deepest = result

        if deepest is None:
            for area in ("integrity", "audit_trail", "recovery"):
                run.checks.append(CheckResult(
                    area, False,
                    "No collection succeeded, so this area could not be evaluated."))
        else:
            # --- integrity ---------------------------------------------------
            verification = deepest.verification or {}
            run.checks.append(CheckResult(
                "integrity", bool(verification.get("ok")),
                f"Working copy hash-verified ({verification.get('verified', 0)} files)."
                if verification.get("ok") else
                "Working copy did not hash-match the original extraction.",
                verification))

            # --- audit trail -------------------------------------------------
            audit = deepest.audit or {}
            record = deepest.acquisition_record or {}
            audit_ok = bool(audit.get("event_count")) and bool(deepest.custody)
            run.checks.append(CheckResult(
                "audit_trail", audit_ok,
                "Audit events and chain of custody retained." if audit_ok else
                "Audit trail or chain of custody is incomplete.",
                {"audit_events": audit.get("event_count"),
                 "custody_links": len(deepest.custody),
                 "record_complete": record.get("record_complete"),
                 "record_missing_fields": record.get("missing_fields")}))

            # --- recovery ----------------------------------------------------
            manifest = (deepest.package or {}).get("hash_manifest")
            original = (deepest.paths or {}).get("original")
            recovered = False
            if manifest and original and Path(manifest).is_file():
                from app.services.mobile_acquire.integrity import verify_against_manifest
                recheck = verify_against_manifest(
                    original, json.loads(Path(manifest).read_text()))
                recovered = recheck.ok
            run.checks.append(CheckResult(
                "recovery", recovered,
                "Sealed original re-verifies against its manifest." if recovered else
                "Sealed original could not be re-verified.",
                {"manifest": manifest}))

        # --- areas requiring a human or external system ---------------------
        for area, note in (
            ("analysis_import",
             "Load the extraction into the authorised analysis tool and confirm it parses."),
            ("report_generation",
             "Generate a report from the validation extraction and confirm expected findings."),
            ("network_controls",
             "Confirm from the examiner zone that only approved destinations are reachable."),
            ("peer_review",
             "A second examiner must independently reproduce the key findings."),
        ):
            if not any(c.area == area for c in run.checks):
                run.checks.append(CheckResult(area, True, note, skipped=True))

        run.ended_utc = _now().isoformat()
        return run


# ---------------------------------------------------------------------------
# Version ledger (§15)
# ---------------------------------------------------------------------------

@dataclass
class ValidationRecord:
    tool_version: str
    device_family: str
    validated_utc: str
    examiner: str
    passed: bool
    approver: str = ""
    notes: str = ""
    areas_tested: list[str] = field(default_factory=list)
    areas_skipped: list[str] = field(default_factory=list)

    def age_days(self) -> float:
        try:
            when = datetime.fromisoformat(self.validated_utc)
        except ValueError:
            return float("inf")
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (_now() - when).total_seconds() / 86400

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "age_days": round(self.age_days(), 1)}


class ToolVersionLedger:
    """Records which tool version was validated against which device family.

    Backed by a JSON file so the record survives restarts and can be placed
    under change control alongside the installer it describes.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        validity_days: int = DEFAULT_VALIDITY_DAYS,
    ) -> None:
        self.path = Path(path)
        self.validity_days = validity_days
        self._records: list[ValidationRecord] = []
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text())
        except Exception:
            return
        for entry in data.get("records", []):
            try:
                self._records.append(ValidationRecord(
                    tool_version=entry["tool_version"],
                    device_family=entry["device_family"],
                    validated_utc=entry["validated_utc"],
                    examiner=entry.get("examiner", ""),
                    passed=bool(entry.get("passed")),
                    approver=entry.get("approver", ""),
                    notes=entry.get("notes", ""),
                    areas_tested=list(entry.get("areas_tested", [])),
                    areas_skipped=list(entry.get("areas_skipped", [])),
                ))
            except KeyError:
                continue

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "validity_days": self.validity_days,
            "updated_utc": _now().isoformat(),
            "records": [asdict(r) for r in self._records],
        }, indent=2), encoding="utf-8")

    # ---------- recording ----------

    def record(self, run: ValidationRun, *, approver: str = "", notes: str = "") -> ValidationRecord:
        entry = ValidationRecord(
            tool_version=run.tool_version,
            device_family=run.device_family,
            validated_utc=run.ended_utc or _now().isoformat(),
            examiner=run.examiner,
            passed=run.passed,
            approver=approver,
            notes=notes,
            areas_tested=[c.area for c in run.checks if not c.skipped],
            areas_skipped=run.skipped_areas,
        )
        self._records.append(entry)
        self._save()
        return entry

    def record_manual(
        self,
        *,
        tool_version: str,
        device_family: str,
        examiner: str,
        passed: bool,
        approver: str = "",
        notes: str = "",
    ) -> ValidationRecord:
        """Record an area validated outside the harness (peer review, network controls)."""
        entry = ValidationRecord(
            tool_version=tool_version,
            device_family=device_family,
            validated_utc=_now().isoformat(),
            examiner=examiner,
            passed=passed,
            approver=approver,
            notes=notes,
        )
        self._records.append(entry)
        self._save()
        return entry

    # ---------- queries ----------

    def latest(self, tool_version: str, device_family: str) -> ValidationRecord | None:
        candidates = [r for r in self._records
                      if r.tool_version == tool_version and r.device_family == device_family]
        return max(candidates, key=lambda r: r.validated_utc) if candidates else None

    def requires_revalidation(self, tool_version: str, device_family: str) -> tuple[bool, str]:
        """Is this (version, family) pair cleared for production use?

        Returns (blocked, reason). Both axes matter: a new build invalidates
        every family, and an old build goes stale over time.
        """
        record = self.latest(tool_version, device_family)
        if record is None:
            prior = [r for r in self._records if r.device_family == device_family]
            if prior:
                newest = max(prior, key=lambda r: r.validated_utc)
                return True, (
                    f"Tool version {tool_version} has never been validated against "
                    f"'{device_family}'. The most recent validation was against version "
                    f"{newest.tool_version}. Run known-device regression tests before "
                    "production deployment (section 15)."
                )
            return True, (
                f"No validation record exists for '{device_family}'. Complete acceptance "
                "testing before using this platform on casework (section 22)."
            )
        if not record.passed:
            return True, (
                f"The most recent validation of '{device_family}' on version {tool_version} "
                f"FAILED ({record.validated_utc}). Do not use for casework until resolved."
            )
        age = record.age_days()
        if age > self.validity_days:
            return True, (
                f"Validation of '{device_family}' on version {tool_version} is "
                f"{age:.0f} days old, exceeding the {self.validity_days}-day validity "
                "period. Revalidate."
            )
        return False, (
            f"Validated {age:.0f} days ago by {record.examiner or 'unknown'}"
            + (f", approved by {record.approver}" if record.approver else "")
            + "."
        )

    def status(self, tool_version: str) -> dict[str, Any]:
        """Production-readiness across every critical device family."""
        families = []
        blocked_any = False
        for family in CRITICAL_DEVICE_FAMILIES:
            blocked, reason = self.requires_revalidation(tool_version, family)
            blocked_any = blocked_any or blocked
            record = self.latest(tool_version, family)
            families.append({
                "device_family": family,
                "critical": True,
                "blocked": blocked,
                "reason": reason,
                "last_validation": record.as_dict() if record else None,
            })
        return {
            "tool_version": tool_version,
            "ledger": str(self.path),
            "validity_days": self.validity_days,
            "production_ready": not blocked_any,
            "families": families,
            "record_count": len(self._records),
        }

    def versions_seen(self) -> list[str]:
        return sorted({r.tool_version for r in self._records})

    def drift_from(self, tool_version: str) -> list[str]:
        """Families validated on an OTHER version but not on this one."""
        validated_here = {r.device_family for r in self._records
                          if r.tool_version == tool_version and r.passed}
        validated_anywhere = {r.device_family for r in self._records if r.passed}
        return sorted(validated_anywhere - validated_here)


# ---------------------------------------------------------------------------
# Pre-acquisition gate
# ---------------------------------------------------------------------------

def device_family_for(os_family: str, os_version: str) -> str:
    """Map an observed device to a validation corpus family."""
    fam = (os_family or "").strip().lower()
    major = 0
    try:
        major = int(str(os_version).split(".")[0])
    except (ValueError, IndexError):
        pass
    if fam == "android":
        return "android_modern" if major >= 12 else "android_legacy"
    if fam == "ios":
        return "ios_modern" if major >= 16 else "ios_legacy"
    if fam in ("sim", "removable"):
        return "sim" if fam == "sim" else "removable_media"
    return fam or "unknown"


def preflight_validation_gate(
    ledger: ToolVersionLedger | None,
    *,
    tool_version: str,
    os_family: str,
    os_version: str,
) -> dict[str, Any]:
    """Check validation status before a collection begins.

    Deliberately advisory, not blocking. An unvalidated tool on an urgent seizure
    is a decision for the examiner and the case owner, not for the software — but
    it must be a RECORDED decision, so the warning goes into the audit trail and
    the report regardless of what is chosen.
    """
    family = device_family_for(os_family, os_version)
    if ledger is None:
        return {
            "device_family": family,
            "validated": False,
            "blocking": False,
            "warning": (
                "No validation ledger is configured. The tool version used for this "
                "acquisition cannot be shown to have passed known-device regression "
                "testing (section 15)."
            ),
        }
    blocked, reason = ledger.requires_revalidation(tool_version, family)
    return {
        "device_family": family,
        "validated": not blocked,
        "blocking": False,
        "warning": reason if blocked else "",
        "detail": reason,
    }
