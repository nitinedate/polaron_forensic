"""Audit logger and chain of custody — Architecture §14 and Appendix C.

The audit log is append-only JSONL written next to the extraction. Two
properties matter for defensibility:

  * every entry is timestamped in UTC at the moment it is recorded, not when the
    run finishes, so the ordering survives a crash mid-acquisition;
  * warnings, errors, interruptions and examiner deviations are recorded with
    the same weight as successes — §20 requires that a capability gap be
    reported rather than presented as a zero result.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Appendix C — acquisition record fields. Kept as an explicit ordered tuple so
# a missing field is a reportable gap rather than an absent dict key.
ACQUISITION_RECORD_FIELDS: tuple[str, ...] = (
    "case_id", "evidence_id", "examiner", "legal_authority",
    "device_make_model", "serial_imei", "device_condition_state",
    "tool_version", "license_endpoint_id", "collection_method",
    "cable_adapter", "start_time", "end_time", "output_path", "output_size",
    "hash_integrity_value", "warnings_errors", "reviewer",
)

# §14 — chain-of-custody record groups.
CUSTODY_STAGES: tuple[str, ...] = (
    "seizure", "intake", "identification", "isolation", "collection",
    "integrity_verification", "immutable_storage", "working_copy",
    "export",  # portable .zip/.ufdx/.ufd/.pas packages under 05_Exports
    "analysis", "peer_review", "report", "archive",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEvent:
    timestamp_utc: str
    stage: str
    action: str
    severity: str = "info"          # info | warning | error | deviation
    detail: dict[str, Any] = field(default_factory=dict)
    actor: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLog:
    """Append-only JSONL audit trail for one acquisition run."""

    def __init__(self, path: str | os.PathLike[str], *, actor: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.actor = actor
        self.events: list[AuditEvent] = []

    def record(
        self,
        stage: str,
        action: str,
        *,
        severity: str = "info",
        **detail: Any,
    ) -> AuditEvent:
        event = AuditEvent(
            timestamp_utc=_now(),
            stage=stage,
            action=action,
            severity=severity,
            detail=detail,
            actor=self.actor,
        )
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event.as_dict()) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return event

    # Convenience wrappers so callers cannot accidentally downgrade a problem.
    def warn(self, stage: str, action: str, **detail: Any) -> AuditEvent:
        return self.record(stage, action, severity="warning", **detail)

    def error(self, stage: str, action: str, **detail: Any) -> AuditEvent:
        return self.record(stage, action, severity="error", **detail)

    def deviation(self, stage: str, action: str, **detail: Any) -> AuditEvent:
        """Examiner departed from the documented procedure — always reportable."""
        return self.record(stage, action, severity="deviation", **detail)

    @property
    def warnings(self) -> list[str]:
        return [f"{e.stage}: {e.action}" for e in self.events if e.severity == "warning"]

    @property
    def errors(self) -> list[str]:
        return [f"{e.stage}: {e.action}" for e in self.events
                if e.severity in ("error", "deviation")]

    def summary(self) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        for e in self.events:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        return {
            "path": str(self.path),
            "event_count": len(self.events),
            "by_severity": by_severity,
            "first_event_utc": self.events[0].timestamp_utc if self.events else None,
            "last_event_utc": self.events[-1].timestamp_utc if self.events else None,
        }


@dataclass
class AcquisitionRecord:
    """Appendix C acquisition record, plus the §14 evidence-identity fields."""

    case_id: str = ""
    evidence_id: str = ""
    examiner: str = ""
    legal_authority: str = ""
    device_make_model: str = ""
    serial_imei: str = ""
    device_condition_state: str = ""
    tool_version: str = ""
    license_endpoint_id: str = ""
    collection_method: str = ""
    cable_adapter: str = ""
    start_time: str = ""
    end_time: str = ""
    output_path: str = ""
    output_size: int = 0
    hash_integrity_value: str = ""
    warnings_errors: list[str] = field(default_factory=list)
    reviewer: str = ""

    # §14 evidence identity beyond the appendix minimum
    imsi: str = ""
    iccid: str = ""
    sd_card_identifier: str = ""
    os_version: str = ""
    security_patch_level: str = ""
    lock_state: str = ""
    encryption_state: str = ""
    network_isolation: str = ""

    def missing_fields(self) -> list[str]:
        """Which mandatory Appendix C fields are still blank."""
        return [f for f in ACQUISITION_RECORD_FIELDS
                if not getattr(self, f, None) and f not in ("warnings_errors", "reviewer")]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["missing_fields"] = self.missing_fields()
        data["record_complete"] = not data["missing_fields"]
        return data

    def write(self, path: str | os.PathLike[str]) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.as_dict(), indent=2), encoding="utf-8")
        return str(target)


def custody_entry(
    stage: str,
    *,
    actor: str,
    detail: str = "",
    location: str = "",
) -> dict[str, Any]:
    """One link in the §14 chain: seizure -> ... -> archive/disposition.

    Unknown stages are coerced to ``collection`` so a packaging/export typo can
    never abort a run after evidence has already been written to disk.
    """
    resolved = stage if stage in CUSTODY_STAGES else "collection"
    note = detail
    if resolved != stage:
        note = f"[stage:{stage}] {detail}".strip()
    return {
        "stage": resolved,
        "actor": actor,
        "detail": note,
        "location": location,
        "timestamp_utc": _now(),
    }
