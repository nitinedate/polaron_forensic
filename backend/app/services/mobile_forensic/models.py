"""Normalized mobile artifact envelope + evidence-state vocabulary.

The mobile pipeline is intentionally deterministic: rerunning analysis for the same
source row/file produces the same artifact_id, which makes processing resumable and
prevents duplicate artifacts after a worker restart.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

EvidenceState = Literal[
    "allocated",
    "historical",
    "database_deleted",
    "wal_recovered",
    "journal_recovered",
    "freelist_candidate",
    "backup_historical",
    "orphaned",
    "fragment",
    "filesystem_recovered",
    "cache_derived",
    "unverified",
    "unsupported",
    "error",
]

UI_STATE_LABELS: dict[str, str] = {
    "allocated": "CURRENT",
    "historical": "HISTORICAL",
    "database_deleted": "DELETED-SUPPORTED",
    "wal_recovered": "RECOVERED",
    "journal_recovered": "RECOVERED",
    "freelist_candidate": "UNVERIFIED",
    "backup_historical": "HISTORICAL",
    "orphaned": "ORPHANED",
    "fragment": "FRAGMENT",
    "filesystem_recovered": "RECOVERED",
    "cache_derived": "CACHE-DERIVED",
    "unverified": "UNVERIFIED",
    "unsupported": "UNSUPPORTED",
    "error": "ERROR",
}

SOURCE_DOMAINS = (
    "device_os",
    "accounts_contacts",
    "telephony",
    "sms_mms_rcs",
    "messaging_apps",
    "email",
    "media",
    "files",
    "browser",
    "location",
    "calendar_notes",
    "network",
    "system",
)


@dataclass
class Provenance:
    case_id: str | None = None
    source_id: str | None = None
    artifact_id: str = ""
    artifact_type: str = ""
    parser: str = ""
    parser_version: str = "1.0.0"
    recovery_status: str = "allocated"
    source_path: str = ""
    source_table: str | None = None
    source_row_id: str | None = None
    source_offset: int | None = None
    source_sha256: str | None = None
    parsed_at_utc: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Confidence:
    label: Literal["HIGH", "MEDIUM", "LOW", "UNVERIFIED"] = "UNVERIFIED"
    score: float = 0.0
    validation: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def attach_decryption_provenance(record, item):
    """Carry the original encrypted source through native file/content parsers."""
    meta = item.meta if isinstance(item.meta, dict) else {}
    for key in ("encrypted_source_path", "encrypted_source_sha256", "decrypted_payload_sha256", "decryption_integrity", "decryption_authenticated"):
        if key in meta:
            record.forensic[key] = meta[key]
    if meta.get("whatsapp_derivation") and record.forensic.get("state") in {"allocated", "historical"}:
        record.forensic.update(state="backup_historical", recovery_source="decrypted_backup",
                               ui_label=UI_STATE_LABELS["backup_historical"], examiner_status="pending_review")
    return record


@dataclass
class NormalizedArtifact:
    artifact_id: str
    artifact_type: str
    source_domain: str
    timestamp_utc: str | None
    data: dict[str, Any]
    forensic: dict[str, Any]
    job_id: str | None = None

    @staticmethod
    def make_id(prefix: str = "ART") -> str:
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def make_stable_id(
        *,
        job_id: str | None,
        artifact_type: str,
        source_path: str,
        source_table: str | None = None,
        source_row_id: str | None = None,
        source_offset: int | None = None,
        state: str = "allocated",
        data: dict[str, Any] | None = None,
    ) -> str:
        """Return a deterministic id for one evidentiary record.

        Source row/offset is preferred.  File artifacts without a database row use a
        small stable identity subset (path/name/hash), not the complete mutable JSON.
        """
        identity_data: dict[str, Any] = {}
        if data:
            for key in (
                "sha256",
                "path",
                "name",
                "message_id",
                "conversation_id",
                "contact_id",
                "call_id",
                "url",
            ):
                if data.get(key) is not None:
                    identity_data[key] = data.get(key)
        payload = {
            "job_id": job_id or "",
            "artifact_type": artifact_type,
            "source_path": (source_path or "").replace("\\", "/"),
            "source_table": source_table or "",
            "source_row_id": source_row_id or "",
            "source_offset": source_offset,
            "state": state,
            "identity_data": identity_data,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]
        return f"MOB-{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_type": self.artifact_type,
            "source_domain": self.source_domain,
            "timestamp_utc": self.timestamp_utc,
            "data": self.data,
            "forensic": self.forensic,
            "job_id": self.job_id,
        }

    @classmethod
    def create(
        cls,
        *,
        artifact_type: str,
        source_domain: str,
        data: dict[str, Any],
        state: EvidenceState = "allocated",
        recovery_source: str = "live_database",
        source_path: str = "",
        parser: str = "",
        parser_version: str = "1.0.0",
        timestamp_utc: str | None = None,
        source_table: str | None = None,
        source_row_id: str | None = None,
        source_offset: int | None = None,
        confidence: Confidence | None = None,
        job_id: str | None = None,
        artifact_id: str | None = None,
        source_sha256: str | None = None,
        source_id: str | None = None,
    ) -> "NormalizedArtifact":
        aid = artifact_id or cls.make_stable_id(
            job_id=job_id,
            artifact_type=artifact_type,
            source_path=source_path,
            source_table=source_table,
            source_row_id=source_row_id,
            source_offset=source_offset,
            state=state,
            data=data,
        )
        conf = confidence or Confidence(
            label="HIGH" if state == "allocated" else "MEDIUM",
            score=0.9 if state == "allocated" else 0.6,
        )
        forensic = {
            "state": state,
            "recovery_source": recovery_source,
            "source_id": source_id,
            "source_path": source_path,
            "source_table": source_table,
            "source_row_id": source_row_id,
            "source_offset": source_offset,
            "source_sha256": source_sha256,
            "parser": parser,
            "parser_version": parser_version,
            "ui_label": UI_STATE_LABELS.get(state, state.upper()),
            "confidence": conf.to_dict(),
            "examiner_status": "pending_review" if state not in ("allocated",) else "accepted",
        }
        return cls(
            artifact_id=aid,
            artifact_type=artifact_type,
            source_domain=source_domain,
            timestamp_utc=timestamp_utc,
            data=data,
            forensic=forensic,
            job_id=job_id,
        )


@dataclass
class InventoryItem:
    path: str
    size: int = 0
    extension: str = ""
    mime_hint: str = ""
    sha256: str | None = None
    status: str = "discovered"  # discovered|queued|parsing|parsed|unsupported|error
    parser: str | None = None
    error: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
