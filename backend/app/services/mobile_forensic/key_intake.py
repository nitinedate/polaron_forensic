"""Capture acquired WhatsApp key files into job Intake, without exposing secrets."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from app.db.sql_helpers import execute, fetchone
from app.services.mobile_forensic.whatsapp_crypt import (
    WhatsAppKeyCandidate,
    parse_key_material,
)

KEY_NAMES = {"key", "encrypted_backup.key", "whatsapp.key", "whatsapp_key.hex"}
PUBLIC_FIELDS = (
    "source_path",
    "source_kind",
    "sha256",
    "size_bytes",
    "key_kind",
    "key_offset",
    "captured_at",
)


def _object(value):
    if isinstance(value, str):
        value = json.loads(value)
    return value if isinstance(value, dict) else {}


def is_whatsapp_key_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    return name in KEY_NAMES and (
        name != "key" or normalized == "key" or "whatsapp" in normalized
    )


def key_capture_status(disk_source: dict | None) -> dict:
    ds = _object(disk_source)
    intake = _object(ds.get("case_intake"))
    sources = [
        {field: entry.get(field) for field in PUBLIC_FIELDS if field in entry}
        for entry in intake.get("whatsapp_key_files", [])
        if isinstance(entry, dict)
    ]
    results = [{k: row[k] for k in ("source_path", "source_sha256", "decrypted_sha256", "state", "authenticated", "reason", "key_source", "container", "export_state", "validation", "payload_kind") if k in row}
               for row in intake.get("whatsapp_backup_results", []) if isinstance(row, dict)]
    verified = [row for row in results if row.get("authenticated") is True and row.get("state") == "decrypted"]
    return {
        "sources": sources,
        "selected_source": intake.get("whatsapp_key_selected_source"),
        "format_validated": bool(sources),
        # A structurally usable key is not proof of a matching backup.
        "backup_match_verified": bool(verified),
        "verified_backup_count": len(verified),
        "legacy_unverified_count": sum(row.get("validation") == "legacy_structural_only" and row.get("state") == "decrypted" for row in results),
        "blocked_backup_count": sum(row.get("state") == "blocked" for row in results),
        "backup_results": results,
    }


def persist_captured_keys(db, job_id: str, candidates, *, attachments=None) -> dict:
    """Lock the job; retain every source, and preserve a key entered by the examiner."""
    from app.services.mobile_forensic.integrity import utc_now_iso

    row = fetchone(
        db, "SELECT id,disk_source FROM jobs WHERE id=:jid FOR UPDATE", {"jid": job_id}
    )
    if not row:
        raise ValueError("Job not found")
    ds = _object(row.get("disk_source"))
    intake = dict(_object(ds.get("case_intake")))
    records = [
        dict(entry)
        for entry in intake.get("whatsapp_key_files", [])
        if isinstance(entry, dict)
    ]
    references = attachments or {}
    original = ds.get("whatsapp_key_hex") or intake.get("whatsapp_key_hex")
    selected = parse_key_material(original)
    if selected and not intake.get("whatsapp_key_selected_source"):
        intake["whatsapp_key_selected_source"] = "case_intake"
    added = 0
    key_changed = False
    for candidate in candidates:
        if not isinstance(candidate.material, bytes):
            continue
        material = candidate.material
        key = parse_key_material(material)
        if not key or len(material) > 512:
            continue
        digest = hashlib.sha256(material).hexdigest()
        record = {
            "source_path": candidate.source,
            "source_kind": "intake_attachment"
            if candidate.source in references
            else "materialized_evidence",
            "sha256": digest,
            "size_bytes": len(material),
            "key_kind": key.kind,
            "captured_at": utc_now_iso(),
        }
        if len(material) == 158 and key.kind in {"keyfile158", "java_keyfile158"}:
            record["key_offset"] = 126
        if candidate.source in references:
            record["storage_uri"] = references[candidate.source]
        if not any(
            entry.get("sha256") == digest
            and entry.get("source_path") == candidate.source
            for entry in records
        ):
            records.append(record)
            added += 1
        if not selected:
            # For the classic 158-byte file this is exactly material[126:158].hex().
            ds["whatsapp_key_hex"] = key.raw32.hex()
            intake["whatsapp_key_hex"] = key.raw32.hex()
            intake["whatsapp_key_selected_source"] = candidate.source
            selected = key
            key_changed = True
    if added or key_changed:
        intake["whatsapp_key_files"] = records
        ds["case_intake"] = intake
        execute(
            db,
            "UPDATE jobs SET disk_source=CAST(:ds AS jsonb),updated_at=NOW() WHERE id=:jid",
            {"ds": json.dumps(ds), "jid": job_id},
        )
    return {
        "status": "captured" if records else "key_unavailable",
        "added": added,
        "forensic_key_status": {"whatsapp_key_hex_set": selected is not None},
        "whatsapp_key_capture": key_capture_status(ds),
    }


def attach_key_file(db, job_id: str, material: bytes, *, filename: str = "key") -> dict:
    """Preserve the complete collected file, including crypt12 header material."""
    from app.services.storage import put_bytes

    if len(material) > 512 or parse_key_material(material) is None:
        raise ValueError(
            "Invalid WhatsApp key file. ADB errors, truncated files and unsupported formats are rejected."
        )
    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name not in KEY_NAMES:
        name = "key"
    digest = hashlib.sha256(material).hexdigest()
    source = f"intake/whatsapp-keys/{digest}/{name}"
    uri = put_bytes(f"jobs/{job_id}/{source}", material)
    return persist_captured_keys(
        db, job_id, [WhatsAppKeyCandidate(material, source)], attachments={source: uri}
    )


def _folder_candidates(folder: Path):
    """Bounded discovery inside the registered case folder; never follow symlinks."""
    root = folder.resolve()
    examined = 0
    deadline = time.monotonic() + 8
    for current, directories, names in os.walk(root, followlinks=False):
        if time.monotonic() >= deadline:
            raise ValueError(
                "Case-folder key search reached its time limit. Upload the collected key file in Intake."
            )
        directories[:] = [
            name
            for name in sorted(directories)
            if not (Path(current) / name).is_symlink()
        ]
        for name in sorted(names):
            examined += 1
            if examined > 50_000:
                raise ValueError(
                    "Case-folder key search reached 50,000 files. Upload the collected key file in Intake."
                )
            path = Path(current) / name
            root_key = path.parent == root and name.lower() == "key"
            if path.is_symlink() or not (
                root_key or is_whatsapp_key_path(str(path.relative_to(root)))
            ):
                continue
            try:
                if not 24 <= path.stat().st_size <= 512:
                    continue
                with path.open("rb") as stream:
                    material = stream.read(513)
                if len(material) <= 512 and parse_key_material(material):
                    yield WhatsAppKeyCandidate(
                        material, str(path.relative_to(root)).replace("\\", "/")
                    )
            except OSError:
                continue


def capture_registered_keys(
    db, job_id: str, *, include_case_folder: bool = False
) -> dict:
    from app.services.mobile_forensic.sqlite_counts import discover_whatsapp_keys

    candidates = [
        candidate
        for candidate in discover_whatsapp_keys(db, job_id)
        if candidate.source != "case_intake"
    ]
    if candidates or not include_case_folder:
        return persist_captured_keys(db, job_id, candidates)
    row = (
        fetchone(
            db,
            "SELECT disk_source,extracted_disk_uri FROM jobs WHERE id=:jid",
            {"jid": job_id},
        )
        or {}
    )
    # After extraction, only verified materialized evidence or an explicit key
    # upload is accepted. Do not silently read an original source tree again.
    if not row.get("extracted_disk_uri"):
        from app.services.host_evidence import (
            load_job_evidence_folder,
            resolve_host_path,
        )
        from app.services.storage import put_bytes

        raw = load_job_evidence_folder(db, job_id)
        if raw:
            folder = resolve_host_path(raw, strict=True, job_id=job_id)
            attachments = {}
            found = list(_folder_candidates(folder))
            for candidate in found:
                digest = hashlib.sha256(candidate.material).hexdigest()
                attachments[candidate.source] = put_bytes(
                    f"jobs/{job_id}/intake/whatsapp-keys/{digest}/key",
                    candidate.material,
                )
            return persist_captured_keys(db, job_id, found, attachments=attachments)
    return persist_captured_keys(db, job_id, [])


def redact_forensic_keys(disk_source):
    """Job metadata may show presence/provenance, never the actual Intake secrets."""
    if not isinstance(disk_source, dict):
        return disk_source
    secret_fields = {
        "whatsapp_key_hex",
        "whatsapp_legacy_account",
        "signal_db_key_hex",
        "ios_backup_password",
        "signal_passphrase",
        "keychain_password",
        "adb_backup_password",
        "storage_uri",
        "decrypted_storage_uri",
    }

    def redact(value):
        if isinstance(value, dict):
            return {
                key: redact(item)
                for key, item in value.items()
                if key not in secret_fields
                or (key == "storage_uri" and not value.get("key_kind"))
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return redact(disk_source)


def persist_decryption_results(db, job_id: str, results: list[dict]) -> dict:
    """Store current-run per-backup verification, never keys or plaintext."""
    row = fetchone(db, "SELECT id,disk_source FROM jobs WHERE id=:jid FOR UPDATE", {"jid": job_id})
    if not row:
        raise ValueError("Job not found")
    ds = _object(row.get("disk_source"))
    intake = dict(_object(ds.get("case_intake")))
    fields = {"source_path", "source_sha256", "decrypted_sha256", "decrypted_storage_uri",
              "state", "authenticated", "reason", "key_source", "key_sha256_prefix", "container", "export_state", "validation", "payload_kind"}
    by_source = {}
    for result in results:
        if isinstance(result, dict) and result.get("source_path"):
            by_source[result["source_path"]] = {k: result[k] for k in fields if k in result}
    intake["whatsapp_backup_results"] = list(by_source.values())
    ds["case_intake"] = intake
    execute(db, "UPDATE jobs SET disk_source=CAST(:ds AS jsonb),updated_at=NOW() WHERE id=:jid",
            {"ds": json.dumps(ds), "jid": job_id})
    return key_capture_status(ds)
