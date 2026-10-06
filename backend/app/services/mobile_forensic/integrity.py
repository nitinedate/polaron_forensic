"""Evidence integrity — hashing, manifests, chain-of-custody for mobile import."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("mobile_forensic.integrity")

PARSER_PLATFORM_VERSION = "2.0.0"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha512_file(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha512()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hash_evidence_paths(
    paths: list[Path],
    *,
    include_sha512: bool = False,
) -> list[dict[str, Any]]:
    """Hash registered evidence segment files (read-only; never modifies sources)."""
    out: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            entry: dict[str, Any] = {
                "path": str(path),
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            if include_sha512:
                entry["sha512"] = sha512_file(path)
            out.append(entry)
        except OSError as exc:
            log.warning("hash failed %s: %s", path, exc)
            out.append({"path": str(path), "name": path.name, "error": str(exc)})
    return out


def build_evidence_manifest(
    *,
    job_id: str,
    source_paths: list[str],
    hashed: list[dict[str, Any]],
    mobile_os: str | None,
    acquisition_mode: str,
    formats: list[str],
    adapter: str | None,
    intake_keys: dict[str, Any] | None = None,
    device_info: dict[str, Any] | None = None,
    ufdx_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Document-required intake manifest (immutable original + working-copy metadata)."""
    source_id = f"SOURCE-{uuid.uuid4().hex[:12]}"
    keys = dict(intake_keys or {})
    # Never persist raw key material into logs; store presence flags only in manifest public section.
    key_flags = {
        "whatsapp_key_present": bool(keys.get("whatsapp_key_hex")),
        "signal_db_key_present": bool(keys.get("signal_db_key_hex")),
        "ios_backup_password_present": bool(keys.get("ios_backup_password")),
    }
    return {
        "schema_version": "1",
        "source_id": source_id,
        "job_id": job_id,
        "created_at_utc": utc_now_iso(),
        "parser_platform_version": PARSER_PLATFORM_VERSION,
        "acquisition_mode": acquisition_mode or "import",
        "mobile_os": mobile_os,
        "formats": formats,
        "adapter": adapter,
        "immutable_original": True,
        "source_paths": source_paths,
        "hashes": hashed,
        "key_material": key_flags,
        "device_info": device_info or {},
        "ufdx_extraction_paths": list(ufdx_paths or []),
        "working_copy": {
            "status": "pending_verify",
            "note": "Analysis uses extracted working representation after hash verification",
        },
    }


def write_manifest_sidecar(folder: Path, manifest: dict[str, Any]) -> Path | None:
    """Write manifest.json beside evidence (best-effort; never fails registration)."""
    try:
        folder.mkdir(parents=True, exist_ok=True)
        dest = folder / "aetheris_evidence_manifest.json"
        dest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return dest
    except OSError as exc:
        log.warning("manifest write failed %s: %s", folder, exc)
        return None


def load_intake_keys_from_disk_source(disk_source: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(disk_source, dict):
        return {}
    intake = disk_source.get("case_intake") or disk_source.get("intake") or {}
    if not isinstance(intake, dict):
        intake = {}
    return {
        "whatsapp_key_hex": disk_source.get("whatsapp_key_hex") or intake.get("whatsapp_key_hex"),
        "whatsapp_legacy_account": disk_source.get("whatsapp_legacy_account") or intake.get("whatsapp_legacy_account"),
        "signal_db_key_hex": disk_source.get("signal_db_key_hex") or intake.get("signal_db_key_hex"),
        "ios_backup_password": disk_source.get("ios_backup_password") or intake.get("ios_backup_password"),
    }


def persist_forensic_keys_to_disk_source(db, job_id: str, keys: dict[str, Any] | None) -> dict[str, bool]:
    """Store examiner-supplied decrypt keys on the job (presence-only in logs)."""
    from app.db.sql_helpers import execute, fetchone

    incoming = keys if isinstance(keys, dict) else {}
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id FOR UPDATE", {"id": job_id}) or {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        ds = {}
    intake = ds.get("case_intake") if isinstance(ds.get("case_intake"), dict) else {}
    mapping = {
        "whatsapp_key_hex": "whatsapp_key_hex",
        "whatsapp_legacy_account": "whatsapp_legacy_account",
        "signal_db_key_hex": "signal_db_key_hex",
        "ios_backup_password": "ios_backup_password",
        "signal_passphrase": "signal_passphrase",
        "keychain_password": "keychain_password",
        "adb_backup_password": "adb_backup_password",
    }
    for src, dest in mapping.items():
        raw = incoming.get(src)
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        if src == "whatsapp_legacy_account" and ("@" not in text or len(text) > 320 or any(ord(ch) < 32 for ch in text)):
            raise ValueError("CRYPT5 requires the original Android Google account email")
        if src == "whatsapp_key_hex":
            from app.services.mobile_forensic.whatsapp_crypt import parse_key_material
            previous = parse_key_material(ds.get(dest) or intake.get(dest))
            entered = parse_key_material(text)
            if entered is None:
                raise ValueError("Invalid WhatsApp key")
            if previous is None or entered.raw32 != previous.raw32:
                intake["whatsapp_key_selected_source"] = "case_intake"
                intake.pop("whatsapp_backup_results", None)
        if src == "whatsapp_legacy_account" and text != (ds.get(dest) or intake.get(dest)):
            intake.pop("whatsapp_backup_results", None)
        ds[dest] = text
        intake[dest] = text
    ds["case_intake"] = intake
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
        {"ds": json.dumps(ds), "jid": job_id},
    )
    return forensic_key_status_from_disk_source(ds)


def forensic_key_status_from_disk_source(disk_source: dict[str, Any] | None) -> dict[str, bool]:
    from app.services.mobile_forensic.whatsapp_crypt import parse_key_material

    keys = load_intake_keys_from_disk_source(disk_source)
    extra = disk_source if isinstance(disk_source, dict) else {}
    intake = extra.get("case_intake") if isinstance(extra.get("case_intake"), dict) else {}
    return {
        "whatsapp_key_hex_set": parse_key_material(keys.get("whatsapp_key_hex")) is not None,
        "whatsapp_legacy_account_set": bool(keys.get("whatsapp_legacy_account")),
        "signal_db_key_hex_set": bool(keys.get("signal_db_key_hex")),
        "ios_backup_password_set": bool(keys.get("ios_backup_password")),
        "signal_passphrase_set": bool(extra.get("signal_passphrase") or intake.get("signal_passphrase")),
        "keychain_password_set": bool(extra.get("keychain_password") or intake.get("keychain_password")),
        "adb_backup_password_set": bool(extra.get("adb_backup_password") or intake.get("adb_backup_password")),
    }
