"""Register decrypted WhatsApp working copies before native parsing and RAG.

Original encrypted artifacts are retained. Only registered case bytes are read;
the source acquisition directory is never reopened by the server.
"""
from __future__ import annotations

import hashlib
import io
import json
import mimetypes
import re
import zipfile
from pathlib import Path, PurePosixPath

from app.services.mobile_forensic.whatsapp_crypt import (
    MAX_PAYLOAD_BYTES, decrypt_with_candidates, is_whatsapp_crypt_path,
    last_decrypt_diagnostics, payload_kind,
)

MAX_ARCHIVE_MEMBERS = 20_000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024 * 1024
DERIVATION_VERSION = "1.1.0-crypt-family"
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def _safe_member(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if normalized.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        return None
    if any(":" in part or any(ord(ch) < 32 for ch in part) or part.endswith((".", " "))
           or part.split(".", 1)[0].lower() in _RESERVED for part in parts):
        return None
    return normalized


def decoded_filename(source: str, kind: str) -> str:
    from app.services.mobile_forensic.whatsapp_crypt import crypt_extension
    name = PurePosixPath(source.replace("\\", "/")).name
    extension = crypt_extension(name)
    if extension:
        name = name[:-(len(extension) + 1)]
    name = re.sub(r'[^a-zA-Z0-9._ -]', '_', name).strip(". ") or "payload"
    if name.split(".", 1)[0].lower() in _RESERVED:
        name = "payload_" + name
    required = {"sqlite": ".db", "zip": ".zip", "json": ".json", "webp": ".webp", "png": ".png", "jpeg": ".jpg"}.get(kind)
    if required and (kind != "sqlite" or not name.lower().endswith((".db", ".sqlite", ".sqlite3"))):
        if not name.lower().endswith(required):
            name += required
    if kind == "binary" and not PurePosixPath(name).suffix:
        name += ".bin"
    return name


def iter_derived_payloads(plain: bytes, source: str, warnings: list[str]):
    """Yield authenticated payload plus safe, CRC-verified ZIP members.

    The archive itself is retained even when a member cannot be expanded. Limits
    and unsafe members are reported, never silently counted as recovered chats.
    """
    kind = payload_kind(plain)
    yield decoded_filename(source, kind), plain, {"payload_kind": kind}
    if kind != "zip":
        return
    try:
        with zipfile.ZipFile(io.BytesIO(plain)) as archive:
            files = [item for item in archive.infolist() if not item.is_dir()]
            if len(files) > MAX_ARCHIVE_MEMBERS or sum(item.file_size for item in files) > MAX_ARCHIVE_EXPANDED_BYTES:
                warnings.append("Authenticated ZIP retained; member expansion exceeds the documented count/size limit")
                return
            names = set()
            for item in files:
                member = _safe_member(item.filename)
                folded = member.casefold() if member else ""
                is_link = ((item.external_attr >> 16) & 0o170000) == 0o120000
                if not member or folded in names or is_link or item.flag_bits & 1:
                    warnings.append(f"ZIP member retained inside archive but not expanded (unsafe, duplicate, symlink or separately encrypted): {item.filename!r}")
                    continue
                names.add(folded)
                if item.file_size > MAX_MEMBER_BYTES:
                    warnings.append(f"ZIP member retained inside archive; exceeds {MAX_MEMBER_BYTES}-byte limit: {item.filename!r}")
                    continue
                try:
                    body = archive.read(item)  # verifies CRC; no extract() or paths from an archive
                except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                    warnings.append(f"ZIP member could not be validated: {item.filename!r} ({type(exc).__name__})")
                    continue
                yield "members/" + member, body, {"payload_kind": payload_kind(body), "archive_member": item.filename,
                                                "archive_crc32": f"{item.CRC:08x}"}
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        warnings.append(f"Authenticated archive retained; ZIP expansion failed ({type(exc).__name__})")


def _metadata(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            pass
    return {}


def read_registered_derivation(db, job_id: str, artifact: dict, *, max_bytes: int) -> bytes:
    """Read a job-owned derived object after finalization, with full hash checks."""
    from app.db.sql_helpers import fetchone
    from app.config import get_settings
    from app.services.storage import get_bytes, _local_root
    meta = _metadata(artifact.get("metadata"))
    path = str(artifact.get("file_path") or "")
    size = int(artifact.get("size_bytes") or 0)
    uri = str(artifact.get("minio_uri") or "")
    if meta.get("whatsapp_derivation") != DERIVATION_VERSION or not path.startswith("derived/whatsapp_decrypted/"):
        raise ValueError("Object is not a registered WhatsApp derivation")
    if size > MAX_PAYLOAD_BYTES or size < 0 or max_bytes < 0 or not artifact.get("sha256") or not meta.get("encrypted_source_sha256"):
        raise ValueError("Derived object lacks a bounded size or evidence hashes")
    storage_key = f"jobs/{job_id}/{path}"
    if uri.startswith("s3://"):
        if uri != f"s3://{get_settings().minio_bucket}/{storage_key}":
            raise ValueError("Derived object is outside its job storage namespace")
    elif uri.startswith("file://"):
        expected = (_local_root() / storage_key).resolve()
        if not expected.is_relative_to(_local_root().resolve()) or Path(uri[7:]).resolve() != expected:
            raise ValueError("Derived object is outside its job storage directory")
    else:
        raise ValueError("Derived object has no supported case storage URI")
    original = fetchone(db, "SELECT sha256,metadata FROM job_artifacts WHERE job_id=:jid AND file_path=:path",
                        {"jid": job_id, "path": meta.get("encrypted_source_path")}) or {}
    recovery = _metadata(_metadata(original.get("metadata")).get("whatsapp_decryption"))
    if original.get("sha256") != meta["encrypted_source_sha256"] or path not in (recovery.get("derived_paths") or []):
        raise ValueError("Derived object is not linked to registered encrypted evidence")
    body = get_bytes(uri, max_bytes=size + 1)
    if body is None or len(body) != size or hashlib.sha256(body).hexdigest() != artifact["sha256"]:
        raise ValueError("Derived object size or hash does not match its registered evidence")
    return body[:max_bytes]


def materialize_registered_whatsapp_backups(db, job_id: str, *, progress=None) -> dict:
    from app.db.sql_helpers import execute, fetchall, fetchone
    from app.services.mobile_forensic.integrity import load_intake_keys_from_disk_source
    from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes, discover_whatsapp_keys
    from app.services.storage import put_bytes

    rows = fetchall(db, """SELECT file_path,size_bytes,sha256,metadata FROM job_artifacts
                           WHERE job_id=:jid AND lower(file_path) ~ '\\.crypt[a-z0-9_-]*$'
                           ORDER BY file_path""", {"jid": job_id})
    sources = [row for row in rows if is_whatsapp_crypt_path(str(row.get("file_path") or ""))
               and not _metadata(row.get("metadata")).get("whatsapp_derivation")]
    result = {"encrypted_files": len(sources), "decrypted_files": 0, "blocked_files": 0,
              "derived_artifacts": 0, "cached_files": 0, "partial_files": 0}
    if not sources:
        return result
    candidates = discover_whatsapp_keys(db, job_id)
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    legacy_account = load_intake_keys_from_disk_source(_metadata(row.get("disk_source"))).get("whatsapp_legacy_account")
    # Cache identity includes every candidate and the legacy identity without
    # exposing either. A newly uploaded key causes blocked sources to be retried.
    fingerprint = hashlib.sha256()
    for candidate in candidates:
        material = candidate.material.encode() if isinstance(candidate.material, str) else candidate.material
        fingerprint.update(hashlib.sha256(material).digest())
        fingerprint.update(candidate.source.encode())
    fingerprint.update(str(legacy_account or "").encode())
    key_set = fingerprint.hexdigest()
    outcomes = []

    for index, source in enumerate(sources, 1):
        from app.services.job_control import pipeline_should_stop
        if pipeline_should_stop(db, job_id):
            from app.services.forensic_serial_pipeline import StageWaiting
            raise StageWaiting("WhatsApp decryption paused by user")
        path = str(source["file_path"])
        meta = _metadata(source.get("metadata"))
        previous = _metadata(meta.get("whatsapp_decryption"))
        identity = {"version": DERIVATION_VERSION, "source_sha256": source.get("sha256"), "key_set": key_set}
        cached = bool(source.get("sha256")) and all(previous.get(key) == value for key, value in identity.items())
        if cached and previous.get("state") in {"decrypted", "partial"}:
            derived = previous.get("derived_paths") or []
            registered = fetchall(db, "SELECT file_path FROM job_artifacts WHERE job_id=:jid AND file_path=ANY(:paths)",
                                 {"jid": job_id, "paths": derived}) if derived else []
            cached = len(registered) == len(derived) and bool(derived)
        if cached:
            result["cached_files"] += 1
            if previous.get("state") in {"decrypted", "partial"}:
                result["decrypted_files"] += 1
                result["partial_files"] += int(previous.get("state") == "partial")
            else:
                result["blocked_files"] += 1
        else:
            expected = int(source.get("size_bytes") or 0)
            raw = _read_artifact_bytes(db, job_id, path, max_bytes=MAX_PAYLOAD_BYTES) if expected <= MAX_PAYLOAD_BYTES else None
            source_hash = hashlib.sha256(raw).hexdigest() if raw is not None else source.get("sha256")
            if expected > MAX_PAYLOAD_BYTES:
                plain, diag = None, {"reason": "source_size_limit", "authenticated": False}
            elif raw is not None and source.get("sha256") and source_hash != source["sha256"]:
                plain, diag = None, {"reason": "source_hash_mismatch", "authenticated": False}
            else:
                plain = decrypt_with_candidates(raw or b"", candidates, path=path, expected_size=expected,
                                                allow_payloads=True, legacy_account=legacy_account)
                diag = last_decrypt_diagnostics()
            state = {**identity, "source_sha256": source_hash, "state": "blocked", "diagnostics": diag, "derived_paths": [], "warnings": []}
            if plain is not None:
                digest = hashlib.sha256(plain).hexdigest()
                state.update(state="decrypted", decrypted_sha256=digest)
                prefix = "derived/whatsapp_decrypted/" + hashlib.sha256(path.encode()).hexdigest()[:24] + "/" + digest[:24]
                for name, body, details in iter_derived_payloads(plain, path, state["warnings"]):
                    derived_path = prefix + "/" + name
                    body_hash = hashlib.sha256(body).hexdigest()
                    derived_meta = {"whatsapp_derivation": DERIVATION_VERSION, "encrypted_source_path": path,
                                    "encrypted_source_sha256": source_hash, "decrypted_payload_sha256": digest,
                                    "decryption_integrity": diag.get("integrity"), "decryption_authenticated": bool(diag.get("authenticated")),
                                    **details}
                    # Native acquisition may already have emitted this same DB.
                    # Reuse identical derived bytes instead of parsing chats twice.
                    if details["payload_kind"] == "sqlite":
                        existing = fetchone(db, """SELECT file_path,metadata FROM job_artifacts WHERE job_id=:jid
                            AND sha256=:sha AND lower(file_path) LIKE '%/whatsapp_decrypted/%'
                            ORDER BY file_path LIMIT 1""", {"jid": job_id, "sha": body_hash})
                        if existing:
                            existing_meta = _metadata(existing.get("metadata"))
                            proofs = existing_meta.get("whatsapp_encrypted_sources") or []
                            proof = {"path": path, "sha256": source_hash}
                            if proof not in proofs:
                                proofs.append(proof)
                            patch = {**derived_meta, **{key: existing_meta[key] for key in derived_meta if key in existing_meta},
                                     "whatsapp_encrypted_sources": proofs}
                            execute(db, """UPDATE job_artifacts SET metadata=coalesce(metadata,'{}'::jsonb)||CAST(:patch AS jsonb),
                                updated_at=NOW() WHERE job_id=:jid AND file_path=:path""",
                                {"jid": job_id, "path": existing["file_path"], "patch": json.dumps(patch)})
                            state["derived_paths"].append(existing["file_path"])
                            continue
                    uri = put_bytes(f"jobs/{job_id}/{derived_path}", body, mimetypes.guess_type(name)[0] or "application/octet-stream")
                    execute(db, """INSERT INTO job_artifacts
                        (job_id,file_path,file_name,extension,size_bytes,sha256,minio_uri,parse_status,metadata)
                        VALUES (:jid,:path,:name,:ext,:size,:sha,:uri,'pending',CAST(:meta AS jsonb))
                        ON CONFLICT (job_id,file_path) DO UPDATE SET minio_uri=EXCLUDED.minio_uri,
                            metadata=coalesce(job_artifacts.metadata,'{}'::jsonb)||EXCLUDED.metadata,updated_at=NOW()""",
                        {"jid": job_id, "path": derived_path, "name": PurePosixPath(name).name,
                         "ext": PurePosixPath(name).suffix.lower(), "size": len(body), "sha": body_hash,
                         "uri": uri, "meta": json.dumps(derived_meta)})
                    state["derived_paths"].append(derived_path)
                    result["derived_artifacts"] += 1
                if state["warnings"]:
                    state["state"] = "partial"
                    result["partial_files"] += 1
                result["decrypted_files"] += 1
            else:
                result["blocked_files"] += 1
            execute(db, """UPDATE job_artifacts SET metadata=coalesce(metadata,'{}'::jsonb)||CAST(:patch AS jsonb),
                            sha256=COALESCE(sha256,:source_sha),
                            updated_at=NOW() WHERE job_id=:jid AND file_path=:path""",
                    {"jid": job_id, "path": path, "source_sha": source_hash, "patch": json.dumps({"whatsapp_decryption": state})})
        outcome = previous if cached else state
        diagnostic = outcome.get("diagnostics") or {}
        outcomes.append({"source_path": path, "source_sha256": outcome.get("source_sha256"),
                         "decrypted_sha256": outcome.get("decrypted_sha256"), "state": outcome.get("state"),
                         "authenticated": bool(diagnostic.get("authenticated")), "reason": diagnostic.get("reason"),
                         "validation": diagnostic.get("validation"), "container": diagnostic.get("container"),
                         "payload_kind": diagnostic.get("payload_kind"), "key_source": diagnostic.get("key_source"),
                         "key_sha256_prefix": diagnostic.get("key_sha256_prefix"),
                         "export_state": "registered" if outcome.get("derived_paths") else "not_applicable"})
        db.commit()
        if progress:
            progress(index, len(sources), result)
    from app.services.mobile_forensic.key_intake import persist_decryption_results
    result["intake_status"] = persist_decryption_results(db, job_id, outcomes)
    db.commit()
    return result
