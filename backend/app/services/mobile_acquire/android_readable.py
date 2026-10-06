"""Android-only trash / WhatsApp leftover recovery from pulled shared storage.

iOS jobs must not import or call this module. iPhone backup unpacking and
lockdown media pulls live on the iOS agent modules only.
"""

from __future__ import annotations


import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

_MEDIA_SUFFIXES = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".heic",
    ".heif",
    ".webp",
    ".mp4",
    ".mov",
    ".m4v",
    ".3gp",
    ".opus",
    ".aac",
    ".m4a",
    ".mp3",
    ".amr",
)

_TRASH_PARTS = (
    ".trashed",
    "/.trash/",
    "/trash/",
    "$recycle.bin",
    ".trashes",
    "/.deleted/",
)

_ANDROID_ROOTS = (
    "adb_logical",
    "filesystem",
    "shared_storage",
    "mtp_shared",
    "android_backup",
)


def _win_long(path: Path) -> str:
    text = str(path)
    if len(text) >= 240 and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + str(path.resolve())
    return text


def _link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    try:
        os.link(_win_long(src), _win_long(dest))
        return
    except OSError:
        shutil.copy2(_win_long(src), _win_long(dest))


def _is_android_tree(original: Path) -> bool:
    if (original / "ios_image").is_dir() or (original / "ios_backup").is_dir():
        return False
    return any((original / name).is_dir() for name in _ANDROID_ROOTS)


def _is_trash_path(rel: str) -> bool:
    low = rel.replace("\\", "/").lower()
    return any(part in low for part in _TRASH_PARTS)


def _count_android_whatsapp_deleted(msgstore: Path) -> int:
    """Android msgstore flags only — never iOS Core Data message-type columns."""
    try:
        con = sqlite3.connect(f"file:{msgstore}?mode=ro", uri=True)
    except sqlite3.Error:
        return 0
    try:
        cur = con.cursor()
        tables = {r[0].lower(): r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        msg_t = tables.get("message") or tables.get("messages")
        if not msg_t:
            return 0
        cols = {r[1].lower(): r[1] for r in cur.execute(f'PRAGMA table_info("{msg_t}")')}
        total = 0
        for name in ("is_deleted", "deleted", "deleted_ts"):
            col = cols.get(name)
            if not col:
                continue
            if name == "deleted_ts":
                total = max(
                    total,
                    int(cur.execute(f'SELECT COUNT(*) FROM "{msg_t}" WHERE "{col}" IS NOT NULL AND "{col}" != 0').fetchone()[0] or 0),
                )
            else:
                total = max(
                    total,
                    int(cur.execute(f'SELECT COUNT(*) FROM "{msg_t}" WHERE CAST("{col}" AS INTEGER) != 0').fetchone()[0] or 0),
                )
        deleted_t = tables.get("deleted_messages") or tables.get("message_deletes")
        if deleted_t:
            total = max(total, int(cur.execute(f'SELECT COUNT(*) FROM "{deleted_t}"').fetchone()[0] or 0))
        return total
    except sqlite3.Error:
        return 0
    finally:
        con.close()


def _carve_android_msgstore(msgstore: Path, dest: Path, out: dict[str, Any]) -> None:
    try:
        from app.services.mobile_acquire.sqlite_deleted import recover_sqlite_residuals
    except Exception as exc:
        out["errors"].append(f"android sqlite carve unavailable: {exc}")
        return
    try:
        dest.mkdir(parents=True, exist_ok=True)
        item = recover_sqlite_residuals(msgstore, dest / msgstore.stem)
        out["deleted_sqlite_residuals"] = int(item.get("carved_strings") or 0)
        out["deleted_sqlite_chat_like"] = int(item.get("chat_like_residuals") or 0)
    except Exception as exc:
        out["errors"].append(f"android carve {msgstore.name}: {exc}")



def _looks_like_whatsapp_key(rel: str, name: str, size: int) -> bool:
    low = rel.replace("\\", "/").lower()
    # Includes Java-serialized encrypted_backup.key (59 bytes), device files/key
    # (158 bytes, AES at 126), and copied hex key text.
    if not (24 <= size <= 512):
        return False
    if name.lower() not in {"key", "encrypted_backup.key", "whatsapp.key", "whatsapp_key.hex"}:
        return False
    return "whatsapp" in low or name.lower() in {"encrypted_backup.key", "whatsapp.key", "whatsapp_key.hex"}


def _is_whatsapp_crypt_backup(name: str, rel: str) -> bool:
    from app.services.mobile_forensic.whatsapp_crypt import is_whatsapp_crypt_path
    return is_whatsapp_crypt_path(rel)


def _materialize_whatsapp_decrypted(
    crypt_files: list[Path],
    key_files: list[Path],
    dest: Path,
    out: dict[str, Any],
    *,
    legacy_account: str | None = None,
) -> None:
    if not crypt_files:
        return
    out.setdefault("errors", [])
    out.setdefault("limitations", [])
    out.setdefault("copied", [])
    try:
        from app.services.mobile_forensic.whatsapp_crypt import (
            WhatsAppKeyCandidate, decrypt_with_candidates, last_decrypt_diagnostics, parse_key_material,
        )
    except Exception as exc:
        out["errors"].append(f"WhatsApp decryptor unavailable: {exc}")
        return

    candidates = []
    for key_path in key_files:
        try:
            with key_path.open("rb") as handle:
                material = handle.read(513)
        except OSError:
            continue
        if parse_key_material(material):
            candidates.append(WhatsAppKeyCandidate(material, str(key_path)))
    from app.services.mobile_forensic.whatsapp_derivation import iter_derived_payloads
    from app.services.mobile_forensic.whatsapp_crypt import MAX_PAYLOAD_BYTES, payload_kind

    dest.mkdir(parents=True, exist_ok=True)
    seen_plain: dict[str, list[str]] = {}
    decrypted = 0
    decoded_files = 0
    failed = 0
    max_backups = max(0, int(os.environ.get("MOBILE_WHATSAPP_DECRYPT_MAX", "0") or 0))
    # Newer backups first; historical unique DBs are retained for deleted-history correlation.
    ordered = sorted(crypt_files, key=lambda x: x.stat().st_mtime if x.exists() else 0, reverse=True)
    if max_backups and len(ordered) > max_backups:
        out["limitations"].append(f"WhatsApp backup decrypt limited by MOBILE_WHATSAPP_DECRYPT_MAX={max_backups}; {len(ordered) - max_backups} backup(s) deferred.")
        ordered = ordered[:max_backups]
    backup_results = out.setdefault("whatsapp_backup_results", [])
    for src in ordered:
        try:
            size = src.stat().st_size
            if size > MAX_PAYLOAD_BYTES:
                raw, plain = b"", None
                diagnostics = {"reason": "source_size_limit", "authenticated": False}
            else:
                raw = src.read_bytes()
                plain = decrypt_with_candidates(raw, candidates, path=str(src), expected_size=size,
                                                allow_payloads=True, legacy_account=legacy_account)
                diagnostics = last_decrypt_diagnostics()
        except Exception as exc:
            failed += 1
            if len(out["errors"]) < 50:
                out["errors"].append(f"WhatsApp decrypt {src.name}: {exc}")
            continue
        if plain is None:
            failed += 1
            backup_results.append({"source": str(src), "state": "blocked", "diagnostics": diagnostics})
            continue
        digest = hashlib.sha256(plain).hexdigest()
        provenance = {"source": str(src), "source_sha256": hashlib.sha256(raw).hexdigest(),
                      "decrypted_sha256": digest, "state": "decrypted", "diagnostics": diagnostics,
                      "derived_paths": [], "warnings": []}
        backup_results.append(provenance)
        decoded_files += 1
        if digest in seen_plain and payload_kind(plain) == "sqlite":
            provenance["derived_paths"] = seen_plain[digest]
            provenance["duplicate_plaintext"] = True
            continue
        source_id = hashlib.sha256(str(src).encode("utf-8")).hexdigest()[:12]
        for name, body, details in iter_derived_payloads(plain, str(src), provenance["warnings"]):
            target = dest / source_id / name
            temporary = None
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                # Check resolved parents too: an output symlink must not redirect
                # a derived member into the input evidence directory.
                if not target.parent.resolve().is_relative_to(dest.resolve()) or target.is_symlink():
                    raise OSError("Derived destination escapes its output directory")
                import tempfile
                with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".decrypt-", delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(body)
                temporary.chmod(0o600)
                os.replace(temporary, target)
                proof = {**provenance, **details, "derived_file_sha256": hashlib.sha256(body).hexdigest()}
                sidecar = target.with_suffix(target.suffix + ".provenance.json")
                if sidecar.is_symlink():
                    raise OSError("Provenance destination is a symlink")
                sidecar.write_text(json.dumps(proof, indent=2), encoding="utf-8")
                sidecar.chmod(0o600)
            except OSError as exc:
                provenance["warnings"].append(f"Could not save derived payload {name}: {exc}")
                continue
            finally:
                if temporary and temporary.exists():
                    temporary.unlink(missing_ok=True)
            provenance["derived_paths"].append(str(target))
            if details["payload_kind"] == "sqlite":
                decrypted += 1
            out["copied"].append({"dest": str(target), "rel": str(src), "deleted": False,
                                  "recovery_state": "decrypted_backup", "source_sha256": provenance["source_sha256"],
                                  "decrypted_sha256": digest, **details})
        seen_plain[digest] = provenance["derived_paths"]
        if provenance["warnings"]:
            provenance["state"] = "partial"
            failed += 1
            out["limitations"].extend(provenance["warnings"])

    out["whatsapp_decryption_state"] = ("partial" if failed else "decrypted") if decoded_files else (
        "key_unavailable" if not key_files and not legacy_account else "key_invalid" if not candidates and not legacy_account else "decrypt_failed")
    out["whatsapp_decrypted_backups"] = decrypted
    out["whatsapp_decrypted_files"] = decoded_files
    out["whatsapp_decrypt_failed"] = failed
    # Record only provenance; never raw key bytes/hex.
    out["whatsapp_key_sources"] = list(dict.fromkeys(c.source for c in candidates))

def materialize_android_readable_artifacts(
    original: Path,
    *,
    dest_root: Path | None = None,
) -> dict[str, Any]:
    """Copy Android trash + leftover WhatsApp media into readable_artifacts/."""
    original = Path(original)
    out: dict[str, Any] = {
        "ok": False,
        "agent": "androidagent",
        "copied": [],
        "errors": [],
        "deleted_whatsapp_messages": 0,
        "deleted_media": 0,
        "whatsapp_media": 0,
        "camera_media": 0,
        "whatsapp_decrypted_backups": 0,
        "whatsapp_decryption_state": "not_applicable",
        "limitations": [],
    }
    if not original.is_dir():
        out["errors"].append("No Android extraction directory.")
        return out
    if not _is_android_tree(original):
        out["errors"].append("Not an Android extraction — androidagent will not touch iOS trees.")
        return out

    readable = Path(dest_root) if dest_root else original / "readable_artifacts"
    try:
        readable.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        out["errors"].append(str(exc))
        return out
    out["readable_root"] = str(readable)
    trash_dir = readable / "android_deleted"
    wa_dir = readable / "whatsapp"
    media_dir = readable / "media"

    msgstore: Path | None = None
    whatsapp_keys: list[Path] = []
    whatsapp_crypts: list[Path] = []
    for dirpath, _dirs, files in os.walk(original):
        _dirs[:] = [name for name in _dirs if not (Path(dirpath) / name).resolve().is_relative_to(readable.resolve())]
        for name in files:
            src = Path(dirpath) / name
            try:
                rel = str(src.relative_to(original)).replace("\\", "/")
            except ValueError:
                continue
            low = rel.lower()
            if "readable_artifacts" in low or src.is_symlink():
                continue
            try:
                size = src.stat().st_size
            except OSError:
                size = 0
            if _looks_like_whatsapp_key(rel, name, size):
                whatsapp_keys.append(src)
            if _is_whatsapp_crypt_backup(name, rel):
                whatsapp_crypts.append(src)
            suffix = Path(name).suffix.lower()
            is_media = suffix in _MEDIA_SUFFIXES
            is_wa = "whatsapp" in low or "com.whatsapp" in low
            is_camera = any(tok in low for tok in ("/dcim/", "\\dcim\\", "/pictures/", "/movies/", "/camera/"))
            if name.lower() in {"msgstore.db", "msgstore.db-wal"} and "crypt" not in low:
                if name.lower() == "msgstore.db":
                    msgstore = src
            if is_wa and is_media:
                dest = wa_dir / f"{abs(hash(rel)) & 0xFFFFFFFF:08x}_{name}"
                try:
                    _link_or_copy(src, dest)
                    out["whatsapp_media"] += 1
                    tagged = _is_trash_path(rel)
                    out["copied"].append({"dest": str(dest), "rel": rel, "deleted": tagged})
                    if tagged:
                        out["deleted_media"] += 1
                except OSError as exc:
                    out["errors"].append(f"{rel}: {exc}")
                continue
            if is_media and (_is_trash_path(rel) or is_camera):
                dest_root_dir = trash_dir if _is_trash_path(rel) else media_dir
                dest = dest_root_dir / f"{abs(hash(rel)) & 0xFFFFFFFF:08x}_{name}"
                try:
                    _link_or_copy(src, dest)
                    rec = {"dest": str(dest), "rel": rel, "deleted": _is_trash_path(rel)}
                    out["copied"].append(rec)
                    if _is_trash_path(rel):
                        out["deleted_media"] += 1
                    else:
                        out["camera_media"] += 1
                except OSError as exc:
                    out["errors"].append(f"{rel}: {exc}")

    _materialize_whatsapp_decrypted(
        whatsapp_crypts,
        whatsapp_keys,
        readable / "whatsapp_decrypted",
        out,
    )

    if msgstore and msgstore.is_file():
        out["deleted_whatsapp_messages"] = _count_android_whatsapp_deleted(msgstore)
        try:
            _link_or_copy(msgstore, wa_dir / msgstore.name)
        except OSError:
            pass
        _carve_android_msgstore(msgstore, readable / "deleted_recovery", out)

    out["ok"] = True
    return out
