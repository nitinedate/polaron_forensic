"""Count mobile artifacts from Cellebrite/AXIOM portable packages.

Supported layouts (Magnet AXIOM / Cellebrite PA style):

* ``.ufd`` INI → ``FileDump=*.zip`` + ``ZIPLogicalPath=Dump``
* ``.zip`` filesystem dump (``Dump/data/data/...``)
* ``.ufdx`` XML evidence index (points at .ufd/.pas)
* ``.pas`` native PA object (ignored as payload; dump is the zip)
* Aetheris thin ZIP ``.pas``/``.ufd`` packages (legacy)

When ``job_artifacts`` only holds package shells, this module still produces
AXIOM-style family counts by listing/reading DBs inside the dump zip.
"""

from __future__ import annotations

import logging
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any

from app.db.sql_helpers import fetchall
from app.services.mobile_forensic.cellebrite_ufed import (
    is_native_cellebrite_pas,
    parse_ufd_file,
    resolve_ufd_dump_zip,
    resolve_ufdx_referenced_paths,
)

log = logging.getLogger("mobile_forensic.package_inventory")

_PORTABLE_ZIP_SUFFIXES = frozenset({".zip", ".pas", ".ufd"})
_IMAGE = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".tif", ".tiff"})
_VIDEO = frozenset({".mp4", ".mkv", ".3gp", ".mov", ".avi", ".m4v", ".webm"})
_AUDIO = frozenset({".opus", ".mp3", ".m4a", ".wav", ".aac", ".amr", ".ogg", ".flac"})
_DOC = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"})
_MEDIA = _IMAGE | _VIDEO | _AUDIO

# Only open these DB basenames from multi‑GB dump zips (AXIOM-style targets).
_PRIMARY_DB_NAMES = frozenset({
    "msgstore.db",
    "wa.db",
    "chatstorage.sqlite",
    "extchatdatabase.sqlite",
    "mmssms.db",
    "sms.db",
    "calllog.db",
    "calls.db",
    "contacts2.db",
    "addressbook.sqlitedb",
    "addressbook.sqlite",
})


def is_portable_zip_archive(path: Path) -> bool:
    """True when path is a ZIP container (Aetheris package or UFED FileDump zip)."""
    try:
        if not path.is_file():
            return False
        lower = path.suffix.lower()
        if lower == ".ufdx":
            return False
        if lower == ".ufd":
            # Native Cellebrite .ufd is INI text, not ZIP.
            try:
                head = path.read_bytes()[:32]
                if head.startswith(b"[DeviceInfo]") or head.startswith(b"\xff\xfe[") or b"[Dumps]" in head:
                    return False
            except OSError:
                return False
        if lower == ".pas" and is_native_cellebrite_pas(path):
            return False
        if lower in _PORTABLE_ZIP_SUFFIXES or lower == ".zip":
            return zipfile.is_zipfile(path)
    except OSError:
        return False
    return False


def _resolve_path(raw: str) -> Path | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        from app.services.virtual_disk import _resolve_evidence_path

        p = _resolve_evidence_path(text)
        if p.exists():
            return p
    except Exception:
        pass
    p = Path(text)
    try:
        return p if p.exists() else None
    except OSError:
        return None


def _empty_counts() -> dict[str, int]:
    return {
        "whatsapp_messages": 0,
        "whatsapp_chats": 0,
        "whatsapp_calls": 0,
        "whatsapp_contacts": 0,
        "whatsapp_groups": 0,
        "whatsapp_media": 0,
        "whatsapp_encrypted_backups": 0,
        "whatsapp_deleted_messages": 0,
        "sms": 0,
        "sms_chats": 0,
        "call_logs": 0,
        "emails": 0,
        "email_attachments": 0,
        "sms_attachments": 0,
        "contacts": 0,
        "pictures": 0,
        "videos": 0,
        "audio": 0,
        "documents": 0,
        "installed_apps": 0,
        "telegram": 0,
        "signal": 0,
        "instagram": 0,
        "facebook": 0,
        "linkedin": 0,
        "device_info": 0,
        "sim_info": 0,
    }


def _merge_count_dicts(base: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
    out = dict(base)
    for k, v in extra.items():
        out[k] = max(int(out.get(k) or 0), int(v or 0))
    return out


def _parse_aetheris_ufdx_counts(path: Path) -> dict[str, int]:
    """Optional Aetheris ``<Count category=…>`` extension (not native Cellebrite)."""
    counts: dict[str, int] = {}
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag != "Count":
                continue
            cat = (el.attrib.get("category") or "").strip().lower().replace("-", "_").replace(" ", "_")
            if not cat:
                continue
            try:
                counts[cat] = int(el.attrib.get("value") or 0)
            except (TypeError, ValueError):
                continue
    except Exception:
        pass
    return counts


def _count_installed_apps_list(path: Path) -> tuple[int, list[str]]:
    try:
        lines = [
            ln.strip()
            for ln in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    except OSError:
        return 0, []
    return len(lines), [str(path)]


def _scan_dump_zip(archive: Path, *, logical_prefix: str | None = None) -> dict[str, Any]:
    """AXIOM-style inventory over a UFED FileDump zip (path counts + primary SQLite DBs)."""
    from app.services.mobile_forensic.sqlite_counts import (
        analyze_addressbook_db,
        analyze_calllog_db,
        analyze_sms_db,
        analyze_whatsapp_db,
        _is_calllog_db,
        _is_sms_db,
        _is_whatsapp_msgstore_crypt,
        _is_whatsapp_msgstore,
        _is_whatsapp_wa_db,
    )

    counts = _empty_counts()
    samples: dict[str, list[str]] = {k: [] for k in counts}
    db_paths: dict[str, list[str]] = {"whatsapp": [], "sms": [], "call_logs": []}
    limitations: list[str] = []
    primary_db_members: list[tuple[str, int]] = []
    whatsapp_key_members: list[tuple[str, int]] = []
    whatsapp_crypt_members: list[tuple[str, int]] = []

    def _sample(key: str, path: str) -> None:
        bucket = samples.setdefault(key, [])
        if path not in bucket and len(bucket) < 12:
            bucket.append(path)

    prefix = (logical_prefix or "").replace("\\", "/").strip("/")
    prefix_l = prefix.lower()

    try:
        zf = zipfile.ZipFile(archive, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        return {
            "counts": counts,
            "samples": samples,
            "db_paths": db_paths,
            "limitations": [f"Could not open dump zip {archive.name}: {exc}"],
            "total_files": 0,
        }

    total = 0
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = info.filename.replace("\\", "/")
            # Prefer Dump/ tree when declared; still accept members outside it.
            p = rel.lower()
            if prefix_l and not (p.startswith(prefix_l + "/") or p == prefix_l):
                # Still count top-level helpers, but primary dump is under prefix.
                pass
            total += 1
            name = PurePosixPath(p).name
            ext = PurePosixPath(p).suffix.lower()
            display = f"{archive.name}/{rel}"
            size = int(info.file_size or 0)

            # Only msgstore*.crypt12/14/15 are encrypted chat backups.  Theme/media
            # sidecars such as *.webp.crypt14 must not inflate chat-backup counts.
            if _is_whatsapp_msgstore_crypt(p):
                counts["whatsapp_encrypted_backups"] += 1
                _sample("whatsapp_encrypted_backups", display)
                if 0 < size <= 200 * 1024 * 1024:
                    whatsapp_crypt_members.append((rel, size))

            # Android WhatsApp classic key file. Keep only a bounded, same-evidence
            # candidate and never expose its raw bytes in logs/results.
            from app.services.mobile_forensic.key_intake import is_whatsapp_key_path
            if is_whatsapp_key_path(p) and 32 <= size <= 512:
                whatsapp_key_members.append((rel, size))

            if "whatsapp" in p and ext in _MEDIA:
                counts["whatsapp_media"] += 1
                _sample("whatsapp_media", display)
            if ext in _IMAGE:
                counts["pictures"] += 1
                if counts["pictures"] <= 12:
                    _sample("pictures", display)
            if ext in _VIDEO:
                counts["videos"] += 1
                if counts["videos"] <= 12:
                    _sample("videos", display)
            if ext in _AUDIO:
                counts["audio"] += 1
                if counts["audio"] <= 12:
                    _sample("audio", display)
            if ext in _DOC and name not in {"installedappslist.txt", "format.txt"}:
                counts["documents"] += 1
                if counts["documents"] <= 12:
                    _sample("documents", display)

            if name == "packages.xml" or p.endswith(".apk") or "/data/app/" in p:
                counts["installed_apps"] += 1
                _sample("installed_apps", display)
            # Messaging apps: count private databases only — never APK/DEX/dalvik-cache.
            def _is_app_db() -> bool:
                if "/databases/" not in p and "/db/" not in p:
                    return False
                if not (
                    name.endswith(".db")
                    or name.endswith(".sqlite")
                    or name.endswith(".sqlite3")
                    or ".db-" in name
                ):
                    return False
                if name.endswith(("-wal", "-shm", "-journal")):
                    return False
                if any(
                    x in p
                    for x in (
                        "/dalvik-cache/",
                        "/preload/",
                        "/data/app/",
                        "facebook-appmanager",
                        "facebook.appmanager",
                        "facebook-services",
                    )
                ):
                    return False
                return True

            if ("telegram" in p or "org.telegram" in p) and _is_app_db():
                counts["telegram"] += 1
                if counts["telegram"] <= 12:
                    _sample("telegram", display)
            if ("signal" in p or "org.thoughtcrime" in p) and _is_app_db():
                counts["signal"] += 1
                if counts["signal"] <= 12:
                    _sample("signal", display)
            if ("instagram" in p or "com.instagram" in p) and _is_app_db():
                counts["instagram"] += 1
                if counts["instagram"] <= 12:
                    _sample("instagram", display)
            if (
                any(
                    x in p
                    for x in (
                        "com.facebook.orca",
                        "com.facebook.katana",
                        "com.facebook.mlite",
                        "com.facebook.messaging",
                    )
                )
                or ("messenger" in p and "facebook" in p)
            ) and _is_app_db():
                counts["facebook"] += 1
                if counts["facebook"] <= 12:
                    _sample("facebook", display)
            if ("linkedin" in p or "com.linkedin" in p) and _is_app_db():
                counts["linkedin"] += 1
                if counts["linkedin"] <= 12:
                    _sample("linkedin", display)
            if name in {"build.prop", "device_info.json", "acquisition_manifest.json"} or name.endswith("info.plist"):
                counts["device_info"] += 1
                _sample("device_info", display)
            if any(m in p for m in ("iccid", "imsi", "siminfo", "ef_iccid")):
                counts["sim_info"] += 1
                _sample("sim_info", display)

            if name in _PRIMARY_DB_NAMES and size > 0 and size <= 200 * 1024 * 1024:
                if (
                    _is_whatsapp_msgstore(p)
                    or _is_whatsapp_wa_db(p)
                    or _is_sms_db(p)
                    or _is_calllog_db(p)
                    or name in {"contacts2.db", "addressbook.sqlitedb", "addressbook.sqlite"}
                ):
                    primary_db_members.append((rel, size))

        # Analyze primary DBs (dedupe by basename preference: prefer /data/data/ over pass_through).
        primary_db_members.sort(
            key=lambda item: (
                0 if "/data/data/" in item[0].replace("\\", "/").lower() else 1,
                0 if "/databases/" in item[0].replace("\\", "/").lower() else 1,
                -item[1],
            )
        )
        seen_db_keys: set[str] = set()
        for rel, _size in primary_db_members:
            p = rel.replace("\\", "/").lower()
            name = PurePosixPath(p).name
            # One analysis per logical DB name (prefer first sorted = data/data).
            if name in seen_db_keys:
                continue
            display = f"{archive.name}/{rel}"
            try:
                data = zf.read(rel)
            except Exception as exc:
                limitations.append(f"Could not read {display}: {exc}")
                continue
            if not data[:16].startswith(b"SQLite format"):
                continue
            seen_db_keys.add(name)

            if _is_whatsapp_msgstore(p) or _is_whatsapp_wa_db(p):
                analyzed = analyze_whatsapp_db(data, display)
                counts["whatsapp_messages"] = max(counts["whatsapp_messages"], analyzed["messages"])
                counts["whatsapp_chats"] = max(counts["whatsapp_chats"], analyzed["chats"])
                counts["whatsapp_calls"] = max(counts["whatsapp_calls"], analyzed["calls"])
                counts["whatsapp_contacts"] = max(counts["whatsapp_contacts"], analyzed["contacts"])
                counts["whatsapp_groups"] = max(counts["whatsapp_groups"], analyzed["groups"])
                counts["whatsapp_deleted_messages"] = max(
                    counts["whatsapp_deleted_messages"],
                    int(analyzed.get("deleted_messages") or 0),
                )
                db_paths["whatsapp"].append(display)
                _sample("whatsapp_messages", display)
            elif _is_sms_db(p):
                analyzed = analyze_sms_db(data, display)
                counts["sms"] = max(counts["sms"], analyzed["sms"])
                counts["sms_chats"] = max(counts["sms_chats"], int(analyzed.get("chats") or 0))
                counts["sms_attachments"] = max(
                    counts.get("sms_attachments", 0), int(analyzed.get("attachments") or 0)
                )
                db_paths["sms"].append(display)
                _sample("sms", display)
            elif _is_calllog_db(p):
                analyzed = analyze_calllog_db(data, display)
                counts["call_logs"] = max(counts["call_logs"], analyzed["calls"])
                db_paths["call_logs"].append(display)
                _sample("call_logs", display)
            elif name in {"contacts2.db", "addressbook.sqlitedb", "addressbook.sqlite"}:
                analyzed = analyze_addressbook_db(data, display)
                if analyzed["contacts"] > 0:
                    counts["contacts"] = max(counts["contacts"], analyzed["contacts"])
                    _sample("contacts", display)

        # A sealed UFED/ZIP often contains only the shared-storage encrypted
        # WhatsApp msgstore plus the app-private same-device key.  Reuse the
        # existing fail-closed decryptor so package-only evidence receives the
        # same treatment as materialised artifacts.  No key guessing/brute force.
        if whatsapp_crypt_members:
            from app.services.mobile_forensic.whatsapp_crypt import (
                WhatsAppKeyCandidate, parse_key_material, decrypt_with_candidates,
            )

            candidates = []
            # Prefer the canonical /data/data/com.whatsapp key over other
            # WhatsApp variants when more than one candidate exists.
            whatsapp_key_members.sort(
                key=lambda item: (
                    0
                    if "/data/data/com.whatsapp/files/key"
                    in item[0].replace("\\", "/").lower()
                    else 1,
                    item[1],
                )
            )
            for key_rel, _key_size in whatsapp_key_members:
                try:
                    material = zf.read(key_rel)
                    candidate = parse_key_material(material)
                except Exception as exc:
                    limitations.append(
                        f"Could not read WhatsApp key candidate {archive.name}/{key_rel}: {exc}"
                    )
                    continue
                if candidate:
                    candidates.append(WhatsAppKeyCandidate(material, f"{archive.name}/{key_rel}"))

            decrypted_any = False
            decrypt_failures = 0
            if candidates:
                # Current msgstore first, then dated backups.  Every valid chat
                # backup is still examined; counts are merged with max(), never
                # blindly summed across snapshots.
                whatsapp_crypt_members.sort(
                    key=lambda item: (
                        0
                        if PurePosixPath(item[0].replace("\\", "/").lower()).name
                        .startswith("msgstore.db.crypt")
                        else 1,
                        -item[1],
                        item[0].lower(),
                    )
                )
                for crypt_rel, _crypt_size in whatsapp_crypt_members:
                    display = f"{archive.name}/{crypt_rel}"
                    try:
                        encrypted = zf.read(crypt_rel)
                    except Exception as exc:
                        decrypt_failures += 1
                        limitations.append(f"Could not read {display}: {exc}")
                        continue
                    plain = decrypt_with_candidates(encrypted, candidates, path=display, expected_size=_crypt_size)
                    if plain is None or not plain[:16].startswith(b"SQLite format"):
                        decrypt_failures += 1
                        continue
                    analyzed = analyze_whatsapp_db(plain, display + "#decrypted")
                    counts["whatsapp_messages"] = max(
                        counts["whatsapp_messages"], int(analyzed.get("messages") or 0)
                    )
                    counts["whatsapp_chats"] = max(
                        counts["whatsapp_chats"], int(analyzed.get("chats") or 0)
                    )
                    counts["whatsapp_calls"] = max(
                        counts["whatsapp_calls"], int(analyzed.get("calls") or 0)
                    )
                    counts["whatsapp_contacts"] = max(
                        counts["whatsapp_contacts"], int(analyzed.get("contacts") or 0)
                    )
                    counts["whatsapp_groups"] = max(
                        counts["whatsapp_groups"], int(analyzed.get("groups") or 0)
                    )
                    counts["whatsapp_deleted_messages"] = max(
                        counts["whatsapp_deleted_messages"],
                        int(analyzed.get("deleted_messages") or 0),
                    )
                    db_paths["whatsapp"].append(display + "#decrypted")
                    _sample("whatsapp_messages", display + "#decrypted")
                    decrypted_any = True

            if not candidates:
                limitations.append(
                    f"Found {len(whatsapp_crypt_members)} WhatsApp encrypted chat backup(s), "
                    "but no usable same-device WhatsApp key file was present in this package; "
                    "encrypted chat rows were not inferred."
                )
            elif not decrypted_any:
                limitations.append(
                    f"{len(candidates)} usable WhatsApp key candidate(s) were present, "
                    f"but none of {len(whatsapp_crypt_members)} encrypted chat backup(s) decoded to "
                    "a valid SQLite database; no encrypted chat rows were inferred."
                )
            elif decrypt_failures:
                limitations.append(
                    f"Recovered WhatsApp chat data from encrypted backup(s), but "
                    f"{decrypt_failures} encrypted backup(s) did not decode to valid SQLite."
                )

    if counts["whatsapp_encrypted_backups"] and counts["whatsapp_messages"] == 0:
        limitations.append(
            f"Found {counts['whatsapp_encrypted_backups']} WhatsApp encrypted msgstore backup(s) "
            "in the dump zip; no readable WhatsApp chat database could be counted."
        )
    if counts["whatsapp_messages"] == 0 and not db_paths["whatsapp"]:
        limitations.append(
            "No WhatsApp msgstore.db found under Dump/data/data/com.whatsapp in the FileDump zip."
        )

    return {
        "counts": counts,
        "samples": samples,
        "db_paths": db_paths,
        "limitations": limitations,
        "total_files": total,
    }


def _discover_dump_targets(evidence_paths: list[Path]) -> list[tuple[Path, str | None]]:
    """Discover (zip_path, logical_prefix) targets from .ufd / .zip evidence."""
    targets: list[tuple[Path, str | None]] = []
    seen: set[str] = set()

    def _add(zip_path: Path, prefix: str | None) -> None:
        try:
            key = str(zip_path.resolve())
        except OSError:
            key = str(zip_path)
        if key in seen:
            return
        if not zip_path.is_file() or not zipfile.is_zipfile(zip_path):
            return
        seen.add(key)
        targets.append((zip_path, prefix))

    expanded_paths: list[Path] = list(evidence_paths)
    seen_expanded = {str(p.resolve()) for p in expanded_paths if p.exists()}
    for descriptor in list(evidence_paths):
        if descriptor.suffix.lower() != ".ufdx":
            continue
        for ref in resolve_ufdx_referenced_paths(descriptor):
            try:
                key = str(ref.resolve())
            except OSError:
                key = str(ref)
            if key not in seen_expanded:
                seen_expanded.add(key)
                expanded_paths.append(ref)

    for path in expanded_paths:
        lower = path.suffix.lower()
        if lower == ".ufd":
            resolved = resolve_ufd_dump_zip(path)
            if resolved:
                zpath, prefix = resolved
                _add(zpath, prefix)
                continue
            # Aetheris thin ZIP .ufd
            if is_portable_zip_archive(path):
                _add(path, None)
            continue
        if lower == ".zip":
            _add(path, "Dump")  # UFED default; scanner still counts all members
            continue
        if lower == ".pas":
            if is_native_cellebrite_pas(path):
                # Payload is sibling FileDump zip from matching .ufd — already handled.
                continue
            if is_portable_zip_archive(path):
                _add(path, None)
    return targets


def collect_portable_package_inventory(db, job_id: str) -> dict[str, Any]:
    """Scan registered Cellebrite/Aetheris packages for AXIOM-style family counts."""
    rows = fetchall(
        db,
        """SELECT host_path, original_name, size_bytes
           FROM evidence_files WHERE job_id=:jid""",
        {"jid": job_id},
    )
    empty = {
        "counts": {},
        "samples": {},
        "db_paths": {"whatsapp": [], "sms": [], "call_logs": []},
        "limitations": [],
        "total_files": 0,
        "packages_scanned": 0,
    }
    if not rows:
        return empty

    evidence_paths: list[Path] = []
    for row in rows:
        host = str(row.get("host_path") or "")
        path = _resolve_path(host)
        if path is not None:
            evidence_paths.append(path)

    merged_counts: dict[str, int] = {}
    merged_samples: dict[str, list[str]] = {}
    merged_db: dict[str, list[str]] = {"whatsapp": [], "sms": [], "call_logs": []}
    limitations: list[str] = []
    total_files = 0
    packages_scanned = 0

    # InstalledAppsList.txt beside UFED export
    for path in evidence_paths:
        if path.name.lower() == "installedappslist.txt":
            n, samples = _count_installed_apps_list(path)
            if n:
                merged_counts["installed_apps"] = max(int(merged_counts.get("installed_apps") or 0), n)
                merged_samples.setdefault("installed_apps", [])
                for s in samples:
                    if s not in merged_samples["installed_apps"]:
                        merged_samples["installed_apps"].append(s)

    # Native / Aetheris .ufdx metadata
    for path in evidence_paths:
        if path.suffix.lower() == ".ufdx":
            packages_scanned += 1
            for cat, val in _parse_aetheris_ufdx_counts(path).items():
                if val > 0:
                    merged_counts[cat] = max(int(merged_counts.get(cat) or 0), val)
            desc_bits = []
            for ufd in evidence_paths:
                if ufd.suffix.lower() == ".ufd":
                    parsed = parse_ufd_file(ufd)
                    if parsed and parsed.device_info:
                        desc_bits.append(
                            f"{parsed.device_info.get('Vendor', '')} {parsed.device_info.get('Model', '')}".strip()
                        )
                        merged_counts["device_info"] = max(int(merged_counts.get("device_info") or 0), 1)
                        merged_samples.setdefault("device_info", []).append(str(ufd))
            if desc_bits:
                limitations.append(f"Cellebrite device: {', '.join(desc_bits)}")

    targets = _discover_dump_targets(evidence_paths)
    if not targets:
        # Fallback: any zipfile among evidence
        for path in evidence_paths:
            if path.suffix.lower() == ".zip" and zipfile.is_zipfile(path):
                targets.append((path, "Dump"))

    for zip_path, prefix in targets:
        packages_scanned += 1
        log.info(
            "Scanning UFED/AXIOM dump zip job=%s zip=%s prefix=%s",
            job_id,
            zip_path.name,
            prefix,
        )
        part = _scan_dump_zip(zip_path, logical_prefix=prefix)
        total_files += int(part.get("total_files") or 0)
        merged_counts = _merge_count_dicts(merged_counts, part.get("counts") or {})
        for k, paths in (part.get("samples") or {}).items():
            bucket = merged_samples.setdefault(k, [])
            for pth in paths:
                if pth not in bucket and len(bucket) < 12:
                    bucket.append(pth)
        for k in ("whatsapp", "sms", "call_logs"):
            for pth in part.get("db_paths", {}).get(k) or []:
                if pth not in merged_db[k]:
                    merged_db[k].append(pth)
        limitations.extend(part.get("limitations") or [])

        # Aetheris thin package may point at sealed ORIGINAL_PATH
        if is_portable_zip_archive(zip_path) and zip_path.suffix.lower() != ".zip":
            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    names = set(zf.namelist())
                    if "ORIGINAL_PATH.txt" in names:
                        raw = zf.read("ORIGINAL_PATH.txt").decode("utf-8", errors="replace").strip()
                        sealed = _resolve_path(raw)
                        if sealed and sealed.is_dir():
                            # Directory sealed tree — light path counts only via nested zip if present
                            for nested in sealed.rglob("*.zip"):
                                if zipfile.is_zipfile(nested):
                                    nested_part = _scan_dump_zip(nested, logical_prefix="Dump")
                                    total_files += int(nested_part.get("total_files") or 0)
                                    merged_counts = _merge_count_dicts(merged_counts, nested_part["counts"])
            except Exception as exc:
                log.debug("thin package sealed follow failed: %s", exc)

    if not targets:
        limitations.append(
            "No UFED FileDump zip found. Native .pas is a PA case object — "
            "register the sibling .ufd + FileDump .zip (Dump/ filesystem) for AXIOM-style counts."
        )

    uniq_lim: list[str] = []
    for lim in limitations:
        if lim not in uniq_lim:
            uniq_lim.append(lim)

    return {
        "counts": merged_counts,
        "samples": merged_samples,
        "db_paths": merged_db,
        "limitations": uniq_lim,
        "total_files": total_files,
        "packages_scanned": packages_scanned,
    }
