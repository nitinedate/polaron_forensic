"""Post-collection inventory of high-value artefacts (WhatsApp, SMS domains, etc.).

Examiners often see only photos under AFC/shared storage and conclude chats are
missing. This module scans the sealed tree and reports what was (and was not)
collected so the UI and limitations stay honest.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import sqlite3

from app.services.mobile_acquire.adb_tar_pull import iter_tree_files


_WHATSAPP_NAME_HINTS = (
    "whatsapp",
    "chatstorage.sqlite",
    "msgstore.db",
    "msgstore.db.crypt",
    "crypt12",
    "crypt14",
    "crypt15",
    "wa.db",
    "axolotl.db",
    "com.whatsapp",
)
_SMS_HINTS = (
    "sms.db",
    "sms.db-wal",
    "home_domain/library/sms",
    "providers/sms.txt",
    "providers/mms.txt",
    "providers/call_log",
)
_MEDIA_HINTS = ("dcim", "photodata", "pictures", "movies", "camera roll", ".trashed", "afc_media", "house_arrest")


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path)


def _inventory_ios_manifest(root: Path, found: dict[str, list[str]]) -> dict[str, Any]:
    """Enrich inventory from Manifest.db domain/path names (hashed backup files)."""
    extra: dict[str, Any] = {
        "manifest_path": "",
        "whatsapp_domains": [],
        "whatsapp_db_paths": [],
        "sms_paths": [],
        "ios_backup_complete": False,
    }
    backup_root = root / "ios_backup"
    if not backup_root.is_dir():
        alt = root / "ios_image"
        if alt.is_dir():
            backup_root = alt
    manifests = list(backup_root.rglob("Manifest.db")) if backup_root.is_dir() else []
    if not manifests and backup_root.is_dir():
        # iOS 9 and some tool paths write Manifest.plist without Manifest.db.
        plists = [
            p for p in backup_root.rglob("Manifest.plist")
            if p.is_file() and p.stat().st_size > 64
        ]
        if plists:
            extra["manifest_path"] = _rel(root, plists[0])
            extra["ios_backup_complete"] = True
        return extra
    if not manifests:
        return extra
    manifests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    manifest = manifests[0]
    extra["manifest_path"] = _rel(root, manifest)
    extra["ios_backup_complete"] = True
    try:
        con = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
        cur = con.cursor()
        domains = [
            r[0]
            for r in cur.execute(
                "SELECT DISTINCT domain FROM Files WHERE lower(domain) LIKE '%whatsapp%'"
            ).fetchall()
            if r and r[0]
        ]
        extra["whatsapp_domains"] = domains
        for domain in domains:
            label = f"ios_backup:{domain}"
            if label not in found["whatsapp"]:
                found["whatsapp"].append(label)
        rows = cur.execute(
            "SELECT domain, relativePath FROM Files WHERE domain LIKE '%whatsapp%' "
            "AND (relativePath LIKE '%ChatStorage.sqlite' OR relativePath LIKE '%ContactsV2.sqlite' "
            "OR relativePath LIKE '%CallHistory.sqlite')"
        ).fetchall()
        for domain, rel in rows:
            entry = f"{domain}/{rel}"
            extra["whatsapp_db_paths"].append(entry)
            if entry not in found["whatsapp"]:
                found["whatsapp"].append(entry)
        sms_rows = cur.execute(
            "SELECT domain, relativePath FROM Files WHERE relativePath LIKE '%Library/SMS/sms.db%' "
            "OR relativePath LIKE '%sms.db'"
        ).fetchall()
        for domain, rel in sms_rows:
            entry = f"{domain}/{rel}"
            extra["sms_paths"].append(entry)
            if entry not in found["sms_imessage"]:
                found["sms_imessage"].append(entry)
        camera_n = int(
            cur.execute(
                """SELECT COUNT(*) FROM Files WHERE flags=1 AND relativePath != ''
                   AND lower(domain) NOT LIKE '%whatsapp%'
                   AND (
                     lower(domain) LIKE '%camera%' OR lower(domain) LIKE '%media%'
                     OR lower(relativePath) LIKE '%dcim%' OR lower(relativePath) LIKE '%photodata%'
                   )
                   AND (
                     lower(relativePath) LIKE '%.jpg' OR lower(relativePath) LIKE '%.jpeg'
                     OR lower(relativePath) LIKE '%.heic' OR lower(relativePath) LIKE '%.png'
                     OR lower(relativePath) LIKE '%.mp4' OR lower(relativePath) LIKE '%.mov'
                     OR lower(relativePath) LIKE '%.heif' OR lower(relativePath) LIKE '%.m4v'
                   )"""
            ).fetchone()[0]
            or 0
        )
        wa_media_n = int(
            cur.execute(
                """SELECT COUNT(*) FROM Files WHERE flags=1 AND relativePath != ''
                   AND lower(domain) LIKE '%whatsapp%'
                   AND (
                     lower(relativePath) LIKE '%.jpg' OR lower(relativePath) LIKE '%.jpeg'
                     OR lower(relativePath) LIKE '%.heic' OR lower(relativePath) LIKE '%.png'
                     OR lower(relativePath) LIKE '%.mp4' OR lower(relativePath) LIKE '%.mov'
                     OR lower(relativePath) LIKE '%.opus' OR lower(relativePath) LIKE '%.webp'
                     OR lower(relativePath) LIKE '%.gif' OR lower(relativePath) LIKE '%.m4a'
                   )"""
            ).fetchone()[0]
            or 0
        )
        extra["camera_media_files"] = camera_n
        extra["whatsapp_media_files"] = wa_media_n
        if camera_n:
            label = f"ios_manifest:camera_media:{camera_n}"
            if label not in found["media"]:
                found["media"].append(label)
        if wa_media_n:
            label = f"ios_manifest:whatsapp_media:{wa_media_n}"
            if label not in found["media"]:
                found["media"].append(label)
        con.close()
    except Exception as exc:
        extra["error"] = str(exc)
    return extra


def inventory_extraction(original: Path) -> dict[str, Any]:
    """Walk an extraction root and classify noteworthy artefacts."""
    root = Path(original)
    found: dict[str, list[str]] = {
        "whatsapp": [],
        "sms_imessage": [],
        "media": [],
        "android_backup": [],
        "ios_backup": [],
        "other_app_data": [],
    }
    totals = {"files": 0, "bytes": 0}

    if not root.is_dir():
        return {
            "ok": False,
            "categories": found,
            "totals": totals,
            "summary": "No extraction directory to inventory.",
            "gaps": ["Extraction folder missing — nothing to inventory."],
        }

    for full, rel in iter_tree_files(root, follow_junctions=True):
        try:
            size = os.path.getsize(full)
        except OSError:
            size = 0
        totals["files"] += 1
        totals["bytes"] += size
        low = rel.lower()
        name = Path(rel).name.lower()
        if name.endswith((".log", ".err.log")) or low.endswith(".err.txt"):
            continue
        if name.endswith(".ab") and size < 64:
            continue
        if name.endswith(".txt") and "providers/" not in low.replace("\\", "/"):
            # Keep provider dumps; skip other text noise.
            pass

        if "readable_artifacts/whatsapp" in low or any(h in low for h in _WHATSAPP_NAME_HINTS):
            found["whatsapp"].append(rel)
        elif "readable_artifacts/sms" in low or any(h in low for h in _SMS_HINTS) or "sms" in name:
            found["sms_imessage"].append(rel)
        elif (
            low.startswith("afc_media/")
            or low.startswith("house_arrest/")
            or low.startswith("shared_storage/")
            or low.startswith("readable_artifacts/media")
            or low.startswith("readable_artifacts/android_deleted")
            or "filesystem/" in low
            or "mtp_shared/" in low
            or "/sdcard_" in low
        ):
            if any(h in low for h in _MEDIA_HINTS) or name.endswith(
                (".jpg", ".jpeg", ".heic", ".png", ".mp4", ".mov", ".webp")
            ):
                if len(found["media"]) < 50:
                    found["media"].append(rel)
        elif "android_backup" in low or name.endswith(".ab"):
            found["android_backup"].append(rel)
        elif (
            "ios_backup" in low
            or "ios_image" in low
            or name in ("manifest.db", "status.plist", "info.plist")
        ):
            found["ios_backup"].append(rel)
        elif "app_domain" in low or "/data/data/" in low or low.startswith("data/"):
            if len(found["other_app_data"]) < 40:
                found["other_app_data"].append(rel)

    manifest_info = _inventory_ios_manifest(root, found)

    gaps: list[str] = []
    has_ios_backup = (root / "ios_backup").is_dir() or (root / "ios_image").is_dir()
    has_manifest = bool(manifest_info.get("ios_backup_complete"))
    has_whatsapp = bool(found["whatsapp"])
    has_afc = (root / "afc_media").is_dir()
    has_house = (root / "house_arrest").is_dir()
    has_media = bool(found["media"]) or has_afc or (
        root / "shared_storage"
    ).is_dir() or (root / "mtp_shared").is_dir() or (root / "adb_logical").is_dir() or has_house

    if has_ios_backup and has_manifest:
        if not has_afc:
            gaps.append(
                "iOS backup is complete, but AFC shared photos/videos (DCIM/PhotoData) were not "
                "pulled. Keep the iPhone unlocked and Trust This Computer, then re-run so live "
                "Camera Roll and Recently Deleted that AFC exposes are collected."
            )
        if not has_house and has_whatsapp:
            gaps.append(
                "WhatsApp chats are in the iTunes backup (ChatStorage). The live WhatsApp "
                "container (house_arrest) was not pulled — some Documents/media next to the app "
                "may be missing until AFC/house_arrest runs with the phone unlocked."
            )

    if has_media and not has_whatsapp:
        if has_ios_backup and not has_manifest:
            gaps.append(
                "Photos/media were collected, but the iOS backup has no Manifest.db "
                "or Manifest.plist. WhatsApp chats and SMS live in the backup — "
                "re-run Advanced Logical. Unlock the screen only if the tool reports Error 208."
            )
        elif has_ios_backup and has_manifest and not has_whatsapp:
            gaps.append(
                "iOS backup Manifest.db has no WhatsApp domains. WhatsApp may be absent "
                "on the device."
            )
        elif (root / "shared_storage").is_dir() or (root / "adb_logical").is_dir() or (
            root / "mtp_shared"
        ).is_dir():
            gaps.append(
                "Android shared storage was pulled, but no WhatsApp media/DB paths were "
                "found. Chat databases under /data/data need root or a successful adb "
                "backup of com.whatsapp (user must confirm the on-screen backup prompt)."
            )
        elif not has_ios_backup and not (root / "android_backup").is_dir():
            gaps.append(
                "Only media/logical trees were collected. Select Advanced Logical / Backup "
                "to capture WhatsApp and messages."
            )

    if has_ios_backup and not has_manifest:
        gaps.append(
            "ios_backup folder is incomplete without Manifest.db or Manifest.plist — "
            "do not treat hash-named files alone as a readable WhatsApp/SMS source."
        )

    plaintext_wa = any(
        ("msgstore.db" in p.lower() or p.lower().endswith("wa.db"))
        and "crypt" not in p.lower()
        for p in found["whatsapp"]
    )
    ios_plain_wa = any("chatstorage.sqlite" in p.lower() for p in found["whatsapp"]) or bool(
        manifest_info.get("whatsapp_db_paths")
    )
    # Android-only gap. iOS plaintext chats are ChatStorage.sqlite in the iTunes backup.
    if has_whatsapp and not plaintext_wa and not has_ios_backup and not ios_plain_wa:
        gaps.append(
            "WhatsApp media or encrypted local backups (CRYPT family) were collected. "
            "Plaintext chat databases (msgstore.db) were not — they live under /data/data "
            "and need an already-rooted phone or a successful adb backup prompt."
        )

    parts = []
    if found["whatsapp"]:
        parts.append(f"WhatsApp artefacts: {len(found['whatsapp'])}")
    if found["sms_imessage"]:
        parts.append(f"SMS/iMessage artefacts: {len(found['sms_imessage'])}")
    if has_media:
        parts.append("media trees present")
    if found["ios_backup"]:
        parts.append(f"iOS backup files: {len(found['ios_backup'])}")
    if found["android_backup"]:
        parts.append(f"Android backup files: {len(found['android_backup'])}")
    summary = "; ".join(parts) if parts else "No high-value chat artefacts indexed yet."

    capped = {k: v[:80] for k, v in found.items()}
    return {
        "ok": True,
        "categories": capped,
        "counts": {k: len(v) for k, v in found.items()},
        "totals": totals,
        "summary": summary,
        "gaps": gaps,
        "ios_backup_complete": manifest_info.get("ios_backup_complete"),
        "ios_manifest": manifest_info,
    }
