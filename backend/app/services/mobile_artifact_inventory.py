"""Mobile artifact inventory — classify extracted files into AXIOM-style families.

Produces counts, descriptions, and sample evidence paths for WhatsApp, SMS, media,
apps, email, SIM/device info, documents, and social apps when those files exist in
the acquisition. Locked/MTP-only acquisitions correctly show 0 with a limitation note.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

_IMAGE_EXT = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".tif", ".tiff"})
_VIDEO_EXT = frozenset({".mp4", ".mkv", ".3gp", ".mov", ".avi", ".m4v", ".webm"})
_AUDIO_EXT = frozenset({".opus", ".mp3", ".m4a", ".wav", ".aac", ".amr", ".ogg", ".flac"})
_DOC_EXT = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf", ".odt",
})
_EMAIL_EXT = frozenset({".eml", ".msg", ".mbox", ".pst", ".ost"})
_DB_EXT = frozenset({".db", ".sqlite", ".sqlite3"})


@dataclass
class MobileFamily:
    key: str
    label: str
    category: str
    description: str
    axiom_name_hints: tuple[str, ...] = ()
    path_markers: tuple[str, ...] = ()
    name_markers: tuple[str, ...] = ()
    extensions: frozenset[str] = field(default_factory=frozenset)
    requires_db: bool = False
    locked_note: str = (
        "Not present in this acquisition. App databases usually require an unlocked backup, "
        "UFED/Cellebrite extraction, or rooted/jailbroken access — not available via MTP alone."
    )


# Families examiners expect on mobile jobs (aligned to mobile_forensic template + extras).
MOBILE_FAMILIES: tuple[MobileFamily, ...] = (
    MobileFamily(
        key="device_info",
        label="Device Information",
        category="Operating System",
        description="Hardware/software identity (model, OS build, serial) from build.prop / Info.plist / acquisition manifest.",
        axiom_name_hints=("android device information", "ios device information", "device information"),
        path_markers=("build.prop", "info.plist", "device_info.json", "acquisition_manifest.json"),
        name_markers=("build.prop", "info.plist", "device_info.json", "acquisition_manifest.json"),
    ),
    MobileFamily(
        key="sim_info",
        label="SIM Card Information",
        category="Operating System",
        description="SIM ICCID / IMSI / MSISDN / carrier artifacts when present in telephony or UFED exports.",
        axiom_name_hints=("sim card", "sim card iccid", "sim card imsi", "sim card phone number", "sim card provider"),
        path_markers=("iccid", "imsi", "siminfo", "telephony", "ef_iccid", "subscriberinfo"),
        name_markers=("iccid", "imsi", "sim"),
        locked_note="SIM identifiers require full file-system/UFED or privileged telephony access.",
    ),
    MobileFamily(
        key="installed_apps",
        label="Installed Applications",
        category="Operating System",
        description="Installed / removed application packages (packages.xml, .apk paths, iOS app bundles).",
        axiom_name_hints=("installed applications", "installed apps", "application"),
        path_markers=("packages.xml", "/data/app/", "application/", ".apk", "appdomain-group", "bundle/application"),
        name_markers=("packages.xml", ".apk"),
    ),
    MobileFamily(
        key="accounts",
        label="Accounts",
        category="Operating System",
        description="Device and cloud accounts (Google, Apple ID, OEM accounts).",
        axiom_name_hints=("accounts", "account"),
        path_markers=("accounts.db", "accounts.xml", "com.google", "apple account", "mobileme"),
        name_markers=("accounts.db", "accounts.xml"),
    ),
    MobileFamily(
        key="whatsapp_messages",
        label="WhatsApp Messages",
        category="Communication",
        description="WhatsApp chat databases and message stores (msgstore.db / ChatStorage.sqlite).",
        axiom_name_hints=("whatsapp messages", "whatsapp"),
        path_markers=("msgstore.db", "wa.db", "chatstorage.sqlite", "com.whatsapp", "net.whatsapp"),
        name_markers=("msgstore", "wa.db", "chatstorage"),
        requires_db=True,
    ),
    MobileFamily(
        key="whatsapp_media",
        label="WhatsApp Media",
        category="Communication",
        description="WhatsApp media folders (images, voice notes, documents shared in chats).",
        axiom_name_hints=("whatsapp",),
        path_markers=("whatsapp/media", "whatsapp images", "whatsapp video", "whatsapp audio", "whatsapp documents"),
        name_markers=(),
    ),
    MobileFamily(
        key="whatsapp_calls",
        label="WhatsApp Calls",
        category="Communication",
        description="WhatsApp call history artifacts when present in databases or UFED exports.",
        axiom_name_hints=("whatsapp calls",),
        path_markers=("whatsapp", "call_log", "wacall"),
        name_markers=("call_log_database",),
        requires_db=True,
    ),
    MobileFamily(
        key="sms",
        label="SMS / MMS Messages",
        category="Communication",
        description="Native SMS/MMS databases (mmssms.db / sms.db).",
        axiom_name_hints=("sms messages", "android sms", "sms/mms", "imessage/sms"),
        path_markers=("mmssms.db", "/sms.db", "telephony.db", "library/sms"),
        name_markers=("mmssms.db", "sms.db"),
        requires_db=True,
    ),
    MobileFamily(
        key="call_logs",
        label="Call Logs",
        category="Communication",
        description="Native phone call history (calllog.db / CallHistory.storedata).",
        axiom_name_hints=("call logs", "android call logs", "ios call logs"),
        path_markers=("calllog.db", "calls.db", "callhistory", "call_history"),
        name_markers=("calllog.db", "calls.db"),
        requires_db=True,
    ),
    MobileFamily(
        key="telegram",
        label="Telegram",
        category="Communication",
        description="Telegram app data and media caches.",
        axiom_name_hints=("telegram",),
        path_markers=("org.telegram", "telegram", "tgnet"),
        name_markers=("telegram",),
    ),
    MobileFamily(
        key="signal",
        label="Signal",
        category="Communication",
        description="Signal secure messaging artifacts.",
        axiom_name_hints=("signal",),
        path_markers=("org.thoughtcrime.securesms", "signal"),
        name_markers=("signal",),
        requires_db=True,
    ),
    MobileFamily(
        key="instagram",
        label="Instagram",
        category="Communication",
        description="Instagram app data, caches, and media.",
        axiom_name_hints=("instagram",),
        path_markers=("com.instagram", "instagram"),
        name_markers=("instagram",),
    ),
    MobileFamily(
        key="facebook",
        label="Facebook / Messenger",
        category="Communication",
        description="Facebook and Messenger app artifacts.",
        axiom_name_hints=("facebook", "facebook messenger", "messenger"),
        path_markers=("com.facebook", "facebook", "messenger"),
        name_markers=("facebook", "messenger"),
    ),
    MobileFamily(
        key="linkedin",
        label="LinkedIn",
        category="Communication",
        description="LinkedIn app / cache artifacts.",
        axiom_name_hints=("linkedin",),
        path_markers=("com.linkedin", "linkedin"),
        name_markers=("linkedin",),
    ),
    MobileFamily(
        key="email",
        label="Email Messages",
        category="Email",
        description="Email client databases and message files (.eml/.msg/mbox).",
        axiom_name_hints=("email", "emails", "gmail", "outlook"),
        path_markers=("com.google.android.gm", "mail", "outlook", "mbox", "imap"),
        extensions=_EMAIL_EXT,
        name_markers=("email", "gmail"),
    ),
    MobileFamily(
        key="email_attachments",
        label="Email Attachments",
        category="Email",
        description="Files recovered from email attachment stores or attachment folders.",
        axiom_name_hints=("email attachments", "email attachment"),
        path_markers=("attachment", "attachments", "/mail/"),
        extensions=_DOC_EXT | _IMAGE_EXT,
    ),
    MobileFamily(
        key="pictures",
        label="Pictures / Photos",
        category="Media",
        description="Image files recovered from DCIM, camera rolls, downloads, and app media.",
        axiom_name_hints=("pictures", "picture", "photos"),
        path_markers=("dcim", "camera", "pictures", "photo"),
        extensions=_IMAGE_EXT,
    ),
    MobileFamily(
        key="videos",
        label="Videos",
        category="Media",
        description="Video files from camera, downloads, and messaging apps.",
        axiom_name_hints=("videos", "video"),
        path_markers=("dcim", "camera", "movies", "video"),
        extensions=_VIDEO_EXT,
    ),
    MobileFamily(
        key="audio",
        label="Audio",
        category="Media",
        description="Audio / voice-note files.",
        axiom_name_hints=("audio",),
        path_markers=("audio", "voice", "recordings", "music"),
        extensions=_AUDIO_EXT,
    ),
    MobileFamily(
        key="documents",
        label="Downloaded Documents",
        category="Documents",
        description="Office/PDF/text documents from Downloads and shared storage.",
        axiom_name_hints=("documents", "pdf", "microsoft word", "microsoft excel"),
        path_markers=("download", "documents", "docs"),
        extensions=_DOC_EXT,
    ),
    MobileFamily(
        key="databases",
        label="Application Databases",
        category="Operating System",
        description="SQLite and other app databases recovered from the extraction.",
        axiom_name_hints=("sqlite", "database"),
        extensions=_DB_EXT,
        path_markers=(".db",),
    ),
)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _path_blob(row: dict[str, Any]) -> str:
    return f"{row.get('file_path') or ''} {row.get('file_name') or ''}".lower().replace("\\", "/")


def _ext_of(row: dict[str, Any]) -> str:
    ext = (row.get("extension") or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    if ext:
        return ext
    name = str(row.get("file_name") or row.get("file_path") or "")
    return Path(name).suffix.lower()


def _family_matches(family: MobileFamily, row: dict[str, Any]) -> bool:
    blob = _path_blob(row)
    ext = _ext_of(row)
    name = str(row.get("file_name") or "").lower()

    if family.extensions and ext in family.extensions:
        # Avoid classifying every image as email attachment.
        if family.key == "email_attachments":
            return "attach" in blob or "/mail/" in blob or "email" in blob
        if family.key in {"pictures", "videos", "audio", "documents", "databases", "email"}:
            return True

    for marker in family.path_markers:
        if marker.lower() in blob:
            return True
    for marker in family.name_markers:
        if marker.lower() in name or marker.lower() in blob:
            return True
    return False


def _load_job_files(db, job_id: str) -> list[dict[str, Any]]:
    return fetchall(
        db,
        """SELECT id, file_path, file_name, extension, size_bytes
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )


def _acquisition_methods(db, job_id: str) -> list[str]:
    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = job.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        ds = {}
    methods = ds.get("acquisition_methods") or ds.get("methods") or []
    if isinstance(methods, list):
        return [str(m) for m in methods]
    summary = ds.get("collection_summary") or {}
    if isinstance(summary, dict) and summary.get("methods"):
        return [str(m) for m in summary["methods"]]
    return []


def classify_mobile_artifacts(db, job_id: str) -> dict[str, Any]:
    """Return board rows: count, description, sample paths, artifact ids for open."""
    files = _load_job_files(db, job_id)
    methods = _acquisition_methods(db, job_id)
    mtp_only = bool(methods) and all(m in {"mtp_logical", "none"} for m in methods)

    rows_out: list[dict[str, Any]] = []
    for family in MOBILE_FAMILIES:
        matched = [f for f in files if _family_matches(family, f)]
        # Deduplicate WhatsApp media vs messages: messages prefer DBs.
        if family.key == "whatsapp_messages":
            matched = [
                f
                for f in matched
                if _ext_of(f) in _DB_EXT
                or any(x in _path_blob(f) for x in ("msgstore", "wa.db", "chatstorage"))
            ]
        if family.key == "whatsapp_media":
            matched = [
                f
                for f in matched
                if _ext_of(f) not in _DB_EXT
                and "whatsapp" in _path_blob(f)
            ]
        if family.key == "whatsapp_calls":
            matched = [
                f
                for f in matched
                if "call" in _path_blob(f) and "whatsapp" in _path_blob(f)
            ]

        sample = matched[:12]
        paths = [str(f.get("file_path") or f.get("file_name") or "") for f in sample]
        artifact_ids = [str(f["id"]) for f in sample if f.get("id")]
        count = len(matched)
        available = count > 0
        note = ""
        if not available:
            note = family.locked_note
            if mtp_only and family.requires_db:
                note = (
                    "Unavailable on this MTP/logical acquisition. Unlock the device and use "
                    "ADB backup / idevicebackup2 / UFED import to recover this artifact family."
                )

        rows_out.append(
            {
                "key": family.key,
                "label": family.label,
                "category": family.category,
                "count": count,
                "description": family.description if available else f"{family.description} {note}".strip(),
                "available": available,
                "sample_paths": paths,
                "primary_path": paths[0] if paths else None,
                "artifact_ids": artifact_ids,
                "primary_artifact_id": artifact_ids[0] if artifact_ids else None,
                "axiom_name_hints": list(family.axiom_name_hints),
                "limitation": note if not available else None,
            }
        )

    total_files = len(files)
    available_families = sum(1 for r in rows_out if r["available"])
    return {
        "job_id": job_id,
        "total_files": total_files,
        "families_available": available_families,
        "families_total": len(rows_out),
        "acquisition_methods": methods,
        "mtp_only": mtp_only,
        "rows": rows_out,
        "note": (
            "Counts reflect files present in the registered extraction. "
            "Locked phones over USB/MTP typically expose media only — not WhatsApp/SMS databases."
        ),
    }


def count_mobile_family_for_axiom_name(db, job_id: str, artifact_name: str) -> tuple[int, list[str], list[str]]:
    """Map an AXIOM artifact name to a mobile family count + sample paths + artifact ids."""
    name = _norm(artifact_name)
    board = classify_mobile_artifacts(db, job_id)
    best: dict[str, Any] | None = None
    for row in board["rows"]:
        hints = [_norm(h) for h in row.get("axiom_name_hints") or []]
        label = _norm(row.get("label") or "")
        if name == label or name in hints or any(h and (h in name or name in h) for h in hints):
            # Prefer exact-ish matches
            if name == label or name in hints:
                best = row
                break
            if best is None:
                best = row
    if not best:
        # Media fallbacks by keyword
        if "picture" in name or "photo" in name:
            best = next((r for r in board["rows"] if r["key"] == "pictures"), None)
        elif "video" in name:
            best = next((r for r in board["rows"] if r["key"] == "videos"), None)
        elif name == "audio":
            best = next((r for r in board["rows"] if r["key"] == "audio"), None)
        elif "whatsapp" in name and "call" in name:
            best = next((r for r in board["rows"] if r["key"] == "whatsapp_calls"), None)
        elif "whatsapp" in name:
            best = next((r for r in board["rows"] if r["key"] == "whatsapp_messages"), None)
        elif "sms" in name or "mms" in name:
            best = next((r for r in board["rows"] if r["key"] == "sms"), None)
        elif "call log" in name:
            best = next((r for r in board["rows"] if r["key"] == "call_logs"), None)
        elif "installed" in name and "app" in name:
            best = next((r for r in board["rows"] if r["key"] == "installed_apps"), None)
        elif "device information" in name:
            best = next((r for r in board["rows"] if r["key"] == "device_info"), None)
        elif "sim" in name:
            best = next((r for r in board["rows"] if r["key"] == "sim_info"), None)
        elif "linkedin" in name:
            best = next((r for r in board["rows"] if r["key"] == "linkedin"), None)
        elif "account" in name:
            best = next((r for r in board["rows"] if r["key"] == "accounts"), None)
    if not best:
        return 0, [], []
    return (
        int(best.get("count") or 0),
        list(best.get("sample_paths") or []),
        list(best.get("artifact_ids") or []),
    )


def persist_mobile_board_to_disk_source(db, job_id: str) -> dict[str, Any]:
    """Cache board summary on jobs.disk_source for quick UI/report use."""
    board = classify_mobile_artifacts(db, job_id)
    job = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = job.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        ds = {}
    ds["mobile_artifact_board"] = {
        "total_files": board["total_files"],
        "families_available": board["families_available"],
        "families_total": board["families_total"],
        "acquisition_methods": board["acquisition_methods"],
        "rows": [
            {
                "key": r["key"],
                "label": r["label"],
                "category": r["category"],
                "count": r["count"],
                "description": r["description"],
                "primary_path": r["primary_path"],
                "primary_artifact_id": r["primary_artifact_id"],
                "available": r["available"],
                "limitation": r.get("limitation"),
            }
            for r in board["rows"]
        ],
    }
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
        {"ds": json.dumps(ds), "jid": job_id},
    )
    return board
