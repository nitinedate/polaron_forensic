"""Completeness/coverage accounting for mobile evidence processing."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.storage import upsert_coverage

_IMAGE = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff", ".dng", ".avif"}
_VIDEO = {".mp4", ".mkv", ".3gp", ".3gpp", ".mov", ".avi", ".m4v", ".webm", ".mpeg", ".mpg"}
_AUDIO = {".mp3", ".m4a", ".aac", ".opus", ".wav", ".amr", ".ogg", ".flac", ".3ga", ".caf"}
_DOC = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf", ".odt", ".ods", ".odp", ".pages", ".numbers", ".key", ".epub"}
_DB = {".db", ".sqlite", ".sqlite3", ".sqlitedb"}


def inventory_families(item: InventoryItem) -> set[str]:
    p = item.path.lower().replace("\\", "/")
    ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
    from app.services.mobile_forensic.parsers.files_media import file_kind
    kind = file_kind(item)
    out = {"all_files"}
    if kind:
        out.add({"image":"pictures","video":"videos","audio":"audio","document":"documents"}.get(kind,"archives"))
    if ext in _IMAGE:
        out.add("pictures")
    if ext in _VIDEO:
        out.add("videos")
    if ext in _AUDIO:
        out.add("audio")
    if ext in _DOC:
        out.add("documents")
    if ext in _DB:
        out.add("databases")
    if "/download/" in p or "/downloads/" in p or "sdcard_download" in p:
        out.add("downloads")
    if "whatsapp" in p or "com.whatsapp" in p or "net.whatsapp" in p:
        out.add("whatsapp")
        if ext in _IMAGE | _VIDEO | _AUDIO | _DOC:
            out.add("whatsapp_media")
        if "msgstore" in p or "chatstorage" in p:
            out.add("whatsapp_messages")
        if p.endswith(("-wal", "-journal", "-shm")):
            out.add("whatsapp_recovery_sources")
    if any(x in p for x in ("mmssms.db", "/sms.db", "library/sms")):
        out.add("sms")
    if any(x in p for x in ("calllog", "callhistory", "call_log")):
        out.add("call_logs")
    if any(x in p for x in ("chrome", "safari", "browser", "/history")):
        out.add("browser")
    if any(x in p for x in ("location", "consolidated.db", "fusedlocation", "places.sqlite")):
        out.add("location")
    if any(x in p for x in (".trashed-", "/.trash", "/trash/", "deleted_recovery", "/recently deleted/")):
        out.add("deleted_files")
    return out


def build_inventory_coverage(items: list[InventoryItem]) -> dict[str, dict[str, int]]:
    cov: dict[str, dict[str, int]] = {}
    for item in items:
        for key in inventory_families(item):
            row = cov.setdefault(key, {"discovered": 0, "processed": 0, "errors": 0})
            row["discovered"] += 1
            if item.status in {"parsed", "unsupported", "error"}:
                row["processed"] += 1
            if item.status == "error":
                row["errors"] += 1
    return cov


def persist_coverage_snapshot(db, job_id: str, items: list[InventoryItem], artifact_counts: dict[str, Any]) -> dict[str, Any]:
    cov = build_inventory_coverage(items)
    by_family = artifact_counts.get("by_family") or {}
    # Families that may only exist as normalized records still get a row.
    for family in by_family:
        if family and family != "(unclassified)":
            cov.setdefault(str(family), {"discovered": 0, "processed": 0, "errors": 0})

    for key, row in cov.items():
        discovered = int(row.get("discovered") or 0)
        processed = int(row.get("processed") or 0)
        errors = int(row.get("errors") or 0)
        artifacts = int(by_family.get(key) or 0)
        if discovered == 0:
            status = "available" if artifacts > 0 else "not_present"
        elif processed >= discovered and errors == 0:
            status = "complete"
        elif processed >= discovered:
            status = "complete_with_errors"
        elif processed > 0:
            status = "partial"
        else:
            status = "pending"
        upsert_coverage(
            db, job_id, key,
            discovered=discovered, processed=processed, artifacts=artifacts,
            recovered=0, errors=errors, status=status,
            details={"artifact_count": artifacts},
        )
    return cov
