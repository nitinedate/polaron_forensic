"""Deleted / recovered evidence helpers for disk and mobile jobs.

Surfaces Recycle Bin, trashed media, SQLite freelist residuals, and social-app
deleted markers with `deleted_at` metadata used for titles like:
  report.docx (deleted 2024-03-15)
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import fetchall, fetchone

_TRASH_MARKERS = (
    "$recycle.bin/",
    "/recycle.bin/",
    "/.trash/",
    "/.trashes/",
    "/trash/",
    "/.trash-",
    "deleted_recovery/",
    "/lost+found/",
)
_TRASH_NAME_PREFIXES = (".trashed-", ".$trashed", "$i", "$r")
_SOCIAL_MARKERS = (
    "whatsapp",
    "telegram",
    "signal",
    "instagram",
    "facebook",
    "messenger",
    "linkedin",
    "snapchat",
    "tiktok",
    "discord",
    "viber",
    "wechat",
    "line/",
    "skype",
    "slack",
    "teams",
    "org.telegram",
    "org.thoughtcrime",
    "com.instagram",
    "com.facebook",
    "com.whatsapp",
    "net.whatsapp",
    "com.snapchat",
    "com.discord",
    "com.linkedin",
    "jp.naver.line",
)

_IMAGE_EXTS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".tif", ".tiff"})
_VIDEO_EXTS = frozenset({".mp4", ".mkv", ".3gp", ".mov", ".avi", ".m4v", ".webm"})
_DOC_EXTS = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"})


def format_deleted_date_bracket(deleted_at: str | None) -> str:
    """Return `(deleted YYYY-MM-DD)` or `(deleted)` when date unknown."""
    if not deleted_at:
        return "(deleted)"
    raw = str(deleted_at).strip()
    if not raw:
        return "(deleted)"
    # Already ISO-ish
    day = raw[:10]
    if re.match(r"^\d{4}-\d{2}-\d{2}$", day):
        return f"(deleted {day})"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return f"(deleted {dt.date().isoformat()})"
    except ValueError:
        pass
    # Unix ms / s heuristics
    try:
        n = float(raw)
        if n > 1e12:
            n /= 1000.0
        if n > 1e9:
            return f"(deleted {datetime.utcfromtimestamp(n).date().isoformat()})"
    except (TypeError, ValueError, OSError, OverflowError):
        pass
    return "(deleted)"


def title_with_deleted_date(file_name: str | None, metadata: dict[str, Any] | None) -> str:
    """Append deleted date bracket to display title when metadata marks deletion."""
    name = (file_name or "").strip() or "file"
    meta = metadata if isinstance(metadata, dict) else {}
    if not meta.get("is_deleted") and not meta.get("deleted_at") and meta.get("recovery_state") not in {
        "recycle_bin",
        "trashed",
        "sqlite_freelist",
        "unallocated",
        "mft_deleted",
        "social_deleted",
    }:
        return name
    # Avoid double-appending
    if re.search(r"\(deleted(?:\s+\d{4}-\d{2}-\d{2})?\)$", name, re.I):
        return name
    return f"{name} {format_deleted_date_bracket(meta.get('deleted_at'))}"


def detect_deleted_path_hint(path: str) -> dict[str, Any] | None:
    """Path-based deleted/trash hint used at materialize time (before $I parse)."""
    norm = (path or "").replace("\\", "/").lower()
    if not norm:
        return None
    name = PurePosixPath(norm).name
    recovery_state = None
    if "$recycle.bin" in norm or "/recycle.bin/" in norm:
        recovery_state = "recycle_bin"
    elif any(m in norm for m in _TRASH_MARKERS):
        recovery_state = "trashed"
    elif name.startswith(_TRASH_NAME_PREFIXES):
        recovery_state = "trashed"
    elif "deleted_recovery" in norm:
        recovery_state = "sqlite_freelist"
    if not recovery_state:
        return None
    social = next((m for m in _SOCIAL_MARKERS if m in norm), None)
    meta: dict[str, Any] = {
        "is_deleted": True,
        "recovery_state": recovery_state,
        "deleted_source": "path_hint",
    }
    if name.startswith("$i"):
        meta["recycle_descriptor"] = True
    if name.startswith("$r"):
        meta["recycle_payload"] = True
    if social:
        meta["social_app"] = social.rstrip("/")
        if recovery_state in {"trashed", "sqlite_freelist"}:
            meta["recovery_state"] = "social_deleted"
    return meta


def metadata_from_parse_records(records: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Pull deleted_* fields from parser output into job_artifacts.metadata."""
    out: dict[str, Any] = {}
    if not records:
        return out
    for rec in records:
        if not isinstance(rec, dict):
            continue
        rtype = str(rec.get("record_type") or "")
        if rtype in {
            "recycle_bin_item",
            "linux_trash_item",
            "whatsapp_message_deleted",
            "social_message_deleted",
            "deleted_file",
            "sqlite_deleted_residual",
            "file_metadata",
        } or rec.get("is_deleted"):
            if rtype != "file_metadata" or rec.get("is_deleted"):
                if rec.get("is_deleted") or rtype in {
                    "recycle_bin_item",
                    "linux_trash_item",
                    "whatsapp_message_deleted",
                    "social_message_deleted",
                    "deleted_file",
                    "sqlite_deleted_residual",
                }:
                    out["is_deleted"] = True
            if rec.get("deleted_at") and not out.get("deleted_at"):
                out["deleted_at"] = rec.get("deleted_at")
            if rec.get("original_path") and not out.get("original_path"):
                out["original_path"] = rec.get("original_path")
            if rec.get("original_name") and not out.get("original_name"):
                out["original_name"] = rec.get("original_name")
            if rec.get("original_extension") and not out.get("original_extension"):
                out["original_extension"] = rec.get("original_extension")
            if rec.get("recovery_state") and not out.get("recovery_state"):
                out["recovery_state"] = rec.get("recovery_state")
            if rec.get("social_app") and not out.get("social_app"):
                out["social_app"] = rec.get("social_app")
            if rec.get("is_modified"):
                out["is_modified"] = True
            if rec.get("magic_hex") and not out.get("magic_hex"):
                out["magic_hex"] = rec.get("magic_hex")
            if rtype == "recycle_bin_item":
                out["recovery_state"] = "recycle_bin"
                out["is_modified"] = True
            if rtype == "linux_trash_item":
                out["recovery_state"] = "linux_trash"
                out["is_modified"] = True
            if rtype.startswith("whatsapp"):
                out["social_app"] = out.get("social_app") or "whatsapp"
            if rtype == "sqlite_deleted_residual":
                out["recovery_state"] = out.get("recovery_state") or "sqlite_freelist"
                out.setdefault("carved_strings", rec.get("carved_count"))
    return out


def merge_metadata(existing: Any, patch: dict[str, Any]) -> dict[str, Any]:
    base = existing if isinstance(existing, dict) else {}
    if isinstance(existing, str):
        try:
            base = json.loads(existing)
        except Exception:
            base = {}
    merged = dict(base)
    for k, v in (patch or {}).items():
        if v is None:
            continue
        if k not in merged or merged.get(k) in (None, "", {}, []):
            merged[k] = v
        elif k == "is_deleted":
            merged[k] = bool(merged.get(k) or v)
    return merged


def count_deleted_job_artifacts(db, job_id: str) -> dict[str, Any]:
    """Aggregate deleted evidence across disk + mobile indexed artifacts."""
    rows = fetchall(
        db,
        """SELECT id, file_path, file_name, metadata
           FROM job_artifacts
           WHERE job_id=:jid
             AND (
               coalesce(metadata->>'is_deleted','') IN ('true','1','t')
               OR metadata ? 'deleted_at'
               OR lower(replace(file_path,'\\\\','/')) LIKE '%$recycle.bin%'
               OR lower(replace(file_path,'\\\\','/')) LIKE '%/.trash%'
               OR lower(replace(file_path,'\\\\','/')) LIKE '%/trash/%'
               OR lower(file_name) LIKE '.trashed-%'
               OR lower(replace(file_path,'\\\\','/')) LIKE '%deleted_recovery%'
             )""",
        {"jid": job_id},
    )
    total = 0
    recycle = 0
    social = 0
    whatsapp = 0
    with_dates = 0
    deleted_photos = 0
    deleted_videos = 0
    deleted_documents = 0
    by_app: dict[str, int] = {}
    samples: list[dict[str, Any]] = []
    for r in rows:
        total += 1
        meta = r.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        path = str(r.get("file_path") or "").replace("\\", "/").lower()
        name = str(r.get("file_name") or "")
        state = str(meta.get("recovery_state") or "")
        app = str(meta.get("social_app") or "")
        if state == "recycle_bin" or "$recycle.bin" in path or name.lower().startswith("$i"):
            recycle += 1
        if app or any(m in path for m in _SOCIAL_MARKERS):
            social += 1
            app_key = app or next((m for m in _SOCIAL_MARKERS if m in path), "social")
            app_key = app_key.rstrip("/")
            by_app[app_key] = by_app.get(app_key, 0) + 1
        if "whatsapp" in path or app == "whatsapp":
            whatsapp += 1
        if meta.get("deleted_at"):
            with_dates += 1
        ext = PurePosixPath(name or path).suffix.lower()
        if ext in _IMAGE_EXTS:
            deleted_photos += 1
        elif ext in _VIDEO_EXTS:
            deleted_videos += 1
        elif ext in _DOC_EXTS:
            deleted_documents += 1
        if len(samples) < 20:
            samples.append({
                "id": str(r["id"]),
                "file_name": name,
                "file_path": r.get("file_path"),
                "deleted_at": meta.get("deleted_at"),
                "original_path": meta.get("original_path"),
                "recovery_state": state or None,
                "social_app": app or None,
                "title": title_with_deleted_date(
                    meta.get("original_name") or name,
                    meta if meta.get("is_deleted") or meta.get("deleted_at") else {
                        **meta,
                        "is_deleted": True,
                    },
                ),
            })
    # Parsed recycle-bin / deleted message records (may exceed path hits)
    parse_recycle = fetchone(
        db,
        """SELECT count(*) c
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid
             AND (
               apr.normalized::text ILIKE '%recycle_bin_item%'
               OR apr.parser_name = 'recycle_bin'
             )""",
        {"jid": job_id},
    )
    # WhatsApp deleted count must come from actual recovered/deleted message
    # records.  Do NOT count every ``mobile_deleted_pipeline`` parse result: that
    # previously made encrypted backup/file counts look like deleted messages.
    parse_wa_del = fetchone(
        db,
        """SELECT coalesce(sum(
                    CASE
                      WHEN apr.parser_name = 'mobile_deleted_pipeline'
                       AND apr.normalized::text ILIKE '%whatsapp%'
                      THEN apr.record_count
                      WHEN apr.normalized::text ILIKE '%whatsapp_message_deleted%'
                        OR apr.normalized::text ILIKE '%whatsapp_deleted_message%'
                      THEN apr.record_count
                      ELSE 0
                    END
                  ), 0) c
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid""",
        {"jid": job_id},
    )
    parse_residual = fetchone(
        db,
        """SELECT coalesce(sum(apr.record_count), 0) c
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:jid
             AND (
               apr.parser_name = 'mobile_deleted_pipeline'
               OR apr.normalized::text ILIKE '%sqlite_deleted_residual%'
             )""",
        {"jid": job_id},
    )
    residual_n = int(parse_residual["c"]) if parse_residual else 0
    return {
        "deleted_files": total,
        "recycle_bin": max(recycle, int(parse_recycle["c"]) if parse_recycle else 0),
        "deleted_social": max(social, residual_n),
        "deleted_whatsapp": max(whatsapp, int(parse_wa_del["c"]) if parse_wa_del else 0),
        "deleted_photos": deleted_photos,
        "deleted_videos": deleted_videos,
        "deleted_documents": deleted_documents,
        "deleted_by_app": by_app,
        "with_deleted_dates": with_dates,
        "carved_chat_residuals": residual_n,
        "samples": samples,
    }


def count_critical_file_artifacts(db, job_id: str) -> dict[str, Any]:
    """Counts for Deleted / Modified / Anomalous examiner board (Win/iOS/Linux)."""
    from app.services.artifact_file_forensics import (
        anomalous_files_where_sql,
        build_file_summary,
        critical_files_where_sql,
        modified_files_where_sql,
    )

    crit_sql, _ = critical_files_where_sql()
    rows = fetchall(
        db,
        f"""SELECT id, file_path, file_name, extension, metadata, size_bytes
            FROM job_artifacts
            WHERE job_id=:jid {crit_sql}
            LIMIT 50000""",
        {"jid": job_id},
    )
    items = [
        {
            "id": str(r["id"]),
            "source_path": r.get("file_path"),
            "file_name": r.get("file_name"),
            "extension": r.get("extension"),
            "size_bytes": r.get("size_bytes"),
            "metadata": r.get("metadata") if isinstance(r.get("metadata"), dict) else {},
            "title": r.get("file_name"),
        }
        for r in rows
    ]
    summary = build_file_summary(items)

    anom_sql, _ = anomalous_files_where_sql()
    anom = fetchone(
        db,
        f"SELECT count(*)::int AS n FROM job_artifacts WHERE job_id=:jid {anom_sql}",
        {"jid": job_id},
    )
    mod_sql, _ = modified_files_where_sql()
    mod = fetchone(
        db,
        f"SELECT count(*)::int AS n FROM job_artifacts WHERE job_id=:jid {mod_sql}",
        {"jid": job_id},
    )
    return {
        "critical_files": int(summary.get("total") or 0),
        "anomalous_files": int((anom or {}).get("n") or summary.get("anomalous") or 0),
        "modified_files": int((mod or {}).get("n") or summary.get("modified") or 0),
        "extensionless": int(summary.get("extensionless") or 0),
        "file_summary": summary,
    }
