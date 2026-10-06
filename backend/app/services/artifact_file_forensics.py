"""Deleted / modified / anomalous file forensics for Windows, iOS, and Linux.

Classifies extracted files for examiner browse tabs:
  All | Deleted | Photos | Videos | Documents | Extensionless | Anomalous | Modified | With dates

Uses path trash markers, recycle/trash metadata, magic-byte mismatch, and
extension anomalies so even small or renamed files stay in scope.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from app.services.deleted_evidence import detect_deleted_path_hint

_IMAGE_EXTS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff", ".ico", ".raw", ".cr2", ".nef",
})
_VIDEO_EXTS = frozenset({
    ".mp4", ".mkv", ".3gp", ".mov", ".avi", ".m4v", ".webm", ".wmv", ".flv", ".mpeg", ".mpg",
})
_AUDIO_EXTS = frozenset({
    ".mp3", ".m4a", ".aac", ".wav", ".opus", ".ogg", ".amr", ".flac", ".wma", ".aiff",
})
_DOC_EXTS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf",
    ".odt", ".ods", ".odp", ".pages", ".numbers", ".key", ".md", ".json", ".xml", ".html", ".htm",
})
_ARCHIVE_EXTS = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz"})
_EXEC_EXTS = frozenset({".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".msi", ".scr", ".com", ".apk", ".dex", ".so"})

# magic prefix (hex) → (detected_ext, kind)
_MAGIC_MAP: list[tuple[bytes, str, str]] = [
    (b"\xff\xd8\xff", ".jpg", "image"),
    (b"\x89PNG\r\n\x1a\n", ".png", "image"),
    (b"GIF87a", ".gif", "image"),
    (b"GIF89a", ".gif", "image"),
    (b"RIFF", ".webp", "image"),  # refined below for WEBP/AVI/WAV
    (b"BM", ".bmp", "image"),
    (b"\x00\x00\x00\x18ftypheic", ".heic", "image"),
    (b"\x00\x00\x00\x1cftypheic", ".heic", "image"),
    (b"\x00\x00\x00 ftypheic", ".heic", "image"),
    (b"\x00\x00\x00\x14ftypqt", ".mov", "video"),
    (b"\x00\x00\x00\x18ftypmp4", ".mp4", "video"),
    (b"\x00\x00\x00\x1cftypmp4", ".mp4", "video"),
    (b"\x00\x00\x00 ftypisom", ".mp4", "video"),
    (b"\x00\x00\x00\x18ftypiso", ".mp4", "video"),
    (b"\x1aE\xdf\xa3", ".mkv", "video"),
    (b"%PDF", ".pdf", "document"),
    (b"PK\x03\x04", ".zip", "archive"),  # also office xml — refined
    (b"\xd0\xcf\x11\xe0", ".doc", "document"),  # OLE
    (b"SQLite format 3", ".db", "database"),
    (b"MZ", ".exe", "executable"),
    (b"\x7fELF", ".so", "executable"),
    (b"\xca\xfe\xba\xbe", ".class", "executable"),
    (b"{\\rtf", ".rtf", "document"),
    (b"#!", ".sh", "script"),
]

_DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|gif|txt|csv|zip|rar)\.(exe|dll|scr|bat|cmd|ps1|js|vbs|apk)$",
    re.I,
)

_FILE_FORENSIC_FAMILIES = frozenset({
    "critical_files",
    "anomalous_files",
    "modified_files",
    "deleted_files",
    "deleted_photos",
    "deleted_videos",
    "deleted_documents",
    "deleted_with_dates",
})


def family_supports_file_forensics(family: str | None) -> bool:
    return (family or "").strip().lower() in _FILE_FORENSIC_FAMILIES


def _norm_ext(ext: str | None) -> str:
    e = (ext or "").strip().lower()
    if not e or e in {".", "(none)", "none", "null"}:
        return ""
    return e if e.startswith(".") else f".{e}"


def _ext_from_name(name: str | None, path: str | None = None) -> str:
    base = (name or PurePosixPath((path or "").replace("\\", "/")).name or "").strip()
    # Android .trashed-<ts>-name.ext
    if base.lower().startswith(".trashed-"):
        parts = base.split("-", 2)
        if len(parts) >= 3:
            base = parts[2]
    return _norm_ext(PurePosixPath(base).suffix)


def detect_type_from_magic(magic_hex: str | None, head: bytes | None = None) -> tuple[str | None, str | None]:
    """Return (detected_extension, kind) from magic hex or raw head bytes."""
    raw = head
    if raw is None and magic_hex:
        try:
            raw = bytes.fromhex(str(magic_hex).strip())
        except ValueError:
            raw = None
    if not raw:
        return None, None
    # RIFF refinement
    if raw.startswith(b"RIFF") and len(raw) >= 12:
        kind4 = raw[8:12]
        if kind4 == b"WEBP":
            return ".webp", "image"
        if kind4 == b"AVI ":
            return ".avi", "video"
        if kind4 == b"WAVE":
            return ".wav", "audio"
    # ZIP / Office
    if raw.startswith(b"PK\x03\x04"):
        # Cannot fully distinguish without zip central dir; treat as archive/document.
        return ".zip", "archive"
    # ftyp brands anywhere in first 32 bytes
    if b"ftypheic" in raw[:32] or b"ftypmif1" in raw[:32]:
        return ".heic", "image"
    if b"ftypmp4" in raw[:32] or b"ftypisom" in raw[:32] or b"ftypiso" in raw[:32]:
        return ".mp4", "video"
    if b"ftypqt" in raw[:32]:
        return ".mov", "video"
    for magic, ext, kind in _MAGIC_MAP:
        if raw.startswith(magic):
            return ext, kind
    return None, None


def kind_from_ext(ext: str) -> str | None:
    e = _norm_ext(ext)
    if not e:
        return None
    if e in _IMAGE_EXTS:
        return "image"
    if e in _VIDEO_EXTS:
        return "video"
    if e in _AUDIO_EXTS:
        return "audio"
    if e in _DOC_EXTS:
        return "document"
    if e in _ARCHIVE_EXTS:
        return "archive"
    if e in _EXEC_EXTS:
        return "executable"
    if e in {".db", ".sqlite", ".sqlite3", ".sqlitedb"}:
        return "database"
    return "other"


def _is_extensionless(ext: str, name: str) -> bool:
    if _norm_ext(ext):
        return False
    base = (name or "").strip().lower()
    if not base:
        return True
    # Known extensionless system/forensic names still count as evidence.
    return True


def _is_modified_meta(meta: dict[str, Any], path: str) -> bool:
    if meta.get("is_modified") or meta.get("modified_at"):
        return True
    if str(meta.get("recovery_state") or "").lower() in {"mft_deleted", "unallocated"}:
        # Recovered from filesystem structures — treat as modified/deleted critical.
        return True
    p = (path or "").replace("\\", "/").lower()
    if "zone.identifier" in p or ":zone.identifier" in p:
        return True
    # Original name/path differs from current (recycle / trash rename).
    original = str(meta.get("original_name") or meta.get("original_path") or "")
    current = str(meta.get("file_name") or PurePosixPath(p).name or "")
    if original and current:
        o_base = PurePosixPath(original.replace("\\", "/")).name.lower()
        c_base = current.lower()
        # $I/$R recycle names always count as renamed recoveries when original is known.
        if o_base and c_base and o_base != c_base:
            return True
    # Timestamp anomaly when both present
    mtime = meta.get("mtime") or meta.get("modified_time") or meta.get("last_write")
    ctime = meta.get("ctime") or meta.get("created_time") or meta.get("created")
    if mtime and ctime and str(mtime) < str(ctime):
        return True
    return False


def classify_file_row(row: dict[str, Any]) -> dict[str, Any]:
    """Enrich a job_artifact-shaped row with forensic file classification."""
    out = dict(row)
    meta = dict(out.get("metadata") or {}) if isinstance(out.get("metadata"), dict) else {}
    path = str(out.get("source_path") or out.get("file_path") or meta.get("source_path") or "")
    name = str(out.get("file_name") or out.get("title") or PurePosixPath(path.replace("\\", "/")).name or "")
    declared = _norm_ext(out.get("extension") or meta.get("extension") or _ext_from_name(name, path))
    # Prefer original extension from Recycle Bin / trash.info when current is $R / .trashed
    original_name = str(meta.get("original_name") or "")
    original_path = str(meta.get("original_path") or "")
    original_ext = _ext_from_name(original_name, original_path)

    magic_hex = meta.get("magic_hex")
    detected_ext, detected_kind = detect_type_from_magic(
        str(magic_hex) if magic_hex else None,
    )
    if not detected_kind and declared:
        detected_kind = kind_from_ext(declared)
    if not detected_kind and original_ext:
        detected_kind = kind_from_ext(original_ext)

    effective_ext = declared or original_ext or detected_ext or ""
    kind = detected_kind or kind_from_ext(effective_ext) or "unknown"

    deleted_hint = detect_deleted_path_hint(path) or {}
    is_deleted = bool(
        meta.get("is_deleted")
        or meta.get("deleted_at")
        or deleted_hint.get("is_deleted")
        or str(meta.get("recovery_state") or "") in {
            "recycle_bin", "trashed", "sqlite_freelist", "unallocated", "mft_deleted", "social_deleted", "linux_trash",
        }
    )
    if deleted_hint and not meta.get("recovery_state"):
        meta["recovery_state"] = deleted_hint.get("recovery_state")

    extensionless = _is_extensionless(declared, name)

    def _ext_equiv(a: str, b: str) -> bool:
        aliases = {
            ".jpeg": ".jpg",
            ".jpg": ".jpg",
            ".htm": ".html",
            ".html": ".html",
            ".sqlite": ".db",
            ".sqlite3": ".db",
            ".db": ".db",
        }
        return aliases.get(a, a) == aliases.get(b, b)

    mismatch = False
    if detected_ext and declared and not _ext_equiv(detected_ext, declared):
        if not (detected_ext == ".zip" and declared in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}):
            mismatch = True
    # Declared executable/document but magic says image/video — always mismatch.
    if detected_kind and declared:
        decl_kind = kind_from_ext(declared)
        if decl_kind and detected_kind != decl_kind and {decl_kind, detected_kind} != {"archive", "document"}:
            mismatch = True
    # Recycle/trash original extension differs from current name (renamed / spoofed).
    if original_ext and declared and not _ext_equiv(original_ext, declared):
        mismatch = True
    if original_ext and detected_ext and not _ext_equiv(original_ext, detected_ext):
        mismatch = True

    double_ext = bool(_DOUBLE_EXT.search(name))
    anomalous = bool(extensionless or mismatch or double_ext)
    modified = _is_modified_meta(meta, path)
    with_dates = bool(meta.get("deleted_at"))

    # Platform hint from path
    platform = "unknown"
    pl = path.replace("\\", "/").lower()
    if "$recycle.bin" in pl or "/users/" in pl or "ntuser.dat" in pl or "/windows/" in pl:
        platform = "windows"
    elif "/.trash" in pl or "appdomain-" in pl or "/private/var/" in pl or "ios" in pl:
        platform = "ios" if ("appdomain-" in pl or "/private/var/" in pl) else "linux"
    elif "/home/" in pl or "/.local/share/trash" in pl:
        platform = "linux"

    meta.update(
        {
            "evidence_kind": meta.get("evidence_kind") or "file",
            "declared_extension": declared or None,
            "original_extension": original_ext or None,
            "detected_extension": detected_ext,
            "detected_kind": kind,
            "extension_mismatch": mismatch,
            "extensionless": extensionless,
            "double_extension": double_ext,
            "is_anomalous": anomalous,
            "is_deleted": is_deleted or bool(meta.get("is_deleted")),
            "is_modified": modified,
            "has_deleted_date": with_dates,
            "forensic_platform": meta.get("forensic_platform") or platform,
            "recovery_state": meta.get("recovery_state") or deleted_hint.get("recovery_state"),
            "file_forensics": {
                "kind": kind,
                "deleted": is_deleted,
                "modified": modified,
                "anomalous": anomalous,
                "extensionless": extensionless,
                "extension_mismatch": mismatch,
                "double_extension": double_ext,
                "with_deleted_date": with_dates,
                "declared_extension": declared or None,
                "detected_extension": detected_ext,
                "original_extension": original_ext or None,
                "platform": platform,
            },
        }
    )
    tags = list(out.get("tags") or [])
    for t in ("deleted", "anomalous", "modified", "extensionless", "extension_mismatch"):
        flag = {
            "deleted": is_deleted,
            "anomalous": anomalous,
            "modified": modified,
            "extensionless": extensionless,
            "extension_mismatch": mismatch,
        }[t]
        if flag and t not in [str(x).lower() for x in tags]:
            tags.append(t)
    out["metadata"] = meta
    out["tags"] = tags
    if not out.get("extension"):
        out["extension"] = declared or detected_ext or original_ext or None
    return out


def filter_file_rows(rows: list[dict[str, Any]], file_filter: str | None) -> list[dict[str, Any]]:
    """Apply examiner tab filter to enriched file rows."""
    ff = (file_filter or "all").strip().lower()
    enriched = [classify_file_row(r) for r in rows]
    if ff in {"", "all", "all_files", "everything"}:
        return enriched

    out: list[dict[str, Any]] = []
    for row in enriched:
        meta = row.get("metadata") or {}
        ff_meta = meta.get("file_forensics") if isinstance(meta.get("file_forensics"), dict) else {}
        kind = str(ff_meta.get("kind") or meta.get("detected_kind") or "")
        deleted = bool(ff_meta.get("deleted") or meta.get("is_deleted"))
        if ff in {"deleted", "trash", "recycle"}:
            if deleted:
                out.append(row)
        elif ff in {"photos", "images", "picture", "pictures"}:
            # Deleted/anomalous images (incl. spoofed/extensionless detected as image).
            if kind == "image" and (deleted or meta.get("is_anomalous") or meta.get("extension_mismatch")):
                out.append(row)
        elif ff in {"videos", "video"}:
            if kind == "video" and (deleted or meta.get("is_anomalous") or meta.get("extension_mismatch")):
                out.append(row)
        elif ff in {"documents", "docs", "document"}:
            if kind in {"document", "archive"} and (
                deleted or meta.get("is_anomalous") or meta.get("extension_mismatch")
            ):
                out.append(row)
        elif ff in {"extensionless", "no_extension"}:
            if meta.get("extensionless") or ff_meta.get("extensionless"):
                out.append(row)
        elif ff in {"anomalous", "anomaly", "spoofed", "mismatch"}:
            if meta.get("is_anomalous") or ff_meta.get("anomalous"):
                out.append(row)
        elif ff in {"modified", "modifications"}:
            if meta.get("is_modified") or ff_meta.get("modified"):
                out.append(row)
        elif ff in {"with_dates", "dated", "deleted_with_dates"}:
            if meta.get("has_deleted_date") or meta.get("deleted_at"):
                out.append(row)
        elif ff in {"audio"}:
            if kind == "audio" and deleted:
                out.append(row)
        else:
            out.append(row)
    return out


def build_file_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Tab badge counts for the file forensics shell."""
    enriched = [classify_file_row(r) for r in rows]
    summary = {
        "total": len(enriched),
        "deleted": 0,
        "photos": 0,
        "videos": 0,
        "documents": 0,
        "audio": 0,
        "extensionless": 0,
        "anomalous": 0,
        "modified": 0,
        "with_dates": 0,
        "platforms": {},
    }
    platforms: dict[str, int] = {}
    for row in enriched:
        meta = row.get("metadata") or {}
        ff = meta.get("file_forensics") if isinstance(meta.get("file_forensics"), dict) else {}
        kind = str(ff.get("kind") or "")
        deleted = bool(ff.get("deleted"))
        if deleted:
            summary["deleted"] += 1
        if kind == "image" and (deleted or ff.get("anomalous")):
            summary["photos"] += 1
        if kind == "video" and (deleted or ff.get("anomalous")):
            summary["videos"] += 1
        if kind in {"document", "archive"} and (deleted or ff.get("anomalous")):
            summary["documents"] += 1
        if kind == "audio" and deleted:
            summary["audio"] += 1
        if ff.get("extensionless"):
            summary["extensionless"] += 1
        if ff.get("anomalous"):
            summary["anomalous"] += 1
        if ff.get("modified"):
            summary["modified"] += 1
        if ff.get("with_deleted_date") or meta.get("deleted_at"):
            summary["with_dates"] += 1
        plat = str(ff.get("platform") or "unknown")
        platforms[plat] = platforms.get(plat, 0) + 1
    summary["platforms"] = platforms
    return summary


def critical_files_where_sql() -> tuple[str, dict]:
    """SQL fragment: deleted/trash OR extensionless OR known anomalous markers."""
    sql = """ AND (
      coalesce(metadata->>'is_deleted','') IN ('true','1','t')
      OR metadata ? 'deleted_at'
      OR coalesce(metadata->>'is_modified','') IN ('true','1','t')
      OR coalesce(metadata->>'extension_mismatch','') IN ('true','1','t')
      OR coalesce(metadata->>'is_anomalous','') IN ('true','1','t')
      OR coalesce(metadata->>'extensionless','') IN ('true','1','t')
      OR lower(replace(file_path,'\\\\','/')) LIKE '%$recycle.bin%'
      OR lower(replace(file_path,'\\\\','/')) LIKE '%/.trash%'
      OR lower(replace(file_path,'\\\\','/')) LIKE '%/.trashes%'
      OR lower(replace(file_path,'\\\\','/')) LIKE '%/trash/%'
      OR lower(replace(file_path,'\\\\','/')) LIKE '%/trashinfo%'
      OR lower(replace(file_path,'\\\\','/')) LIKE '%deleted_recovery%'
      OR lower(replace(file_path,'\\\\','/')) LIKE '%lost+found%'
      OR lower(file_name) LIKE '.trashed-%'
      OR lower(file_name) LIKE '.$trashed%'
      OR lower(file_name) LIKE '%.trashinfo'
      OR lower(file_name) LIKE 'zone.identifier'
      OR lower(file_name) LIKE '%\\:zone.identifier%'
      OR coalesce(nullif(trim(extension), ''), '') = ''
      OR lower(coalesce(extension,'')) IN ('.', '(none)', 'none')
    )"""
    return sql, {}


def anomalous_files_where_sql() -> tuple[str, dict]:
    sql = """ AND (
      coalesce(metadata->>'extension_mismatch','') IN ('true','1','t')
      OR coalesce(metadata->>'is_anomalous','') IN ('true','1','t')
      OR coalesce(metadata->>'extensionless','') IN ('true','1','t')
      OR coalesce(nullif(trim(extension), ''), '') = ''
      OR lower(coalesce(extension,'')) IN ('.', '(none)', 'none')
      OR lower(file_name) ~* '\\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip)\\.(exe|dll|scr|bat|cmd|ps1|js|vbs|apk)$'
    )"""
    return sql, {}


def modified_files_where_sql() -> tuple[str, dict]:
    sql = """ AND (
      coalesce(metadata->>'is_modified','') IN ('true','1','t')
      OR metadata ? 'modified_at'
      OR coalesce(metadata->>'recovery_state','') IN ('mft_deleted', 'unallocated')
      OR lower(file_name) LIKE '%zone.identifier%'
      OR (
        metadata ? 'original_name'
        AND coalesce(metadata->>'original_name','') <> ''
        AND coalesce(metadata->>'original_name','') <> coalesce(file_name,'')
      )
    )"""
    return sql, {}
