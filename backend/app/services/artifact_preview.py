"""Inline artifact preview and raw content delivery."""

from __future__ import annotations


import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
from collections.abc import Iterator
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchone
from app.services.storage import get_bytes, open_object_stream, put_bytes

log = logging.getLogger("artifact_preview")

_TEXT_EXTENSIONS = frozenset({
    # .msg is Outlook OLE — handled via _MAIL_EXTENSIONS, never as raw text.
    ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".eml", ".emlx",
    ".md", ".ini", ".cfg", ".yaml", ".yml", ".sql", ".bat", ".ps1", ".vbs", ".js", ".css",
})
_IMAGE_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".heic", ".heif",
})
_DOWNLOADABLE_BINARY_EXTENSIONS = frozenset({
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",
    ".rtf", ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz",
    ".exe", ".dll", ".msi", ".apk", ".ipa", ".dmg", ".iso", ".bin",
})
_PREVIEW_TEXT_LIMIT = 120_000
_STORE_MAX_BYTES = 50_000_000
_PREVIEW_READ_MAX_BYTES = 10 * 1024 * 1024
_EMAIL_READ_MAX_BYTES = 32 * 1024 * 1024
# Forensic examiners must open large evidence (UFED media, chat DBs, archives).
_CONTENT_READ_MAX_BYTES = int(
    os.environ.get("ARTIFACT_CONTENT_MAX_BYTES", str(2 * 1024 * 1024 * 1024))
)
_CONTENT_STREAM_CHUNK = 1_048_576
_MAIL_EXTENSIONS = frozenset({".eml", ".emlx", ".msg", ".pst", ".ost", ".mbox"})


class ArtifactContentTooLargeError(Exception):
    def __init__(self, size_bytes: int, limit_bytes: int):
        self.size_bytes = size_bytes
        self.limit_bytes = limit_bytes
        super().__init__(f"Artifact content too large ({size_bytes} bytes; limit {limit_bytes})")


def _size_hint_bytes(row: dict[str, Any]) -> int | None:
    raw = row.get("size_bytes")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _format_carved_deleted_json_preview(data: bytes, path: str) -> str | None:
    """Turn carved_deleted_residuals.json into examiner-readable deleted chat rows."""
    try:
        payload = json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    if not isinstance(items, list):
        return None
    chat_items = [it for it in items if isinstance(it, dict) and it.get("chat_like")]
    rows = chat_items or [it for it in items if isinstance(it, dict)]
    lines = [
        "WhatsApp / chat deleted residuals (freelist/WAL carve)",
        f"Path: {path}",
        f"Chat-like residuals: {payload.get('chat_like_residuals') or len(chat_items)}",
        f"Recovered at: {payload.get('recovered_at') or '—'}",
        "",
        "⚠ RECOVERED / DELETED ARTIFACT",
        "",
    ]
    shown = 0
    for it in rows[:120]:
        text = str(it.get("text") or it.get("text_body") or it.get("body") or "").strip()
        if not text:
            continue
        ts = it.get("deleted_at") or it.get("timestamp") or "—"
        recovery = str(it.get("recovery_state") or "sqlite_freelist").replace("_", " ")
        lines.append(f"{ts} unknown: {text}")
        lines.append(f"  Recovery status: DELETED | Recovered from: {recovery}")
        lines.append("")
        shown += 1
    if not shown:
        lines.append("No chat-like residual text was recovered from this carve file.")
    return "\n".join(lines)


def _format_contacts_sqlite_preview(data: bytes, path: str) -> str | None:
    """Human-readable contact list from AddressBook / contacts2 SQLite."""
    try:
        from app.services.artifact_evidence_browse import _extract_contacts_from_bytes

        people = _extract_contacts_from_bytes(data, path)
    except Exception:
        return None
    if not people:
        return None
    lines = [
        "Device contacts (parsed from address book database)",
        f"Path: {path}",
        f"Contacts shown: {min(len(people), 200)} of {len(people)}",
        "",
    ]
    for p in people[:200]:
        name = p.get("display_name") or "Unknown"
        phones = ", ".join(p.get("phones") or []) or "—"
        emails = ", ".join(p.get("emails") or []) or "—"
        org = p.get("org") or "—"
        lines.append(f"{name}")
        lines.append(f"  Phone: {phones}")
        lines.append(f"  Email: {emails}")
        if org and org != "—":
            lines.append(f"  Org: {org}")
        lines.append("")
    return "\n".join(lines)


def _ensure_heif_support() -> None:
    """Register HEIC/HEIF opener once (Pillow cannot decode HEIC alone)."""
    if getattr(_ensure_heif_support, "_done", False):
        return
    try:
        from pillow_heif import register_heif_opener

        register_heif_opener()
    except Exception as exc:
        log.warning("pillow-heif unavailable — HEIC preview will fail: %s", exc)
    setattr(_ensure_heif_support, "_done", True)


def _image_preview_bytes(
    data: bytes,
    *,
    ext: str,
    content_type: str,
) -> tuple[bytes, str] | None:
    """Convert HEIC/odd formats to JPEG/PNG for browser preview when possible."""
    low_ext = (ext or "").lower()
    if not low_ext.startswith("."):
        low_ext = f".{low_ext}" if low_ext else low_ext
    needs_heif = low_ext in {".heic", ".heif"} or "heic" in (content_type or "") or "heif" in (
        content_type or ""
    )
    # Already browser-friendly — return as-is (capped by caller).
    if (
        content_type in {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp"}
        and not needs_heif
    ):
        return data, content_type
    try:
        from io import BytesIO

        from PIL import Image

        if needs_heif:
            _ensure_heif_support()
        img = Image.open(BytesIO(data))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = BytesIO()
        img.save(buf, format="JPEG", quality=85)
        return buf.getvalue(), "image/jpeg"
    except Exception as exc:
        log.debug("Image conversion skipped (%s): %s", low_ext or content_type, exc)
        return None


def _is_app_runtime_binary(path: str, name: str, data: bytes | None = None) -> bool:
    """True for APK/DEX/ART/ELF package noise — never treat as chat/media preview."""
    p = (path or "").replace("\\", "/").lower()
    n = (name or p.rsplit("/", 1)[-1] or "").lower()
    if any(
        n.endswith(ext)
        for ext in (".apk", ".dex", ".odex", ".vdex", ".art", ".oat", ".so", ".jar", ".prof")
    ):
        return True
    if ".apk@" in n or "@classes" in n or n.startswith("classes") and "dex" in n:
        return True
    if any(
        x in p
        for x in (
            "/dalvik-cache/",
            "/oat/",
            "/data/app/",
            "/preload/",
            "facebook-appmanager",
            "facebook.appmanager",
            "facebook-services",
            "facebook-installer",
        )
    ):
        return True
    if data and len(data) >= 4 and (data[:4] == b"\x7fELF" or data[:4] == b"dex\n"):
        return True
    return False


def _app_runtime_preview_text(path: str, size: int) -> str:
    return (
        "Not conversation or media content — Android app / runtime binary\n"
        f"Path: {path}\n"
        f"Size: {size:,} bytes\n\n"
        "This file is an APK, DEX, ART, ELF, or dalvik-cache object.\n"
        "It cannot be converted into chats or messages.\n\n"
        "To see actual conversations, open messaging databases under:\n"
        "  /data/data/<app>/databases/\n"
        "Examples:\n"
        "  WhatsApp → msgstore.db\n"
        "  Messenger → threads_db* / msys_database*\n"
        "  Telegram → cache4.db\n"
        "If those databases are missing from the dump, no chat text is available."
    )


def _format_plist_preview(data: bytes, path: str, *, max_items: int = 80) -> str | None:
    """Pretty-print binary/XML plist (Info.plist, preferences) instead of hex."""
    import plistlib
    from pprint import pformat

    head = data[:16]
    if not (
        head.startswith(b"bplist")
        or (b"<plist" in data[:200] or data.lstrip()[:5] == b"<?xml")
    ):
        name = (path or "").lower()
        if not name.endswith(".plist") and "info.plist" not in name:
            return None
    try:
        obj = plistlib.loads(data)
    except Exception:
        return None

    def _flatten(prefix: str, value: Any, out: list[str], depth: int = 0) -> None:
        if len(out) >= max_items:
            return
        if isinstance(value, dict):
            if depth > 4:
                out.append(f"{prefix} = {{…}}")
                return
            for k, v in list(value.items())[:40]:
                _flatten(f"{prefix}.{k}" if prefix else str(k), v, out, depth + 1)
        elif isinstance(value, list):
            out.append(f"{prefix} = [{len(value)} item(s)]")
            for i, v in enumerate(value[:8]):
                _flatten(f"{prefix}[{i}]", v, out, depth + 1)
        elif isinstance(value, (bytes, bytearray)):
            out.append(f"{prefix} = <{len(value)} bytes>")
        else:
            text = str(value)
            if len(text) > 200:
                text = text[:200] + "…"
            out.append(f"{prefix} = {text}")

    lines = [
        "Property list (parsed)",
        f"Source: {path}",
        f"Size: {len(data):,} bytes",
        "",
    ]
    flat: list[str] = []
    if isinstance(obj, dict):
        _flatten("", obj, flat)
        lines.extend(flat[:max_items])
    else:
        lines.append(pformat(obj, width=96, compact=True)[:8000])
    if isinstance(obj, dict) and len(flat) >= max_items:
        lines.append("")
        lines.append(f"… truncated after {max_items} keys/values.")
    return "\n".join(lines)


def _format_sqlite_overview(data: bytes, path: str, *, max_tables: int = 12) -> str | None:
    """Human-readable SQLite table overview when chat/contact extractors do not apply."""
    import sqlite3
    import tempfile

    if not data[:16].startswith(b"SQLite format"):
        return None
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    try:
        tmp.write(data)
        tmp.close()
        conn = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
        tables = [r[0] for r in cur.fetchall()]
        if not tables:
            conn.close()
            return None
        lines = [
            "SQLite database (structured overview — not a hex dump)",
            f"Source: {path}",
            f"Size: {len(data):,} bytes",
            f"Tables: {len(tables)}",
            "",
        ]
        for tname in tables[:max_tables]:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{tname}"')
                n = int(cur.fetchone()[0] or 0)
            except sqlite3.Error:
                n = -1
            try:
                cur.execute(f'PRAGMA table_info("{tname}")')
                cols = [r[1] for r in cur.fetchall()]
            except sqlite3.Error:
                cols = []
            lines.append(f"• {tname}: {n if n >= 0 else '?'} row(s)")
            if cols:
                lines.append(f"  columns: {', '.join(cols[:16])}" + ("…" if len(cols) > 16 else ""))
            # Sample a few text-ish rows when small.
            if 0 < n <= 5000 and cols:
                try:
                    col_sql = ", ".join(f'"{c}"' for c in cols[:6])
                    cur.execute(f'SELECT {col_sql} FROM "{tname}" LIMIT 3')
                    for sample in cur.fetchall():
                        cell = " | ".join(
                            (str(v)[:60] if v is not None else "NULL") for v in sample
                        )
                        lines.append(f"  sample: {cell}")
                except sqlite3.Error:
                    pass
        if len(tables) > max_tables:
            lines.append("")
            lines.append(f"… {len(tables) - max_tables} more table(s) not shown.")
        conn.close()
        return "\n".join(lines)
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _binary_preview_text(data: bytes, *, path: str, max_bytes: int = 4096) -> str:
    """CTA for opaque binaries — never hex-dump Office/docs/media (looks like bytecode in UI)."""
    del max_bytes  # retained for call-site compatibility
    name = (path or "").replace("\\", "/").rsplit("/", 1)[-1]
    if _is_app_runtime_binary(path, name, data):
        return _app_runtime_preview_text(path, len(data))
    return (
        f"Binary file ({len(data):,} bytes) — cannot be rendered inline.\n"
        f"Source: {path}\n\n"
        "Use Open in new tab to download or view the original file.\n"
        "Raw dumps are not shown for documents, archives, or opaque binaries."
    )


def _is_office_or_archive_mime(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(
        x in ct
        for x in (
            "officedocument",
            "msword",
            "ms-excel",
            "ms-powerpoint",
            "application/zip",
            "application/x-zip",
            "application/gzip",
            "application/x-7z",
            "application/vnd.rar",
            "application/octet-stream",
            "application/rtf",
            "application/vnd.oasis",
        )
    )


def _is_downloadable_binary(ext: str, content_type: str, data: bytes) -> bool:
    if ext in _DOWNLOADABLE_BINARY_EXTENSIONS:
        return True
    if _is_office_or_archive_mime(content_type) and content_type != "application/octet-stream":
        return True
    head = data[:8] if data else b""
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return True
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return True
    if head.startswith(b"\x1f\x8b") or head.startswith(b"Rar!\x1a\x07"):
        return True
    return False


def _guess_content_type(path: str, extension: str | None) -> str:
    ext = (extension or "").lower()
    if not ext.startswith(".") and ext:
        ext = f".{ext}"
    if ext in {".heic", ".heif"}:
        return "image/heic" if ext == ".heic" else "image/heif"
    if ext in _IMAGE_EXTENSIONS:
        return mimetypes.types_map.get(ext, "image/jpeg")
    if ext in {".pdf"}:
        return "application/pdf"
    if ext in {".xls", ".xlsx"}:
        return "application/vnd.ms-excel" if ext == ".xls" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    if ext in {".doc", ".docx"}:
        return "application/msword" if ext == ".doc" else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if ext in {".mp4", ".m4v", ".webm"}:
        return "video/mp4"
    if ext in {".mp3", ".m4a"}:
        return "audio/mpeg"
    if ext in {".wav"}:
        return "audio/wav"
    if ext in {".json"}:
        return "application/json"
    if ext in {".html", ".htm"}:
        return "text/html"
    if ext in {".eml", ".emlx"}:
        return "message/rfc822"
    guessed, _ = mimetypes.guess_type(path)
    return guessed or "application/octet-stream"


def _load_artifact_row(db: Session, job_id: str, artifact_id: str) -> dict[str, Any] | None:
    """Load a real job_artifacts row. Virtual evidence ids (ev-*) are not UUIDs."""
    aid = str(artifact_id or "").strip()
    if not aid or aid.startswith("ev-") or aid.startswith("carve-"):
        return None
    # Guard: Postgres uuid columns raise 500 on non-uuid text.
    try:
        import uuid as _uuid

        _uuid.UUID(aid)
    except (ValueError, TypeError, AttributeError):
        return None
    row = fetchone(
        db,
        "SELECT * FROM job_artifacts WHERE job_id=:jid AND id=:id",
        {"jid": job_id, "id": aid},
    )
    return dict(row) if row else None


def _decode_text(data: bytes) -> str:
    """Decode text without forcing latin-1 on binary blobs (avoids mojibake/'bytecode')."""
    sample = data[:8192]
    has_nul = b"\x00" in sample
    encodings = ("utf-16-le", "utf-8") if has_nul else ("utf-8", "utf-16-le")
    for enc in encodings:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    # latin-1 only when mostly printable — otherwise replace so UI never looks like garbage bytes
    try:
        text = data.decode("latin-1")
    except Exception:
        return data.decode("utf-8", errors="replace")
    probe = text[:4000]
    if not probe:
        return text
    printable = sum(1 for c in probe if c.isprintable() or c in "\r\n\t")
    if printable / len(probe) < 0.85:
        return data.decode("utf-8", errors="replace")
    return text


def _parse_eml_attachments(body: str) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for match in re.finditer(
        r'Content-Disposition:\s*attachment;\s*filename="?([^"\r\n;]+)"?',
        body,
        re.I,
    ):
        attachments.append({"filename": match.group(1).strip(), "content_type": "application/octet-stream"})
    return attachments[:40]


def _link_attachment_artifacts(
    db: Session,
    job_id: str,
    parent_path: str,
    attachments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Match MIME attachment filenames to indexed job_artifacts when possible."""
    if not attachments or not parent_path:
        return attachments
    parent_norm = parent_path.replace("\\", "/")
    parent_dir = parent_norm.rsplit("/", 1)[0] if "/" in parent_norm else parent_norm
    linked: list[dict[str, Any]] = []
    for att in attachments:
        entry = dict(att)
        filename = str(entry.get("filename") or "").strip()
        if not filename:
            linked.append(entry)
            continue
        row = fetchone(
            db,
            """SELECT id FROM job_artifacts
               WHERE job_id=:jid
                 AND (file_name ILIKE :fn OR file_path ILIKE :fnpat)
                 AND (
                   file_path ILIKE :parent
                   OR file_path ILIKE :attach
                   OR file_path ILIKE :parentdir
                 )
               ORDER BY CASE WHEN file_path ILIKE :parent THEN 0 ELSE 1 END
               LIMIT 1""",
            {
                "jid": job_id,
                "fn": filename,
                "fnpat": f"%/{filename}",
                "parent": f"%{parent_norm}%",
                "attach": "%attach%",
                "parentdir": f"%{parent_dir}%",
            },
        )
        if row:
            entry["artifact_id"] = str(row["id"])
        linked.append(entry)
    return linked


def _apply_email_preview(
    db: Session,
    job_id: str,
    preview: dict[str, Any],
    row: dict[str, Any],
    data: bytes,
) -> None:
    from app.parsers.email_mime_parser import (
        build_email_preview_details,
        extract_rfc_message_bytes,
        is_extensionless_email_candidate,
    )

    path = row.get("file_path") or ""
    ext = (row.get("extension") or "").lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"

    if ext == ".msg":
        # OLE .msg needs a dedicated parser; surface a clear message instead of a raw dump.
        preview["email"] = {
            "from": "",
            "to": "",
            "subject": row.get("file_name") or "Outlook .msg message",
            "date": "",
        }
        preview["body_text"] = (
            "This is an Outlook .msg (OLE) file. Inline MIME preview is not available yet — "
            "use Open in new tab to download the original message, or convert to .eml for full body/attachments."
        )
        preview["body"] = preview["body_text"]
        preview["content_type"] = "application/vnd.ms-outlook"
        preview["attachments"] = None
        preview["attachment_count"] = 0
        return

    if ext in {".pst", ".ost", ".mbox"}:
        size = row.get("size_bytes")
        try:
            size_n = int(size) if size is not None else len(data)
        except (TypeError, ValueError):
            size_n = len(data)
        kind = ext.lstrip(".").upper()
        preview["email"] = {
            "from": "",
            "to": "",
            "subject": row.get("file_name") or f"Outlook {kind} mailbox",
            "date": "",
        }
        preview["body_text"] = (
            f"This is an Outlook {kind} mailbox container ({size_n:,} bytes).\n\n"
            f"Source path:\n{path}\n\n"
            "Messages and attachments inside this store are evidence for Email & Calendar. "
            "Open the file to preserve/export the mailbox; full per-message expansion "
            "requires the mailbox parser (in progress)."
        )
        preview["body"] = preview["body_text"]
        preview["content_type"] = "application/vnd.ms-outlook"
        preview["attachments"] = None
        preview["attachment_count"] = 0
        return

    details = build_email_preview_details(data, path)
    if not details.get("parse_ok"):
        if ext in {".eml", ".emlx"} or preview.get("content_type") == "message/rfc822" or is_extensionless_email_candidate(data):
            # Retry with full RFC bytes; still expose email shell so the UI mounts EmailPreviewView.
            text = _decode_text(extract_rfc_message_bytes(data, path)[:_PREVIEW_TEXT_LIMIT])
            preview["email"] = {
                "from": "",
                "to": "",
                "subject": row.get("file_name") or "Email message",
                "date": "",
            }
            preview["body"] = text
            preview["body_text"] = text
            # Re-parse for real part_index values when possible.
            retry = build_email_preview_details(data, path)
            atts = retry.get("attachments") or []
            if atts:
                preview["attachments"] = _link_attachment_artifacts(db, job_id, path, atts)
                preview["attachment_count"] = len(preview["attachments"])
            else:
                preview["attachments"] = None
                preview["attachment_count"] = 0
            preview["content_type"] = "message/rfc822"
        return

    headers = details.get("headers") or {}
    # Always set email object so the UI opens structured email view (even if some headers empty).
    preview["email"] = {
        "from": headers.get("from") or "",
        "to": headers.get("to") or "",
        "cc": headers.get("cc") or "",
        "bcc": headers.get("bcc") or "",
        "subject": headers.get("subject") or (row.get("file_name") or "Email message"),
        "date": headers.get("date") or "",
        "message_id": headers.get("message_id") or "",
    }
    preview["body_text"] = details.get("body_text") or ""
    preview["body_html"] = details.get("body_html") or ""
    preview["body"] = preview["body_text"] or preview["body_html"] or preview.get("body") or ""
    preview["content_type"] = "message/rfc822"
    attachments = _link_attachment_artifacts(db, job_id, path, details.get("attachments") or [])
    preview["attachments"] = attachments or None
    preview["attachment_count"] = len(attachments)


def _read_bytes_from_extraction(
    db: Session,
    job_id: str,
    row: dict[str, Any],
    *,
    max_bytes: int | None = None,
) -> bytes | None:
    from app.services.artifact_live_counts import _read_job_files

    path = (row.get("file_path") or "").replace("\\", "/")
    if not path:
        return None
    hint = _size_hint_bytes(row)
    if max_bytes is not None and hint is not None and hint > max_bytes:
        raise ArtifactContentTooLargeError(hint, max_bytes)
    contents = _read_job_files(db, job_id, [row], max_bytes=max_bytes)
    data = contents.get(path)
    if data:
        return data

    try:
        from app.services.virtual_disk import open_virtual_disk_cached, read_full_file_from_disk

        vd = open_virtual_disk_cached(db, job_id)
        return read_full_file_from_disk(vd, path, max_bytes=max_bytes)
    except ArtifactContentTooLargeError:
        raise
    except Exception as exc:
        log.debug("Virtual disk read failed job=%s path=%s: %s", job_id, path, exc)
        return None


def _persist_artifact_bytes(
    db: Session,
    job_id: str,
    artifact_id: str,
    row: dict[str, Any],
    data: bytes,
) -> str | None:
    if row.get("minio_uri") or len(data) > _STORE_MAX_BYTES:
        return row.get("minio_uri")

    path = (row.get("file_path") or "").replace("\\", "/")
    ext = (row.get("extension") or "").lower()
    content_type = _guess_content_type(path, ext)
    digest = hashlib.sha256(data).hexdigest()
    safe_name = re.sub(r"[^\w.\-]+", "_", row.get("file_name") or "file")[:120]
    key = f"jobs/{job_id}/artifact-bytes/{artifact_id}/{digest[:16]}-{safe_name}"
    try:
        minio_uri = put_bytes(key, data, content_type=content_type)
        execute(
            db,
            """UPDATE job_artifacts
               SET minio_uri=:uri,
                   sha256=COALESCE(NULLIF(sha256, ''), :sha),
                   updated_at=NOW()
               WHERE id=:id AND job_id=:jid""",
            {"uri": minio_uri, "sha": digest, "id": artifact_id, "jid": job_id},
        )
        db.commit()
        return minio_uri
    except Exception as exc:
        log.warning("Failed to persist artifact bytes job=%s id=%s: %s", job_id, artifact_id, exc)
        db.rollback()
        return None


def resolve_artifact_bytes(
    db: Session,
    job_id: str,
    row: dict[str, Any],
    *,
    persist: bool = True,
    max_bytes: int | None = _PREVIEW_READ_MAX_BYTES,
) -> bytes | None:
    """Load artifact bytes from MinIO, extracted tar shards, or virtual disk."""
    metadata = row.get("metadata") or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    if metadata.get("whatsapp_derivation") and str(row.get("file_path") or "").startswith("derived/whatsapp_decrypted/"):
        from app.services.mobile_forensic.whatsapp_derivation import read_registered_derivation, MAX_PAYLOAD_BYTES
        size = int(row.get("size_bytes") or 0)
        if max_bytes is not None and size > max_bytes:
            raise ArtifactContentTooLargeError(size, max_bytes)
        return read_registered_derivation(db, job_id, row, max_bytes=max_bytes if max_bytes is not None else MAX_PAYLOAD_BYTES)
    storage_uri = row.get("minio_uri")
    if storage_uri:
        data = get_bytes(storage_uri)
        if data:
            if max_bytes is not None and len(data) > max_bytes:
                data = data[:max_bytes]
            return data

    data = _read_bytes_from_extraction(db, job_id, row, max_bytes=max_bytes)
    if data and persist and len(data) <= _STORE_MAX_BYTES:
        artifact_id = str(row.get("id") or "")
        if artifact_id:
            _persist_artifact_bytes(db, job_id, artifact_id, row, data)
    return data


def _extract_document_preview_text(data: bytes, *, ext: str, path: str) -> str | None:
    """Pull readable text from PDF / DOCX / XLSX / PPTX for the examiner pane."""
    if not data:
        return None
    ext = (ext or "").lower()
    if not ext.startswith(".") and ext:
        ext = f".{ext}"
    head = data[:8]
    try:
        if ext == ".pdf" or data[:4] == b"%PDF":
            from io import BytesIO

            from pypdf import PdfReader

            reader = PdfReader(BytesIO(data), strict=False)
            parts: list[str] = []
            for page in reader.pages[:40]:
                try:
                    text = page.extract_text() or ""
                except Exception:
                    text = ""
                if text.strip():
                    parts.append(text.strip())
            if not parts:
                return None
            body = "\n\n".join(parts)
            return body[:_PREVIEW_TEXT_LIMIT]

        if ext in {".docx"} or (
            ext in {"", ".zip"} and head.startswith(b"PK") and b"word/document.xml" in data[:8000]
        ):
            from io import BytesIO

            from docx import Document

            doc = Document(BytesIO(data))
            paras = [p.text.strip() for p in doc.paragraphs if p.text and p.text.strip()]
            for table in doc.tables[:20]:
                for row in table.rows:
                    cells = [c.text.strip() for c in row.cells if c.text and c.text.strip()]
                    if cells:
                        paras.append(" | ".join(cells))
            if not paras:
                return None
            return "\n".join(paras)[:_PREVIEW_TEXT_LIMIT]

        if ext in {".xlsx", ".xlsm"} or (head.startswith(b"PK") and b"xl/" in data[:4000]):
            from io import BytesIO

            from openpyxl import load_workbook

            wb = load_workbook(BytesIO(data), read_only=True, data_only=True)
            lines: list[str] = []
            for sheet in wb.worksheets[:6]:
                lines.append(f"## {sheet.title}")
                for i, row in enumerate(sheet.iter_rows(values_only=True)):
                    if i >= 80:
                        break
                    cells = [str(c) for c in row if c is not None and str(c).strip()]
                    if cells:
                        lines.append("\t".join(cells))
            try:
                wb.close()
            except Exception:
                pass
            if len(lines) <= 1:
                return None
            return "\n".join(lines)[:_PREVIEW_TEXT_LIMIT]

        if ext == ".pptx" or (head.startswith(b"PK") and b"ppt/slides/" in data[:8000]):
            import zipfile
            from io import BytesIO
            from xml.etree import ElementTree

            with zipfile.ZipFile(BytesIO(data)) as zf:
                names = sorted(
                    n for n in zf.namelist() if n.startswith("ppt/slides/slide") and n.endswith(".xml")
                )
                chunks: list[str] = []
                for name in names[:30]:
                    xml = zf.read(name)
                    try:
                        root = ElementTree.fromstring(xml)
                    except Exception:
                        continue
                    texts = [
                        (el.text or "").strip()
                        for el in root.iter()
                        if el.tag.endswith("}t") and (el.text or "").strip()
                    ]
                    if texts:
                        chunks.append(" ".join(texts))
            if not chunks:
                return None
            return "\n\n".join(chunks)[:_PREVIEW_TEXT_LIMIT]
    except Exception as exc:
        log.debug("document text extract failed for %s: %s", path, exc)
        return None
    return None


def _is_whatsapp_msgstore_crypt_name(path: str) -> bool:
    from app.services.mobile_forensic.whatsapp_crypt import crypt_extension
    name = (path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return "msgstore" in name and bool(crypt_extension(name))


def _is_whatsapp_media_crypt_name(path: str) -> bool:
    p = (path or "").replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    if "msgstore" in name:
        return False
    return any(
        x in p
        for x in (
            "payment background",
            "payment_background",
            "/stickers/",
            "/sticker",
            "_theme.",
            ".webp.crypt",
            ".was.crypt",
            ".jpg.crypt",
            ".jpeg.crypt",
            ".png.crypt",
        )
    )


def _whatsapp_crypt_preview_body(db: Session, job_id: str, path: str, data: bytes) -> str:
    """Examiner text for .crypt*/.enc — honest about chats vs theme media vs missing key."""
    size = len(data or b"")
    is_msgstore = _is_whatsapp_msgstore_crypt_name(path)
    is_media = _is_whatsapp_media_crypt_name(path)
    try:
        from app.db.sql_helpers import fetchone
        source = fetchone(db, "SELECT metadata FROM job_artifacts WHERE job_id=:jid AND file_path=:path", {"jid": job_id, "path": path}) or {}
        source_meta = source.get("metadata") or {}
        if isinstance(source_meta, str):
            source_meta = json.loads(source_meta)
        recovery = source_meta.get("whatsapp_decryption") if isinstance(source_meta, dict) else None
        if isinstance(recovery, dict):
            diag = recovery.get("diagnostics") or {}
            description = "Chat backup" if is_msgstore else "WhatsApp payload; NOT a chat database unless its parsed schema establishes messages"
            paths = "\n".join(str(value) for value in recovery.get("derived_paths") or [])
            warnings = "\n".join(str(value) for value in recovery.get("warnings") or [])
            return (f"{description}\nPath: {path}\nRecovery: {recovery.get('state')}\n"
                    f"Format: {diag.get('container') or 'unknown'}\nPayload: {diag.get('payload_kind') or 'unavailable'}\n"
                    f"Integrity: {diag.get('integrity') or 'unverified'}\nReason: {diag.get('reason') or 'none'}\n"
                    f"Encrypted source SHA256: {recovery.get('source_sha256') or ''}\n\n"
                    f"Derived evidence files:\n{paths or 'None'}\n{warnings}\n\n"
                    "Open the derived files in Artifacts. Parsed conversations are under WhatsApp Messages; recovered text enters RAG and report evidence.")
    except Exception:
        pass
    keys = []
    try:
        from app.services.mobile_forensic.sqlite_counts import discover_whatsapp_keys

        keys = discover_whatsapp_keys(db, job_id)
    except Exception:
        keys = []

    if is_media and not is_msgstore:
        return (
            "Encrypted WhatsApp media / theme sidecar (.crypt14)\n"
            f"Path: {path}\n"
            f"Size: {size:,} bytes\n\n"
            "This is NOT a chat database. Payment backgrounds, stickers, and themed "
            "images also use .crypt14. There is no conversation text in this file.\n\n"
            "Chat text is in msgstore.db.crypt14 under WhatsApp/Databases/ "
            "(see WhatsApp Encrypted Backups on the mobile board). Those files still "
            "need their matching key. Open WhatsApp Messages for parsed conversation records."
        )

    if is_msgstore and data:
        try:
            from app.services.mobile_forensic.whatsapp_crypt import decrypt_with_candidates, last_decrypt_diagnostics

            plain = decrypt_with_candidates(data, keys, path=path)
            diagnostic = last_decrypt_diagnostics()
        except Exception:
            plain = None
        if plain and plain[:15] == b"SQLite format 3":
            try:
                from app.services.chat_message_extract import (
                    extract_chat_messages_from_bytes,
                    format_chat_preview_body,
                )

                messages = extract_chat_messages_from_bytes(plain, path, limit=500)
                if messages:
                    warning = "Legacy decoded backup: authenticity is not verified.\n\n" if diagnostic.get("validation") == "legacy_structural_only" else ""
                    return warning + format_chat_preview_body(messages, path=path)
            except Exception as exc:
                log.debug("decrypted msgstore preview failed: %s", exc)
            return (
                "Decrypted WhatsApp msgstore (SQLite)\n"
                f"Path: {path}\n"
                f"Size: {size:,} bytes\n\n"
                + ("Legacy backup decoded; authenticity not verified. " if diagnostic.get("validation") == "legacy_structural_only" else "Backup opened successfully. ") + "Open WhatsApp Messages / Chats "
                "on the mobile board for the full conversation list."
            )

    kind = "WhatsApp encrypted chat database backup (msgstore)" if is_msgstore else (
        "Encrypted WhatsApp / app sidecar (.crypt* or .enc)"
    )
    key_line = (
        "Collected key candidates did not produce an authenticated SQLite store for this backup."
        if keys
        else (
            "No valid matching key material is available on this job. For crypt12/14 use the installation's files/key; "
            "for crypt15 use encrypted_backup.key or the owner's 64-character backup key. The key is not inside this backup."
        )
    )
    return (
        f"{kind}\n"
        f"Path: {path}\n"
        f"Size: {size:,} bytes\n\n"
        "This file is encrypted. Chat text is not visible as a hex dump.\n"
        f"{key_line}\n\n"
        "Collect private databases/keys from an already-accessible filesystem extraction, "
        "or import owner-supplied WhatsApp chat exports with media. Save a valid key on Case Intake, "
        "then Reprocess mobile evidence on an idle job; refreshing the board alone does not rerun recovery."
    )


def build_artifact_preview(db: Session, job_id: str, artifact_id: str) -> dict[str, Any]:
    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise LookupError("Artifact not found")

    path = row.get("file_path") or ""
    ext = (row.get("extension") or "").lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    content_type = _guess_content_type(path, ext)
    title = row.get("file_name") or path.rsplit("/", 1)[-1] or "artifact"
    meta = row.get("metadata") or {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}

    preview: dict[str, Any] = {
        "artifact_id": str(row["id"]),
        "title": title,
        "artifact_type": ext.lstrip(".") or "file",
        "content_type": content_type,
        "body": "",
        "encoding": None,
        "content_url": f"/api/jobs/{job_id}/artifacts/{artifact_id}/content",
        "attachments": None,
        "device_name": meta.get("device_name"),
    }

    is_mail = ext in _MAIL_EXTENSIONS or content_type == "message/rfc822"
    is_media = (
        content_type.startswith("image/")
        or content_type.startswith("video/")
        or content_type.startswith("audio/")
        or content_type == "application/pdf"
    )
    # Large browser-native media/PDFs stream via content URL (size-independent).
    # HEIC/HEIF always attempt conversion so the UI can show JPEG.
    hint = _size_hint_bytes(row)
    needs_convert = ext in {".heic", ".heif"} or "heic" in content_type or "heif" in content_type
    if (
        is_media
        and not needs_convert
        and hint is not None
        and hint > _PREVIEW_READ_MAX_BYTES
    ):
        preview["encoding"] = "url"
        preview["body"] = ""
        preview["size_bytes"] = hint
        return preview

    read_limit = _EMAIL_READ_MAX_BYTES if is_mail else _PREVIEW_READ_MAX_BYTES
    try:
        data = resolve_artifact_bytes(
            db,
            job_id,
            row,
            persist=True,
            max_bytes=read_limit,
        )
    except ArtifactContentTooLargeError as exc:
        # Still openable via streaming content URL (size-independent).
        preview["encoding"] = "url"
        preview["body"] = ""
        preview["size_bytes"] = exc.size_bytes
        preview["content_type"] = content_type
        return preview

    if not data:
        preview["body"] = f"No stored content for this artifact.\n\nSource path:\n{path}"
        preview["content_type"] = "text/plain"
        return preview

    # Sniff magic before branching so mistyped/extensionless images/PDFs/OLE never fall to hex.
    sniffed = _sniff_extension_and_type(data[:64])
    if sniffed:
        sniff_ext, sniff_type = sniffed
        keep_office = (
            ext in _DOWNLOADABLE_BINARY_EXTENSIONS
            or "officedocument" in content_type
            or "msword" in content_type
            or "ms-excel" in content_type
            or "ms-powerpoint" in content_type
        ) and sniff_type in {"application/zip", "application/gzip"}
        if not keep_office:
            media_sniff = (
                sniff_type.startswith("image/")
                or sniff_type.startswith("video/")
                or sniff_type.startswith("audio/")
                or sniff_type == "application/pdf"
            )
            if media_sniff and not (
                content_type.startswith("image/")
                or content_type.startswith("video/")
                or content_type.startswith("audio/")
                or content_type == "application/pdf"
            ):
                content_type = sniff_type
                if not ext:
                    ext = sniff_ext
                preview["content_type"] = content_type
                is_media = True
            elif (not ext or content_type == "application/octet-stream") and not media_sniff:
                # Extensionless OLE/zip/sqlite — upgrade type; keep path ext when present.
                if not ext:
                    ext = sniff_ext
                if content_type == "application/octet-stream":
                    content_type = sniff_type
                    preview["content_type"] = content_type

    if content_type.startswith("image/") or needs_convert:
        converted = _image_preview_bytes(data, ext=ext, content_type=content_type)
        if converted:
            out_bytes, out_type = converted
            preview["encoding"] = "base64"
            preview["content_type"] = out_type
            preview["body"] = base64.b64encode(out_bytes[:8_000_000]).decode("ascii")
            return preview
        # Never stream raw HEIC as image/jpeg — browsers cannot render it.
        if needs_convert or ext in {".heic", ".heif"}:
            preview["encoding"] = None
            preview["content_type"] = "text/plain"
            preview["body"] = (
                f"HEIC/HEIF image could not be decoded for browser preview.\n"
                f"File: {path}\n"
                f"Size: {len(data):,} bytes\n\n"
                "Use Open file / Open in new tab to download the original HEIC.\n"
                "Server-side conversion requires pillow-heif."
            )
            return preview
        # Fallback: stream original browser-friendly image bytes in the UI.
        preview["encoding"] = "url"
        preview["body"] = ""
        return preview

    if content_type.startswith("video/") or content_type.startswith("audio/") or content_type == "application/pdf":
        preview["encoding"] = "url"
        preview["body"] = ""
        if content_type == "application/pdf":
            extracted = _extract_document_preview_text(data, ext=ext or ".pdf", path=path)
            if extracted:
                preview["body"] = extracted
                preview["body_text"] = extracted
        return preview

    low_path = (path or "").replace("\\", "/").lower()

    if is_mail or ext in _TEXT_EXTENSIONS or content_type.startswith("text/") or content_type in {"application/json", "message/rfc822"}:
        # Freelist carve envelopes → examiner chat rows, not raw JSON metadata.
        if "carved_deleted_residuals" in low_path or (
            content_type == "application/json" and b'"sqlite_deleted_residual"' in data[:8000]
        ):
            formatted = _format_carved_deleted_json_preview(data, path)
            if formatted:
                preview["content_type"] = "text/plain"
                preview["encoding"] = None
                preview["body"] = formatted
                return preview
        text = _decode_text(data[:_PREVIEW_TEXT_LIMIT])
        preview["body"] = text
        if is_mail or content_type == "message/rfc822":
            _apply_email_preview(db, job_id, preview, row, data)
            if preview.get("email"):
                return preview
        return preview

    from app.parsers.email_mime_parser import is_extensionless_email_candidate

    if is_extensionless_email_candidate(data):
        _apply_email_preview(db, job_id, preview, row, data)
        if preview.get("email"):
            preview["content_type"] = "message/rfc822"
            return preview
    # App package / runtime binaries are not chat/media evidence — never hex-dump them.
    if _is_app_runtime_binary(path, title, data):
        preview["content_type"] = "text/plain"
        preview["encoding"] = None
        preview["artifact_type"] = "app_binary"
        preview["body"] = _app_runtime_preview_text(path, len(data))
        return preview

    # Property lists (Info.plist, preferences) — key/value view, never hex.
    if (
        ext == ".plist"
        or low_path.endswith(".plist")
        or data[:6] == b"bplist"
        or (b"<plist" in data[:240])
    ):
        plist_body = _format_plist_preview(data, path)
        if plist_body:
            preview["content_type"] = "text/plain"
            preview["encoding"] = None
            preview["artifact_type"] = "plist"
            preview["body"] = plist_body
            return preview

    # Encrypted WhatsApp sidecars — never hex-dump. Distinguish chat DBs from media.
    from app.services.mobile_forensic.whatsapp_crypt import crypt_extension
    if (
        crypt_extension(low_path)
        or low_path.endswith(".enc")
        or ".sqlite.enc" in low_path
    ):
        preview["content_type"] = "text/plain"
        preview["encoding"] = None
        preview["artifact_type"] = "whatsapp_encrypted"
        preview["body"] = _whatsapp_crypt_preview_body(db, job_id, path, data)
        return preview

    # Address book / contacts SQLite → people list (never hex dump).
    if data[:16].startswith(b"SQLite format") and (
        "addressbook" in low_path
        or "contacts2.db" in low_path
        or "/contacts/" in low_path
        or low_path.endswith("contacts.db")
    ):
        contacts_body = _format_contacts_sqlite_preview(data, path)
        if contacts_body:
            preview["content_type"] = "text/plain"
            preview["encoding"] = None
            preview["artifact_type"] = "contacts"
            preview["body"] = contacts_body
            return preview

    # Messaging SQLite → human-readable chat/SMS extract (mobile + disk).
    if data[:16].startswith(b"SQLite format") or ext in {".db", ".sqlite", ".sqlite3"}:
        try:
            from app.services.chat_message_extract import (
                extract_chat_messages_from_bytes,
                format_chat_preview_body,
                is_messaging_sqlite,
            )

            if is_messaging_sqlite(path) or data[:16].startswith(b"SQLite format"):
                messages = extract_chat_messages_from_bytes(data, path, limit=500)
                if messages or is_messaging_sqlite(path):
                    preview["content_type"] = "text/plain"
                    preview["encoding"] = None
                    preview["artifact_type"] = "chat_messages"
                    preview["body"] = format_chat_preview_body(messages, path=path, max_msgs=80)
                    preview["chat_messages"] = [
                        {
                            "sender": m.get("sender"),
                            "conversation": m.get("conversation") or m.get("chat"),
                            "timestamp": m.get("timestamp"),
                            "body": m.get("text_body") or m.get("body"),
                            "app": m.get("social_app"),
                        }
                        for m in messages[:200]
                    ]
                    return preview
        except Exception:
            pass

        # Non-messaging SQLite → structured table overview (never hex dump).
        overview = _format_sqlite_overview(data, path)
        if overview:
            preview["content_type"] = "text/plain"
            preview["encoding"] = None
            preview["artifact_type"] = "sqlite_overview"
            preview["body"] = overview
            return preview

        if any(
            x in low_path
            for x in (
                "resourceloadstatistics",
                "observations.db",
                "absabshadow",
                "webkit",
                "tips-store",
            )
        ):
            preview["content_type"] = "text/plain"
            preview["encoding"] = None
            preview["body"] = (
                "SQLite database (not an email attachment or contact list)\n"
                f"Path: {path}\n"
                f"Size: {len(data):,} bytes\n\n"
                "This file is browser/WebKit or AddressBook shadow metadata.\n"
                "It is not rendered as a hex dump. Open Contacts for people, "
                "or Email Attachments for real MIME attachments."
            )
            return preview

    # Unknown / opaque binary — never hex-dump or force text/plain (opens as bytecode in browser).
    plist_body = _format_plist_preview(data, path)
    if plist_body:
        preview["content_type"] = "text/plain"
        preview["encoding"] = None
        preview["artifact_type"] = "plist"
        preview["body"] = plist_body
        return preview
    overview = _format_sqlite_overview(data, path)
    if overview:
        preview["content_type"] = "text/plain"
        preview["encoding"] = None
        preview["artifact_type"] = "sqlite_overview"
        preview["body"] = overview
        return preview

    # Office / ZIP / OLE / archives — extract readable text; keep MIME for Open/download.
    if _is_downloadable_binary(ext, content_type, data):
        if content_type == "application/octet-stream":
            content_type = _guess_content_type(path, ext) or content_type
            if content_type == "application/octet-stream" and sniffed:
                content_type = sniffed[1]
        preview["encoding"] = "url"
        preview["content_type"] = content_type
        extracted = _extract_document_preview_text(data, ext=ext, path=path)
        if extracted:
            preview["body"] = (
                f"{extracted}\n\n"
                f"—\nSource: {path}\n"
                "Use Open in new tab to download the original file."
            )
            preview["body_text"] = extracted
        else:
            preview["body"] = (
                f"Document or archive ({len(data):,} bytes).\n"
                f"Type: {content_type}\n"
                f"Source: {path}\n\n"
                "Cannot be rendered inline. Use Open in new tab to download the original file."
            )
        return preview

    # Truly opaque binary — CTA with preserved MIME (never text/plain hex dump).
    preview["encoding"] = "url"
    if content_type == "text/plain":
        content_type = _guess_content_type(path, ext) or "application/octet-stream"
    preview["content_type"] = content_type or "application/octet-stream"
    preview["body"] = _binary_preview_text(data, path=path)
    return preview


def _sniff_extension_and_type(head: bytes) -> tuple[str, str] | None:
    """Return (extension_with_dot, content_type) from magic bytes when path has no ext."""
    if not head:
        return None
    if head.startswith(b"SQLite format 3"):
        return ".db", "application/x-sqlite3"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return ".zip", "application/zip"
    if head.startswith(b"\xd0\xcf\x11\xe0"):
        return ".doc", "application/msword"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png", "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return ".jpg", "image/jpeg"
    if head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        return ".gif", "image/gif"
    if head.startswith(b"%PDF"):
        return ".pdf", "application/pdf"
    if head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WEBP":
        return ".webp", "image/webp"
    if head.startswith(b"\x1f\x8b"):
        return ".gz", "application/gzip"
    if head.startswith(b"Rar!\x1a\x07"):
        return ".rar", "application/vnd.rar"
    # UTF-8 / ASCII text heuristic
    sample = head[:512]
    if sample and not any(b == 0 for b in sample[:64]):
        try:
            sample.decode("utf-8")
            return ".txt", "text/plain; charset=utf-8"
        except UnicodeDecodeError:
            pass
    return None


def _artifact_filename_and_type(row: dict[str, Any], *, head: bytes | None = None) -> tuple[str, str]:
    path = row.get("file_path") or row.get("file_name") or "artifact"
    ext = (row.get("extension") or "").lower().strip()
    if ext in {".", "(none)", "none", "null"}:
        ext = ""
    content_type = _guess_content_type(path, ext)
    filename = row.get("file_name") or str(path).rsplit("/", 1)[-1] or "artifact"
    # Sanitize for Content-Disposition
    filename = re.sub(r'["\r\n]+', "_", str(filename))[:180] or "artifact"
    # Extensionless Android paths (e.g. "accounts", "com.whatsapp") download as
    # nameless blobs in some browsers — invent a safe name + sniffed type.
    has_dot_ext = "." in filename and not filename.startswith(".")
    path_has_ext = bool(ext) or ("." in str(path).rsplit("/", 1)[-1])
    if not has_dot_ext or not path_has_ext:
        sniffed = _sniff_extension_and_type(head or b"")
        if sniffed:
            add_ext, sniffed_type = sniffed
            if not filename.lower().endswith(add_ext):
                filename = f"{filename}{add_ext}"
            if content_type == "application/octet-stream":
                content_type = sniffed_type
        elif not has_dot_ext:
            # Still give the browser a real filename so Open doesn't save as "download".
            safe = re.sub(r"[^\w.\-]+", "_", filename).strip("._") or "artifact"
            filename = f"{safe}.bin"
            content_type = content_type or "application/octet-stream"
    return filename, content_type


def iter_artifact_content(
    db: Session,
    job_id: str,
    row: dict[str, Any],
    *,
    max_bytes: int | None = _CONTENT_READ_MAX_BYTES,
) -> Iterator[bytes]:
    """Stream artifact bytes in chunks for large forensic downloads."""
    storage_uri = row.get("minio_uri")
    if storage_uri:
        stream = open_object_stream(str(storage_uri))
        if stream is not None:
            try:
                remaining = max_bytes
                while True:
                    n = _CONTENT_STREAM_CHUNK if remaining is None else min(_CONTENT_STREAM_CHUNK, remaining)
                    if n <= 0:
                        break
                    chunk = stream.read(n)
                    if not chunk:
                        break
                    yield chunk
                    if remaining is not None:
                        remaining -= len(chunk)
            finally:
                stream.close()
            return
        # Fallback: buffered get_bytes for non-streamable URIs
        data = get_bytes(str(storage_uri))
        if data:
            yield data if max_bytes is None else data[:max_bytes]
            return

    # Prefer virtual-disk / zip member streaming for UFED package paths.
    path = (row.get("file_path") or "").replace("\\", "/")
    if path:
        try:
            from app.services.virtual_disk import iter_file_from_disk, open_virtual_disk_cached

            vd = open_virtual_disk_cached(db, job_id)
            yielded = False
            for chunk in iter_file_from_disk(vd, path, max_bytes=max_bytes):
                yielded = True
                yield chunk
            if yielded:
                return
        except FileNotFoundError:
            pass
        except Exception as exc:
            log.debug("Stream from disk failed job=%s path=%s: %s", job_id, path, exc)

    # Last resort: buffered resolve (still capped).
    data = resolve_artifact_bytes(
        db, job_id, row, persist=False, max_bytes=max_bytes
    )
    if not data:
        raise FileNotFoundError("No stored content for artifact")
    yield data


def load_artifact_content(db: Session, job_id: str, artifact_id: str) -> tuple[bytes, str, str]:
    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise LookupError("Artifact not found")
    hint = _size_hint_bytes(row)
    # For very large files callers should use iter_artifact_content / StreamingResponse.
    if hint is not None and hint > _CONTENT_READ_MAX_BYTES:
        raise ArtifactContentTooLargeError(hint, _CONTENT_READ_MAX_BYTES)
    try:
        data = resolve_artifact_bytes(
            db,
            job_id,
            row,
            persist=True,
            max_bytes=_CONTENT_READ_MAX_BYTES,
        )
    except ArtifactContentTooLargeError as exc:
        raise ArtifactContentTooLargeError(exc.size_bytes, exc.limit_bytes) from exc
    if not data:
        raise FileNotFoundError("No stored content for artifact")
    filename, content_type = _artifact_filename_and_type(row, head=data[:64])
    return data, content_type, filename


def load_email_attachment_content(
    db: Session,
    job_id: str,
    artifact_id: str,
    part_index: int,
) -> tuple[bytes, str, str]:
    from app.parsers.email_mime_parser import load_mime_part_bytes

    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise LookupError("Artifact not found")
    # Full message bytes required — preview truncation would break attachment part indexes.
    data = resolve_artifact_bytes(
        db, job_id, row, persist=True, max_bytes=_EMAIL_READ_MAX_BYTES
    )
    if not data:
        raise FileNotFoundError("No stored content for artifact")
    path = row.get("file_path") or row.get("file_name") or ""
    return load_mime_part_bytes(data, path, part_index)
