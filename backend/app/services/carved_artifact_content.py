"""Open and preview signature-carved forensic artifacts without rewriting evidence.

Signature inventory rows are virtual objects (``carve-*``), not ``job_artifacts``
UUID rows.  This service reopens only the exact bounded range in the original
source file/inode, trims common container endings where possible, resolves the
actual MIME from bytes, and exposes the same preview/content contract used by
normal artifacts.

The original E01/source bytes and hashes are never modified.
"""

from __future__ import annotations

import json
import re
from email import policy
from email.parser import BytesParser
from typing import Any

from app.db.sql_helpers import fetchone
from app.parsers.email_mime_parser import build_email_preview_details, load_mime_part_bytes
from app.services.artifact_type_resolver import FORENSIC_DATA_MIME, resolve_artifact_type
from app.services.signature_carve_inventory import get_cached_signature_carve_inventory


_KIND_INFO: dict[str, tuple[str, str, str, str]] = {
    # extension, AXIOM category, AXIOM artifact name, display type
    "eml": (".eml", "Email & Calendar", "EML(X) Files", "Email message"),
    "msg": (".msg", "Email & Calendar", "Outlook Emails", "Outlook message"),
    "pdf": (".pdf", "Documents", "PDF Documents", "PDF document"),
    "rtf": (".rtf", "Documents", "RTF Documents", "Rich Text Format document"),
    "jpeg": (".jpg", "Media", "Pictures", "JPEG image"),
    "png": (".png", "Media", "Pictures", "PNG image"),
    "gif": (".gif", "Media", "Pictures", "GIF image"),
    "bmp": (".bmp", "Media", "Pictures", "Bitmap image"),
    "tiff": (".tif", "Media", "Pictures", "TIFF image"),
    "mp4": (".mp4", "Media", "Videos", "MP4 video"),
    "avi": (".avi", "Media", "Videos", "AVI video"),
    "mkv": (".mkv", "Media", "Videos", "Matroska video"),
    "doc": (".doc", "Documents", "Microsoft Word Documents", "Microsoft Word document"),
    "docx": (".docx", "Documents", "Microsoft Word Documents", "Microsoft Word document"),
    "xls": (".xls", "Documents", "Microsoft Excel Documents", "Microsoft Excel workbook"),
    "xlsx": (".xlsx", "Documents", "Microsoft Excel Documents", "Microsoft Excel workbook"),
    "ppt": (".ppt", "Documents", "Microsoft PowerPoint Documents", "Microsoft PowerPoint presentation"),
    "pptx": (".pptx", "Documents", "Microsoft PowerPoint Documents", "Microsoft PowerPoint presentation"),
    "psd": (".psd", "Media", "Photoshop Files", "Photoshop image"),
}


def _hit_by_id(db, job_id: str, artifact_id: str) -> dict[str, Any] | None:
    if not str(artifact_id or "").startswith("carve-"):
        return None
    inv = get_cached_signature_carve_inventory(db, job_id)
    if inv is None:
        return None
    for hit in inv.get("evidence_rows") or []:
        if str(hit.get("id") or "") == str(artifact_id):
            return dict(hit)
    return None


def _safe_offset(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _safe_limit(hit: dict[str, Any]) -> int:
    try:
        n = int(hit.get("max_size") or 8 * 1024 * 1024)
    except (TypeError, ValueError):
        n = 8 * 1024 * 1024
    # A virtual carve should never cause an unbounded source-file read.
    return min(max(n, 64 * 1024), 256 * 1024 * 1024)


def _read_from_source_artifact(db, job_id: str, source_artifact_id: str, offset: int, limit: int) -> bytes:
    """Bounded fallback for sources stored in object storage rather than a VD."""
    from app.services.artifact_preview import _load_artifact_row, iter_artifact_content

    row = _load_artifact_row(db, job_id, source_artifact_id)
    if not row:
        return b""
    want_end = offset + limit
    cursor = 0
    chunks: list[bytes] = []
    for chunk in iter_artifact_content(db, job_id, row, max_bytes=want_end):
        if not chunk:
            continue
        next_cursor = cursor + len(chunk)
        if next_cursor <= offset:
            cursor = next_cursor
            continue
        start = max(offset - cursor, 0)
        remaining = limit - sum(len(part) for part in chunks)
        if remaining <= 0:
            break
        chunks.append(chunk[start : start + remaining])
        cursor = next_cursor
        if sum(len(part) for part in chunks) >= limit:
            break
    return b"".join(chunks)


def _read_hit_bytes(db, job_id: str, hit: dict[str, Any]) -> bytes:
    source = str(hit.get("source_path") or "").replace("\\", "/")
    offset = _safe_offset(hit.get("offset"))
    limit = _safe_limit(hit)
    inode = hit.get("source_inode")
    try:
        inode_n = int(inode) if inode is not None else None
    except (TypeError, ValueError):
        inode_n = None

    # Preferred zero-copy path: read the exact range from the mounted E01/host
    # evidence.  For ``unallocated:inode:N`` the logical path is irrelevant and
    # pytsk opens the inode directly.
    try:
        from app.services.virtual_disk import open_virtual_disk_cached, read_file_range_from_disk

        vd = open_virtual_disk_cached(db, job_id)
        rel_path = source
        if source.lower().startswith("unallocated:inode:"):
            if inode_n is None:
                match = re.search(r"inode:(\d+)", source, re.I)
                inode_n = int(match.group(1)) if match else None
            rel_path = ""
        if inode_n is not None or rel_path:
            data = read_file_range_from_disk(
                vd,
                rel_path,
                start_offset=offset,
                inode=inode_n,
                max_bytes=limit,
            )
            if data:
                return data
    except Exception:
        pass

    source_id = str(hit.get("source_artifact_id") or "").strip()
    if source_id:
        try:
            return _read_from_source_artifact(db, job_id, source_id, offset, limit)
        except Exception:
            return b""
    return b""


def _trim_jpeg(data: bytes) -> bytes:
    end = data.find(b"\xff\xd9", 2)
    return data[: end + 2] if end >= 0 else data


def _trim_png(data: bytes) -> bytes:
    # IEND chunk = length(4)=0 + IEND + CRC(4)
    marker = b"\x00\x00\x00\x00IEND"
    pos = data.find(marker, 8)
    return data[: pos + 12] if pos >= 0 and pos + 12 <= len(data) else data


def _trim_gif(data: bytes) -> bytes:
    # Trailer byte. False positives inside compressed image data are possible,
    # so keep full bytes unless the trailer is reasonably far into the object.
    pos = data.find(b"\x3b", 13)
    return data[: pos + 1] if pos >= 32 else data


def _trim_bmp(data: bytes) -> bytes:
    if len(data) >= 6 and data.startswith(b"BM"):
        size = int.from_bytes(data[2:6], "little")
        if 54 <= size <= len(data):
            return data[:size]
    return data


def _trim_pdf(data: bytes) -> bytes:
    # Prefer the last EOF marker inside the bounded carve, because incremental
    # PDFs may contain earlier %%EOF markers.
    pos = data.rfind(b"%%EOF")
    if pos >= 0:
        end = pos + 5
        while end < len(data) and data[end : end + 1] in {b"\r", b"\n", b" ", b"\t"}:
            end += 1
        return data[:end]
    return data


def _trim_riff(data: bytes) -> bytes:
    if len(data) >= 8 and data.startswith(b"RIFF"):
        total = int.from_bytes(data[4:8], "little") + 8
        if 12 <= total <= len(data):
            return data[:total]
    return data


def _trim_zip(data: bytes) -> bytes:
    # End of central directory + variable comment.
    pos = data.rfind(b"PK\x05\x06")
    if pos >= 0 and pos + 22 <= len(data):
        comment_len = int.from_bytes(data[pos + 20 : pos + 22], "little")
        end = pos + 22 + comment_len
        if end <= len(data):
            return data[:end]
    return data


def _trim_eml(data: bytes) -> bytes:
    """Best-effort carve boundary for an RFC822 message.

    MIME parser tolerates partial recovered messages, so only trim when a strong
    boundary is available.  Never manufacture missing body/attachment bytes.
    """
    if not data:
        return data
    header_end = data.find(b"\r\n\r\n")
    sep_len = 4
    if header_end < 0:
        header_end = data.find(b"\n\n")
        sep_len = 2
    if header_end < 0:
        return data

    header_blob = data[: header_end + sep_len]
    try:
        msg = BytesParser(policy=policy.default).parsebytes(header_blob, headersonly=True)
    except Exception:
        msg = None

    # Content-Length (when supplied by a store/export) is the strongest bound.
    if msg is not None:
        try:
            content_len = int(str(msg.get("Content-Length") or "").strip())
        except (TypeError, ValueError):
            content_len = 0
        if content_len > 0:
            end = header_end + sep_len + content_len
            if end <= len(data):
                return data[:end]

        boundary = msg.get_boundary()
        if boundary:
            token = b"--" + boundary.encode("utf-8", errors="ignore") + b"--"
            pos = data.find(token, header_end + sep_len)
            if pos >= 0:
                end = pos + len(token)
                # Include the closing line ending when present.
                if data[end : end + 2] == b"\r\n":
                    end += 2
                elif data[end : end + 1] == b"\n":
                    end += 1
                return data[:end]

    # Single-part or damaged MIME: find a later strong message-header start.
    # Require a blank-line/message separator before the next header to avoid a
    # normal "From:" line inside the body.
    probe_start = max(header_end + sep_len + 256, 512)
    next_msg = re.search(
        rb"(?:\r?\n){2}(?=(?:Return-Path:|From:)[^\r\n]*\r?\n(?:Received:|Date:|To:|Subject:|Message-ID:))",
        data[probe_start:],
        re.I,
    )
    if next_msg:
        return data[: probe_start + next_msg.start()]
    return data


def _trim_hit_bytes(kind: str, data: bytes) -> bytes:
    kind = (kind or "").lower()
    if kind == "eml":
        return _trim_eml(data)
    if kind == "pdf":
        return _trim_pdf(data)
    if kind == "jpeg":
        return _trim_jpeg(data)
    if kind == "png":
        return _trim_png(data)
    if kind == "gif":
        return _trim_gif(data)
    if kind in {"bmp", "avi"}:
        return _trim_bmp(data) if kind == "bmp" else _trim_riff(data)
    if kind in {"docx", "xlsx", "pptx"}:
        return _trim_zip(data)
    return data


def _file_name_for_hit(hit: dict[str, Any]) -> str:
    kind = str(hit.get("kind") or "carve").lower()
    ext, _category, _artifact_name, _label = _KIND_INFO.get(
        kind, (".dat", "Carved Evidence", "Recovered Evidence", "Recovered evidence")
    )
    offset = _safe_offset(hit.get("offset"))
    source = str(hit.get("source_path") or "evidence").replace("\\", "/").rsplit("/", 1)[-1]
    source = re.sub(r"[^A-Za-z0-9._-]+", "_", source)[:60] or "evidence"
    return f"carved-{kind}-{source}-{offset}{ext}"


def carved_artifact_record(db, job_id: str, artifact_id: str) -> dict[str, Any]:
    hit = _hit_by_id(db, job_id, artifact_id)
    if not hit:
        raise LookupError("Carved artifact not found")
    kind = str(hit.get("kind") or "carve").lower()
    _ext, category, artifact_name, _label = _KIND_INFO.get(
        kind, (".dat", "Carved Evidence", "Recovered Evidence", "Recovered evidence")
    )
    filename = _file_name_for_hit(hit)
    resolved = resolve_artifact_type({"file_name": filename, "file_path": filename, "metadata": {}})
    source = str(hit.get("source_path") or "")
    title = f"Carved {kind.upper()} @ {source}:{_safe_offset(hit.get('offset'))}"
    return {
        "id": artifact_id,
        "job_id": job_id,
        "file_id": None,
        "parent_artifact_id": hit.get("source_artifact_id"),
        "artifact_type": kind,
        "axiom_category": category,
        "axiom_category_label": category,
        "axiom_sub_category": artifact_name,
        "title": title[:220],
        "file_name": filename,
        "source_path": source,
        "size_bytes": None,
        "extension": resolved.extension,
        "artifact_datetime": None,
        "preview_uri": None,
        "storage_uri": None,
        "metadata": {
            "evidence_kind": "carved_signature",
            "kind": kind,
            "offset": _safe_offset(hit.get("offset")),
            "source_path": source,
            "source_artifact_id": hit.get("source_artifact_id"),
            "source_inode": hit.get("source_inode"),
            "max_size": hit.get("max_size"),
            "content_type": resolved.content_type,
            "resolved_content_type": resolved.content_type,
            "type_label": resolved.label,
            "detected_extension": resolved.extension,
            "normalized_filename": resolved.normalized_filename,
            "preview_body": (
                f"Recovered {kind} object from {source} at offset {_safe_offset(hit.get('offset')):,}. "
                "Open this virtual artifact to parse the recovered bytes."
            ),
        },
        "tags": ["carved", kind],
        "examiner_comment": None,
        "parser_version": "signature_carve_inventory:v3",
        "confidence": None,
        "created_at": "",
    }


def load_carved_content(db, job_id: str, artifact_id: str) -> tuple[bytes, str, str, dict[str, Any]]:
    hit = _hit_by_id(db, job_id, artifact_id)
    if not hit:
        raise LookupError("Carved artifact not found")
    data = _read_hit_bytes(db, job_id, hit)
    if not data:
        raise FileNotFoundError("Recovered source range is no longer readable")
    kind = str(hit.get("kind") or "carve").lower()
    data = _trim_hit_bytes(kind, data)
    filename = _file_name_for_hit(hit)
    resolved = resolve_artifact_type(
        {"file_name": filename, "file_path": filename, "metadata": {}},
        data=data[:256 * 1024],
    )
    return data, resolved.content_type, resolved.normalized_filename, hit


def build_carved_preview(db, job_id: str, artifact_id: str) -> dict[str, Any]:
    data, content_type, filename, hit = load_carved_content(db, job_id, artifact_id)
    kind = str(hit.get("kind") or "carve").lower()
    source = str(hit.get("source_path") or "")
    resolved = resolve_artifact_type(
        {"file_name": filename, "file_path": filename, "metadata": {}},
        data=data[:256 * 1024],
    )
    preview: dict[str, Any] = {
        "artifact_id": artifact_id,
        "title": filename,
        "artifact_type": kind,
        "content_type": content_type or FORENSIC_DATA_MIME,
        "type_label": resolved.label,
        "type_source": resolved.source,
        "type_confidence": resolved.confidence,
        "detected_extension": resolved.extension,
        "normalized_filename": resolved.normalized_filename,
        "body": "",
        "encoding": "url",
        "content_url": f"/api/jobs/{job_id}/artifacts/{artifact_id}/content",
        "attachments": None,
        "attachment_count": 0,
        "device_name": None,
        "size_bytes": len(data),
    }

    # EML is a first-class MIME message: show headers/body and every recoverable
    # attachment in the third panel rather than the old "signature hit" text.
    if kind == "eml" or content_type == "message/rfc822":
        details = build_email_preview_details(data, filename)
        if details.get("parse_ok"):
            headers = details.get("headers") or {}
            preview.update(
                {
                    "content_type": "message/rfc822",
                    "artifact_type": "eml",
                    "encoding": None,
                    "email": {
                        "from": headers.get("from") or "",
                        "to": headers.get("to") or "",
                        "cc": headers.get("cc") or "",
                        "bcc": headers.get("bcc") or "",
                        "subject": headers.get("subject") or filename,
                        "date": headers.get("date") or "",
                        "message_id": headers.get("message_id") or "",
                    },
                    "body_text": details.get("body_text") or "",
                    "body_html": details.get("body_html") or "",
                    "body": (details.get("body_text") or details.get("body_html") or ""),
                    "attachments": details.get("attachments") or [],
                    "attachment_count": len(details.get("attachments") or []),
                }
            )
            return preview
        preview["encoding"] = None
        preview["content_type"] = "text/plain"
        preview["body"] = (
            "Recovered email fragment could not be reconstructed into a complete RFC822 message.\n"
            f"Source: {source}\nOffset: {_safe_offset(hit.get('offset')):,}\n"
            "The original bytes remain available from Open/Download."
        )
        return preview

    if content_type.startswith(("image/", "audio/", "video/")) or content_type == "application/pdf":
        preview["encoding"] = "url"
        return preview

    # For unknown carved content, still make it openable and show the detector
    # result.  Do not lie by inventing a MIME type.
    if content_type == FORENSIC_DATA_MIME:
        preview["encoding"] = "url"
        preview["body"] = (
            f"Recovered forensic data object ({len(data):,} bytes).\n"
            f"Source: {source}\nOffset: {_safe_offset(hit.get('offset')):,}\n\n"
            "No reliable file signature was found. The object is still openable/downloadable, "
            "but its MIME remains application/x-forensic-data rather than a fabricated type."
        )
        return preview

    if content_type.startswith("text/") or content_type in {"application/json", "application/xml"}:
        preview["encoding"] = None
        preview["body"] = data[:500_000].decode("utf-8", errors="replace")
    return preview


def carved_properties(db, job_id: str, artifact_id: str, *, probe_media: bool = False) -> dict[str, Any]:
    """Return carved-object properties without re-reading evidence by default.

    Preview already performs the bounded source-range read.  V36 duplicated that
    I/O via /properties on every click, which was especially expensive for
    pagefile/unallocated EML hits.  The fast path uses the signature kind and
    persisted hit metadata; explicit ``probe_media=True`` retains byte-level
    verification when an examiner requests it.
    """
    hit = _hit_by_id(db, job_id, artifact_id)
    if not hit:
        raise LookupError("Carved artifact not found")
    filename = _file_name_for_hit(hit)
    kind = str(hit.get("kind") or "carve").lower()
    resolved = resolve_artifact_type({"file_name": filename, "file_path": filename, "metadata": {}})
    size_bytes = None
    content_type = resolved.content_type
    probe_source = "signature_inventory"
    if probe_media:
        data = _read_hit_bytes(db, job_id, hit)
        if not data:
            raise FileNotFoundError("Recovered source range is no longer readable")
        data = _trim_hit_bytes(kind, data)
        resolved = resolve_artifact_type(
            {"file_name": filename, "file_path": filename, "metadata": {}},
            data=data[:256 * 1024],
        )
        content_type = resolved.content_type
        size_bytes = len(data)
        probe_source = "signature_carve"
    return {
        "artifact_id": artifact_id,
        "job_id": job_id,
        "file_name": filename,
        "source_path": hit.get("source_path"),
        "sha256": None,
        "size_bytes": size_bytes,
        "content_type": content_type,
        "type_label": resolved.label,
        "type_source": resolved.source,
        "type_confidence": resolved.confidence,
        "detected_extension": resolved.extension,
        "normalized_filename": resolved.normalized_filename,
        "original_filename": filename,
        "kind": resolved.kind,
        "extension": resolved.extension,
        "width": None,
        "height": None,
        "pixels": None,
        "duration_seconds": None,
        "format": None,
        "orientation": None,
        "video_codec": None,
        "audio_codec": None,
        "sample_rate": None,
        "channels": None,
        "is_deleted": str(hit.get("source_path") or "").lower().startswith("unallocated:"),
        "deleted_at": None,
        "probe_source": probe_source,
        "probe_deferred": not probe_media,
        "probe_error": None,
        "downloadable": True,
        "content_url": f"/api/jobs/{job_id}/artifacts/{artifact_id}/content",
    }


def load_carved_email_attachment(
    db, job_id: str, artifact_id: str, part_index: int
) -> tuple[bytes, str, str]:
    data, _content_type, filename, hit = load_carved_content(db, job_id, artifact_id)
    if str(hit.get("kind") or "").lower() != "eml":
        raise LookupError("Carved artifact is not an RFC822 email")
    payload, declared_type, part_name = load_mime_part_bytes(data, filename, part_index)
    resolved = resolve_artifact_type(
        {"file_name": part_name, "file_path": part_name, "metadata": {"content_type": declared_type}},
        data=payload[:256 * 1024] or None,
    )
    return payload, resolved.content_type, resolved.normalized_filename
