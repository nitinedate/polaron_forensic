"""RFC/MIME email parsing — EML, EMLX and extensionless message discovery (PDF guide aligned)."""

from __future__ import annotations

import hashlib
import mimetypes
import re
from email import policy
from email.parser import BytesParser
from typing import Any

# Require at least three structured headers near the start (extensionless detection).
_RFC_HEADER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.I | re.M)
    for p in (
        r"^From:\s*",
        r"^To:\s*",
        r"^Subject:\s*",
        r"^Date:\s*",
        r"^Message-ID:\s*",
        r"^MIME-Version:\s*",
        r"^Content-Type:\s*",
        r"^Received:\s*",
    )
)

_MAX_MESSAGE_BYTES = 100 * 1024 * 1024
_HEADER_SCAN_BYTES = 65536


def extract_rfc_message_bytes(raw: bytes, path: str = "") -> bytes:
    """Return RFC message bytes from .eml or Apple Mail .emlx (first line = byte length)."""
    if not raw:
        return b""
    norm = (path or "").replace("\\", "/").lower()
    if norm.endswith(".emlx"):
        line_end = raw.find(b"\n")
        if line_end > 0:
            first = raw[:line_end].strip()
            try:
                msg_len = int(first.decode("ascii", errors="ignore").strip())
                start = line_end + 1
                end = start + msg_len
                if msg_len > 0 and end <= len(raw):
                    return raw[start:end]
            except ValueError:
                pass
    return raw


def is_extensionless_email_candidate(raw: bytes) -> bool:
    """True when the file head contains at least three RFC-style headers."""
    if not raw or len(raw) < 32:
        return False
    head = raw[: min(len(raw), _HEADER_SCAN_BYTES)]
    try:
        text = head.decode("utf-8", errors="replace")
    except Exception:
        return False
    matches = sum(1 for pat in _RFC_HEADER_PATTERNS if pat.search(text))
    return matches >= 3


def analyze_mime_message(raw: bytes, path: str = "") -> dict[str, Any]:
    """Parse one message and count attachment-related MIME part occurrences."""
    rfc = extract_rfc_message_bytes(raw, path)
    out: dict[str, Any] = {
        "parse_ok": False,
        "message_occurrences": 0,
        "attachment_occurrences": 0,
        "inline_occurrences": 0,
        "attached_rfc822": 0,
        "message_id": None,
        "unique_content_hashes": [],
    }
    if not rfc or len(rfc) > _MAX_MESSAGE_BYTES:
        return out
    try:
        msg = BytesParser(policy=policy.default).parsebytes(rfc)
    except Exception:
        return out

    out["parse_ok"] = True
    out["message_occurrences"] = 1
    out["message_id"] = msg.get("Message-ID")

    content_hashes: set[str] = set()
    attachment_occ = 0
    inline_occ = 0
    attached_rfc822 = 0

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type() or ""
        is_attachment = disposition == "attachment"
        is_inline_file = disposition == "inline" and filename is not None
        is_named_leaf = filename is not None
        is_attached_email = content_type == "message/rfc822"

        if not (is_attachment or is_inline_file or is_named_leaf or is_attached_email):
            continue

        payload = part.get_payload(decode=True)
        if payload is None and is_attached_email:
            try:
                payload = part.as_bytes(policy=policy.default)
            except Exception:
                payload = b""
        if payload is None:
            payload = b""

        if payload:
            content_hashes.add(hashlib.sha256(payload).hexdigest())

        if is_attached_email:
            attached_rfc822 += 1
        elif is_inline_file:
            inline_occ += 1
        else:
            attachment_occ += 1

    out["attachment_occurrences"] = attachment_occ + inline_occ + attached_rfc822
    out["inline_occurrences"] = inline_occ
    out["attached_rfc822"] = attached_rfc822
    out["explicit_attachments"] = attachment_occ
    out["unique_content_hashes"] = sorted(content_hashes)
    out["unique_attachment_content"] = len(content_hashes)
    return out


def parse_email_file(data: bytes, path: str) -> list[dict[str, Any]]:
    """Parser plugin output for one RFC822/EMLX message.

    The normalized message record deliberately includes examiner-useful headers and
    body text.  Older builds stored only ``record_type/count`` which meant an EML
    could be counted while RAG/search had no message content to work with.
    """
    info = analyze_mime_message(data, path)
    if not info.get("parse_ok"):
        return []
    details = build_email_preview_details(data, path, max_body_chars=None)
    headers = details.get("headers") if isinstance(details.get("headers"), dict) else {}
    body_text = str(details.get("body_text") or "")
    body_html = str(details.get("body_html") or "")
    attachments = list(details.get("attachments") or [])
    subject = str(headers.get("subject") or "")
    sender = str(headers.get("from") or "")
    recipients = str(headers.get("to") or "")
    date = str(headers.get("date") or "")
    message_id = str(headers.get("message_id") or info.get("message_id") or "")
    searchable = "\n".join(
        x for x in (
            f"From: {sender}" if sender else "",
            f"To: {recipients}" if recipients else "",
            f"Subject: {subject}" if subject else "",
            f"Date: {date}" if date else "",
            body_text,
        ) if x
    )
    records: list[dict[str, Any]] = [{
        "record_type": "email_message",
        "count": 1,
        "path": path,
        "message_id": message_id or None,
        "from": sender,
        "to": recipients,
        "cc": str(headers.get("cc") or ""),
        "bcc": str(headers.get("bcc") or ""),
        "subject": subject,
        "date": date,
        "body_text": body_text,
        "body_html": body_html,
        "attachment_count": len(attachments),
        "attachments": attachments,
        "text": searchable,
        "preview": (subject or body_text or path)[:2_000],
    }]
    att = int(info.get("attachment_occurrences") or 0)
    if att > 0:
        records.append({
            "record_type": "email_attachment",
            "count": att,
            "path": path,
            "explicit_attachments": info.get("explicit_attachments"),
            "inline_occurrences": info.get("inline_occurrences"),
            "attached_rfc822": info.get("attached_rfc822"),
            "unique_attachment_content": info.get("unique_attachment_content"),
            "attachments": attachments,
            "text": f"{att} MIME attachment occurrence(s) in {path}",
        })
    return records


def _decode_part_text(part: Any) -> str:
    try:
        content = part.get_content()
    except Exception:
        payload = part.get_payload(decode=True)
        if not payload:
            return ""
        for enc in ("utf-8", "latin-1"):
            try:
                return payload.decode(enc)
            except UnicodeDecodeError:
                continue
        return payload.decode("utf-8", errors="replace")
    if isinstance(content, bytes):
        for enc in ("utf-8", "latin-1"):
            try:
                return content.decode(enc)
            except UnicodeDecodeError:
                continue
        return content.decode("utf-8", errors="replace")
    return str(content or "")


def _extract_bodies(msg: Any) -> tuple[str, str]:
    body_text = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            ctype = part.get_content_type() or ""
            if ctype == "text/plain" and not body_text:
                body_text = _decode_part_text(part)
            elif ctype == "text/html" and not body_html:
                body_html = _decode_part_text(part)
    else:
        ctype = msg.get_content_type() or ""
        content = _decode_part_text(msg)
        if ctype == "text/html":
            body_html = content
        else:
            body_text = content
    return body_text.strip(), body_html.strip()


def _is_downloadable_part(part: Any) -> bool:
    if part.is_multipart():
        return False
    filename = part.get_filename()
    disposition = part.get_content_disposition()
    content_type = part.get_content_type() or ""
    if disposition == "attachment":
        return True
    if disposition == "inline" and filename:
        return True
    if filename and content_type not in {"text/plain", "text/html"}:
        return True
    if content_type == "message/rfc822":
        return True
    return False


def build_email_preview_details(
    raw: bytes, path: str = "", *, sibling_paths: list[str] | None = None, max_body_chars: int | None = 120_000
) -> dict[str, Any]:
    """Structured headers, body, and attachment metadata for artifact preview.

    V45: for Apple Mail ``.emlx`` the trailing plist (flags, date-received,
    remote-id, gmail-labels) is decoded into ``out["emlx"]`` and
    ``.partial.emlx`` sidecar attachments are appended to ``attachments`` with
    ``source="apple_mail_sidecar"`` so the attachment count is complete.
    """
    rfc = extract_rfc_message_bytes(raw, path)
    out: dict[str, Any] = {
        "parse_ok": False,
        "headers": {},
        "body_text": "",
        "body_html": "",
        "attachments": [],
    }
    try:
        from app.parsers.emlx_sidecar import enrich_emlx

        emlx_meta = enrich_emlx(raw, path, sibling_paths=sibling_paths)
        if emlx_meta.get("is_emlx"):
            out["emlx"] = emlx_meta
    except Exception:
        emlx_meta = {}
    if not rfc or len(rfc) > _MAX_MESSAGE_BYTES:
        return out
    try:
        msg = BytesParser(policy=policy.default).parsebytes(rfc)
    except Exception:
        return out

    out["parse_ok"] = True
    out["headers"] = {
        "from": msg.get("From") or "",
        "to": msg.get("To") or "",
        "cc": msg.get("Cc") or "",
        "bcc": msg.get("Bcc") or "",
        "subject": msg.get("Subject") or "",
        "date": msg.get("Date") or "",
        "message_id": msg.get("Message-ID") or "",
    }
    body_text, body_html = _extract_bodies(msg)
    out["body_text"] = body_text if max_body_chars is None else body_text[:max_body_chars]
    out["body_html"] = body_html if max_body_chars is None else body_html[:max_body_chars]

    attachments: list[dict[str, Any]] = []
    for part_index, part in enumerate(msg.walk()):
        if not _is_downloadable_part(part):
            continue
        filename = part.get_filename()
        if not filename and part.get_content_type() == "message/rfc822":
            filename = "attached-message.eml"
        if not filename:
            ext = mimetypes.guess_extension(part.get_content_type() or "") or ".bin"
            filename = f"part-{part_index}{ext}"
        payload = part.get_payload(decode=True)
        if payload is None and part.get_content_type() == "message/rfc822":
            try:
                payload = part.as_bytes(policy=policy.default)
            except Exception:
                payload = b""
        attachments.append({
            "part_index": part_index,
            "filename": filename,
            "content_type": part.get_content_type() or "application/octet-stream",
            "size": len(payload or b""),
            "disposition": part.get_content_disposition() or "attachment",
            "inline": part.get_content_disposition() == "inline",
        })
    for sc in (emlx_meta.get("sidecar_attachments") or []):
        attachments.append({
            "part_index": None,
            "filename": sc["file_name"],
            "content_type": mimetypes.guess_type(sc["file_name"])[0] or "application/octet-stream",
            "size": None,
            "disposition": "attachment",
            "inline": False,
            "source": "apple_mail_sidecar",
            "sidecar_path": sc["path"],
            "mime_part_index": sc.get("mime_part_index"),
        })
    out["attachments"] = attachments[:60]
    if emlx_meta.get("date_received") and not out["headers"].get("date"):
        out["headers"]["date"] = emlx_meta["date_received"]
    return out


def load_mime_part_bytes(raw: bytes, path: str, part_index: int) -> tuple[bytes, str, str]:
    """Return attachment bytes, content type, and filename for a MIME walk index."""
    rfc = extract_rfc_message_bytes(raw, path)
    if not rfc:
        raise LookupError("Empty message")
    msg = BytesParser(policy=policy.default).parsebytes(rfc)
    for idx, part in enumerate(msg.walk()):
        if idx != part_index:
            continue
        if not _is_downloadable_part(part):
            raise LookupError("Part is not an attachment")
        filename = part.get_filename()
        if not filename and part.get_content_type() == "message/rfc822":
            filename = "attached-message.eml"
        if not filename:
            ext = mimetypes.guess_extension(part.get_content_type() or "") or ".bin"
            filename = f"part-{part_index}{ext}"
        payload = part.get_payload(decode=True)
        if payload is None and part.get_content_type() == "message/rfc822":
            try:
                payload = part.as_bytes(policy=policy.default)
            except Exception:
                payload = b""
        if payload is None:
            payload = b""
        return payload, part.get_content_type() or "application/octet-stream", filename
    raise LookupError("Attachment part not found")
