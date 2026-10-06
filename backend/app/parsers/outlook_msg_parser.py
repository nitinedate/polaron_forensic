"""Outlook .msg parser with attachment extraction.

Uses ``extract-msg`` when available.  The source evidence is never rewritten;
conversion here is only an in-memory examiner preview/download representation.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any


def _decode_html(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        for enc in ("utf-8", "utf-16-le", "windows-1252", "latin-1"):
            try:
                return value.decode(enc)
            except Exception:
                continue
        return value.decode("utf-8", errors="replace")
    return str(value)


def _attachment_bytes(att: Any) -> bytes:
    value = getattr(att, "data", None)
    if callable(value):
        try:
            value = value()
        except Exception:
            value = None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return b""


def _attachment_name(att: Any, index: int) -> str:
    for attr in ("longFilename", "shortFilename", "displayName", "name"):
        value = getattr(att, attr, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value:
            return str(value).strip()[:180]
    return f"attachment-{index + 1}.dat"


def _open_msg(data: bytes):
    import extract_msg  # type: ignore

    fd, path = tempfile.mkstemp(suffix=".msg")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        msg = extract_msg.Message(path)
        return msg, path
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def build_msg_preview_details(data: bytes, path: str = "") -> dict[str, Any]:
    if not data:
        return {"parse_ok": False, "error": "empty"}
    try:
        msg, temp_path = _open_msg(data)
    except Exception as exc:
        return {"parse_ok": False, "error": str(exc)[:200]}

    try:
        headers = {
            "from": str(getattr(msg, "sender", "") or ""),
            "to": str(getattr(msg, "to", "") or ""),
            "cc": str(getattr(msg, "cc", "") or ""),
            "bcc": str(getattr(msg, "bcc", "") or ""),
            "subject": str(getattr(msg, "subject", "") or ""),
            "date": str(getattr(msg, "date", "") or ""),
            "message_id": str(getattr(msg, "messageId", "") or ""),
        }
        body_text = str(getattr(msg, "body", "") or "")
        body_html = _decode_html(getattr(msg, "htmlBody", None))

        attachments: list[dict[str, Any]] = []
        from app.services.artifact_type_resolver import resolve_artifact_type

        for index, att in enumerate(list(getattr(msg, "attachments", []) or [])):
            payload = _attachment_bytes(att)
            filename = _attachment_name(att, index)
            declared = str(getattr(att, "mimetype", "") or getattr(att, "mimeType", "") or "")
            resolved = resolve_artifact_type(
                {
                    "file_name": filename,
                    "file_path": filename,
                    "metadata": {"content_type": declared},
                },
                data=payload[:256 * 1024] if payload else None,
            )
            attachments.append(
                {
                    "part_index": index,
                    "filename": resolved.normalized_filename,
                    "content_type": resolved.content_type,
                    "type_label": resolved.label,
                    "size": len(payload),
                    "inline": bool(getattr(att, "cid", None)),
                }
            )
        return {
            "parse_ok": True,
            "headers": headers,
            "body_text": body_text,
            "body_html": body_html,
            "attachments": attachments,
            "attachment_count": len(attachments),
            "source_path": path,
        }
    finally:
        try:
            close = getattr(msg, "close", None)
            if callable(close):
                close()
        except Exception:
            pass
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def load_msg_attachment_bytes(data: bytes, index: int) -> tuple[bytes, str | None, str]:
    try:
        msg, temp_path = _open_msg(data)
    except Exception as exc:
        raise LookupError("MSG attachment parser unavailable") from exc
    try:
        attachments = list(getattr(msg, "attachments", []) or [])
        if index < 0 or index >= len(attachments):
            raise LookupError("MSG attachment not found")
        att = attachments[index]
        payload = _attachment_bytes(att)
        if payload is None:
            raise LookupError("MSG attachment has no content")
        filename = _attachment_name(att, index)
        declared = str(getattr(att, "mimetype", "") or getattr(att, "mimeType", "") or "") or None
        return payload, declared, filename
    finally:
        try:
            close = getattr(msg, "close", None)
            if callable(close):
                close()
        except Exception:
            pass
        try:
            os.unlink(temp_path)
        except OSError:
            pass
