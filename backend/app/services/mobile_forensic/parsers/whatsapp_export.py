"""Read owner-supplied WhatsApp text exports, preserving source lines and limits."""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

from app.services.mobile_forensic.models import Confidence, NormalizedArtifact

PARSER = "whatsapp_text_export"
VERSION = "1.0.0"
_STAMP = r"\d{1,4}[/.\-]\d{1,2}[/.\-]\d{1,4},?\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s*[aApP]\.?[mM]\.?)?"
_LINE = re.compile(rf"^(?:\[(?P<bracket>{_STAMP})\]\s*|(?P<dash>{_STAMP})\s+-\s+)(?P<body>.*)$")
_MEDIA = re.compile(r"^(.+?)\s+\((?:file attached|attached)\)(?:\s|$)", re.I)
_IOS_MEDIA = re.compile(r"<attached:\s*([^>]+)>", re.I)
_URL = re.compile(r"https?://[^\s<>]+", re.I)


def is_whatsapp_export_path(path: str) -> bool:
    low = path.replace("\\", "/").lower()
    name = PurePosixPath(low).name
    return name.endswith(".txt") and ("whatsapp" in low or name == "_chat.txt")


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


def iter_export_messages(data: bytes | str):
    """Emit all records, including multiline bodies and system notices."""
    text = _decode(data) if isinstance(data, bytes) else data
    record = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.lstrip("\u200e\u200f\ufeff")
        match = _LINE.match(line)
        if match:
            if record is not None:
                yield record
            payload = match["body"]
            sender, separator, body = payload.partition(": ")
            record = {
                "source_line_start": number,
                "source_line_end": number,
                "timestamp_local": match["bracket"] or match["dash"],
                "sender": sender if separator else None,
                "body": body if separator else payload,
                "system_message": not bool(separator),
                # Exports contain local timestamps without an offset. Do not
                # invent UTC, date order, sender JID or incoming/outgoing status.
                "timestamp_timezone": "unspecified",
                "direction": "unknown",
            }
        elif record is not None:
            record["body"] += "\n" + raw
            record["source_line_end"] = number
    if record is not None:
        yield record


def iter_whatsapp_export(item, context):
    data = context.read_artifact_bytes(item.path, max_bytes=768_000_000)
    if not data:
        return
    if item.size and len(data) < item.size:
        raise ValueError(f"Incomplete WhatsApp export read: {len(data)} of {item.size} bytes")
    try:
        # Decode validation is performed before emitting any record.
        text = _decode(data)
    except UnicodeError:
        return
    name = PurePosixPath(item.path.replace("\\", "/")).stem
    title = re.sub(r"^WhatsApp Chat (?:with|-)\s*", "", name, flags=re.I)
    conversation = "export:" + hashlib.sha256(item.path.encode("utf-8")).hexdigest()[:24]
    paths = context.extra.get("evidence_paths") or ()
    by_name = context.extra.get("media_paths_by_name")
    if by_name is None:
        by_name = {}
        for path in paths:
            base = PurePosixPath(str(path).replace("\\", "/")).name.casefold()
            by_name.setdefault(base, []).append(str(path))
        context.extra["media_paths_by_name"] = by_name
    messages = iter_export_messages(text)
    first = next(messages, None)
    if first is None:
        return

    def envelope(kind, family, row, body):
        return NormalizedArtifact.create(
            artifact_type=kind, source_domain="messaging_apps",
            data={"application": "whatsapp", "artifact_family": family,
                  "conversation_id": conversation, "conversation_title": title,
                  "export_complete_history": False, **body},
            state="historical", recovery_source="owner_chat_export",
            source_path=item.path, source_sha256=item.sha256 or hashlib.sha256(data).hexdigest(),
            source_table="whatsapp_text_export", source_row_id=str(row),
            parser=PARSER, parser_version=VERSION,
            confidence=Confidence(label="MEDIUM", score=0.7, validation=["structured_text_export", "source_lines_preserved"]),
            job_id=context.job_id, source_id=context.source_id,
        )

    yield envelope("app_conversation", "whatsapp_chats", "conversation", {"title": title})
    import itertools

    for message in itertools.chain((first,), messages):
        body = message["body"]
        media = _MEDIA.search(body) or _IOS_MEDIA.search(body)
        media_name = None
        matches = []
        if media:
            media_name = PurePosixPath(media[1].strip().replace("\\", "/")).name
            matches = by_name.get(media_name.casefold(), [])
        message.update({
            "message_id": f"line:{message['source_line_start']}",
            "has_attachment": bool(media_name), "media_name": media_name,
            "media_path": matches[0] if len(matches) == 1 else None,
            "media_candidates": matches, "media_available": bool(matches),
            "url_references": list(dict.fromkeys(url.rstrip(".,;)") for url in _URL.findall(body))),
        })
        yield envelope("app_message", "whatsapp_messages", message["source_line_start"], message)
