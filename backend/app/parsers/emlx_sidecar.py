"""Apple Mail ``.emlx`` / ``.partial.emlx`` completeness (V45).

An emlx file is::

    <decimal byte count>\\n
    <RFC-822 message, exactly that many bytes>
    <XML plist>            <- ignored before V45

The plist carries examiner-relevant state that the RFC-822 body does not:
``flags`` (read / deleted / answered / flagged / forwarded / junk …),
``date-received``, ``date-sent``, ``remote-id`` (IMAP UID), ``original-mailbox``,
and for Gmail accounts ``gmail-labels``.

``.partial.emlx`` means Apple Mail stripped large attachments out of the MIME
body and stored them as plain files under::

    <Mailbox>.mbox/<UUID>/Data/<n>/<n>/Messages/<msgnum>.partial.emlx
    <Mailbox>.mbox/<UUID>/Data/<n>/<n>/Attachments/<msgnum>/<part>/<filename>

so an attachment count derived from MIME parts alone is wrong. This module
resolves those sidecars by message number so the artifact UI can open them.
"""

from __future__ import annotations

import plistlib
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

# Apple Mail message flag bits (MFMessageFlags).
_FLAG_BITS: tuple[tuple[int, str], ...] = (
    (1 << 0, "read"),
    (1 << 1, "deleted"),
    (1 << 2, "answered"),
    (1 << 3, "encrypted"),
    (1 << 4, "flagged"),
    (1 << 5, "recent"),
    (1 << 6, "draft"),
    (1 << 7, "initial"),
    (1 << 8, "forwarded"),
    (1 << 9, "redirected"),
    (1 << 16, "signed"),
    (1 << 17, "junk"),
    (1 << 18, "not_junk"),
    (1 << 22, "is_not_junk_by_user"),
    (1 << 23, "has_attachments"),   # observed in practice, informational
)

_EMLX_NAME_RE = re.compile(r"^(?P<num>\d+)(?P<partial>\.partial)?\.emlx$", re.I)


def split_emlx(raw: bytes) -> tuple[bytes, bytes]:
    """Return (rfc822_bytes, plist_bytes). Tolerates malformed length prefixes."""
    if not raw:
        return b"", b""
    nl = raw.find(b"\n")
    if nl <= 0 or nl > 20:
        return raw, b""
    try:
        n = int(raw[:nl].strip().decode("ascii"))
    except ValueError:
        return raw, b""
    start = nl + 1
    end = start + n
    if n <= 0 or end > len(raw):
        return raw[start:], b""
    return raw[start:end], raw[end:]


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return None


def parse_emlx_plist(plist_bytes: bytes) -> dict[str, Any]:
    """Decode the trailing plist into normalized keys. Never raises."""
    out: dict[str, Any] = {"emlx_plist_present": False}
    if not plist_bytes:
        return out
    blob = plist_bytes.strip()
    idx = blob.find(b"<?xml")
    if idx < 0:
        idx = blob.find(b"bplist")
    if idx < 0:
        return out
    try:
        data = plistlib.loads(blob[idx:])
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    out["emlx_plist_present"] = True
    flags = data.get("flags")
    try:
        flags_i = int(flags) if flags is not None else None
    except (TypeError, ValueError):
        flags_i = None
    out["emlx_flags_raw"] = flags_i
    out["emlx_flags"] = [name for bit, name in _FLAG_BITS if flags_i is not None and flags_i & bit]
    out["emlx_is_read"] = bool(flags_i & 1) if flags_i is not None else None
    out["emlx_is_deleted"] = bool(flags_i & 2) if flags_i is not None else None
    out["emlx_is_flagged"] = bool(flags_i & 16) if flags_i is not None else None
    out["emlx_is_junk"] = bool(flags_i & (1 << 17)) if flags_i is not None else None
    out["date_received"] = _iso(data.get("date-received"))
    out["date_sent"] = _iso(data.get("date-sent"))
    out["date_last_viewed"] = _iso(data.get("date-last-viewed"))
    out["remote_id"] = data.get("remote-id")
    out["original_mailbox"] = data.get("original-mailbox")
    out["gmail_labels"] = data.get("gmail-labels")
    out["conversation_id"] = data.get("conversation-id")
    out["color"] = data.get("color")
    out["plist_subject"] = data.get("subject")
    out["plist_sender"] = data.get("sender")
    out["plist_to"] = data.get("to")
    return out


def emlx_message_number(path: str) -> tuple[int | None, bool]:
    """(message number, is_partial) from a Messages/<num>[.partial].emlx path."""
    name = PurePosixPath((path or "").replace("\\", "/")).name
    m = _EMLX_NAME_RE.match(name)
    if not m:
        return None, False
    return int(m.group("num")), bool(m.group("partial"))


def attachment_sidecar_prefix(path: str) -> str | None:
    """Folder (posix, relative like the input) holding sidecar attachments for this message.

    ``…/Data/3/1/Messages/13.partial.emlx`` -> ``…/Data/3/1/Attachments/13/``
    """
    p = (path or "").replace("\\", "/")
    num, _ = emlx_message_number(p)
    if num is None:
        return None
    parent = PurePosixPath(p).parent
    if parent.name.lower() != "messages":
        return None
    return str(parent.parent / "Attachments" / str(num)) + "/"


def link_sidecar_attachments(path: str, all_paths: list[str] | None) -> list[dict[str, Any]]:
    """Return sidecar attachment files for an emlx from a job-wide path list.

    Callers that keep an inventory index should pass the subset under
    ``attachment_sidecar_prefix(path)``; passing the full list is fine for
    modest mailboxes.
    """
    prefix = attachment_sidecar_prefix(path)
    if not prefix or not all_paths:
        return []
    pl = prefix.lower()
    out: list[dict[str, Any]] = []
    for cand in all_paths:
        c = cand.replace("\\", "/")
        if not c.lower().startswith(pl):
            continue
        rest = c[len(prefix):]
        parts = rest.split("/", 1)
        part_index = parts[0] if parts and parts[0].isdigit() else None
        out.append({
            "path": cand,
            "file_name": PurePosixPath(c).name,
            "mime_part_index": int(part_index) if part_index else None,
            "source": "apple_mail_sidecar",
        })
    out.sort(key=lambda d: (d["mime_part_index"] or 0, d["file_name"]))
    return out


def enrich_emlx(raw: bytes, path: str, *, sibling_paths: list[str] | None = None) -> dict[str, Any]:
    """One-call enrichment used by the email parser/preview (safe on .eml too)."""
    low = (path or "").lower()
    if not low.endswith(".emlx"):
        return {"is_emlx": False}
    rfc, plist_bytes = split_emlx(raw)
    num, partial = emlx_message_number(path)
    meta = parse_emlx_plist(plist_bytes)
    meta.update({
        "is_emlx": True,
        "emlx_message_number": num,
        "emlx_partial": partial,
        "rfc822_length": len(rfc),
        "sidecar_attachments": link_sidecar_attachments(path, sibling_paths) if partial or sibling_paths else [],
    })
    if partial and not meta["sidecar_attachments"]:
        meta["sidecar_note"] = "partial.emlx — large attachments were stored under Attachments/<msgnum>/; none found in inventory"
    return meta
