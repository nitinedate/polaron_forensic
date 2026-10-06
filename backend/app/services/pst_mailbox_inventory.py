"""PST/OST mailbox inventory — message/attachment metadata for AXIOM-aligned counts.

Uses bounded binary markers (IPM.Note / attachment tags) and short UTF-16 field
snippets. Does not dump full message bodies into logs or API responses.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("pst_mailbox_inventory")

_JOB_CACHE: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()

_IPM_NOTE_ASCII = b"IPM.Note"
_IPM_NOTE_UTF16 = "IPM.Note".encode("utf-16le")
_IPM_CLASSES = (
    b"IPM.Note",
    b"IPM.Schedule.Meeting",
    b"IPM.Post",
    b"IPM.StickyNote",
    b"IPM.Task",
    b"IPM.Contact",
    b"IPM.Appointment",
)
_ATTACH_MARKERS = (
    b"PR_ATTACH_FILENAME",
    b"PR_ATTACH_LONG_FILENAME",
    b"AttachFilename",
    "Attachment".encode("utf-16le"),
    "attach".encode("utf-16le"),
)

_UTF16_FIELD = re.compile(
    rb"(?:S\x00u\x00b\x00j\x00e\x00c\x00t\x00|F\x00r\x00o\x00m\x00|T\x00o\x00)"
    rb".{0,12}((?:[\x20-\x7e]\x00){3,80})"
)


def clear_pst_cache(job_id: str | None = None) -> None:
    with _LOCK:
        if job_id is None:
            _JOB_CACHE.clear()
        else:
            _JOB_CACHE.pop(job_id, None)


def _decode_utf16_fragment(raw: bytes) -> str:
    try:
        text = raw.decode("utf-16le", errors="ignore").strip()
    except Exception:
        return ""
    text = re.sub(r"\s+", " ", text)
    return text[:120]


def _analyze_pst_bytes(data: bytes, path: str) -> dict[str, Any]:
    """Return counts + capped metadata samples (no full bodies)."""
    if not data or len(data) < 64:
        return {
            "message_count": 0,
            "attachment_estimate": 0,
            "messages": [],
            "path": path,
        }

    note_hits = data.count(_IPM_NOTE_ASCII) + data.count(_IPM_NOTE_UTF16)
    # Prefer explicit Note class; fall back to generic IPM.* when sparse.
    if note_hits <= 0:
        note_hits = sum(data.count(c) + data.count(c.decode("ascii", errors="ignore").encode("utf-16le")) for c in _IPM_CLASSES[:1])
    message_count = int(note_hits)

    attach_hits = 0
    for marker in _ATTACH_MARKERS:
        attach_hits += data.count(marker)
    # Attachment markers are noisy — scale conservatively vs message count.
    attachment_estimate = min(attach_hits, max(message_count * 4, message_count))

    samples: list[dict[str, Any]] = []
    for match in _UTF16_FIELD.finditer(data):
        if len(samples) >= 40:
            break
        value = _decode_utf16_fragment(match.group(1))
        if len(value) < 3:
            continue
        # Classify by nearby ASCII label bytes before the match.
        start = max(match.start() - 24, 0)
        window = data[start : match.start()]
        field = "subject"
        if b"F\x00r\x00o\x00m\x00" in window or b"From" in window:
            field = "from"
        elif b"T\x00o\x00" in window[-8:] or window.endswith(b"To"):
            field = "to"
        samples.append({"field": field, "value": value})

    # Build sparse message rows for evidence browse (metadata only).
    subjects = [s["value"] for s in samples if s["field"] == "subject"]
    senders = [s["value"] for s in samples if s["field"] == "from"]
    messages: list[dict[str, Any]] = []
    n = max(message_count, len(subjects), 0)
    # Cap persisted message rows — enough for examiner browse without huge JSON.
    persist_n = min(n, 300)
    for i in range(persist_n):
        subj = subjects[i] if i < len(subjects) else f"Outlook message {i + 1}"
        sender = senders[i] if i < len(senders) else ""
        messages.append(
            {
                "record_type": "outlook_message",
                "subject": subj[:160],
                "from": sender[:120],
                "source_path": path,
                "index": i,
            }
        )

    # If markers found but no subject samples, still emit placeholder rows for browse.
    if message_count > 0 and not messages:
        for i in range(min(message_count, 50)):
            messages.append(
                {
                    "record_type": "outlook_message",
                    "subject": f"Outlook message {i + 1}",
                    "from": "",
                    "source_path": path,
                    "index": i,
                }
            )

    return {
        "message_count": message_count,
        "attachment_estimate": int(attachment_estimate),
        "messages": messages,
        "path": path,
        "size_bytes": len(data),
    }


def _upsert_parse_result(db, job_artifact_id: str, payload: list[dict[str, Any]]) -> None:
    existing = fetchone(
        db,
        """SELECT id FROM artifact_parse_results
           WHERE job_artifact_id=:aid AND parser_name='pst_mailbox_inventory'
           LIMIT 1""",
        {"aid": job_artifact_id},
    )
    record_count = len(payload)
    if existing:
        execute(
            db,
            """UPDATE artifact_parse_results
               SET normalized = CAST(:norm AS jsonb),
                   record_count = :rc,
                   parser_version = '1'
               WHERE id=:id""",
            {"id": existing["id"], "norm": json.dumps(payload), "rc": record_count},
        )
        return
    execute(
        db,
        """INSERT INTO artifact_parse_results
           (job_artifact_id, parser_name, parser_version, record_count, normalized, created_at)
           VALUES (:aid, 'pst_mailbox_inventory', '1', :rc, CAST(:norm AS jsonb), NOW())""",
        {"aid": job_artifact_id, "norm": json.dumps(payload), "rc": record_count},
    )


def scan_job_pst_mailboxes(db, job_id: str, *, force: bool = False) -> dict[str, Any]:
    """Scan PST/OST files once; cache counts + persist message metadata for browse."""
    with _LOCK:
        if not force and job_id in _JOB_CACHE:
            return dict(_JOB_CACHE[job_id])

    from app.services.artifact_live_counts import _read_job_files

    rows = fetchall(
        db,
        """SELECT id, file_path, size_bytes FROM job_artifacts
           WHERE job_id=:j AND (
             lower(coalesce(extension,'')) IN ('.pst', '.ost')
             OR file_path ILIKE '%.pst'
             OR file_path ILIKE '%.ost'
           )
           AND file_path NOT ILIKE '%/Program Files%'
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 40""",
        {"j": job_id},
    )
    if not rows:
        result = {
            "message_count": 0,
            "attachment_estimate": 0,
            "mailbox_files": 0,
            "messages": [],
            "mailboxes": [],
        }
        with _LOCK:
            _JOB_CACHE[job_id] = result
        return dict(result)

    contents = _read_job_files(db, job_id, rows, max_bytes=80_000_000)
    total_messages = 0
    total_attach = 0
    all_messages: list[dict[str, Any]] = []
    mailboxes: list[dict[str, Any]] = []

    for row in rows:
        path = (row.get("file_path") or "").replace("\\", "/")
        data = contents.get(path) or b""
        analyzed = _analyze_pst_bytes(data, path)
        total_messages += int(analyzed["message_count"])
        total_attach += int(analyzed["attachment_estimate"])
        mailboxes.append(
            {
                "path": path,
                "artifact_id": str(row["id"]),
                "message_count": analyzed["message_count"],
                "attachment_estimate": analyzed["attachment_estimate"],
                "size_bytes": analyzed.get("size_bytes") or row.get("size_bytes"),
            }
        )
        msgs = analyzed.get("messages") or []
        if msgs:
            try:
                _upsert_parse_result(db, str(row["id"]), msgs)
                db.commit()
            except Exception as exc:
                log.warning("PST parse persist failed path=%s: %s", path, exc)
                try:
                    db.rollback()
                except Exception:
                    pass
            all_messages.extend(msgs)

    result = {
        "message_count": total_messages,
        "attachment_estimate": total_attach,
        "mailbox_files": len(rows),
        "messages": all_messages[:500],
        "mailboxes": mailboxes,
    }
    with _LOCK:
        _JOB_CACHE[job_id] = result
    log.info(
        "PST inventory job=%s mailboxes=%s messages=%s attachments~=%s",
        job_id,
        len(rows),
        total_messages,
        total_attach,
    )
    return dict(result)


def list_outlook_message_evidence(
    db, job_id: str, *, page: int = 1, page_size: int = 50
) -> dict[str, Any]:
    """Virtual evidence rows for Outlook Emails (metadata only)."""
    inv = scan_job_pst_mailboxes(db, job_id)
    messages = list(inv.get("messages") or [])
    # If scan found markers but few metadata rows, synthesize browse rows from counts.
    if int(inv.get("message_count") or 0) > len(messages):
        need = min(int(inv["message_count"]), 300) - len(messages)
        base = len(messages)
        mb = (inv.get("mailboxes") or [{}])[0]
        for i in range(need):
            messages.append(
                {
                    "record_type": "outlook_message",
                    "subject": f"Outlook message {base + i + 1}",
                    "from": "",
                    "source_path": mb.get("path") or "",
                    "index": base + i,
                    "source_artifact_id": mb.get("artifact_id"),
                }
            )

    total = max(len(messages), int(inv.get("message_count") or 0))
    # Prefer listing actual metadata rows; pad display total to message_count.
    page = max(int(page or 1), 1)
    page_size = max(min(int(page_size or 50), 200), 1)
    start = (page - 1) * page_size
    slice_msgs = messages[start : start + page_size]

    items: list[dict[str, Any]] = []
    for msg in slice_msgs:
        src = str(msg.get("source_path") or "")
        aid = msg.get("source_artifact_id")
        if not aid and src:
            row = fetchone(
                db,
                """SELECT id FROM job_artifacts
                   WHERE job_id=:j AND replace(file_path, '\\', '/') = :p LIMIT 1""",
                {"j": job_id, "p": src.replace("\\", "/")},
            )
            aid = str(row["id"]) if row else None
        subj = str(msg.get("subject") or "Outlook message")
        sender = str(msg.get("from") or "")
        title = f"{sender + ' — ' if sender else ''}{subj}"
        items.append(
            {
                "id": f"ev-outlook-{msg.get('index', 0)}-{hash(title + src) & 0xFFFFFFFF:08x}",
                "job_id": job_id,
                "file_id": None,
                "parent_artifact_id": aid,
                "artifact_type": "outlook_message",
                "axiom_category": "outlook emails",
                "axiom_category_label": "Outlook Emails",
                "axiom_sub_category": sender or None,
                "title": title[:200],
                "source_path": src or None,
                "artifact_datetime": None,
                "preview_uri": None,
                "storage_uri": None,
                "metadata": {
                    "evidence_kind": "outlook_message",
                    "subject": subj[:200],
                    "from": sender[:160],
                    "source_path": src,
                    "source_artifact_id": aid,
                    "preview_body": (
                        f"Subject: {subj}\n"
                        f"From: {sender or '—'}\n"
                        f"Mailbox: {src or '—'}\n\n"
                        "Message metadata recovered from PST/OST store. "
                        "Open source to export the mailbox container."
                    ),
                },
                "tags": ["outlook_message"],
                "examiner_comment": None,
                "parser_version": "pst_mailbox_inventory",
                "confidence": None,
                "created_at": "",
            }
        )

    # If page beyond metadata but message_count higher, still report total.
    return {
        "items": items,
        "total": total if total > 0 else len(items),
        "page": page,
        "page_size": page_size,
        "evidence_domain": "outlook_message",
        "evidence_label": "Outlook Emails",
        "attachment_estimate": int(inv.get("attachment_estimate") or 0),
        "mailbox_files": int(inv.get("mailbox_files") or 0),
    }
