"""Canonical RFC822/EML inventory used by count, parse and evidence browse.

The important forensic invariant is that an EML(X) count must be reconcilable to
openable evidence rows.  Older builds had three different domains:

* catalog counting could MIME-sniff extensionless messages;
* parsing primarily recognized .eml/.emlx paths; and
* artifact browse filtered almost exclusively on extensions.

That allowed a non-zero catalog count with an empty evidence pane.  This module
promotes byte-validated RFC822 messages into deterministic metadata so all three
paths use the same evidence set without renaming or altering source evidence.
"""

from __future__ import annotations

import json
import logging
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import execute, fetchall
from app.parsers.email_mime_parser import (
    analyze_mime_message,
    build_email_preview_details,
    is_extensionless_email_candidate,
    parse_email_file,
)
from app.services.handbook_query_sql import (
    EML_RFC822_ANY_WHERE,
    EXTENSIONLESS_EML_CANDIDATE_WHERE,
)

log = logging.getLogger("email_mime_inventory")

_JOB_SCAN_CACHE: dict[str, dict[str, Any]] = {}
_EMAIL_SCAN_VERSION = "v44.0"
_EMAIL_MAX_BYTES = 100 * 1024 * 1024
_EMAIL_HEAD_BYTES = 65_536

# Include derived Outlook->EML rows for MIME parsing/attachment extraction.  The
# EML(X) catalog predicate separately excludes ``derived_from_mailbox`` so the
# Outlook Emails and EML(X) categories stay distinct.
EML_EMLX_SCAN_WHERE = EML_RFC822_ANY_WHERE


def clear_email_mime_scan_cache(job_id: str | None = None) -> None:
    if job_id:
        _JOB_SCAN_CACHE.pop(job_id, None)
    else:
        _JOB_SCAN_CACHE.clear()


def _system_mail_exclude() -> str:
    from app.services.email_inventory import _SYSTEM_MAIL_EXCLUDE

    return _SYSTEM_MAIL_EXCLUDE


def _read_artifact_bytes(db, job_id: str, row: dict[str, Any], *, max_bytes: int | None) -> bytes:
    """Read from MinIO, extracted tar shards, or the virtual disk.

    ``minio_uri IS NOT NULL`` used to be a hidden prerequisite for MIME scanning.
    That excluded part-backed/zero-copy evidence even though the Artifact preview
    code could open it.  Reuse the same forensic content resolver as the UI.
    """
    from app.services.artifact_preview import iter_artifact_content

    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in iter_artifact_content(db, job_id, row, max_bytes=max_bytes):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if max_bytes is not None and total >= max_bytes:
                break
    except Exception as exc:
        log.debug("RFC822 read failed job=%s id=%s: %s", job_id, row.get("id"), exc)
        return b""
    data = b"".join(chunks)
    return data if max_bytes is None else data[:max_bytes]


def _normalized_mail_filename(row: dict[str, Any], path: str) -> str:
    current = str(row.get("file_name") or "").strip()
    if current:
        low = current.lower()
        if low.endswith((".eml", ".emlx")):
            return current
        return f"{current}.eml"
    leaf = PurePosixPath((path or "message").replace("\\", "/")).name or "message"
    if leaf.lower().endswith((".eml", ".emlx")):
        return leaf
    return f"{leaf}.eml"


def _persist_email_mime_classification(
    db,
    job_id: str,
    row: dict[str, Any],
    data: bytes,
    path: str,
    info: dict[str, Any],
) -> dict[str, Any]:
    """Persist RFC822 classification + normalized parse records for reconciliation."""
    details = build_email_preview_details(data, path)
    if not details.get("parse_ok"):
        return {"persisted": False, "attachments": 0}

    headers = details.get("headers") if isinstance(details.get("headers"), dict) else {}
    attachments = list(details.get("attachments") or [])
    ext = str(row.get("extension") or "").lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    detected_ext = ".emlx" if ext == ".emlx" or path.lower().endswith(".emlx") else ".eml"
    patch = {
        "email_mime_scan_version": _EMAIL_SCAN_VERSION,
        "email_mime_validated": True,
        "resolved_content_type": "message/rfc822",
        "content_type": "message/rfc822",
        "content_type_label": "RFC822 Email Message",
        "type_label": "Email Message",
        "detected_extension": detected_ext,
        "detected_kind": "email",
        "type_source": "email_mime_parser",
        "type_confidence": "high",
        # Examiner-facing derived filename only; original file_name/file_path remain unchanged.
        "normalized_filename": _normalized_mail_filename(row, path),
        "email_subject": str(headers.get("subject") or ""),
        "email_from": str(headers.get("from") or ""),
        "email_to": str(headers.get("to") or ""),
        "email_cc": str(headers.get("cc") or ""),
        "email_date": str(headers.get("date") or ""),
        "email_message_id": str(headers.get("message_id") or info.get("message_id") or ""),
        "email_mime_attachment_count": len(attachments),
        "email_mime_attachments": attachments,
    }
    artifact_id = str(row.get("id") or "")
    execute(
        db,
        """UPDATE job_artifacts
           SET metadata=coalesce(metadata, '{}'::jsonb) || CAST(:patch AS jsonb),
               parse_status=CASE
                 WHEN coalesce(parse_status,'pending') IN ('pending','no_parser','skipped','error')
                   THEN 'parsed'
                 ELSE parse_status
               END,
               updated_at=NOW()
           WHERE id=:id AND job_id=:jid""",
        {"patch": json.dumps(patch, ensure_ascii=False, default=str), "id": artifact_id, "jid": job_id},
    )

    records = parse_email_file(data, path)
    # Idempotent enrichment row.  Do not delete normal parser results: this row is a
    # reconciliation source that can repair already-finished historical jobs.
    execute(
        db,
        "DELETE FROM artifact_parse_results WHERE job_artifact_id=:aid AND parser_name='email_mime_inventory'",
        {"aid": artifact_id},
    )
    execute(
        db,
        """INSERT INTO artifact_parse_results
             (job_artifact_id, parser_name, parser_version, record_count, byte_offset, normalized)
           VALUES (:aid, 'email_mime_inventory', :ver, :cnt, 0, CAST(:norm AS jsonb))""",
        {
            "aid": artifact_id,
            "ver": _EMAIL_SCAN_VERSION,
            "cnt": len(records),
            "norm": json.dumps(records, ensure_ascii=False, default=str).replace("\\u0000", ""),
        },
    )
    return {"persisted": True, "attachments": len(attachments)}


def _scan_one_message(
    db,
    job_id: str,
    row: dict[str, Any],
    *,
    extensionless_candidate: bool,
) -> tuple[dict[str, Any] | None, bool]:
    path = str(row.get("file_path") or row.get("file_name") or "")
    # Extensionless population can be very large.  A 64 KiB RFC header gate avoids
    # fully reading unrelated browser/cache binaries.
    if extensionless_candidate:
        head = _read_artifact_bytes(db, job_id, row, max_bytes=_EMAIL_HEAD_BYTES)
        if not head or not is_extensionless_email_candidate(head):
            return None, False

    data = _read_artifact_bytes(db, job_id, row, max_bytes=_EMAIL_MAX_BYTES)
    if not data:
        return None, True
    info = analyze_mime_message(data, path)
    if not info.get("parse_ok"):
        return None, True
    persisted = _persist_email_mime_classification(db, job_id, row, data, path, info)
    info = dict(info)
    info["persisted"] = bool(persisted.get("persisted"))
    return info, False


def scan_job_email_mime_inventory(
    db,
    job_id: str,
    *,
    max_eml_files: int = 20_000,
    max_extensionless: int = 4_000,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Validate RFC822 messages and persist one canonical EML evidence set.

    Counts are occurrence counts.  Source evidence is never renamed or modified;
    classification lives in ``job_artifacts.metadata`` and parse records.
    """
    if use_cache and job_id in _JOB_SCAN_CACHE:
        return dict(_JOB_SCAN_CACHE[job_id])

    exclude = _system_mail_exclude()
    totals: dict[str, Any] = {
        "scan_version": _EMAIL_SCAN_VERSION,
        "eml_emlx_files_scanned": 0,
        "extensionless_candidates_scanned": 0,
        "message_occurrences": 0,
        "attachment_occurrences": 0,
        "inline_occurrences": 0,
        "attached_rfc822": 0,
        "unique_attachment_content": 0,
        "extensionless_messages": 0,
        "mime_rows_promoted": 0,
        "parse_failures": 0,
    }
    unique_hashes: set[str] = set()
    processed_ids: set[str] = set()

    columns = "id, file_path, file_name, extension, minio_uri, size_bytes, metadata"
    eml_rows = fetchall(
        db,
        f"""SELECT {columns}
            FROM job_artifacts
            WHERE job_id=:j
              AND ({EML_EMLX_SCAN_WHERE.strip()})
              {exclude}
            ORDER BY
              CASE WHEN coalesce(metadata->>'email_mime_validated','false') IN ('true','1','t') THEN 1 ELSE 0 END,
              size_bytes ASC NULLS LAST, id
            LIMIT :lim""",
        {"j": job_id, "lim": max_eml_files},
    )
    for row in eml_rows:
        aid = str(row.get("id") or "")
        processed_ids.add(aid)
        info, failed = _scan_one_message(db, job_id, row, extensionless_candidate=False)
        totals["eml_emlx_files_scanned"] += 1
        if failed or not info:
            totals["parse_failures"] += 1
            continue
        totals["message_occurrences"] += int(info.get("message_occurrences") or 0)
        totals["attachment_occurrences"] += int(info.get("attachment_occurrences") or 0)
        totals["inline_occurrences"] += int(info.get("inline_occurrences") or 0)
        totals["attached_rfc822"] += int(info.get("attached_rfc822") or 0)
        totals["mime_rows_promoted"] += 1 if info.get("persisted") else 0
        for h in info.get("unique_content_hashes") or []:
            unique_hashes.add(str(h))

    ext_rows = fetchall(
        db,
        f"""SELECT {columns}
            FROM job_artifacts
            WHERE job_id=:j
              AND ({EXTENSIONLESS_EML_CANDIDATE_WHERE.strip()})
              {exclude}
            ORDER BY
              CASE
                WHEN lower(replace(coalesce(file_path,''), '\\', '/')) LIKE '%/mail/%' THEN 0
                WHEN lower(replace(coalesce(file_path,''), '\\', '/')) LIKE '%/downloads/%' THEN 1
                ELSE 2
              END,
              size_bytes ASC NULLS LAST, id
            LIMIT :lim""",
        {"j": job_id, "lim": max_extensionless},
    )
    for row in ext_rows:
        aid = str(row.get("id") or "")
        if aid in processed_ids:
            continue
        totals["extensionless_candidates_scanned"] += 1
        info, failed = _scan_one_message(db, job_id, row, extensionless_candidate=True)
        if failed:
            totals["parse_failures"] += 1
            continue
        if not info:
            continue
        totals["extensionless_messages"] += 1
        totals["message_occurrences"] += int(info.get("message_occurrences") or 0)
        totals["attachment_occurrences"] += int(info.get("attachment_occurrences") or 0)
        totals["inline_occurrences"] += int(info.get("inline_occurrences") or 0)
        totals["attached_rfc822"] += int(info.get("attached_rfc822") or 0)
        totals["mime_rows_promoted"] += 1 if info.get("persisted") else 0
        for h in info.get("unique_content_hashes") or []:
            unique_hashes.add(str(h))

    db.commit()
    totals["unique_attachment_content"] = len(unique_hashes)
    _JOB_SCAN_CACHE[job_id] = dict(totals)
    return dict(totals)


def count_mime_attachment_occurrences(db, job_id: str) -> int:
    try:
        scan = scan_job_email_mime_inventory(db, job_id)
        return int(scan.get("attachment_occurrences") or 0)
    except Exception as exc:
        log.warning("MIME attachment scan failed job=%s: %s", job_id, exc)
        try:
            db.rollback()
        except Exception:
            pass
        return 0


def count_eml_message_occurrences(db, job_id: str) -> dict[str, int]:
    """Message occurrence totals after canonical RFC822 reconciliation."""
    try:
        scan = scan_job_email_mime_inventory(db, job_id)
        return {
            "mime_messages": int(scan.get("message_occurrences") or 0),
            "extensionless_messages": int(scan.get("extensionless_messages") or 0),
            "eml_emlx_scanned": int(scan.get("eml_emlx_files_scanned") or 0),
            "parse_failures": int(scan.get("parse_failures") or 0),
        }
    except Exception as exc:
        log.warning("EML message scan failed job=%s: %s", job_id, exc)
        try:
            db.rollback()
        except Exception:
            pass
        return {
            "mime_messages": 0,
            "extensionless_messages": 0,
            "eml_emlx_scanned": 0,
            "parse_failures": 0,
        }
