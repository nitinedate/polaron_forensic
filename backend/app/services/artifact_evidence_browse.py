"""Evidence-row browse for catalog artifacts whose counts are not file rows.

AXIOM-style Communication / Email counts are often visit or message records.
The Artifacts page must list those records (with source path + preview payload)
so examiners can open what the count represents.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone

# Short TTL cache so repeated Open (dialog remount / sibling merges) stay fast.
_EVIDENCE_ROW_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_EVIDENCE_CACHE_TTL_SEC = 300.0
_EVIDENCE_CACHE_MAX = 64

# On-disk ChatStorage / msgstore so Open / thread / deleted reuse one download.
_STORE_FILE_CACHE: dict[str, tuple[float, str]] = {}
_STORE_FILE_TTL_SEC = 1800.0


def _cache_get(key: str) -> list[dict[str, Any]] | None:
    hit = _EVIDENCE_ROW_CACHE.get(key)
    if not hit:
        return None
    ts, rows = hit
    if time.monotonic() - ts > _EVIDENCE_CACHE_TTL_SEC:
        _EVIDENCE_ROW_CACHE.pop(key, None)
        return None
    return list(rows)


def _cache_set(key: str, rows: list[dict[str, Any]]) -> None:
    if len(_EVIDENCE_ROW_CACHE) >= _EVIDENCE_CACHE_MAX:
        # Drop oldest entries.
        for old_key, _ in sorted(_EVIDENCE_ROW_CACHE.items(), key=lambda kv: kv[1][0])[
            : max(1, _EVIDENCE_CACHE_MAX // 4)
        ]:
            _EVIDENCE_ROW_CACHE.pop(old_key, None)
    _EVIDENCE_ROW_CACHE[key] = (time.monotonic(), list(rows))


def _persist_browse_cache(db: Session, job_id: str, kind: str, rows: list[dict[str, Any]]) -> None:
    try:
        execute(
            db,
            """INSERT INTO job_evidence_browse_cache (job_id, cache_kind, payload, updated_at)
               VALUES (:j, :k, CAST(:p AS jsonb), NOW())
               ON CONFLICT (job_id, cache_kind)
               DO UPDATE SET payload = EXCLUDED.payload, updated_at = NOW()""",
            {"j": job_id, "k": kind, "p": json.dumps(rows, default=str)},
        )
        db.flush()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _load_browse_cache(db: Session, job_id: str, kind: str) -> list[dict[str, Any]] | None:
    try:
        row = fetchone(
            db,
            """SELECT payload FROM job_evidence_browse_cache
               WHERE job_id=:j AND cache_kind=:k""",
            {"j": job_id, "k": kind},
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None
    if not row:
        return None
    payload = row.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return None
    if isinstance(payload, list) and payload:
        return list(payload)
    return None


def _cached_store_path(db: Session, job_id: str, row: dict[str, Any]) -> str | None:
    """Download ChatStorage/msgstore once and reuse the temp file for 30 minutes."""
    aid = str(row.get("id") or "")
    key = f"{job_id}:{aid}"
    hit = _STORE_FILE_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < _STORE_FILE_TTL_SEC and os.path.exists(hit[1]):
        return hit[1]
    from app.services.artifact_preview import resolve_artifact_bytes

    try:
        data = resolve_artifact_bytes(
            db, job_id, row, persist=False, max_bytes=512 * 1024 * 1024
        )
    except Exception:
        return None
    if not data or not data[:16].startswith(b"SQLite format"):
        return None
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    old = _STORE_FILE_CACHE.get(key)
    _STORE_FILE_CACHE[key] = (time.monotonic(), path)
    if old and old[1] != path:
        try:
            os.unlink(old[1])
        except OSError:
            pass
    return path


def _is_placeholder_deleted_body(body: str) -> bool:
    t = (body or "").strip().lower()
    if not t:
        return True
    return (
        "deleted this message" in t
        or t.startswith("🚫")
        or t in {"[deleted]", "this message was deleted", "you deleted this message"}
    )


def _sanitize_deleted_protocol_noise(messages: list[dict[str, Any]]) -> None:
    """Move JID/hash residue out of original content; keep recovered chat text."""
    from app.services.chat_message_extract import (
        _is_whatsapp_protocol_noise,
        _split_whatsapp_carve_text,
        _strip_placeholder_wrappers,
    )

    for item in messages:
        meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else None
        if not meta:
            continue
        oc = str(meta.get("original_content") or "").strip()
        body = str(meta.get("body") or "").strip()
        preview = str(meta.get("preview_body") or "").strip()
        changed = False

        def _clean_field(raw: str) -> tuple[str, str]:
            clean, residue = _split_whatsapp_carve_text(raw)
            return clean, residue

        # Recover text from a stale preview_body when original_content was never set.
        if not oc and "Original content:" in preview:
            clean_p, res_p = _clean_field(preview)
            if clean_p:
                oc = clean_p
                meta["original_content"] = clean_p
                changed = True
            if res_p:
                meta["protocol_residue"] = res_p
                changed = True

        if oc:
            clean, residue = _clean_field(oc)
            if residue:
                meta["protocol_residue"] = residue
                changed = True
            if clean and clean != oc:
                meta["original_content"] = clean
                changed = True
            elif not clean and (_is_whatsapp_protocol_noise(oc) or "@" in oc):
                meta.pop("original_content", None)
                changed = True

        if body:
            core, suffix = _strip_placeholder_wrappers(body)
            clean, residue = _clean_field(core if core else body)
            if residue:
                meta["protocol_residue"] = meta.get("protocol_residue") or residue
                changed = True
            if clean and (clean != core.strip() or residue):
                placeholder = suffix or (
                    "(🚫 You deleted this message)"
                    if meta.get("from_me")
                    else "(🚫 This message was deleted)"
                )
                if "deleted this message" in body.lower() and not suffix:
                    placeholder = (
                        "(🚫 You deleted this message)"
                        if meta.get("from_me")
                        else "(🚫 This message was deleted)"
                    )
                new_body = f"{clean}\n{placeholder}" if "deleted" in body.lower() else clean
                if new_body != body:
                    meta["body"] = new_body
                    changed = True
                meta["original_content"] = clean
                changed = True
            elif _is_whatsapp_protocol_noise(body):
                placeholder = (
                    "🚫 You deleted this message"
                    if meta.get("from_me")
                    else "🚫 This message was deleted"
                )
                media = str(meta.get("media_name") or "").strip()
                meta["body"] = (
                    f"[ATTACHMENT] {media}\n({placeholder})"
                    if media
                    else (
                        "(Original text not recovered — only Delete-for-Everyone placeholder remains)\n"
                        f"({placeholder})"
                    )
                )
                changed = True

        oc_now = str(meta.get("original_content") or "").strip()
        # Always rebuild preview when residue was separated or JID still leaked into text.
        needs_preview = changed or (
            "@g.us" in oc_now.lower()
            or "@g.us" in preview.lower()
            or bool(meta.get("protocol_residue"))
        )
        if needs_preview and (oc_now or meta.get("protocol_residue") or "Original content:" in preview):
            # Re-split in case preview still embeds a glued JID+message line.
            if oc_now and ("@" in oc_now):
                clean2, res2 = _clean_field(oc_now)
                if clean2:
                    oc_now = clean2
                    meta["original_content"] = clean2
                if res2:
                    meta["protocol_residue"] = res2
            meta["preview_body"] = _format_deleted_preview_body(
                conversation=str(meta.get("conversation") or ""),
                sender=str(meta.get("sender") or ""),
                ts=meta.get("timestamp") or item.get("artifact_datetime"),
                body=oc_now
                or "(Original text not recovered — only Delete-for-Everyone placeholder remains)",
                recovery_state=str(meta.get("recovery_state") or ""),
                source_path=str(meta.get("source_path") or item.get("source_path") or ""),
                media_name=meta.get("media_name") if isinstance(meta.get("media_name"), str) else None,
                confidence=str(meta.get("confidence") or "MEDIUM"),
                row_id=meta.get("chat_row_id"),
                protocol_residue=str(meta.get("protocol_residue") or "") or None,
            )
            changed = True

        if changed:
            if meta.get("original_content"):
                item["title"] = (
                    f"{meta.get('conversation') or ''} · {meta.get('sender') or ''}: "
                    f"{str(meta['original_content'])[:100]}"
                ).strip(" ·")
            item["metadata"] = meta


def _enrich_deleted_originals_from_job(
    db: Session,
    job_id: str,
    messages: list[dict[str, Any]],
) -> None:
    """Fill original text for Delete-for-Everyone / unread-deleted rows.

    ChatStorage often keeps only a type-14 placeholder. The actual body may still
    sit in ChatSearch FTS, iOS notification stores, or leftover SQLite pages —
    including messages the local user never opened.
    """
    from app.services.chat_message_extract import _is_whatsapp_protocol_noise

    _sanitize_deleted_protocol_noise(messages)

    pending = []
    for item in messages:
        meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if not meta.get("is_deleted") and "deleted" not in str(item.get("artifact_type") or ""):
            continue
        oc = str(meta.get("original_content") or "").strip()
        # Protocol noise must not block ChatSearch / notification enrichment.
        if oc and not _is_placeholder_deleted_body(oc) and not _is_whatsapp_protocol_noise(oc):
            continue
        if not _is_placeholder_deleted_body(str(meta.get("body") or item.get("title") or "")):
            # Body may still be noise+placeholder; allow those through.
            body = str(meta.get("body") or "")
            if not (_is_whatsapp_protocol_noise(body) or "deleted this message" in body.lower()):
                continue
        pending.append(item)
    if not pending:
        return

    from app.services.chat_message_extract import (
        extract_searchable_message_texts_from_path,
        match_deleted_original_text,
    )

    extras = fetchall(
        db,
        """SELECT id, file_path, file_name, size_bytes, minio_uri, extension
           FROM job_artifacts
           WHERE job_id=:j AND (
             lower(file_name) LIKE 'chatsearch%'
             OR lower(file_name) LIKE '%notification%'
             OR lower(file_name) LIKE 'pushstore%'
             OR lower(file_name) LIKE '%usernotification%'
           )
           AND lower(file_name) NOT LIKE '%.crypt%'
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 12""",
        {"j": job_id},
    )
    corpus: list[dict[str, Any]] = []
    for row in extras:
        store_path = _cached_store_path(db, job_id, dict(row))
        if not store_path:
            continue
        try:
            corpus.extend(
                extract_searchable_message_texts_from_path(
                    store_path, str(row.get("file_path") or "")
                )
            )
        except Exception:
            continue
        if len(corpus) >= 20_000:
            break

    for item in pending:
        meta = item.get("metadata") or {}
        hit = match_deleted_original_text(
            {
                "timestamp": meta.get("timestamp") or item.get("artifact_datetime"),
                "chat_jid": meta.get("chat_jid"),
                "conversation": meta.get("conversation"),
                "sender": meta.get("sender"),
                "stanza_id": meta.get("stanza_id"),
                "body": meta.get("body"),
            },
            corpus,
        )
        if not hit:
            continue
        original = str(hit.get("text") or "").strip()
        if not original or _is_placeholder_deleted_body(original):
            continue
        if _is_whatsapp_protocol_noise(original):
            continue
        ts = meta.get("timestamp") or item.get("artifact_datetime") or "—"
        sender = meta.get("sender") or "unknown"
        conversation = meta.get("conversation") or ""
        preview = _format_deleted_preview_body(
            conversation=conversation,
            sender=sender,
            ts=ts,
            body=original,
            recovery_state=str(hit.get("recovery_state") or "whatsapp_search_index"),
            source_path=str(hit.get("source") or meta.get("source_path") or ""),
            media_name=meta.get("media_name"),
            confidence="HIGH" if hit.get("recovery_state") == "whatsapp_notification" else "MEDIUM",
            row_id=meta.get("chat_row_id"),
        )
        meta["body"] = original[:8000]
        meta["original_content"] = original[:8000]
        meta["preview_body"] = preview
        meta["recovery_state"] = hit.get("recovery_state") or "whatsapp_search_index"
        item["metadata"] = meta
        item["title"] = (
            f"{conversation} · {sender}: {original[:100]}"
            if conversation
            else f"{sender}: {original[:120]}"
        )


def _whatsapp_store_files(db: Session, job_id: str) -> list[dict[str, Any]]:
    """Locate plaintext WhatsApp chat DBs using name indexes (not full-table ILIKE)."""
    files = fetchall(
        db,
        """SELECT id, file_path, file_name, extension, size_bytes, created_at, metadata,
                  encyclopedia_artifact_id, minio_uri
           FROM job_artifacts
           WHERE job_id=:j AND (
             lower(file_name) IN (
               'msgstore.db', 'wa.db', 'chatstorage.sqlite', 'messages.db',
               'extchatdatabase.sqlite'
             )
             OR lower(file_name) LIKE 'msgstore.db-%'
             OR lower(file_name) LIKE 'wa.db-%'
             OR lower(file_name) LIKE 'chatstorage.sqlite%'
           )
           AND lower(file_name) NOT LIKE '%.crypt%'
           AND lower(file_name) NOT LIKE '%.enc'
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 40""",
        {"j": job_id},
    )
    out: list[dict[str, Any]] = []
    for row in files:
        path = str(row.get("file_path") or "")
        name = str(row.get("file_name") or "")
        if _is_whatsapp_chat_store(path, name):
            out.append(dict(row))
    return out


_URL_CATEGORY_NAMES = frozenset({
    "web chat urls",
    "social media urls",
    "malware/phishing urls",
    "malware / phishing urls",
    "pornography urls",
    "dating site urls",
})

# Full browser history (all visited URLs) — not limited to chat/social/malware classifiers.
_BROWSER_HISTORY_NAMES = frozenset({
    "browser history",
    "browsing history",
    "visited urls",
    "url history",
    "web history",
    "all urls",
    "browser history / web data",
})

_WHATSAPP_NAMES = frozenset({
    "whatsapp messages",
    "whatsapp chats",
})

_WHATSAPP_DELETED_NAMES = frozenset({
    "whatsapp deleted messages",
})

_CONTACT_NAMES = frozenset({
    "contacts",
    "contact",
    "address book",
    "device contacts",
})

_EMAIL_ATTACHMENT_NAMES = frozenset({
    "email attachments",
    "email attachment",
})

_SMS_ATTACHMENT_NAMES = frozenset({
    "sms / mms attachments",
    "sms attachments",
    "mms attachments",
})

_DELETED_SOCIAL_NAMES = frozenset({
    "deleted social / chat data",
    "deleted social",
    "deleted chat residuals",
    "deleted chat residuals (all apps)",
})

# These share the WhatsApp product name but must NOT use message browse
# (contacts/calls/groups are different stores — wa.db / CallHistory, not msgstore).
_WHATSAPP_NON_MESSAGE_NAMES = frozenset({
    "whatsapp contacts",
    "whatsapp calls",
    "whatsapp groups",
    "whatsapp media",
    "whatsapp encrypted backups",
    "whatsapp",
})

_SMS_NAMES = frozenset({
    "sms messages",
    "android sms",
    "sms/mms",
    "sms",
    "imessage",
    "imessage messages",
    "mms",
})

_CHAT_APP_NAMES = frozenset({
    "telegram",
    "telegram messages",
    "signal",
    "signal messages",
    "linkedin",
    "linkedin messages",
    "facebook",
    "facebook messenger",
    "messenger",
    "instagram",
    "instagram messages",
    "snapchat",
    "discord",
    "viber",
    "wechat",
    "skype",
    "slack",
    "teams",
    "microsoft teams",
})

_OUTLOOK_EMAIL_NAMES = frozenset({
    "outlook emails",
    "outlook 11 emails",
})

# Pure carve catalogs (no useful allocated filesystem rows).
_CARVE_ONLY_NAMES = frozenset({
    "photoshop files",
})

# Allocated SQL browse + carved signature uplift (Picture / docs / mail files).
_CARVE_MERGE_NAMES = frozenset({
    "picture",
    "pictures",
    "pdf documents",
    "rtf documents",
    "microsoft word documents",
    "microsoft excel documents",
    "microsoft powerpoint documents",
    "eml(x) files",
    "email attachments",
})


def _norm(name: str) -> str:
    s = re.sub(r"\s+", " ", (name or "").strip().lower())
    return re.sub(r"\s*[-–/]\s*(ios|android|windows|macos|mac os)\s*$", "", s).strip()


def resolve_catalog_artifact(db: Session, catalog_key: str) -> dict[str, Any] | None:
    return fetchone(
        db,
        "SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts WHERE artifact_id=:k",
        {"k": catalog_key},
    )


def evidence_browse_mode(artifact_name: str, category: str | None = None) -> str | None:
    """Return browse mode when list must use virtual evidence rows (not job_artifacts SQL)."""
    name = _norm(artifact_name)
    if (
        name in _BROWSER_HISTORY_NAMES
        or name in _URL_CATEGORY_NAMES
        or name.replace(" / ", "/") in _URL_CATEGORY_NAMES
    ):
        return "url_visit"
    if "whatsapp" in name and "group" in name and "deleted" not in name:
        return "whatsapp_group"
    if name in _WHATSAPP_NON_MESSAGE_NAMES:
        return None
    if name in _WHATSAPP_DELETED_NAMES or (
        "whatsapp" in name and "deleted" in name and "contact" not in name
    ):
        return "whatsapp_deleted_message"
    if name in _DELETED_SOCIAL_NAMES or (
        "deleted" in name and any(x in name for x in ("social", "chat residual", "messaging"))
    ):
        return "deleted_social_message"
    if name in _CONTACT_NAMES:
        return "contact"
    if name in _EMAIL_ATTACHMENT_NAMES:
        return "email_attachment"
    if name in _SMS_ATTACHMENT_NAMES:
        return "sms_attachment"
    if name in _WHATSAPP_NAMES or (
        "whatsapp" in name
        and "url" not in name
        and "call" not in name
        and "contact" not in name
        and "group" not in name
        and "media" not in name
        and "deleted" not in name
    ):
        return "whatsapp_message"
    if name in _SMS_NAMES or (
        ("sms" in name or "imessage" in name or "mms" in name)
        and "whatsapp" not in name
        and "url" not in name
    ):
        return "sms_message"
    if name in _CHAT_APP_NAMES or any(
        name.startswith(app) or f" {app}" in name
        for app in (
            "telegram",
            "signal",
            "linkedin",
            "facebook",
            "messenger",
            "instagram",
            "snapchat",
            "discord",
            "viber",
            "wechat",
            "skype",
            "slack",
            "teams",
        )
    ):
        return "chat_message"
    if name in _OUTLOOK_EMAIL_NAMES:
        return "outlook_message"
    if name in _CARVE_ONLY_NAMES:
        return "carved_signature"
    if name == "usb devices":
        return "usb_device"
    if name in {"your phone device", "your phone devices", "your phone contacts"}:
        return "phone_device"
    if name in {"remote desktop protocol", "remote desktop protocol (rdp)"}:
        return "rdp_connection"
    return None


def _virtual_id(kind: str, key: str) -> str:
    digest = hashlib.sha1(f"{kind}|{key}".encode("utf-8", errors="ignore")).hexdigest()[:20]
    return f"ev-{kind}-{digest}"


def _record_evidence_item(
    job_id: str,
    *,
    kind: str,
    title: str,
    source_path: str,
    category_label: str,
    key: str,
    metadata: dict[str, Any],
    parent_artifact_id: str | None = None,
    artifact_datetime: Any = None,
) -> dict[str, Any]:
    preview_lines = [category_label, f"Title: {title}"]
    for label, field in (
        ("Device", "device_name"),
        ("Serial", "serial"),
        ("Class", "class_id"),
        ("Bus", "bus"),
        ("Host", "host"),
        ("User", "user"),
        ("Source", "source"),
    ):
        value = metadata.get(field)
        if value:
            preview_lines.append(f"{label}: {value}")
    if source_path:
        preview_lines.append(f"Path: {source_path}")
    return {
        "id": _virtual_id(kind, key),
        "job_id": job_id,
        "file_id": None,
        "parent_artifact_id": parent_artifact_id,
        "artifact_type": kind,
        "axiom_category": "connected devices",
        "axiom_category_label": category_label,
        "axiom_sub_category": metadata.get("bus") or metadata.get("host"),
        "title": title,
        "source_path": source_path,
        "artifact_datetime": artifact_datetime,
        "preview_uri": None,
        "storage_uri": None,
        "metadata": {"evidence_kind": kind, **metadata},
        "preview_text": "\n".join(preview_lines),
    }


def _usb_device_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    from app.services.catalog_aligned_counts import count_usb_device_records

    _count, devices = count_usb_device_records(db, job_id)
    out: list[dict[str, Any]] = []
    for rec in devices:
        path = str(rec.get("source") or rec.get("path") or "")
        title = str(
            rec.get("device_name")
            or rec.get("friendly_name")
            or rec.get("class_id")
            or rec.get("serial")
            or "USB device"
        )
        key = "|".join([
            str(rec.get("bus") or ""),
            str(rec.get("class_id") or ""),
            str(rec.get("serial") or ""),
            title,
            path,
        ])
        out.append(
            _record_evidence_item(
                job_id,
                kind="usb_device",
                title=title,
                source_path=path,
                category_label="USB Devices",
                key=key,
                metadata={
                    "device_name": rec.get("device_name"),
                    "friendly_name": rec.get("friendly_name"),
                    "serial": rec.get("serial"),
                    "class_id": rec.get("class_id"),
                    "bus": rec.get("bus"),
                    "source": path,
                },
                parent_artifact_id=_source_artifact_id(db, job_id, path),
            )
        )
    return out


def _phone_device_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    from app.services.forensic_inventory import collect_phone_usage

    phone = collect_phone_usage(db, job_id)
    out: list[dict[str, Any]] = []
    for rec in phone.get("devices") or []:
        path = str(rec.get("source") or "")
        title = str(rec.get("device_name") or rec.get("serial") or "Phone device")
        key = "|".join([title, str(rec.get("serial") or ""), path])
        out.append(
            _record_evidence_item(
                job_id,
                kind="phone_device",
                title=title,
                source_path=path,
                category_label="Your Phone Device",
                key=key,
                metadata={
                    "device_name": rec.get("device_name"),
                    "serial": rec.get("serial"),
                    "event_count": rec.get("event_count"),
                    "source": path,
                },
                parent_artifact_id=_source_artifact_id(db, job_id, path),
                artifact_datetime=rec.get("last_seen") or rec.get("first_seen"),
            )
        )
    return out


def _rdp_connection_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    from app.services.catalog_aligned_counts import count_rdp_connection_records

    _count, conns = count_rdp_connection_records(db, job_id)
    out: list[dict[str, Any]] = []
    for rec in conns:
        path = str(rec.get("source") or "")
        host = str(rec.get("host") or "RDP host")
        user = str(rec.get("user") or rec.get("username_hint") or "")
        title = f"{host} · {user}" if user else host
        key = "|".join([host, user, path])
        out.append(
            _record_evidence_item(
                job_id,
                kind="rdp_connection",
                title=title,
                source_path=path,
                category_label="Remote Desktop Protocol",
                key=key,
                metadata={
                    "host": host,
                    "user": rec.get("user"),
                    "username_hint": rec.get("username_hint"),
                    "source": path,
                },
                parent_artifact_id=_source_artifact_id(db, job_id, path),
            )
        )
    return out


def _source_artifact_id(db: Session, job_id: str, source_path: str) -> str | None:
    if not source_path:
        return None
    row = fetchone(
        db,
        """SELECT id FROM job_artifacts
           WHERE job_id=:j AND replace(file_path, '\\', '/') = :p
           LIMIT 1""",
        {"j": job_id, "p": source_path.replace("\\", "/")},
    )
    return str(row["id"]) if row else None


def _browser_history_file_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    """Fallback evidence: browser History / places.sqlite files themselves."""
    from app.services.browser_url_inventory import _BROWSER_SOURCE_SQL

    paths = fetchall(db, _BROWSER_SOURCE_SQL, {"j": job_id})
    out: list[dict[str, Any]] = []
    for p in paths:
        path = str(p.get("file_path") or "")
        aid = _source_artifact_id(db, job_id, path)
        if not aid:
            continue
        size = p.get("size_bytes") or 0
        out.append({
            "id": aid,
            "job_id": job_id,
            "file_id": None,
            "parent_artifact_id": None,
            "artifact_type": "browser_history",
            "axiom_category": "web related files",
            "axiom_category_label": "Browser History",
            "axiom_sub_category": None,
            "title": path.rsplit("/", 1)[-1] or path,
            "source_path": path,
            "artifact_datetime": None,
            "preview_uri": None,
            "storage_uri": None,
            "metadata": {
                "evidence_kind": "browser_history_db",
                "preview_body": (
                    f"Browser history database\nPath: {path}\n"
                    f"Size: {size} bytes\n"
                    "Open this SQLite History DB to inspect URL visits. "
                    "Classified chat/social URLs appear as separate evidence rows when recovered."
                ),
            },
            "tags": ["browser_history"],
            "examiner_comment": None,
            "parser_version": None,
            "confidence": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return out


def _url_visit_rows(db: Session, job_id: str, category: str) -> list[dict[str, Any]]:
    from app.services.browser_url_inventory import (
        collect_job_browser_url_records,
        content_type_short_label,
        infer_browser_label,
        infer_url_content_type,
    )
    from app.services.url_category_counts import classify_url_category

    target = _norm(category).replace(" / ", "/")
    if target == "malware / phishing urls":
        target = "malware/phishing urls"
    all_urls = target in _BROWSER_HISTORY_NAMES
    records = collect_job_browser_url_records(db, job_id)
    out: list[dict[str, Any]] = []
    for rec in records:
        url = str(rec.get("url") or "").strip()
        cat = classify_url_category(url)
        if not all_urls:
            if str(rec.get("record_origin") or "browser_history") != "browser_history":
                continue
            if cat != target:
                continue
        visits = max(int(rec.get("visit_count") or 0), 1)
        source = str(rec.get("source") or "")
        host = urlparse(url).netloc or url[:80]
        source_id = _source_artifact_id(db, job_id, source)
        page_title = (str(rec.get("title") or "").strip() or None)
        content_type = str(rec.get("content_type") or infer_url_content_type(url))
        content_label = content_type_short_label(content_type)
        browser = str(rec.get("browser") or infer_browser_label(source))
        last_visit = rec.get("last_visit")
        row_cat = cat or ("other" if all_urls else target)
        label = category if not all_urls else (
            {"web chat urls": "Web Chat", "social media urls": "Social Media",
             "malware/phishing urls": "Malware/Phishing",
             "pornography urls": "Pornography",
             "dating site urls": "Dating Site"}.get(row_cat or "", "Other")
        )
        vid = _virtual_id("url", f"{'all' if all_urls else target}|{url.lower()}")
        display_title = page_title or url
        out.append({
            "id": vid,
            "job_id": job_id,
            "file_id": None,
            "parent_artifact_id": source_id,
            "artifact_type": "url_visit",
            "axiom_category": row_cat if all_urls else target,
            "axiom_category_label": category if not all_urls else "Browser History",
            "axiom_sub_category": host,
            "title": display_title,
            "source_path": source or None,
            "artifact_datetime": last_visit,
            "preview_uri": None,
            "storage_uri": None,
            "metadata": {
                "evidence_kind": "url_visit",
                "url": url,
                "host": host,
                "page_title": page_title,
                "visit_count": visits,
                "category": row_cat,
                "content_type": content_type,
                "content_type_label": content_label,
                "browser": browser,
                "last_visit": last_visit,
                "source_path": source,
                "source_artifact_id": source_id,
                "preview_body": (
                    f"URL: {url}\n"
                    + (f"Title: {page_title}\n" if page_title else "")
                    + f"Content type: {content_label} ({content_type})\n"
                    + f"Category: {label}\n"
                    + f"Browser: {browser}\n"
                    + f"Visit count: {visits}\n"
                    + (f"Last visit: {last_visit}\n" if last_visit else "")
                    + f"Browser history source:\n{source or '(unknown)'}"
                ),
            },
            "tags": ["url_visit", (row_cat or target).replace(" ", "_")],
            "examiner_comment": None,
            "parser_version": "browser_history",
            "confidence": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    # Highest visits first.
    out.sort(key=lambda r: (-int((r.get("metadata") or {}).get("visit_count") or 0), r.get("title") or ""))
    if out:
        return out
    # No classified visits — still show History DBs so the Artifacts page is never empty
    # when browser evidence exists on the disk.
    return _browser_history_file_rows(db, job_id)


def _is_whatsapp_runtime_junk(path: str, name: str) -> bool:
    """Android package / ART files under com.whatsapp are not chat evidence."""
    p = (path or "").replace("\\", "/").lower()
    n = (name or "").lower()
    if any(n.endswith(ext) for ext in (".apk", ".odex", ".vdex", ".art", ".prof", ".dex")):
        return True
    if "/data/app/" in p or "/oat/" in p:
        return True
    if n in {"base.apk", "base.odex", "base.vdex", "base.art", "base.apk.prof"}:
        return True
    return False


def _is_whatsapp_encrypted_backup(path: str, name: str) -> bool:
    n = (name or "").lower()
    p = (path or "").replace("\\", "/").lower()
    from app.services.mobile_forensic.crypt_formats import is_crypt_file
    return is_crypt_file(n) or is_crypt_file(p)


def _is_whatsapp_noise_path(path: str, name: str) -> bool:
    """WAM metrics, Chrome, logs — not chat/contact evidence."""
    p = (path or "").replace("\\", "/").lower()
    n = (name or "").lower()
    if _is_whatsapp_runtime_junk(path, name):
        return True
    if _is_whatsapp_encrypted_backup(path, name):
        return True
    noise = (
        "/files/wam/",
        "/wam/",
        "/chrome/",
        "favicons",
        "/cache/",
        "/code_cache/",
        "/app_chrome/",
        "harm_configs",
        "kcallinghistory",
        "bizintegrity",
    )
    if any(x in p for x in noise):
        return True
    if n.startswith("wamt-") or n.startswith("wam-"):
        return True
    return False


def _is_whatsapp_chat_store(path: str, name: str) -> bool:
    """Prefer plaintext WhatsApp message / account databases over generic path hits."""
    if _is_whatsapp_noise_path(path, name):
        return False
    p = (path or "").replace("\\", "/").lower()
    n = (name or "").lower()
    if n in {
        "msgstore.db",
        "wa.db",
        "chatstorage.sqlite",
        "messages.db",
        "extchatdatabase.sqlite",
    }:
        return True
    if n.startswith("msgstore.db-") or n.startswith("wa.db-") or n.startswith("chatstorage.sqlite"):
        return True
    if "/databases/" in p and "whatsapp" in p and (n.endswith(".db") or n.endswith(".sqlite")):
        # Exclude axolotl / stickers / etc. noise unless clearly chat-related
        if any(x in n for x in ("msgstore", "wa.db", "chat", "message")):
            return True
    return False


def _looks_like_chat_body(body: str) -> bool:
    """Reject WAM JSON / binary garbage; allow short real chats ('Hi') and [Media] labels."""
    text = (body or "").strip()
    if not text:
        return False
    if "\x00" in text:
        return False
    # Media / placeholder labels from the modern WhatsApp extractor.
    if text.startswith("[") and "]" in text[:40]:
        return True
    if "recovered original:" in text.lower():
        return True
    # WhatsApp iOS revoke placeholders retained in ChatStorage.
    if "deleted this message" in text.lower() or text.startswith("🚫"):
        return True
    # Replacement chars / binary decode artifacts
    if text.count("\ufffd") >= 3 or text.count("�") >= 3:
        return False
    # Freelist schema / Core Data class names / FTS DDL are not messages.
    from app.services.mobile_acquire.sqlite_deleted import _is_schema_or_index_junk

    if _is_schema_or_index_junk(text):
        return False
    # Long CamelCase / ObjC-style identifiers with no spaces.
    if " " not in text and re.fullmatch(r"\$?[A-Za-z][A-Za-z0-9_]{15,}", text.rstrip("_")):
        return False
    if re.fullmatch(r"~?\d{8,20}@(?:s\.whatsapp\.net|g\.us|lid|c\.us)\(?", text.strip("()[] ")):
        return False
    # JID / hex / base64 residue carved next to revoke rows.
    from app.services.chat_message_extract import (
        _is_whatsapp_protocol_noise,
        _split_whatsapp_carve_text,
    )

    clean, _res = _split_whatsapp_carve_text(text)
    check = clean or text
    if _is_whatsapp_protocol_noise(check):
        return False
    low = check.lower()
    if text.startswith("{") and any(
        k in low for k in ('"code":', "bizintegrity", "transport", "harm_configs", "category")
    ):
        return False
    if any(k in low for k in ("failed to deliver", "response errors", "wamt-", "individual_spam")):
        return False
    # Mostly non-printable (only enforce on longer blobs)
    if len(text) >= 24:
        printable = sum(1 for c in text[:200] if c.isprintable() or c in "\n\r\t")
        if printable < int(len(text[:200]) * 0.7):
            return False
    return True


def _is_sms_source_path(path: str | None) -> bool:
    p = (path or "").replace("\\", "/").lower()
    return any(
        x in p
        for x in (
            "/sms.db",
            "sms.db",
            "sms_imessage",
            "/library/sms/",
            "mmssms.db",
            "/mms/",
        )
    )


def _format_deleted_preview_body(
    *,
    conversation: str,
    sender: str,
    ts: Any,
    body: str,
    recovery_state: str,
    source_path: str | None,
    media_name: str | None = None,
    confidence: str = "MEDIUM",
    offset: Any = None,
    row_id: Any = None,
    protocol_residue: str | None = None,
) -> str:
    from app.services.chat_message_extract import _split_whatsapp_carve_text

    recovered_from = recovery_state.replace("_", " ").upper() if recovery_state else "SQLITE FREELIST"
    if "wal" in (recovery_state or "").lower():
        recovered_from = "SQLite WAL"
    elif "freelist" in (recovery_state or "").lower():
        recovered_from = "SQLite freelist"
    elif "carved" in (recovery_state or "").lower():
        recovered_from = "ChatStorage page carve (cleared media fields)"
    elif "type14" in (recovery_state or "").lower():
        recovered_from = "WhatsApp revoke placeholder (ZMESSAGETYPE=14)"
    clean_body, split_residue = _split_whatsapp_carve_text(body or "")
    display_body = clean_body or (body or "—")
    residue = (protocol_residue or split_residue or "").strip() or None
    lines = [
        f"WhatsApp Chat: {conversation or 'Recovered conversation'}",
        "",
        "⚠ RECOVERED / DELETED ARTIFACT",
        "",
        f"Deleted at: {ts or '—'}",
        f"From: {sender}",
        "",
        "Original content:",
        display_body,
    ]
    if residue:
        lines.extend(
            [
                "",
                "Protocol residue (not message text):",
                residue,
            ]
        )
    if media_name and media_name not in (display_body or ""):
        lines.append(f"[ATTACHMENT] {media_name}")
    lines.extend(
        [
            "",
            "Recovery status: DELETED",
            f"Recovered from: {recovered_from}",
            f"Confidence: {confidence}",
        ]
    )
    if row_id is not None:
        lines.append(f"Original row ID: {row_id}")
    if offset is not None:
        lines.append(f"Source offset: {offset}")
    if source_path:
        lines.append(f"Database: {source_path}")
    if "carved" in (recovery_state or "").lower() or "type14" in (recovery_state or "").lower():
        lines.append("Deleted flag: Confirmed WhatsApp Delete-for-Everyone (ZMESSAGETYPE=14)")
    else:
        lines.append("Deleted flag: Confirmed from freelist/WAL residual carve")
    return "\n".join(lines)


def _message_row_from_rec(
    *,
    job_id: str,
    job_artifact_id: str | None,
    source_path: str | None,
    rec: dict[str, Any],
    idx: int,
    parser_version: str,
    media_artifact_id: str | None = None,
) -> dict[str, Any] | None:
    rtype = str(rec.get("record_type") or "").lower()
    if rtype and "summary" in rtype:
        return None
    # Outer carve JSON envelopes are not messages.
    if isinstance(rec.get("items"), list) and "carved_strings" in rec:
        return None
    if rec.get("chat_like") is False and rtype == "sqlite_deleted_residual":
        return None

    body = (
        rec.get("text_body")
        or rec.get("body")
        or rec.get("message")
        or rec.get("data")
        or ""
    )
    raw_text = rec.get("text")
    if not body and isinstance(raw_text, str) and raw_text.strip():
        # Freelist residuals store chat text in `text`; live extract uses "Chat · sender: body".
        if ": " in raw_text and (" · " in raw_text or raw_text.lower().startswith("whatsapp")):
            body = raw_text.split(": ", 1)[-1]
        else:
            body = raw_text
    body = str(body or "").strip()
    media_name = (
        rec.get("media_name")
        or rec.get("media_filename")
        or rec.get("filename")
        or rec.get("file_name")
    )
    if media_name:
        media_name = str(media_name).strip() or None

    # chat_like only means "looks like chat text" (freelist quality filter) — not deleted.
    # recovery_state alone is not enough (must be an explicit deleted/revoke marker).
    recovery_state_raw = str(rec.get("recovery_state") or "").strip().lower()
    deleted = bool(
        rec.get("is_deleted")
        or rec.get("deleted")
        or "deleted" in rtype
        or "residual" in rtype
        or str(rec.get("status") or "").lower() in {"deleted", "revoked"}
        or recovery_state_raw.startswith("whatsapp_revoke")
        or recovery_state_raw.startswith("whatsapp_deleted")
        or recovery_state_raw in {"social_deleted", "sqlite_freelist", "sqlite_wal"}
    )

    # Deleted freelist residuals: require human-like chat text (reject bare JIDs / schema names).
    if rtype == "sqlite_deleted_residual" or (deleted and "residual" in rtype):
        if not body and not media_name:
            return None
        if body and not _looks_like_chat_body(body):
            return None
        # Prefer residuals that look like spoken/written content.
        if body and " " not in body and not media_name and len(body) < 40:
            return None
    else:
        if not _looks_like_chat_body(body) and not rec.get("sender") and not media_name:
            return None
        if body and not _looks_like_chat_body(body) and not media_name:
            return None
    if _is_sms_source_path(source_path) and "whatsapp" not in str(source_path or "").lower():
        # WhatsApp builders must never emit SMS-sourced rows.
        if "whatsapp" in (parser_version or "").lower() or parser_version in {
            "whatsapp_live_extract",
            "whatsapp_parse",
            "whatsapp_deleted_residual",
            "whatsapp_deleted_live_carve",
        }:
            return None

    if media_name and (not body or body in {"[Image]", "[IMAGE]", "[Media]"}):
        body = f"[IMAGE] {media_name}"

    from app.services.artifact_group_browse import enrich_message_record
    from app.services.mobile_acquire.sqlite_deleted import _infer_residual_identity

    rec = enrich_message_record(rec)
    sender = str(rec.get("sender") or rec.get("from") or rec.get("key_remote_jid") or "unknown")
    conversation = str(rec.get("conversation") or rec.get("chat") or "").strip()
    conversation_id = str(rec.get("conversation_id") or "").strip() or None
    chat_jid = str(rec.get("chat_jid") or rec.get("remote_jid") or "").strip() or None
    is_group = bool(rec.get("is_group"))
    # Freelist residuals often hardcode sender=unknown — recover identity from body/JID.
    if (
        (not sender or sender.lower() in {"unknown", "unknown conversation"})
        or (not conversation and not chat_jid)
    ):
        identity = _infer_residual_identity(body or str(rec.get("text") or ""))
        if identity.get("chat_jid") and not chat_jid:
            chat_jid = str(identity["chat_jid"])
            rec["chat_jid"] = chat_jid
        if identity.get("is_group"):
            is_group = True
            rec["is_group"] = True
        if identity.get("sender") and str(identity["sender"]).lower() != "unknown":
            if not sender or sender.lower() == "unknown":
                sender = str(identity["sender"])
                rec["sender"] = sender
        if identity.get("conversation") and not conversation:
            conversation = str(identity["conversation"])
            rec["conversation"] = conversation
    if sender == "unknown" and not body:
        return None
    ts = (
        rec.get("timestamp")
        or rec.get("date")
        or rec.get("timestamp_str")
        or rec.get("deleted_at")
    )
    if conversation:
        title = f"{conversation} · {sender}: {body[:100]}" if body else f"{conversation} · {sender}"
    else:
        title = f"{sender}: {body[:120]}" if body else sender
    vid = _virtual_id(
        "wa-del" if deleted else "wa",
        f"{job_artifact_id}|{conversation_id or ''}|{rec.get('message_row_id') or rec.get('index') or idx}|{title[:80]}",
    )
    recovery_state = str(rec.get("recovery_state") or ("sqlite_freelist" if deleted else ""))
    tags = ["whatsapp_message"]
    if deleted:
        tags.append("deleted")
    evidence_kind = "whatsapp_deleted_message" if deleted else "whatsapp_message"
    if deleted:
        from app.services.chat_message_extract import _split_whatsapp_carve_text

        clean_body, residue = _split_whatsapp_carve_text(body)
        if clean_body:
            if residue:
                rec["protocol_residue"] = residue
            rec["original_content"] = clean_body
            # Keep placeholder lines on body for list view.
            if "deleted this message" in body.lower():
                ph = (
                    "(🚫 You deleted this message)"
                    if rec.get("from_me")
                    else "(🚫 This message was deleted)"
                )
                body = f"{clean_body}\n{ph}"
            else:
                body = clean_body
        preview_body = _format_deleted_preview_body(
            conversation=conversation,
            sender=sender,
            ts=ts,
            body=str(rec.get("original_content") or body),
            recovery_state=recovery_state,
            source_path=source_path,
            media_name=media_name,
            confidence=str(rec.get("confidence") or "MEDIUM").upper(),
            offset=rec.get("source_offset") or rec.get("offset"),
            row_id=rec.get("message_row_id") or rec.get("index"),
            protocol_residue=str(rec.get("protocol_residue") or "") or None,
        )
    else:
        preview_body = (
            f"Conversation: {conversation or '—'}\n"
            f"From: {sender}\n"
            f"Time: {ts or '—'}\n"
            f"Message:\n{body}\n\n"
            f"Source DB:\n{source_path or ''}"
        )
        if media_name:
            preview_body = (
                f"Conversation: {conversation or '—'}\n"
                f"From: {sender}\n"
                f"Time: {ts or '—'}\n"
                f"[IMAGE]\n{media_name}\n\n"
                f"Message:\n{body}\n\n"
                f"Source DB:\n{source_path or ''}"
            )
    return {
        "id": vid,
        "job_id": job_id,
        "file_id": None,
        "parent_artifact_id": str(job_artifact_id or "") or None,
        "artifact_type": evidence_kind,
        "axiom_category": "whatsapp deleted messages" if deleted else "whatsapp messages",
        "axiom_category_label": "WhatsApp Deleted Messages" if deleted else "WhatsApp Messages",
        "axiom_sub_category": conversation or sender,
        "title": title,
        "source_path": source_path,
        "artifact_datetime": str(ts) if ts else None,
        "preview_uri": None,
        "storage_uri": None,
        "metadata": {
            "evidence_kind": evidence_kind,
            "sender": sender,
            "conversation": conversation,
            "conversation_id": conversation_id,
            "chat_jid": chat_jid,
            "is_group": is_group,
            "body": body[:8000],
            "timestamp": str(ts) if ts else None,
            "is_deleted": deleted,
            "from_me": bool(rec.get("from_me")),
            "message_type": rec.get("message_type"),
            "media_name": media_name,
            "chat_row_id": rec.get("chat_row_id"),
            "session_row": bool(rec.get("session_row")),
            "message_count": rec.get("message_count"),
            "media_artifact_id": media_artifact_id,
            "media_path_recovered": rec.get("media_path_recovered"),
            "thumbnail_base64": rec.get("thumbnail_base64"),
            "thumbnail_content_type": rec.get("thumbnail_content_type") or "image/jpeg",
            "preview_quality": rec.get("preview_quality"),
            "original_missing_from_extract": bool(rec.get("original_missing_from_extract")),
            "mime_recovered": rec.get("mime_recovered"),
            "original_content": rec.get("original_content"),
            "protocol_residue": rec.get("protocol_residue"),
            "recovery_state": recovery_state or None,
            "source_path": source_path,
            "source_artifact_id": str(job_artifact_id or "") or None,
            "preview_body": preview_body,
            "social_app": rec.get("social_app") or "whatsapp",
            "stanza_id": rec.get("stanza_id"),
        },
        "tags": tags,
        "examiner_comment": None,
        "parser_version": parser_version,
        "confidence": rec.get("confidence"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _live_extract_whatsapp_messages(
    db: Session,
    job_id: str,
    store_rows: list[dict[str, Any]],
    *,
    sessions_only: bool = False,
    deleted_only: bool = False,
    chat_row_id: Any = None,
    limit: int = 20_000,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Pull chat sessions, deleted rows, or one thread from cached ChatStorage."""
    from app.services.chat_message_extract import (
        extract_chat_messages_from_path,
        extract_chat_sessions_from_connection,
    )

    import sqlite3

    out: list[dict[str, Any]] = []
    candidates = sorted(
        [
            r
            for r in store_rows
            if str(r.get("file_name") or "").lower() in {
                "msgstore.db",
                "chatstorage.sqlite",
                "messages.db",
                "extchatdatabase.sqlite",
            }
            or str(r.get("file_name") or "").lower().startswith("msgstore.db")
            or str(r.get("file_name") or "").lower().startswith("chatstorage.sqlite")
        ],
        key=lambda r: int(r.get("size_bytes") or 0),
        reverse=True,
    )
    seen: set[str] = set()
    parser = (
        "whatsapp_sessions"
        if sessions_only
        else "whatsapp_deleted_extract"
        if deleted_only
        else "whatsapp_live_extract"
    )
    extract_limit = max(int(limit or 20), 1)
    extract_offset = max(int(offset or 0), 0)
    for row in candidates[:2]:
        path = str(row.get("file_path") or "")
        store_path = _cached_store_path(db, job_id, row)
        if not store_path:
            continue
        try:
            if sessions_only:
                conn = sqlite3.connect(f"file:{store_path}?mode=ro", uri=True)
                try:
                    records = extract_chat_sessions_from_connection(
                        conn.cursor(),
                        path,
                        limit=extract_limit,
                        offset=extract_offset,
                    )
                finally:
                    conn.close()
            else:
                records = extract_chat_messages_from_path(
                    store_path,
                    path,
                    limit=extract_limit,
                    offset=extract_offset,
                    deleted_only=deleted_only,
                    chat_row_id=chat_row_id,
                )
        except Exception:
            continue
        for idx, rec in enumerate(records):
            item = _message_row_from_rec(
                job_id=job_id,
                job_artifact_id=str(row.get("id") or "") or None,
                source_path=path,
                rec=rec,
                idx=idx,
                parser_version=parser,
            )
            if not item:
                continue
            key = (
                f"{item['metadata'].get('conversation_id') or ''}|{item['metadata'].get('sender')}|"
                f"{str(item['metadata'].get('body') or '')[:160]}|{item.get('artifact_datetime')}"
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        if sessions_only or deleted_only or chat_row_id is not None or len(out) >= extract_limit:
            break
    return out


def _slice_rows(rows: list[dict[str, Any]], *, limit: int | None, offset: int) -> list[dict[str, Any]]:
    off = max(int(offset or 0), 0)
    if limit is None:
        return rows[off:]
    return rows[off : off + max(int(limit), 1)]


def _whatsapp_store_count(
    db: Session,
    job_id: str,
    *,
    sessions_only: bool = False,
    deleted_only: bool = False,
    chat_row_id: Any = None,
    groups_only: bool = False,
) -> int:
    from app.services.chat_message_extract import (
        count_chat_messages_from_connection,
        count_chat_sessions_from_connection,
    )

    import sqlite3

    store_raw = _whatsapp_store_files(db, job_id)
    candidates = sorted(
        [r for r in store_raw if str(r.get("file_name") or "").lower() in {
            "msgstore.db",
            "chatstorage.sqlite",
            "messages.db",
            "extchatdatabase.sqlite",
        } or str(r.get("file_name") or "").lower().startswith("msgstore.db")
        or str(r.get("file_name") or "").lower().startswith("chatstorage.sqlite")],
        key=lambda r: int(r.get("size_bytes") or 0),
        reverse=True,
    )
    for row in candidates[:2]:
        path = str(row.get("file_path") or "")
        store_path = _cached_store_path(db, job_id, row)
        if not store_path:
            continue
        try:
            conn = sqlite3.connect(f"file:{store_path}?mode=ro", uri=True)
            try:
                cur = conn.cursor()
                if sessions_only:
                    return count_chat_sessions_from_connection(
                        cur, path, groups_only=groups_only
                    )
                return count_chat_messages_from_connection(
                    cur, path, deleted_only=deleted_only, chat_row_id=chat_row_id
                )
            finally:
                conn.close()
        except Exception:
            continue
    return 0


def _whatsapp_message_rows(
    db: Session,
    job_id: str,
    *,
    sessions_only: bool = False,
    deleted_only: bool = False,
    person_id: str | None = None,
    groups_only: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List WhatsApp chats (sessions), deleted rows, or one person's thread."""
    from app.services.artifact_group_browse import (
        _person_key_from_row,
        _split_person_bucket_id,
    )

    mode = "del" if deleted_only else "sess" if sessions_only else "live"
    if groups_only:
        mode = f"{mode}-grp"
    pid_key = (person_id or "").strip()
    # v10: media_artifact_id attached before persist; thumb→full media resolve.
    cache_key = f"wa-{mode}:v10:{job_id}:{pid_key}"
    cached = _cache_get(cache_key)
    if cached is not None:
        # Names list: never block on media linking. Thread open: attach for this contact only.
        if not sessions_only and pid_key:
            _attach_media_refs(
                db, job_id, cached, max_lookups=min(200, max(len(cached), 20))
            )
        return _slice_rows(cached, limit=limit, offset=offset)

    persist_kind = None
    if not pid_key:
        persist_kind = "wa_deleted_v10" if deleted_only else "wa_sessions_v10" if sessions_only else None
        if persist_kind:
            persisted = _load_browse_cache(db, job_id, persist_kind)
            if persisted:
                if groups_only:
                    persisted = [
                        r
                        for r in persisted
                        if (r.get("metadata") or {}).get("is_group")
                    ]
                if not sessions_only and pid_key:
                    _attach_media_refs(
                        db, job_id, persisted, max_lookups=min(200, max(len(persisted), 20))
                    )
                _cache_set(cache_key, persisted)
                return _slice_rows(persisted, limit=limit, offset=offset)

    store_raw = _whatsapp_store_files(db, job_id)

    chat_row_id = None
    if pid_key:
        sessions = _whatsapp_message_rows(db, job_id, sessions_only=True)
        base_id, _deleted_bucket = _split_person_bucket_id(pid_key)
        for sess in sessions:
            try:
                sid, _, _ = _person_key_from_row(sess)
            except Exception:
                continue
            if sid == base_id:
                meta = sess.get("metadata") or {}
                chat_row_id = meta.get("chat_row_id")
                if chat_row_id is not None:
                    break

    page_limit = max(int(limit), 1) if limit is not None else (8_000 if pid_key else 5_000)
    messages = _live_extract_whatsapp_messages(
        db,
        job_id,
        store_raw,
        sessions_only=sessions_only and not pid_key,
        deleted_only=deleted_only,
        chat_row_id=chat_row_id,
        limit=page_limit,
        offset=offset,
    )
    messages = [
        m
        for m in messages
        if not _is_sms_source_path(str(m.get("source_path") or (m.get("metadata") or {}).get("source_path")))
    ]
    if groups_only:
        messages = [m for m in messages if (m.get("metadata") or {}).get("is_group")]

    if deleted_only and not pid_key:
        # Names-list / full rebuild only — never ChatSearch-enrich a person thread open.
        try:
            _enrich_deleted_originals_from_job(db, job_id, messages)
        except Exception:
            pass
    elif deleted_only and pid_key:
        try:
            _sanitize_deleted_protocol_noise(messages)
        except Exception:
            pass

    # Media linking is expensive (many job_artifacts lookups). Only do it when
    # opening one person's thread — never when building the Names list.
    if not sessions_only and pid_key:
        _attach_media_refs(
            db, job_id, messages, max_lookups=min(200, max(len(messages), 20))
        )

    full_extract = offset == 0 and (limit is None or int(limit) >= 5000)
    if sessions_only and not pid_key and persist_kind and not groups_only and full_extract:
        _persist_browse_cache(db, job_id, persist_kind, messages)
        _cache_set(cache_key, messages)
    if deleted_only and not pid_key and persist_kind and messages and full_extract:
        _persist_browse_cache(db, job_id, persist_kind, messages)
        _cache_set(cache_key, messages)
    elif not sessions_only:
        _cache_set(cache_key, messages)

    return messages


def _whatsapp_message_total(
    db: Session,
    job_id: str,
    *,
    sessions_only: bool = False,
    deleted_only: bool = False,
    person_id: str | None = None,
    groups_only: bool = False,
) -> int:
    from app.services.artifact_group_browse import (
        _person_key_from_row,
        _split_person_bucket_id,
    )

    mode = "del" if deleted_only else "sess" if sessions_only else "live"
    if groups_only:
        mode = f"{mode}-grp"
    pid_key = (person_id or "").strip()
    cache_key = f"wa-{mode}:v10:{job_id}:{pid_key}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return len(cached)
    persist_kind = None
    if not pid_key:
        persist_kind = "wa_deleted_v10" if deleted_only else "wa_sessions_v10" if sessions_only else None
        if persist_kind:
            persisted = _load_browse_cache(db, job_id, persist_kind)
            if persisted:
                if groups_only:
                    persisted = [
                        r
                        for r in persisted
                        if (r.get("metadata") or {}).get("is_group")
                    ]
                return len(persisted)

    chat_row_id = None
    if pid_key:
        sessions = _whatsapp_message_rows(db, job_id, sessions_only=True)
        base_id, _ = _split_person_bucket_id(pid_key)
        for sess in sessions:
            try:
                sid, _, _ = _person_key_from_row(sess)
            except Exception:
                continue
            if sid == base_id:
                chat_row_id = (sess.get("metadata") or {}).get("chat_row_id")
                if chat_row_id is not None:
                    break

    return _whatsapp_store_count(
        db,
        job_id,
        sessions_only=sessions_only and not pid_key,
        deleted_only=deleted_only,
        chat_row_id=chat_row_id,
        groups_only=groups_only,
    )


_NOT_MEDIA_FILE_SQL = """
  AND lower(file_name) NOT LIKE '%.db'
  AND lower(file_name) NOT LIKE '%.db-%'
  AND lower(file_name) NOT LIKE '%.sqlite%'
  AND lower(file_name) NOT LIKE '%.sqlitedb%'
  AND lower(file_name) NOT LIKE '%.wal'
  AND lower(file_name) NOT LIKE '%.shm'
  AND lower(file_name) NOT LIKE '%.journal'
  AND lower(file_name) NOT IN ('.nomedia', 'nomedia')
"""

_MEDIA_EXT_PREFER = (
    "jpg",
    "jpeg",
    "png",
    "webp",
    "gif",
    "heic",
    "mp4",
    "mov",
    "m4a",
    "mp3",
    "opus",
    "aac",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "zip",
)


def _media_name_candidates(media_name: str, media_path: str | None = None) -> list[str]:
    """Basenames to try when resolving an attachment (prefer full file over .thumb)."""
    names: list[str] = []
    path = str(media_path or "").replace("\\", "/").strip()
    name = (media_name or "").strip()
    if path and not name:
        name = path.rsplit("/", 1)[-1]
    if name:
        names.append(name)
        # Chat/OCR noise sometimes prefixes a letter: jlaptop-scanner.zip → laptop-scanner.zip
        if len(name) > 6 and name[0].isalpha() and name[1].isalpha() and not name[0].isdigit():
            stripped = name[1:]
            if "." in stripped and stripped not in names:
                names.append(stripped)
        # recovered-<hex>.jpg → also try bare hex + common media extensions
        m = re.match(r"(?i)^recovered[-_]([0-9a-f]{8,})$", name.rsplit(".", 1)[0])
        if m:
            hx = m.group(1)
            names.append(hx)
            for ext in ("jpg", "jpeg", "png", "webp", "mp4", "pdf", "zip"):
                names.append(f"{hx}.{ext}")
    if path:
        base = path.rsplit("/", 1)[-1]
        if base and base not in names:
            names.append(base)
    out: list[str] = []
    seen: set[str] = set()
    for n in names:
        key = n.lower()
        if key and key not in seen:
            seen.add(key)
            out.append(n)
        lower = n.lower()
        if lower.endswith(".thumb") or lower.endswith(".thumb.webp"):
            stem = n.rsplit(".", 1)[0]
            if stem.lower().endswith(".thumb"):
                stem = stem[: -len(".thumb")]
            for ext in _MEDIA_EXT_PREFER:
                cand = f"{stem}.{ext}"
                ck = cand.lower()
                if ck not in seen:
                    seen.add(ck)
                    out.append(cand)
        elif "." not in n and len(n) >= 8:
            for ext in ("jpg", "jpeg", "mp4", "png", "pdf", "opus", "m4a", "zip"):
                cand = f"{n}.{ext}"
                ck = cand.lower()
                if ck not in seen:
                    seen.add(ck)
                    out.append(cand)
    # Prefer non-thumb names first.
    out.sort(key=lambda x: (1 if x.lower().endswith((".thumb", ".thumb.webp")) else 0, x.lower()))
    return out


def _media_stem_fuzzy_needles(stem: str) -> list[str]:
    """Substrings that often match dump filenames when chat labels have carve noise."""
    s = (stem or "").strip().lower()
    if s.endswith(".thumb"):
        s = s[: -len(".thumb")]
    if not s or len(s) < 5:
        return []
    needles: list[str] = []
    seen: set[str] = set()

    def add(n: str) -> None:
        n = n.strip("-_. ")
        if len(n) >= 5 and n not in seen:
            seen.add(n)
            needles.append(n)

    add(s)
    if len(s) > 6 and s[0].isalpha() and s[1].isalpha():
        add(s[1:])
    # recovered-<uuid> → uuid token
    m = re.match(r"^recovered[-_]?([0-9a-f]{8,})$", s)
    if m:
        add(m.group(1))
    # Prefer hyphenated cores: jlaptop-scanner → laptop-scanner, scanner
    if "-" in s:
        parts = [p for p in s.split("-") if p]
        if len(parts) >= 2:
            add("-".join(parts[-2:]))
            add("-".join(parts[1:]))
        for p in parts:
            if len(p) >= 6:
                add(p)
    return needles


def _ios_manifest_file_id(
    db: Session,
    job_id: str,
    relative_path: str,
    *,
    _cache: dict[str, Any] | None = None,
) -> str | None:
    """Map WhatsApp Media/… relative path → iOS backup fileID via Manifest.db."""
    rel = (relative_path or "").replace("\\", "/").strip().lstrip("/")
    if not rel or "Media/" not in rel:
        return None
    candidates = [rel]
    if rel.startswith("Media/"):
        candidates.append(f"Message/{rel}")
    elif rel.startswith("Message/Media/"):
        candidates.append(rel[len("Message/") :])
    base = rel.rsplit("/", 1)[-1]
    if base and len(base) >= 8:
        candidates.append(base)

    cache = _cache if _cache is not None else {}
    con = cache.get("_manifest_con")
    if con is None:
        man = fetchone(
            db,
            """SELECT id, file_path, file_name, size_bytes, minio_uri, extension, job_id
               FROM job_artifacts
               WHERE job_id=:j AND lower(file_name)='manifest.db'
               ORDER BY size_bytes DESC NULLS LAST LIMIT 1""",
            {"j": job_id},
        )
        if not man:
            cache["_manifest_con"] = False
            return None
        try:
            import sqlite3
            import tempfile

            from app.services.artifact_preview import resolve_artifact_bytes

            raw = resolve_artifact_bytes(
                db,
                job_id,
                {
                    k: (str(v) if k in {"id", "job_id"} and v is not None else v)
                    for k, v in dict(man).items()
                },
                persist=False,
                max_bytes=None,
            )
            if not raw:
                cache["_manifest_con"] = False
                return None
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.write(raw)
            tmp.close()
            con = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            cache["_manifest_con"] = con
            cache["_manifest_tmp"] = tmp.name
        except Exception:
            cache["_manifest_con"] = False
            return None
    if con is False:
        return None

    cur = con.cursor()
    for cand in candidates:
        rows = cur.execute(
            "SELECT fileID FROM Files WHERE relativePath = ? OR relativePath LIKE ? LIMIT 3",
            (cand, f"%/{cand}" if "/" not in cand else cand),
        ).fetchall()
        if not rows and "/" in cand:
            rows = cur.execute(
                "SELECT fileID FROM Files WHERE relativePath LIKE ? LIMIT 3",
                (f"%{cand}",),
            ).fetchall()
        for (fid,) in rows:
            if fid:
                return str(fid)
    return None


def _upgrade_chat_thumbnail_from_linked_media(
    db: Session,
    job_id: str,
    meta: dict[str, Any],
    media_artifact_id: str,
) -> None:
    """Replace tiny ChatStorage thumbs with a sharper preview from the linked dump file."""
    import base64
    import io

    try:
        from PIL import Image
    except Exception:
        return
    row = fetchone(
        db,
        """SELECT id, job_id, file_path, file_name, size_bytes, minio_uri, extension
           FROM job_artifacts WHERE id=:i AND job_id=:j""",
        {"i": media_artifact_id, "j": job_id},
    )
    if not row:
        return
    size = int(row.get("size_bytes") or 0)
    if size <= 0 or size > 8_000_000:
        return
    try:
        from app.services.artifact_preview import resolve_artifact_bytes

        raw = resolve_artifact_bytes(
            db,
            job_id,
            {
                k: (str(v) if k in {"id", "job_id"} and v is not None else v)
                for k, v in dict(row).items()
            },
            persist=False,
            max_bytes=8_000_000,
        )
    except Exception:
        return
    if not raw or len(raw) < 200:
        return
    if raw[:3] != b"\xff\xd8" and raw[:8] != b"\x89PNG\r\n\x1a\n":
        return
    try:
        im = Image.open(io.BytesIO(raw)).convert("RGB")
        im.thumbnail((1280, 1280), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, format="JPEG", quality=85, optimize=True)
        meta["thumbnail_base64"] = base64.b64encode(buf.getvalue()).decode("ascii")
        meta["thumbnail_content_type"] = "image/jpeg"
        meta["preview_quality"] = "full_file_preview"
        meta["original_missing_from_extract"] = False
    except Exception:
        return


def _resolve_media_artifact_id(
    db: Session,
    job_id: str,
    media_name: str,
    media_path: str | None = None,
    *,
    manifest_cache: dict[str, Any] | None = None,
) -> str | None:
    name = (media_name or "").strip()
    path = str(media_path or "").replace("\\", "/").strip()
    if path and not name:
        name = path.rsplit("/", 1)[-1]
    if (not name or len(name) < 5) and not path:
        return None

    order_sql = """
               ORDER BY
                 CASE WHEN lower(file_name) LIKE '%.thumb%' THEN 2 ELSE 0 END,
                 CASE WHEN lower(replace(file_path,'\\\\','/')) LIKE '%whatsapp%' THEN 0
                      WHEN lower(replace(file_path,'\\\\','/')) LIKE '%dcim%' THEN 1
                      WHEN lower(replace(file_path,'\\\\','/')) LIKE '%media%' THEN 2
                      ELSE 3 END,
                 size_bytes DESC NULLS LAST
               LIMIT 1"""

    if path and "Media/" in path:
        fid = _ios_manifest_file_id(db, job_id, path, _cache=manifest_cache)
        if fid:
            row = fetchone(
                db,
                f"""SELECT id FROM job_artifacts
                   WHERE job_id=:j
                     AND (lower(file_name)=lower(:f)
                          OR lower(replace(file_path,'\\\\','/')) LIKE :p
                          OR lower(replace(file_path,'\\\\','/')) LIKE :p2)
                     {_NOT_MEDIA_FILE_SQL}
                   {order_sql}""",
                {
                    "j": job_id,
                    "f": fid,
                    "p": f"%/{fid.lower()}",
                    "p2": f"%/{fid.lower()}/%",
                },
            )
            if row:
                return str(row["id"])

    if path:
        # Prefer a real media file under the recovered path tail over .thumb peers.
        tail = path[-120:] if len(path) > 120 else path
        # Strip .thumb from path tail for sibling lookup.
        tail_l = tail.lower()
        if tail_l.endswith(".thumb"):
            tail = tail[: -len(".thumb")]
        row = fetchone(
            db,
            f"""SELECT id FROM job_artifacts
               WHERE job_id=:j
                 AND lower(replace(file_path,'\\\\','/')) LIKE :pat
                 {_NOT_MEDIA_FILE_SQL}
               {order_sql}""",
            {"j": job_id, "pat": f"%{tail.lower()}%"},
        )
        if row:
            return str(row["id"])

    for cand in _media_name_candidates(name, path):
        if not cand or len(cand) < 5:
            continue
        row = fetchone(
            db,
            f"""SELECT id FROM job_artifacts
               WHERE job_id=:j AND lower(file_name)=lower(:n)
                 {_NOT_MEDIA_FILE_SQL}
               {order_sql}""",
            {"j": job_id, "n": cand},
        )
        if row:
            return str(row["id"])

    # Fallback: basename stem / fuzzy needles (IMG-*-WA####, jlaptop→laptop, recovered-HEX).
    stem = name.rsplit(".", 1)[0] if "." in name else name
    for needle in _media_stem_fuzzy_needles(stem):
        row = fetchone(
            db,
            f"""SELECT id FROM job_artifacts
               WHERE job_id=:j AND lower(file_name) LIKE :pat
                 {_NOT_MEDIA_FILE_SQL}
               {order_sql}""",
            {"j": job_id, "pat": f"%{needle}%"},
        )
        if row:
            return str(row["id"])
    return None


def _attach_media_refs(
    db: Session,
    job_id: str,
    messages: list[dict[str, Any]],
    *,
    max_lookups: int = 800,
) -> None:
    """Link media_name / media_path_recovered → job_artifacts id for Open/Download."""
    cache: dict[str, str | None] = {}
    manifest_cache: dict[str, Any] = {}
    lookups = 0
    try:
        for item in messages:
            meta = item.get("metadata")
            if not isinstance(meta, dict):
                continue
            if meta.get("media_artifact_id"):
                if (
                    meta.get("preview_quality") != "full_file_preview"
                    and isinstance(meta.get("thumbnail_base64"), str)
                    and len(str(meta.get("thumbnail_base64"))) < 12_000
                ):
                    _upgrade_chat_thumbnail_from_linked_media(
                        db, job_id, meta, str(meta["media_artifact_id"])
                    )
                continue
            media_name = meta.get("media_name") or meta.get("media_filename")
            media_path = str(meta.get("media_path_recovered") or "").strip() or None
            body = str(meta.get("body") or meta.get("original_content") or "")
            if not media_name and media_path:
                media_name = media_path.replace("\\", "/").rsplit("/", 1)[-1]
            if not media_name:
                tagged = re.search(
                    r"\[(?:IMAGE|VIDEO|AUDIO|PTT|VOICE|DOCUMENT|GIF|STICKER|MEDIA|ATTACHMENT|FILE|PDF)\]\s*"
                    r"([^\s\n\r]+)",
                    body,
                    re.I,
                )
                if tagged:
                    media_name = tagged.group(1).strip("()[]\"'")
                if not media_name:
                    bare = re.search(
                        r"([\w.\- ()+]+\.(?:zip|rar|7z|pdf|jpe?g|png|webp|gif|heic|mp4|mov|"
                        r"m4a|mp3|opus|aac|docx?|xlsx?|pptx?|txt))",
                        body,
                        re.I,
                    )
                    if bare:
                        media_name = bare.group(1).strip()
            if not media_name and not media_path:
                if meta.get("thumbnail_base64"):
                    meta["preview_quality"] = meta.get("preview_quality") or "chat_thumbnail_only"
                continue
            key = str(media_name or media_path or "").lower()
            if key not in cache:
                if lookups >= max_lookups:
                    continue
                cache[key] = _resolve_media_artifact_id(
                    db,
                    job_id,
                    str(media_name or ""),
                    media_path,
                    manifest_cache=manifest_cache,
                )
                lookups += 1
            aid = cache.get(key)
            if aid:
                meta["media_artifact_id"] = aid
                if media_name:
                    meta["media_name"] = str(media_name)
                if "Linked media" not in str(meta.get("preview_body") or ""):
                    meta["preview_body"] = (
                        f"{meta.get('preview_body') or ''}\n\n"
                        f"Linked media file: {media_name or media_path}\n"
                        f"(Open / Download available in detail pane)"
                    ).strip()
                _upgrade_chat_thumbnail_from_linked_media(db, job_id, meta, aid)
            elif meta.get("thumbnail_base64"):
                meta["preview_quality"] = meta.get("preview_quality") or "chat_thumbnail_only"
                meta["original_missing_from_extract"] = True
    finally:
        con = manifest_cache.get("_manifest_con")
        tmp = manifest_cache.get("_manifest_tmp")
        try:
            if con and con is not False:
                con.close()
        except Exception:
            pass
        if tmp:
            try:
                from pathlib import Path

                Path(str(tmp)).unlink(missing_ok=True)
            except Exception:
                pass


def _is_chatsearch_or_fts_path(path: str | None) -> bool:
    """ChatSearch FTS DBs are for original-text enrichment only — never Names rows."""
    p = (path or "").replace("\\", "/").lower()
    if not p:
        return False
    name = p.rsplit("/", 1)[-1]
    return (
        "chatsearch" in name
        or "newsletterchatsearch" in name
        or "/fts/" in p
        or name.endswith("fts.sqlite")
        or name.endswith("fts")
    )


def _expand_deleted_parse_records(norm: Any) -> list[dict[str, Any]]:
    """Normalize mobile_deleted_pipeline / carve JSON into residual message dicts."""
    if isinstance(norm, list):
        return [r for r in norm if isinstance(r, dict)]
    if not isinstance(norm, dict):
        return []
    items = norm.get("items")
    if isinstance(items, list):
        out = [r for r in items if isinstance(r, dict)]
        # Prefer chat_like when the envelope mixed junk + chat residuals.
        chat = [r for r in out if r.get("chat_like")]
        return chat or out
    if norm.get("record_type") or norm.get("text") or norm.get("text_body"):
        return [norm]
    return []


def _whatsapp_contact_label_map(db: Session, job_id: str) -> dict[str, str]:
    """Map phone/JID local-part → display name from ChatStorage sessions."""
    out: dict[str, str] = {}
    try:
        stores = _whatsapp_store_files(db, job_id)
        sessions = _live_extract_whatsapp_messages(
            db, job_id, stores, sessions_only=True, deleted_only=False, limit=5_000
        )
    except Exception:
        return out
    for item in sessions:
        meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        name = str(
            meta.get("person_name")
            or meta.get("conversation")
            or meta.get("sender")
            or item.get("title")
            or ""
        ).strip()
        if not name or name.lower() in {"unknown", "chat", "me", "you"}:
            continue
        jid = str(meta.get("chat_jid") or meta.get("remote_jid") or "").strip().lower()
        if jid:
            out[jid] = name
            local = jid.split("@", 1)[0].lstrip("~")
            if local:
                out[local] = name
        digits = re.sub(r"\D", "", name)
        if len(digits) >= 10:
            out[digits[-12:]] = name
        # Also index normalized display name for later person merges.
        out[_normalize_contact_key(name)] = name
    return out


def _normalize_contact_key(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _apply_whatsapp_contact_labels(
    messages: list[dict[str, Any]],
    labels: dict[str, str],
) -> None:
    """Replace unknown / JID-only senders with ChatStorage contact names in-place."""
    if not labels or not messages:
        return
    for item in messages:
        meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else None
        if not meta:
            continue
        sender = str(meta.get("sender") or "").strip()
        conversation = str(meta.get("conversation") or "").strip()
        jid = str(meta.get("chat_jid") or meta.get("remote_jid") or "").strip().lower()
        resolved = None
        if jid and jid in labels:
            resolved = labels[jid]
        if not resolved and jid:
            local = jid.split("@", 1)[0].lstrip("~")
            resolved = labels.get(local)
        if not resolved:
            for cand in (sender, conversation):
                digits = re.sub(r"\D", "", cand or "")
                if len(digits) >= 10 and digits[-12:] in labels:
                    resolved = labels[digits[-12:]]
                    break
                key = _normalize_contact_key(cand)
                if key and key in labels and labels[key].lower() != key:
                    resolved = labels[key]
                    break
        if not resolved:
            continue
        if not sender or sender.lower() in {"unknown", "me"} or "@" in sender or re.fullmatch(r"\+?\d{8,15}", sender):
            meta["sender"] = resolved
        if not conversation or conversation.lower() in {"unknown", "unknown conversation", "chat"} or "@" in conversation:
            meta["conversation"] = resolved
        # Keep person_name in sync when already stamped.
        if meta.get("person_name") and str(meta.get("person_name")).lower() in {
            "unknown",
            "unknown person",
            "unknown [deleted]",
        }:
            meta["person_name"] = resolved
        item["metadata"] = meta
        # Refresh title if it still starts with unknown.
        title = str(item.get("title") or "")
        if title.lower().startswith("unknown"):
            body = str(meta.get("body") or "")[:100]
            item["title"] = f"{resolved}: {body}" if body else resolved
            item["axiom_sub_category"] = resolved


def _whatsapp_deleted_person_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    """Fast Names list for WhatsApp Deleted — one row per contact/group.

    Uses SQL GROUP BY on ChatStorage (no per-message media scan). Cached as
    ``wa_deleted_persons_v14`` so reopen is instant and scroll pages 20-at-a-time.
    """
    from app.services.artifact_group_browse import group_message_rows_as_persons
    from app.services.chat_message_extract import extract_deleted_chat_summaries_from_path

    cache_key = f"wa-del-persons:v14:{job_id}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    persisted = _load_browse_cache(db, job_id, "wa_deleted_persons_v14")
    if persisted:
        _cache_set(cache_key, persisted)
        return persisted

    stores = _whatsapp_store_files(db, job_id)
    candidates = sorted(
        [
            r
            for r in stores
            if str(r.get("file_name") or "").lower() in {
                "msgstore.db",
                "chatstorage.sqlite",
                "messages.db",
                "extchatdatabase.sqlite",
            }
            or str(r.get("file_name") or "").lower().startswith("msgstore.db")
            or str(r.get("file_name") or "").lower().startswith("chatstorage.sqlite")
        ],
        key=lambda r: int(r.get("size_bytes") or 0),
        reverse=True,
    )
    synthetic: list[dict[str, Any]] = []
    count_by_label: dict[str, int] = {}
    for row in candidates[:2]:
        path = str(row.get("file_path") or "")
        store_path = _cached_store_path(db, job_id, row)
        if not store_path:
            continue
        try:
            summaries = extract_deleted_chat_summaries_from_path(store_path, path, limit=5_000)
        except Exception:
            continue
        for idx, rec in enumerate(summaries):
            item = _message_row_from_rec(
                job_id=job_id,
                job_artifact_id=str(row.get("id") or "") or None,
                source_path=path,
                rec={
                    **rec,
                    "is_deleted": True,
                    "record_type": "whatsapp_deleted_message",
                    "recovery_state": "whatsapp_deleted_flag",
                    "social_app": "whatsapp",
                },
                idx=idx,
                parser_version="whatsapp_deleted_person_summary",
            )
            if not item:
                continue
            label = str(
                (item.get("metadata") or {}).get("conversation")
                or (item.get("metadata") or {}).get("sender")
                or ""
            ).strip()
            cnt = int(rec.get("deleted_count") or 1)
            if label:
                count_by_label[label] = max(count_by_label.get(label, 0), cnt)
                count_by_label[f"{label} [deleted]"] = count_by_label[label]
            synthetic.append(item)
        if synthetic:
            break

    if not synthetic:
        # Fallback: slow path once, then cache persons for next open.
        messages = _whatsapp_deleted_message_rows(db, job_id)
        persons = group_message_rows_as_persons(
            messages, job_id=job_id, split_deleted=True
        )
        if persons:
            _persist_browse_cache(db, job_id, "wa_deleted_persons_v14", persons)
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
            _cache_set(cache_key, persons)
        return persons

    persons = group_message_rows_as_persons(
        synthetic, job_id=job_id, split_deleted=True
    )
    for p in persons:
        meta = p.get("metadata") if isinstance(p.get("metadata"), dict) else {}
        title = str(p.get("title") or meta.get("person_name") or "")
        base = str(meta.get("person_name_base") or title.replace(" [deleted]", "")).strip()
        cnt = count_by_label.get(title) or count_by_label.get(base) or int(meta.get("message_count") or 1)
        meta["message_count"] = cnt
        meta["deleted_count"] = cnt
        meta["current_count"] = 0
        meta["last_message"] = f"{cnt} deleted/recovered messages"
        # Ensure deleted board opens this row as deleted-only thread.
        meta["deleted_bucket"] = True
        meta["is_deleted"] = True
        pid = str(meta.get("person_id") or "")
        if pid and not pid.endswith("::deleted"):
            meta["person_id"] = f"{pid}::deleted"
        p["metadata"] = meta
        p["title"] = title if title.endswith("[deleted]") else f"{base} [deleted]"
        tags = list(p.get("tags") or [])
        if "deleted" not in [str(t).lower() for t in tags]:
            tags.append("deleted")
        p["tags"] = tags

    if persons:
        _persist_browse_cache(db, job_id, "wa_deleted_persons_v14", persons)
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        _cache_set(cache_key, persons)
    return persons


def _load_whatsapp_deleted_browse_cache(
    db: Session,
    job_id: str,
    *,
    upgrade: bool = True,
) -> list[dict[str, Any]] | None:
    """Load deleted-message browse cache, optionally upgrading older versions in place."""
    for kind in (
        "wa_deleted_v17",
        "wa_deleted_v16",
        "wa_deleted_v15",
        "wa_deleted_v14",
        "wa_deleted_v13",
        "wa_deleted_v12",
        "wa_deleted_v11",
        "wa_deleted_v10",
    ):
        rows = _load_browse_cache(db, job_id, kind)
        if not rows:
            continue
        if upgrade and kind != "wa_deleted_v17":
            try:
                _sanitize_deleted_protocol_noise(rows)
                _persist_browse_cache(db, job_id, "wa_deleted_v17", rows)
            except Exception:
                pass
        return rows
    return None


def _whatsapp_deleted_message_rows(
    db: Session,
    job_id: str,
    *,
    person_id: str | None = None,
) -> list[dict[str, Any]]:
    """Human-readable deleted/recovered WhatsApp rows (never carve JSON dumps).

    Sources (in order — fastest first):
      0) Persistent browse cache (wa_deleted_v17+, upgraded from v13+)
      1) ChatStorage revoke / deleted-flag rows (named contacts)
      2) mobile_deleted_pipeline parse cache
      3) freelist/WAL live carve when still empty
    """
    from app.services.artifact_group_browse import (
        _person_key_from_row,
        _split_person_bucket_id,
    )

    pid = (person_id or "").strip()
    # v12: reject FTS schema junk, prefer ChatStorage names, always merge revoke rows.
    cache_key = f"wa-del:v18:{job_id}:{pid}"
    cached = _cache_get(cache_key)
    if cached is not None:
        # Cached thread must stay cheap — never re-run ChatSearch enrich on every open.
        if pid:
            try:
                _sanitize_deleted_protocol_noise(cached)
            except Exception:
                pass
        return cached

    def _filter_person(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not pid:
            return rows
        base_id, deleted_bucket = _split_person_bucket_id(pid)
        kept: list[dict[str, Any]] = []
        for row in rows:
            kind = str(
                ((row.get("metadata") or {}).get("evidence_kind") if isinstance(row.get("metadata"), dict) else None)
                or row.get("artifact_type")
                or ""
            ).lower()
            if kind in {"person", "group", "conversation", "album", "notice"}:
                continue
            try:
                sid, _, _ = _person_key_from_row(row)
            except Exception:
                continue
            meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            stamped = str(meta.get("base_person_id") or meta.get("person_id") or "").strip()
            stamped_base = (
                _split_person_bucket_id(stamped)[0] if stamped else ""
            )
            if sid != base_id and stamped_base != base_id:
                continue
            if deleted_bucket:
                if not (
                    meta.get("is_deleted")
                    or "deleted" in [str(t).lower() for t in (row.get("tags") or [])]
                ):
                    continue
            kept.append(row)
        return kept

    # Persistent cache: open NAMES list must not re-extract or media-link every time.
    # Do NOT migrate v10/v11 — those often stored ChatSearch FTS schema as "unknown".
    if not pid:
        persisted = _load_whatsapp_deleted_browse_cache(db, job_id)
        if persisted:
            _cache_set(cache_key, persisted)
            return persisted
    else:
        # Person thread: reuse full deleted cache then filter (avoids re-carve).
        # Skip full-cache upgrade here — sanitizing/persisting ~2k rows blocks the UI.
        full = _load_whatsapp_deleted_browse_cache(db, job_id, upgrade=False)
        if full:
            filtered = _filter_person(full)
            try:
                _sanitize_deleted_protocol_noise(filtered)
            except Exception:
                pass
            # Do not ChatSearch-enrich or Manifest media-link on thread open — both can
            # block for minutes on large iOS extracts. Thumbnails/body from cache still show;
            # full media resolve happens when the user opens/downloads a single item.
            _cache_set(cache_key, filtered)
            return filtered

        # No full-message cache yet (Names list may still exist from summaries).
        # NEVER fall through to multi-GB live carve / ChatSearch enrich for a single
        # person open — that hangs the Mobile report UI for minutes. Use ChatStorage
        # deleted-flag rows for this person only, then return.
        messages: list[dict[str, Any]] = []
        seen: set[str] = set()
        try:
            flagged = _whatsapp_message_rows(
                db, job_id, deleted_only=True, person_id=person_id
            )
            for item in flagged:
                meta = item.get("metadata") or {}
                if not isinstance(meta, dict):
                    continue
                kind = str(meta.get("evidence_kind") or item.get("artifact_type") or "")
                if kind in {"whatsapp_store", "notice"}:
                    continue
                if _is_chatsearch_or_fts_path(
                    str(item.get("source_path") or meta.get("source_path") or "")
                ):
                    continue
                key = (
                    f"{meta.get('sender')}|{str(meta.get('body') or '')[:160]}|"
                    f"{item.get('artifact_datetime')}"
                )
                if key in seen:
                    continue
                seen.add(key)
                meta = {
                    **meta,
                    "is_deleted": True,
                    "evidence_kind": "whatsapp_deleted_message",
                }
                item = {
                    **item,
                    "metadata": meta,
                    "artifact_type": "whatsapp_deleted_message",
                }
                tags = list(item.get("tags") or [])
                if "deleted" not in [str(t).lower() for t in tags]:
                    tags.append("deleted")
                item["tags"] = tags
                messages.append(item)
                if len(messages) >= 2_000:
                    break
        except Exception:
            messages = []
        try:
            _sanitize_deleted_protocol_noise(messages)
        except Exception:
            pass
        # Skip Manifest media linking on cold person open (same hang as cache path).
        _cache_set(cache_key, messages)
        return messages

    messages: list[dict[str, Any]] = []
    seen: set[str] = set()
    # Names list: enough rows to populate contacts. Thread uses person filter later.
    msg_cap = 5_000 if pid else 2_500

    def _ingest(parsed_rows: list[dict[str, Any]], *, pipeline_only: bool) -> None:
        nonlocal messages
        for prow in parsed_rows:
            path = str(prow.get("file_path") or "")
            # Never promote ChatSearch FTS freelist/schema into the Names list.
            if _is_chatsearch_or_fts_path(path):
                continue
            records = _expand_deleted_parse_records(prow.get("normalized"))
            parser_name = str(prow.get("parser_name") or "")
            is_deleted_pipeline = parser_name == "mobile_deleted_pipeline"
            if pipeline_only and not is_deleted_pipeline:
                continue
            for idx, rec in enumerate(records[:3000]):
                if _is_chatsearch_or_fts_path(str(rec.get("source") or "")):
                    continue
                app = str(rec.get("social_app") or "").lower()
                if app and app not in {"whatsapp", ""}:
                    continue
                if rec.get("chat_like") is False:
                    continue
                rtype = str(rec.get("record_type") or "").lower()
                already_deleted = bool(
                    rec.get("is_deleted")
                    or rec.get("deleted")
                    or "deleted" in rtype
                    or "residual" in rtype
                    or str(rec.get("recovery_state") or "").strip()
                )
                if not is_deleted_pipeline and not already_deleted:
                    continue
                rec = {
                    **rec,
                    "is_deleted": True,
                    "record_type": rec.get("record_type") or "sqlite_deleted_residual",
                    "recovery_state": rec.get("recovery_state") or "sqlite_freelist",
                    "social_app": "whatsapp",
                }
                item = _message_row_from_rec(
                    job_id=job_id,
                    job_artifact_id=str(prow.get("job_artifact_id") or "") or None,
                    source_path=str(rec.get("source") or path),
                    rec=rec,
                    idx=idx,
                    parser_version="whatsapp_deleted_residual",
                )
                if not item:
                    continue
                key = (
                    f"{item['metadata'].get('sender')}|"
                    f"{str(item['metadata'].get('body') or '')[:160]}|"
                    f"{item.get('artifact_datetime')}"
                )
                if key in seen:
                    continue
                seen.add(key)
                messages.append(item)
                if len(messages) >= msg_cap:
                    return
            if len(messages) >= msg_cap:
                return

    # 1) ChatStorage revoke / deleted-flag rows FIRST — these carry real contact names.
    try:
        flagged = _whatsapp_message_rows(
            db, job_id, deleted_only=True, person_id=person_id
        )
        for item in flagged:
            meta = item.get("metadata") or {}
            if not isinstance(meta, dict):
                continue
            kind = str(meta.get("evidence_kind") or item.get("artifact_type") or "")
            if kind in {"whatsapp_store", "notice"}:
                continue
            if _is_chatsearch_or_fts_path(str(item.get("source_path") or meta.get("source_path") or "")):
                continue
            key = (
                f"{meta.get('sender')}|{str(meta.get('body') or '')[:160]}|"
                f"{item.get('artifact_datetime')}"
            )
            if key in seen:
                continue
            seen.add(key)
            meta = {
                **meta,
                "is_deleted": True,
                "evidence_kind": "whatsapp_deleted_message",
            }
            item = {**item, "metadata": meta, "artifact_type": "whatsapp_deleted_message"}
            tags = list(item.get("tags") or [])
            if "deleted" not in [str(t).lower() for t in tags]:
                tags.append("deleted")
            item["tags"] = tags
            messages.append(item)
            if len(messages) >= msg_cap:
                break
    except Exception:
        pass

    # 2) Deleted-pipeline parse results — only to fill gaps when ChatStorage is thin.
    # Skip when we already have named ChatStorage deletes (avoids ChatSearch FTS junk).
    if len(messages) < 50:
        try:
            pipeline_rows = fetchall(
                db,
                """SELECT apr.id, apr.normalized, apr.parser_name, ja.id AS job_artifact_id, ja.file_path
                   FROM artifact_parse_results apr
                   JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
                   WHERE ja.job_id=:j AND apr.parser_name = 'mobile_deleted_pipeline'
                     AND lower(ja.file_name) NOT LIKE 'chatsearch%'
                     AND lower(ja.file_path) NOT LIKE '%/fts/%'
                   ORDER BY ja.size_bytes DESC NULLS LAST
                   LIMIT 80""",
                {"j": job_id},
            )
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            pipeline_rows = []
        _ingest(pipeline_rows, pipeline_only=True)

    # 3) Fallback parses with deleted flags (only when still empty — names list).
    if len(messages) == 0 and not pid:
        try:
            parsed = fetchall(
                db,
                """SELECT apr.id, apr.normalized, apr.parser_name, ja.id AS job_artifact_id, ja.file_path
                   FROM artifact_parse_results apr
                   JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
                   WHERE ja.job_id=:j
                     AND apr.parser_name <> 'mobile_deleted_pipeline'
                     AND (
                       lower(ja.file_name) IN (
                         'chatstorage.sqlite', 'msgstore.db', 'messages.db', 'wa.db'
                       )
                       OR lower(ja.file_name) LIKE 'chatstorage.sqlite%'
                       OR lower(ja.file_name) LIKE 'msgstore.db%'
                       OR ja.file_path ILIKE '%deleted_recovery%whatsapp%'
                     )
                   ORDER BY ja.size_bytes DESC NULLS LAST
                   LIMIT 40""",
                {"j": job_id},
            )
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            parsed = []
        _ingest(parsed, pipeline_only=False)

    # 4) Live freelist carve only when nothing usable — multi‑GB DB read.
    if len(messages) == 0:
        messages.extend(_live_carve_whatsapp_deleted(db, job_id, seen, limit=500))

    # Resolve unknown / JID senders against ChatStorage contact names.
    try:
        _apply_whatsapp_contact_labels(messages, _whatsapp_contact_label_map(db, job_id))
    except Exception:
        pass

    # Enrich revoke placeholders from ChatSearch / notifications (real content).
    try:
        _enrich_deleted_originals_from_job(db, job_id, messages)
    except Exception:
        pass

    if not pid and messages:
        # Persist without media links so Names opens in milliseconds next time.
        _persist_browse_cache(db, job_id, "wa_deleted_v17", messages)
        _cache_set(cache_key, messages)
        return messages

    messages = _filter_person(messages)
    if pid:
        _attach_media_refs(
            db, job_id, messages, max_lookups=min(200, max(len(messages), 20))
        )
    _cache_set(cache_key, messages)
    return messages


def _live_carve_whatsapp_deleted(
    db: Session,
    job_id: str,
    seen: set[str],
    *,
    limit: int = 2000,
) -> list[dict[str, Any]]:
    """Carve chat-like residuals directly from ChatStorage/msgstore for Open browse."""
    from app.services.artifact_preview import resolve_artifact_bytes
    from app.services.mobile_acquire.sqlite_deleted import recover_sqlite_bytes

    stores = fetchall(
        db,
        """SELECT id, file_path, file_name, size_bytes, minio_uri, extension
           FROM job_artifacts
           WHERE job_id=:j AND (
             lower(file_name) IN ('chatstorage.sqlite', 'msgstore.db', 'messages.db')
             OR lower(file_name) LIKE 'chatstorage.sqlite%'
             OR lower(file_name) LIKE 'msgstore.db%'
           )
           AND lower(file_name) NOT LIKE '%.crypt%'
           AND lower(file_name) NOT LIKE '%.enc'
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 3""",
        {"j": job_id},
    )
    out: list[dict[str, Any]] = []
    for row in stores:
        path = str(row.get("file_path") or "")
        try:
            data = resolve_artifact_bytes(
                db, job_id, row, persist=False, max_bytes=512 * 1024 * 1024
            )
        except Exception:
            continue
        if not data or not data[:16].startswith(b"SQLite format"):
            continue
        try:
            recovered = recover_sqlite_bytes(data, source_label=path)
        except Exception:
            continue
        items = list(recovered.get("items") or [])
        chat_items = [it for it in items if isinstance(it, dict) and it.get("chat_like")]
        # Prefer residuals that look like natural language over bare JIDs.
        def _rank(it: dict[str, Any]) -> tuple[int, int, int]:
            t = str(it.get("text") or it.get("text_body") or "")
            has_space = 1 if " " in t else 0
            bare_jid = ("@g.us" in t or "@s.whatsapp.net" in t) and " " not in t
            not_jid = 0 if bare_jid else 1
            return (has_space, not_jid, len(t))

        chat_items.sort(key=_rank, reverse=True)
        for idx, rec in enumerate(chat_items[:limit]):
            rec = {
                **rec,
                "is_deleted": True,
                "record_type": "sqlite_deleted_residual",
                "recovery_state": rec.get("recovery_state") or "sqlite_freelist",
                "social_app": "whatsapp",
            }
            item = _message_row_from_rec(
                job_id=job_id,
                job_artifact_id=str(row.get("id") or "") or None,
                source_path=path,
                rec=rec,
                idx=idx,
                parser_version="whatsapp_deleted_live_carve",
            )
            if not item:
                continue
            key = (
                f"{item['metadata'].get('sender')}|"
                f"{str(item['metadata'].get('body') or '')[:160]}|"
                f"{item.get('artifact_datetime')}"
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
            if len(out) >= limit:
                return out
    return out


def _contact_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    """Parsed address-book people — not raw SQLite hex dumps."""
    from app.services.artifact_preview import resolve_artifact_bytes

    files = fetchall(
        db,
        """SELECT id, file_path, file_name, extension, size_bytes, minio_uri
           FROM job_artifacts
           WHERE job_id=:j AND (
             lower(file_name) IN (
               'addressbook.sqlitedb', 'contacts2.db', 'contacts.db', 'contact.db'
             )
             OR lower(file_name) LIKE 'addressbook%.sqlitedb'
             OR lower(replace(file_path,'\\\\','/')) LIKE '%/addressbook/addressbook.sqlitedb%'
             OR (
               lower(replace(file_path,'\\\\','/')) LIKE '%/com.android.providers.contacts/%'
               AND lower(file_name) LIKE '%.db'
             )
           )
           AND lower(file_name) NOT LIKE '%shadow%'
           AND lower(file_name) NOT LIKE '%duplicate%'
           AND lower(file_name) NOT LIKE '%serverstate%'
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 12""",
        {"j": job_id},
    )
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in files:
        path = str(row.get("file_path") or "")
        try:
            data = resolve_artifact_bytes(
                db, job_id, row, persist=False, max_bytes=128 * 1024 * 1024
            )
        except Exception:
            continue
        if not data or not data[:16].startswith(b"SQLite format"):
            continue
        people = _extract_contacts_from_bytes(data, path)
        for idx, person in enumerate(people):
            name = str(person.get("display_name") or "").strip()
            phones = person.get("phones") or []
            emails = person.get("emails") or []
            if not name and not phones:
                continue
            key = f"{name}|{','.join(phones[:2])}"
            if key in seen:
                continue
            seen.add(key)
            phone_line = ", ".join(phones[:6]) if phones else "—"
            email_line = ", ".join(emails[:4]) if emails else "—"
            title = f"{name or 'Unknown'} · {phone_line}" if phones else (name or "Unknown contact")
            vid = _virtual_id("contact", f"{row.get('id')}|{person.get('contact_id') or idx}|{title[:80]}")
            preview = (
                f"Contact\n"
                f"Name: {name or '—'}\n"
                f"Phone: {phone_line}\n"
                f"Email: {email_line}\n"
                f"Organization: {person.get('org') or '—'}\n\n"
                f"Source DB:\n{path}"
            )
            out.append(
                {
                    "id": vid,
                    "job_id": job_id,
                    "file_id": None,
                    "parent_artifact_id": str(row.get("id") or "") or None,
                    "artifact_type": "contact",
                    "axiom_category": "contacts",
                    "axiom_category_label": "Contacts",
                    "axiom_sub_category": name or None,
                    "title": title,
                    "source_path": path,
                    "artifact_datetime": None,
                    "preview_uri": None,
                    "storage_uri": None,
                    "metadata": {
                        "evidence_kind": "contact",
                        "display_name": name,
                        "phones": phones,
                        "emails": emails,
                        "org": person.get("org"),
                        "source_path": path,
                        "source_artifact_id": str(row.get("id") or "") or None,
                        "preview_body": preview,
                        "body": preview,
                    },
                    "tags": ["contact"],
                    "examiner_comment": None,
                    "parser_version": "contacts_live_extract",
                    "confidence": None,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            if len(out) >= 8000:
                return out
    return out


def _extract_contacts_from_bytes(data: bytes, path: str) -> list[dict[str, Any]]:
    import os
    import sqlite3
    import tempfile

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {str(r[0]).lower(): str(r[0]) for r in cur.fetchall()}
            people: list[dict[str, Any]] = []

            if "abperson" in tables:
                person_t = tables["abperson"]
                phone_map: dict[int, list[str]] = {}
                email_map: dict[int, list[str]] = {}
                if "abmultivalue" in tables:
                    mv = tables["abmultivalue"]
                    try:
                        cur.execute(
                            f"""SELECT record_id, property, value
                                FROM "{mv}"
                                WHERE value IS NOT NULL AND property IN (3, 4)
                                LIMIT 20000"""
                        )
                        for rid, prop, val in cur.fetchall():
                            try:
                                rid_i = int(rid)
                            except (TypeError, ValueError):
                                continue
                            s = str(val or "").strip()
                            if not s:
                                continue
                            if int(prop or 0) == 3:
                                phone_map.setdefault(rid_i, []).append(s)
                            else:
                                email_map.setdefault(rid_i, []).append(s)
                    except sqlite3.Error:
                        pass
                cur.execute(
                    f'SELECT ROWID, First, Last, Organization FROM "{person_t}" LIMIT 5000'
                )
                for rid, first, last, org in cur.fetchall():
                    try:
                        rid_i = int(rid)
                    except (TypeError, ValueError):
                        rid_i = -1
                    name = " ".join(x for x in (first, last) if x).strip() or (org or "")
                    people.append(
                        {
                            "contact_id": rid_i,
                            "display_name": str(name or "").strip(),
                            "org": org,
                            "phones": phone_map.get(rid_i, [])[:8],
                            "emails": email_map.get(rid_i, [])[:6],
                        }
                    )
                return people

            if "view_contacts" in tables:
                t = tables["view_contacts"]
                cur.execute(
                    f'SELECT _id, display_name FROM "{t}" WHERE display_name IS NOT NULL LIMIT 5000'
                )
                for cid, name in cur.fetchall():
                    people.append(
                        {
                            "contact_id": cid,
                            "display_name": str(name or "").strip(),
                            "phones": [],
                            "emails": [],
                        }
                    )
                # Best-effort phones
                if "view_data" in tables or "data" in tables:
                    data_t = tables.get("view_data") or tables.get("data")
                    try:
                        cur.execute(
                            f"""SELECT contact_id, data1 FROM "{data_t}"
                                WHERE mimetype LIKE '%phone%' AND data1 IS NOT NULL
                                LIMIT 20000"""
                        )
                        by_id: dict[Any, list[str]] = {}
                        for cid, phone in cur.fetchall():
                            by_id.setdefault(cid, []).append(str(phone))
                        for p in people:
                            p["phones"] = by_id.get(p["contact_id"], [])[:8]
                    except sqlite3.Error:
                        pass
                return people

            if "raw_contacts" in tables:
                t = tables["raw_contacts"]
                cur.execute(
                    f'SELECT _id, display_name FROM "{t}" WHERE display_name IS NOT NULL LIMIT 5000'
                )
                for cid, name in cur.fetchall():
                    people.append(
                        {
                            "contact_id": cid,
                            "display_name": str(name or "").strip(),
                            "phones": [],
                            "emails": [],
                        }
                    )
                return people
            return people
        finally:
            conn.close()
    except Exception:
        return []
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _deleted_social_message_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    """Cross-app deleted/residual chat rows — never raw SQLite hex dumps."""
    # Start with WhatsApp deleted (highest value), then other apps from parse cache + live carve.
    out = list(_whatsapp_deleted_message_rows(db, job_id))
    seen = {
        f"{(m.get('metadata') or {}).get('sender')}|{str((m.get('metadata') or {}).get('body') or '')[:160]}"
        for m in out
    }
    try:
        parsed = fetchall(
            db,
            """SELECT apr.normalized, apr.parser_name, ja.id AS job_artifact_id, ja.file_path
               FROM artifact_parse_results apr
               JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
               WHERE ja.job_id=:j AND apr.parser_name = 'mobile_deleted_pipeline'
               LIMIT 500""",
            {"j": job_id},
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        parsed = []
    for prow in parsed:
        path = str(prow.get("file_path") or "")
        for idx, rec in enumerate(_expand_deleted_parse_records(prow.get("normalized"))[:2000]):
            if not isinstance(rec, dict) or rec.get("chat_like") is False:
                continue
            app = str(rec.get("social_app") or "chat").lower() or "chat"
            if app == "whatsapp":
                continue  # already included
            if app in {"sms", "imessage"}:
                continue  # keep Deleted Social focused on third-party messengers
            body = str(rec.get("text_body") or rec.get("body") or rec.get("text") or "").strip()
            if not body or not _looks_like_chat_body(body):
                continue
            if _is_sms_source_path(path):
                continue
            from app.services.artifact_group_browse import enrich_message_record

            rec = enrich_message_record({**rec, "social_app": app, "is_deleted": True})
            sender = str(rec.get("sender") or "unknown")
            conversation = str(rec.get("conversation") or rec.get("chat") or "").strip()
            conversation_id = str(rec.get("conversation_id") or "").strip() or None
            key = f"{conversation_id or conversation}|{sender}|{body[:160]}"
            if key in seen:
                continue
            seen.add(key)
            preview = (
                f"{app.replace('_', ' ').title()} chat (recovered)\n\n"
                f"⚠ RECOVERED / DELETED ARTIFACT\n\n"
                f"Conversation: {conversation or '—'}\n"
                f"{rec.get('deleted_at') or '—'} {sender}: {body}\n\n"
                f"Recovery status: DELETED\n"
                f"Recovered from: {str(rec.get('recovery_state') or 'sqlite_freelist').replace('_', ' ')}\n"
                f"Confidence: {str(rec.get('confidence') or 'MEDIUM').upper()}\n"
                f"Database: {path}"
            )
            out.append(
                {
                    "id": _virtual_id("del", f"{prow.get('job_artifact_id')}|{conversation_id or ''}|{idx}|{body[:60]}"),
                    "job_id": job_id,
                    "file_id": None,
                    "parent_artifact_id": str(prow.get("job_artifact_id") or "") or None,
                    "artifact_type": "deleted_chat_residual",
                    "axiom_category": "deleted social",
                    "axiom_category_label": "Deleted Social / Chat Data",
                    "axiom_sub_category": conversation or app,
                    "title": (
                        f"{conversation} · {sender}: {body[:100]}"
                        if conversation
                        else f"{app}: {body[:120]}"
                    ),
                    "source_path": path,
                    "artifact_datetime": str(rec.get("deleted_at") or "") or None,
                    "preview_uri": None,
                    "storage_uri": None,
                    "metadata": {
                        "evidence_kind": "deleted_chat_residual",
                        "social_app": app,
                        "sender": sender,
                        "conversation": conversation,
                        "conversation_id": conversation_id,
                        "chat_jid": rec.get("chat_jid"),
                        "is_group": bool(rec.get("is_group")),
                        "body": body[:8000],
                        "is_deleted": True,
                        "recovery_state": rec.get("recovery_state") or "sqlite_freelist",
                        "source_path": path,
                        "source_artifact_id": str(prow.get("job_artifact_id") or "") or None,
                        "preview_body": preview,
                    },
                    "tags": ["deleted", app, "chat_message"],
                    "examiner_comment": None,
                    "parser_version": "deleted_social_residual",
                    "confidence": rec.get("confidence"),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            if len(out) >= 8000:
                break
        if len(out) >= 8000:
            break

    # Live extract readable chats from trash/deleted_recovery messaging DBs (LINE/FB/etc).
    if len(out) < 2000:
        from app.services.artifact_preview import resolve_artifact_bytes
        from app.services.chat_message_extract import extract_chat_messages_from_bytes

        dbs = fetchall(
            db,
            """SELECT id, file_path, file_name, size_bytes, minio_uri, extension
               FROM job_artifacts
               WHERE job_id=:j
                 AND (
                   lower(replace(file_path,'\\\\','/')) LIKE '%deleted_recovery%'
                   OR coalesce(metadata->>'is_deleted','') IN ('true','1','t')
                   OR coalesce(metadata->>'has_freelist_residuals','') IN ('true','1','t')
                 )
                 AND (
                   lower(file_name) LIKE '%.db'
                   OR lower(file_name) LIKE '%.sqlite%'
                 )
                 AND lower(file_name) NOT LIKE '%-wal'
                 AND lower(file_name) NOT LIKE '%-shm'
               ORDER BY size_bytes DESC NULLS LAST
               LIMIT 25""",
            {"j": job_id},
        )
        for row in dbs:
            path = str(row.get("file_path") or "")
            # Skip pure search-index DBs that never hold message bodies.
            name = str(row.get("file_name") or "").lower()
            if "line_search" in name or name.endswith(".json"):
                continue
            if _is_sms_source_path(path):
                continue
            # Prefer real messaging app trees; skip tipkit / webkit mail junk.
            pl = path.lower().replace("\\", "/")
            if any(x in pl for x in ("webkit", "tipkit", "resourceloadstatistics", "observations.db")):
                continue
            try:
                data = resolve_artifact_bytes(
                    db, job_id, row, persist=False, max_bytes=80 * 1024 * 1024
                )
            except Exception:
                continue
            if not data or not data[:16].startswith(b"SQLite format"):
                continue
            try:
                records = extract_chat_messages_from_bytes(data, path, limit=500)
            except Exception:
                records = []
            for idx, rec in enumerate(records):
                if not isinstance(rec, dict):
                    continue
                body = str(rec.get("text_body") or rec.get("body") or "").strip()
                if not body or not _looks_like_chat_body(body):
                    continue
                from app.services.artifact_group_browse import enrich_message_record

                app = str(rec.get("social_app") or "chat")
                rec = enrich_message_record({**rec, "social_app": app, "is_deleted": True})
                sender = str(rec.get("sender") or "unknown")
                conversation = str(rec.get("conversation") or rec.get("chat") or "").strip()
                conversation_id = str(rec.get("conversation_id") or "").strip() or None
                key = f"{conversation_id or conversation}|{sender}|{body[:160]}"
                if key in seen:
                    continue
                seen.add(key)
                preview = (
                    f"{app.replace('_', ' ').title()} message from deleted/recovery DB\n\n"
                    f"⚠ RECOVERED / DELETED ARTIFACT\n\n"
                    f"Conversation: {conversation or '—'}\n"
                    f"From: {sender}\n"
                    f"Message:\n{body}\n\n"
                    f"Source DB:\n{path}"
                )
                out.append(
                    {
                        "id": _virtual_id(
                            "delsoc", f"{row.get('id')}|{conversation_id or ''}|{idx}|{body[:60]}"
                        ),
                        "job_id": job_id,
                        "parent_artifact_id": str(row.get("id") or "") or None,
                        "artifact_type": "deleted_chat_residual",
                        "axiom_category": "deleted social",
                        "axiom_category_label": "Deleted Social / Chat Data",
                        "axiom_sub_category": conversation or sender,
                        "title": (
                            f"{conversation} · {sender}: {body[:100]}"
                            if conversation
                            else f"{sender}: {body[:120]}"
                        ),
                        "source_path": path,
                        "artifact_datetime": str(rec.get("timestamp") or "") or None,
                        "metadata": {
                            "evidence_kind": "deleted_chat_residual",
                            "social_app": app,
                            "sender": sender,
                            "conversation": conversation,
                            "conversation_id": conversation_id,
                            "chat_jid": rec.get("chat_jid"),
                            "is_group": bool(rec.get("is_group")),
                            "body": body[:8000],
                            "is_deleted": True,
                            "source_path": path,
                            "source_artifact_id": str(row.get("id") or "") or None,
                            "preview_body": preview,
                        },
                        "tags": ["deleted", "chat_message", app],
                        "parser_version": "deleted_social_live_extract",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                if len(out) >= 8000:
                    return out
    return out


def _email_attachment_file_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    """Browseable Email Attachments from files + MIME parts + carved evidence.

    Catalog counts must never point to invisible evidence.  MIME parts live inside
    their parent EML/EMLX and therefore need virtual rows with the parent artifact
    id + MIME walk ``part_index``.  The content endpoint can then open/download the
    exact attachment bytes without creating a duplicate source file.
    """
    import json as _json

    from app.services.email_inventory import email_attachment_browse_where_sql

    # Reconcile historical jobs first.  This promotes extensionless RFC822 rows and
    # stores deterministic attachment metadata on their parent artifact.
    try:
        from app.services.email_mime_inventory import scan_job_email_mime_inventory

        scan_job_email_mime_inventory(db, job_id)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    where = email_attachment_browse_where_sql().strip()
    files = fetchall(
        db,
        f"""SELECT id, file_path, file_name, extension, size_bytes, minio_uri, created_at
            FROM job_artifacts
            WHERE job_id=:j AND ({where})
            ORDER BY size_bytes DESC NULLS LAST
            LIMIT 10000""",
        {"j": job_id},
    )
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in files:
        path = str(row.get("file_path") or "")
        name = str(row.get("file_name") or path.replace("\\", "/").rsplit("/", 1)[-1])
        size = int(row.get("size_bytes") or 0)
        rid = str(row["id"])
        seen.add(rid)
        out.append(
            {
                "id": rid,
                "job_id": job_id,
                "artifact_type": "email_attachment",
                "axiom_category": "email attachments",
                "axiom_category_label": "Email Attachments",
                "title": name,
                "source_path": path,
                "storage_uri": row.get("minio_uri"),
                "size_bytes": size,
                "file_name": name,
                "metadata": {
                    "evidence_kind": "email_attachment_file",
                    "source_artifact_id": rid,
                    "preview_body": (
                        f"Email attachment file\n"
                        f"Name: {name}\n"
                        f"Size: {size:,} bytes\n"
                        f"Path:\n{path}\n\n"
                        "Open file / Open in new tab to view or download."
                    ),
                },
                "tags": ["email_attachment"],
                "created_at": (
                    row["created_at"].isoformat()
                    if hasattr(row.get("created_at"), "isoformat")
                    else str(row.get("created_at") or "")
                ),
            }
        )

    parents = fetchall(
        db,
        """SELECT id, file_path, file_name, created_at, metadata
           FROM job_artifacts
           WHERE job_id=:j
             AND jsonb_typeof(metadata->'email_mime_attachments')='array'
             AND jsonb_array_length(metadata->'email_mime_attachments') > 0
           ORDER BY id
           LIMIT 20000""",
        {"j": job_id},
    )
    for parent in parents:
        parent_id = str(parent.get("id") or "")
        pmeta = parent.get("metadata")
        if isinstance(pmeta, str):
            try:
                pmeta = _json.loads(pmeta)
            except Exception:
                pmeta = {}
        if not isinstance(pmeta, dict):
            pmeta = {}
        attachments = pmeta.get("email_mime_attachments") or []
        if not isinstance(attachments, list):
            continue
        parent_path = str(parent.get("file_path") or "")
        parent_name = str(parent.get("file_name") or parent_path.replace("\\", "/").rsplit("/", 1)[-1])
        subject = str(pmeta.get("email_subject") or "")
        for att in attachments:
            if not isinstance(att, dict):
                continue
            try:
                part_index = int(att.get("part_index"))
            except (TypeError, ValueError):
                continue
            filename = str(att.get("filename") or f"part-{part_index}.bin")
            content_type = str(att.get("content_type") or "application/octet-stream")
            try:
                size = int(att.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            vid = _virtual_id("emailatt", f"{parent_id}|{part_index}|{filename}")
            if vid in seen:
                continue
            seen.add(vid)
            out.append(
                {
                    "id": vid,
                    "job_id": job_id,
                    "file_id": None,
                    "parent_artifact_id": parent_id,
                    "artifact_type": "email_attachment_part",
                    "axiom_category": "email attachments",
                    "axiom_category_label": "Email Attachments",
                    "title": filename,
                    "source_path": parent_path,
                    "size_bytes": size,
                    "file_name": filename,
                    "metadata": {
                        "evidence_kind": "email_attachment_part",
                        "source_artifact_id": parent_id,
                        "parent_artifact_id": parent_id,
                        "parent_file_name": parent_name,
                        "parent_subject": subject,
                        "part_index": part_index,
                        "filename": filename,
                        "content_type": content_type,
                        "size": size,
                        "disposition": str(att.get("disposition") or "attachment"),
                        "inline": bool(att.get("inline")),
                        "preview_body": (
                            f"MIME email attachment\n"
                            f"Filename: {filename}\n"
                            f"Content type: {content_type}\n"
                            f"Size: {size:,} bytes\n"
                            f"Parent message: {subject or parent_name}\n"
                            f"Source message:\n{parent_path}\n\n"
                            "Open attachment to view or download the exact MIME part."
                        ),
                    },
                    "tags": ["email_attachment", "mime_part"],
                    "parser_version": "email_mime_inventory_v44",
                    "created_at": (
                        parent["created_at"].isoformat()
                        if hasattr(parent.get("created_at"), "isoformat")
                        else str(parent.get("created_at") or "")
                    ),
                }
            )

    # Carved mail-adjacent attachments are independently examiner-openable through
    # their source container, so expose the same rows used by the catalog counter.
    try:
        from app.services.signature_carve_inventory import list_carve_evidence

        carved = list_carve_evidence(
            db, job_id, axiom_name="Email Attachments", page=1, page_size=2000
        )
        for item in carved.get("items") or []:
            rid = str(item.get("id") or "")
            if rid and rid not in seen:
                out.append(item)
                seen.add(rid)
    except Exception:
        pass
    return out


def _sms_attachment_rows(db: Session, job_id: str) -> list[dict[str, Any]]:
    """MMS / iMessage attachment records from sms.db (not email)."""
    import os
    import sqlite3
    import tempfile

    from app.services.artifact_preview import resolve_artifact_bytes

    stores = fetchall(
        db,
        """SELECT id, file_path, file_name, size_bytes, minio_uri, extension
           FROM job_artifacts
           WHERE job_id=:j AND (
             lower(file_name)='sms.db'
             OR lower(file_name)='mmssms.db'
             OR lower(replace(file_path,'\\\\','/')) LIKE '%/library/sms/sms.db%'
           )
           ORDER BY size_bytes DESC NULLS LAST LIMIT 3""",
        {"j": job_id},
    )
    out: list[dict[str, Any]] = []
    for row in stores:
        path = str(row.get("file_path") or "")
        try:
            data = resolve_artifact_bytes(
                db, job_id, row, persist=False, max_bytes=200 * 1024 * 1024
            )
        except Exception:
            continue
        if not data or not data[:16].startswith(b"SQLite format"):
            continue
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
            try:
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {str(r[0]).lower(): str(r[0]) for r in cur.fetchall()}
                att_t = tables.get("attachment") or tables.get("attachments")
                if not att_t:
                    continue
                cols = _table_columns_safe(cur, att_t)
                # reuse local pick
                def pick(*cands: str) -> str | None:
                    for c in cands:
                        if c in cols:
                            return cols[c]
                    return None

                filename_c = pick("filename", "transfer_name", "name", "uti")
                path_c = pick("filename", "local_url", "url", "path")
                mime_c = pick("mime_type", "uti", "mime")
                size_c = pick("total_bytes", "size", "transfer_size")
                rowid_c = pick("rowid", "ROWID", "pk") or "rowid"
                sel = [f'"{rowid_c}"']
                for c in (filename_c, path_c, mime_c, size_c):
                    if c and f'"{c}"' not in sel:
                        sel.append(f'"{c}"')
                cur.execute(
                    f'SELECT {", ".join(sel)} FROM "{att_t}" LIMIT 5000'
                )
                for rec in cur.fetchall():
                    values = list(rec)
                    rid = values[0]
                    rest = values[1:]
                    fields = [c for c in (filename_c, path_c, mime_c, size_c) if c]
                    mapped = {fields[i]: rest[i] for i in range(min(len(fields), len(rest)))}
                    fname = str(mapped.get(filename_c) or mapped.get(path_c) or f"attachment-{rid}")
                    fname = fname.replace("\\", "/").rsplit("/", 1)[-1] or fname
                    mime = str(mapped.get(mime_c) or "—")
                    size = mapped.get(size_c) or 0
                    # Resolve matching media file in the job when possible.
                    media_id = _resolve_media_artifact_id(db, job_id, fname) if "." in fname else None
                    preview = (
                        f"SMS / MMS / iMessage attachment\n"
                        f"Filename: {fname}\n"
                        f"MIME: {mime}\n"
                        f"Size: {size}\n"
                        f"Source DB:\n{path}\n"
                    )
                    if media_id:
                        preview += f"\nLinked media artifact id: {media_id}"
                    out.append(
                        {
                            "id": _virtual_id("smsatt", f"{row.get('id')}|{rid}|{fname}"),
                            "job_id": job_id,
                            "parent_artifact_id": str(row.get("id") or "") or None,
                            "artifact_type": "sms_attachment",
                            "axiom_category": "sms attachments",
                            "axiom_category_label": "SMS / MMS Attachments",
                            "title": fname,
                            "source_path": path,
                            "metadata": {
                                "evidence_kind": "sms_attachment",
                                "media_name": fname,
                                "media_artifact_id": media_id,
                                "mime_type": mime,
                                "source_path": path,
                                "source_artifact_id": media_id or str(row.get("id") or "") or None,
                                "preview_body": preview,
                                "body": preview,
                            },
                            "tags": ["sms_attachment", "mms"],
                            "parser_version": "sms_attachment_extract",
                            "created_at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
            finally:
                conn.close()
        except Exception:
            continue
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
    return out


def _table_columns_safe(cur: Any, table: str) -> dict[str, str]:
    try:
        cur.execute(f'PRAGMA table_info("{table}")')
        return {str(r[1]).lower(): str(r[1]) for r in cur.fetchall()}
    except Exception:
        return {}


def _is_app_runtime_junk(path: str, name: str) -> bool:
    """APK / DEX / ART / dalvik-cache — never messaging evidence."""
    p = (path or "").replace("\\", "/").lower()
    n = (name or "").lower()
    if any(
        n.endswith(ext)
        for ext in (
            ".apk",
            ".odex",
            ".vdex",
            ".art",
            ".prof",
            ".dex",
            ".jar",
            ".so",
            ".oat",
        )
    ):
        return True
    if n.startswith("classes") and ".dex" in n:
        return True
    if ".apk@" in n or "@classes" in n:
        return True
    junk_paths = (
        "/dalvik-cache/",
        "/oat/",
        "/data/app/",
        "/preload/",
        "/app_chrome/",
        "/code_cache/",
    )
    if any(x in p for x in junk_paths):
        return True
    if any(
        x in p
        for x in (
            "facebook.appmanager",
            "facebook-appmanager",
            "facebook-services",
            "facebook-installer",
        )
    ):
        return True
    return False


def _is_social_chat_db(path: str, name: str) -> bool:
    """Plaintext SQLite under app databases/ — not WAL/SHM/journal sidecars."""
    if _is_app_runtime_junk(path, name):
        return False
    p = (path or "").replace("\\", "/").lower()
    n = (name or "").lower()
    if n.endswith(("-wal", "-shm", "-journal")):
        return False
    if not (n.endswith(".db") or n.endswith(".sqlite") or n.endswith(".sqlite3") or ".db-" in n):
        return False
    if "/databases/" in p or "/db/" in p:
        return True
    known = (
        "msys_database",
        "threads_db",
        "messages.db",
        "msg_store",
        "cache4.db",
        "db_sqlite",
        "signal.db",
        "sms.db",
        "mmssms.db",
    )
    return any(k in n for k in known)


def _chat_app_message_rows(
    db: Session,
    job_id: str,
    *,
    app: str,
    path_markers: tuple[str, ...],
    label: str,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List messaging DBs + live-extracted chat rows (never APK/DEX/ART junk)."""
    like_clauses = " OR ".join(
        [f"file_path ILIKE :m{i}" for i in range(len(path_markers))]
        + [f"file_name ILIKE :m{i}" for i in range(len(path_markers))]
    )
    params: dict[str, Any] = {"j": job_id}
    for i, marker in enumerate(path_markers):
        params[f"m{i}"] = f"%{marker}%"
    files = fetchall(
        db,
        f"""SELECT id, file_path, file_name, extension, size_bytes, created_at, metadata,
                  encyclopedia_artifact_id, minio_uri
           FROM job_artifacts
           WHERE job_id=:j AND ({like_clauses})
             AND (
               lower(replace(file_path, '\\', '/')) LIKE '%/databases/%'
               OR lower(replace(file_path, '\\', '/')) LIKE '%/db/%'
               OR lower(file_name) LIKE '%.db'
               OR lower(file_name) LIKE '%.sqlite%'
             )
             AND lower(file_name) NOT LIKE '%.apk%'
             AND lower(file_name) NOT LIKE '%.dex%'
             AND lower(file_name) NOT LIKE '%.art'
             AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/dalvik-cache/%'
             AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/preload/%'
             AND lower(replace(file_path, '\\', '/')) NOT LIKE '%/data/app/%'
           ORDER BY size_bytes DESC NULLS LAST
           LIMIT 200""",
        params,
    )
    stores: list[dict[str, Any]] = []
    store_raw: list[dict[str, Any]] = []
    for row in files:
        path = str(row.get("file_path") or "")
        name = str(row.get("file_name") or "")
        if not _is_social_chat_db(path, name):
            continue
        store_raw.append(dict(row))
        meta = row.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        meta = {
            **meta,
            "evidence_kind": f"{app}_store",
            "preview_body": (
                f"{label} chat database (SQLite)\n"
                f"Path: {row.get('file_path')}\n"
                f"Size: {row.get('size_bytes') or 0} bytes\n"
                "Message rows appear above when plaintext chat text can be extracted.\n"
                "App packages (APK/DEX/ART) are excluded from this view."
            ),
        }
        stores.append({
            "id": str(row["id"]),
            "job_id": job_id,
            "file_id": None,
            "parent_artifact_id": None,
            "artifact_type": f"{app}_store",
            "axiom_category": row.get("encyclopedia_artifact_id") or app,
            "axiom_category_label": label,
            "axiom_sub_category": None,
            "title": row.get("file_name") or row.get("file_path"),
            "source_path": row.get("file_path"),
            "artifact_datetime": None,
            "preview_uri": None,
            "storage_uri": row.get("minio_uri"),
            "size_bytes": row.get("size_bytes"),
            "file_name": row.get("file_name"),
            "metadata": meta,
            "tags": [app, "chat_db"],
            "examiner_comment": None,
            "parser_version": None,
            "confidence": None,
            "created_at": (
                row["created_at"].isoformat()
                if hasattr(row.get("created_at"), "isoformat")
                else str(row.get("created_at") or "")
            ),
        })

    messages: list[dict[str, Any]] = []
    from app.services.artifact_preview import resolve_artifact_bytes
    from app.services.chat_message_extract import extract_chat_messages_from_bytes

    extract_cap = max(int(offset or 0) + int(limit or 400), 20)
    seen: set[str] = set()
    for row in sorted(store_raw, key=lambda r: int(r.get("size_bytes") or 0), reverse=True)[:5]:
        path = str(row.get("file_path") or "")
        try:
            data = resolve_artifact_bytes(
                db, job_id, row, persist=False, max_bytes=80 * 1024 * 1024
            )
        except Exception:
            continue
        if not data or not data[:16].startswith(b"SQLite format"):
            continue
        try:
            records = extract_chat_messages_from_bytes(data, path, limit=extract_cap)
        except Exception:
            continue
        for idx, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            body = rec.get("text_body") or rec.get("body") or ""
            if not body or not _looks_like_chat_body(str(body)):
                continue
            from app.services.artifact_group_browse import enrich_message_record

            rec = enrich_message_record({**rec, "social_app": rec.get("social_app") or app})
            sender = str(rec.get("sender") or rec.get("from") or "unknown")
            conversation = str(rec.get("conversation") or rec.get("chat") or "").strip()
            conversation_id = str(rec.get("conversation_id") or "").strip() or None
            chat_jid = str(rec.get("chat_jid") or "").strip() or None
            is_group = bool(rec.get("is_group"))
            ts = rec.get("timestamp") or rec.get("date")
            title = (
                f"{conversation} · {sender}: {str(body)[:100]}"
                if conversation
                else f"{sender}: {str(body)[:120]}"
            )
            key = f"{conversation_id or conversation}|{sender}|{str(body)[:160]}|{ts}"
            if key in seen:
                continue
            seen.add(key)
            vid = _virtual_id(app[:6], f"{row.get('id')}|{conversation_id or ''}|{idx}|{title[:80]}")
            messages.append({
                "id": vid,
                "job_id": job_id,
                "file_id": None,
                "parent_artifact_id": str(row.get("id") or "") or None,
                "artifact_type": f"{app}_message",
                "axiom_category": f"{app} messages",
                "axiom_category_label": f"{label} Messages",
                "axiom_sub_category": conversation or sender,
                "title": title,
                "source_path": path,
                "artifact_datetime": str(ts) if ts else None,
                "preview_uri": None,
                "storage_uri": None,
                "metadata": {
                    "evidence_kind": "chat_message",
                    "social_app": app,
                    "sender": sender,
                    "conversation": conversation,
                    "conversation_id": conversation_id,
                    "chat_jid": chat_jid,
                    "is_group": is_group,
                    "body": str(body)[:8000],
                    "timestamp": str(ts) if ts else None,
                    "source_path": path,
                    "source_artifact_id": str(row.get("id") or "") or None,
                    "preview_body": (
                        f"App: {label}\n"
                        f"Conversation: {conversation or '—'}\n"
                        f"From: {sender}\n"
                        f"Time: {ts or '—'}\n"
                        f"Message:\n{body}\n\n"
                        f"Source DB:\n{path}"
                    ),
                },
                "tags": [f"{app}_message", "chat_message"],
                "examiner_comment": None,
                "parser_version": "chat_live_extract",
                "confidence": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
            if len(messages) >= extract_cap:
                break
        if len(messages) >= extract_cap:
            break

    if len(messages) < extract_cap and store_raw:
        path_likes = " OR ".join(f"ja.file_path ILIKE :pm{i}" for i in range(len(path_markers)))
        pparams: dict[str, Any] = {"j": job_id}
        for i, marker in enumerate(path_markers):
            pparams[f"pm{i}"] = f"%{marker}%"
        parsed = fetchall(
            db,
            f"""SELECT apr.id, apr.normalized, ja.id AS job_artifact_id, ja.file_path, ja.file_name
               FROM artifact_parse_results apr
               JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
               WHERE ja.job_id=:j
                 AND ({path_likes})
                 AND (
                   lower(replace(ja.file_path, '\\', '/')) LIKE '%/databases/%'
                   OR lower(ja.file_name) LIKE '%.db'
                   OR lower(ja.file_name) LIKE '%.sqlite%'
                 )
                 AND lower(replace(ja.file_path, '\\', '/')) NOT LIKE '%/dalvik-cache/%'
               LIMIT 500""",
            pparams,
        )
        for prow in parsed:
            path = str(prow.get("file_path") or "")
            name = str(prow.get("file_name") or path.rsplit("/", 1)[-1])
            if not _is_social_chat_db(path, name):
                continue
            norm = prow.get("normalized")
            if isinstance(norm, list):
                records = norm
            elif isinstance(norm, dict):
                if norm.get("record_type") or norm.get("text_body") or norm.get("body"):
                    records = [norm]
                else:
                    records = norm.get("messages") or norm.get("entries") or [norm]
            else:
                continue
            for idx, rec in enumerate(records[:2000]):
                if not isinstance(rec, dict):
                    continue
                rtype = str(rec.get("record_type") or "").lower()
                if "summary" in rtype:
                    continue
                body = rec.get("text_body") or rec.get("body") or rec.get("message") or ""
                if not body and isinstance(rec.get("text"), str) and ": " in rec["text"]:
                    if "table" in rec["text"].lower() and "rows" in rec["text"].lower():
                        continue
                    body = rec["text"].split(": ", 1)[-1]
                if not body or not _looks_like_chat_body(str(body)):
                    continue
                from app.services.artifact_group_browse import enrich_message_record

                rec = enrich_message_record({**rec, "social_app": rec.get("social_app") or app})
                sender = str(rec.get("sender") or rec.get("from") or "unknown")
                conversation = str(rec.get("conversation") or rec.get("chat") or "").strip()
                conversation_id = str(rec.get("conversation_id") or "").strip() or None
                chat_jid = str(rec.get("chat_jid") or "").strip() or None
                is_group = bool(rec.get("is_group"))
                ts = rec.get("timestamp") or rec.get("deleted_at") or rec.get("date")
                key = f"{conversation_id or conversation}|{sender}|{str(body)[:160]}|{ts}"
                if key in seen:
                    continue
                seen.add(key)
                title = (
                    f"{conversation} · {sender}: {str(body)[:100]}"
                    if conversation
                    else f"{sender}: {str(body)[:120]}"
                )
                vid = _virtual_id(
                    app[:6], f"{prow.get('job_artifact_id')}|{conversation_id or ''}|{idx}|{title[:80]}"
                )
                messages.append({
                    "id": vid,
                    "job_id": job_id,
                    "file_id": None,
                    "parent_artifact_id": str(prow.get("job_artifact_id") or "") or None,
                    "artifact_type": f"{app}_message",
                    "axiom_category": f"{app} messages",
                    "axiom_category_label": f"{label} Messages",
                    "axiom_sub_category": conversation or sender,
                    "title": title,
                    "source_path": path,
                    "artifact_datetime": str(ts) if ts else None,
                    "preview_uri": None,
                    "storage_uri": None,
                    "metadata": {
                        "evidence_kind": "chat_message",
                        "social_app": app,
                        "sender": sender,
                        "conversation": conversation,
                        "conversation_id": conversation_id,
                        "chat_jid": chat_jid,
                        "is_group": is_group,
                        "body": str(body)[:8000],
                        "timestamp": str(ts) if ts else None,
                        "source_path": path,
                        "source_artifact_id": str(prow.get("job_artifact_id") or "") or None,
                        "preview_body": (
                            f"App: {label}\n"
                            f"Conversation: {conversation or '—'}\n"
                            f"From: {sender}\n"
                            f"Time: {ts or '—'}\n"
                            f"Message:\n{body}\n\n"
                            f"Source DB:\n{path}"
                        ),
                    },
                    "tags": [f"{app}_message", "chat_message"],
                    "examiner_comment": None,
                    "parser_version": "chat_message_extract",
                    "confidence": None,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                })

    return _slice_rows(messages + stores, limit=limit, offset=offset)


def merge_carve_into_file_listing(
    db: Session,
    job_id: str,
    *,
    catalog_key: str,
    file_items: list[dict[str, Any]],
    file_total: int,
    page: int,
    page_size: int,
) -> dict[str, Any] | None:
    """Prepend carved signature hits so AXIOM uplift rows are openable beside allocated files."""
    ax = resolve_catalog_artifact(db, catalog_key)
    if not ax:
        return None
    name = _norm(str(ax.get("artifact_name") or ""))
    if name not in _CARVE_MERGE_NAMES:
        return None
    from app.services.signature_carve_inventory import list_carve_evidence

    carved = list_carve_evidence(
        db, job_id, axiom_name=str(ax.get("artifact_name") or name), page=1, page_size=2_000
    )
    carve_items = list(carved.get("items") or [])
    if not carve_items:
        return None

    page = max(int(page or 1), 1)
    page_size = max(min(int(page_size or 50), 200), 1)
    carve_n = len(carve_items)
    combined_total = carve_n + max(int(file_total), 0)
    start = (page - 1) * page_size
    end = start + page_size

    # Carve rows first (examiner sees recovered hits), then allocated files.
    if end <= carve_n:
        items = carve_items[start:end]
    elif start >= carve_n:
        # Entire page from allocated — file_items already page-sliced by caller at wrong offset.
        # Caller must re-query allocated with adjusted offset when start >= carve_n.
        return {
            "items": file_items,
            "total": combined_total,
            "page": page,
            "page_size": page_size,
            "evidence_domain": "file_plus_carve",
            "evidence_label": str(ax.get("artifact_name") or name),
            "carve_prefix": carve_n,
            "_needs_file_offset": start - carve_n,
        }
    else:
        # Span carve → files
        head = carve_items[start:carve_n]
        need = page_size - len(head)
        items = head + file_items[:need]
        return {
            "items": items,
            "total": combined_total,
            "page": page,
            "page_size": page_size,
            "evidence_domain": "file_plus_carve",
            "evidence_label": str(ax.get("artifact_name") or name),
            "carve_prefix": carve_n,
        }

    return {
        "items": items,
        "total": combined_total,
        "page": page,
        "page_size": page_size,
        "evidence_domain": "file_plus_carve",
        "evidence_label": str(ax.get("artifact_name") or name),
        "carve_prefix": carve_n,
    }


def list_evidence_items(
    db: Session,
    job_id: str,
    *,
    catalog_key: str | None = None,
    artifact_name: str | None = None,
    category: str | None = None,
    page: int = 1,
    page_size: int = 50,
    hard_cap: int = 200,
    sessions_only: bool = False,
    person_id: str | None = None,
) -> dict[str, Any] | None:
    """If this catalog item uses virtual evidence rows, return paginated items; else None.

    ``hard_cap`` limits page_size (default 200 for API; family browse may raise it).
    """
    from app.services.evidence_browse_indexes import ensure_evidence_browse_indexes

    ensure_evidence_browse_indexes(db)

    name = artifact_name
    cat = category
    if catalog_key and not name:
        ax = resolve_catalog_artifact(db, catalog_key)
        if not ax:
            return None
        name = ax.get("artifact_name")
        cat = ax.get("category")
    if not name:
        return None
    whatsapp_family = {
        "whatsapp messages": "whatsapp_messages",
        "whatsapp chats": "whatsapp_chats",
        "whatsapp deleted messages": "whatsapp_deleted_messages",
    }.get(str(name).strip().lower())
    if whatsapp_family:
        from app.services.whatsapp_evidence_browse import list_whatsapp_evidence

        normalized = list_whatsapp_evidence(
            db, job_id, family=whatsapp_family, page=page, page_size=page_size,
            group_by="person" if sessions_only or person_id else None, group_id=person_id,
        )
        if normalized is not None:
            return normalized
    mode = evidence_browse_mode(str(name), str(cat) if cat else None)
    if not mode:
        return None

    if mode == "outlook_message":
        from app.services.pst_mailbox_inventory import list_outlook_message_evidence
        from app.services.signature_carve_inventory import list_carve_evidence

        primary = list_outlook_message_evidence(db, job_id, page=page, page_size=page_size)
        carved = list_carve_evidence(
            db, job_id, axiom_name="outlook emails", page=1, page_size=2_000
        )
        rows = list(primary.get("items") or [])
        seen = {str(r.get("id")) for r in rows}
        for hit in carved.get("items") or []:
            hid = str(hit.get("id") or "")
            if hid and hid not in seen:
                rows.append(hit)
                seen.add(hid)
        total = len(rows)
        page = max(int(page or 1), 1)
        page_size = max(min(int(page_size or 50), 200), 1)
        start = (page - 1) * page_size
        return {
            "items": rows[start : start + page_size],
            "total": total,
            "page": page,
            "page_size": page_size,
            "evidence_domain": "outlook_message",
            "evidence_label": str(name),
        }

    if mode == "carved_signature":
        from app.services.signature_carve_inventory import list_carve_evidence

        return list_carve_evidence(
            db,
            job_id,
            axiom_name=str(name),
            page=page,
            page_size=page_size,
        )

    page = max(int(page or 1), 1)
    cap = max(int(hard_cap or 200), 1)
    page_size = max(min(int(page_size or 50), cap), 1)
    start = (page - 1) * page_size
    paged_at_source = False

    if mode == "url_visit":
        rows = _url_visit_rows(db, job_id, str(name))
    elif mode == "whatsapp_deleted_message":
        rows = _whatsapp_deleted_message_rows(db, job_id, person_id=person_id)
    elif mode == "deleted_social_message":
        rows = _deleted_social_message_rows(db, job_id)
    elif mode == "whatsapp_group":
        rows = _whatsapp_message_rows(
            db,
            job_id,
            sessions_only=sessions_only and not person_id,
            person_id=person_id,
            groups_only=True,
            limit=page_size,
            offset=start,
        )
        total = _whatsapp_message_total(
            db,
            job_id,
            sessions_only=sessions_only and not person_id,
            person_id=person_id,
            groups_only=True,
        )
        paged_at_source = True
    elif mode == "whatsapp_message":
        rows = _whatsapp_message_rows(
            db,
            job_id,
            sessions_only=sessions_only and not person_id,
            person_id=person_id,
            limit=page_size,
            offset=start,
        )
        total = _whatsapp_message_total(
            db,
            job_id,
            sessions_only=sessions_only and not person_id,
            person_id=person_id,
        )
        paged_at_source = True
    elif mode == "contact":
        rows = _contact_rows(db, job_id)
    elif mode == "usb_device":
        rows = _usb_device_rows(db, job_id)
    elif mode == "phone_device":
        rows = _phone_device_rows(db, job_id)
    elif mode == "rdp_connection":
        rows = _rdp_connection_rows(db, job_id)
    elif mode == "email_attachment":
        rows = _email_attachment_file_rows(db, job_id)
    elif mode == "sms_attachment":
        rows = _sms_attachment_rows(db, job_id)
    elif mode == "sms_message":
        rows = _chat_app_message_rows(
            db,
            job_id,
            app="sms",
            path_markers=("mmssms", "sms.db", "imessage", "chat.db", "/sms/"),
            label="SMS / iMessage",
            limit=page_size,
            offset=start,
        )
        paged_at_source = True
        total = start + len(rows) + (page_size if len(rows) >= page_size else 0)
    elif mode == "chat_message":
        n = _norm(str(name))
        app = "chat"
        markers = (n.split()[0],)
        label = str(name)
        for cand, m, lab in (
            ("telegram", ("telegram", "org.telegram"), "Telegram"),
            ("signal", ("signal", "org.thoughtcrime", "securesms"), "Signal"),
            ("linkedin", ("linkedin", "com.linkedin"), "LinkedIn"),
            (
                "facebook",
                (
                    "com.facebook.orca",
                    "com.facebook.katana",
                    "com.facebook.mlite",
                    "com.facebook.messaging",
                    "threads_db",
                    "msys_database",
                ),
                "Facebook / Messenger",
            ),
            (
                "messenger",
                (
                    "com.facebook.orca",
                    "com.facebook.messaging",
                    "threads_db",
                    "msys_database",
                ),
                "Facebook / Messenger",
            ),
            ("instagram", ("com.instagram.android", "instagram"), "Instagram"),
            ("snapchat", ("snapchat",), "Snapchat"),
            ("discord", ("discord",), "Discord"),
            ("viber", ("viber",), "Viber"),
            ("wechat", ("wechat", "weixin"), "WeChat"),
            ("skype", ("skype",), "Skype"),
            ("slack", ("slack",), "Slack"),
            ("teams", ("teams", "com.microsoft.teams"), "Microsoft Teams"),
        ):
            if cand in n:
                app = "facebook" if cand == "messenger" else cand
                markers = m
                label = lab
                break
        rows = _chat_app_message_rows(
            db,
            job_id,
            app=app,
            path_markers=markers,
            label=label,
            limit=page_size,
            offset=start,
        )
        paged_at_source = True
        total = start + len(rows) + (page_size if len(rows) >= page_size else 0)
    else:
        return None

    if not paged_at_source:
        total = len(rows)
        rows = rows[start : start + page_size]
    return {
        "items": rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "evidence_domain": mode,
        "evidence_label": str(name),
    }
