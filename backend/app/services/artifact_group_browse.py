"""Group chat evidence by person/group and media by album/folder.

Board Open for messaging families returns person/group summaries first (cross-app
when available). Selecting one returns a chronological thread with filters:
all | current | deleted | media | calls. Media families use album → files.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

_CHAT_FAMILIES = frozenset({
    "whatsapp_messages",
    "whatsapp_chats",
    "whatsapp_deleted_messages",
    "sms",
    "sms_chats",
    "telegram",
    "telegram_deleted",
    "signal",
    "signal_deleted",
    "instagram",
    "instagram_deleted",
    "facebook",
    "facebook_deleted",
    "linkedin",
    "deleted_social",
    "deleted_chat_residuals",
})

_MEDIA_FAMILIES = frozenset({
    "pictures",
    "videos",
    "audio",
    "documents",
    "whatsapp_media",
    "deleted_photos",
    "deleted_videos",
    "deleted_documents",
    "deleted_files",
    "deleted_with_dates",
})

# Evidence names pulled together for person/group cross-app browse.
_PERSON_LIVE_EVIDENCE_NAMES = (
    "WhatsApp Messages",
    "SMS Messages",
    "Telegram",
    "Signal",
    "Instagram",
    "Facebook Messenger",
    "LinkedIn",
)

_PERSON_DELETED_EVIDENCE_NAMES = (
    "WhatsApp Deleted Messages",
    "Deleted Social / Chat Data",
    "Deleted Chat Residuals",
)

# Legacy alias — live + deleted (prefer person_browse_evidence_names_for_family).
_PERSON_BROWSE_EVIDENCE_NAMES = _PERSON_LIVE_EVIDENCE_NAMES + _PERSON_DELETED_EVIDENCE_NAMES

# App-specific deleted boards must not pull live WhatsApp/SMS/etc. on Open.
_APP_DELETED_FAMILIES = frozenset({
    "whatsapp_deleted_messages",
    "telegram_deleted",
    "signal_deleted",
    "instagram_deleted",
    "facebook_deleted",
    "snapchat_deleted",
    "discord_deleted",
    "viber_deleted",
    "wechat_deleted",
})

_DEVICE_OWNER_ALIASES = frozenset({
    "device owner",
    "me",
    "you",
    "owner",
    "self",
    "local user",
})

_MEDIA_HINT = re.compile(
    r"\[(image|video|audio|media|pdf|document|sticker|gif|voice|ptt)\]|\.(jpe?g|png|gif|webp|heic|mp4|mov|pdf|opus|m4a)\b",
    re.I,
)
_CALL_HINT = re.compile(r"\b(call|voice call|video call|missed call|voip)\b", re.I)


def family_supports_conversation_groups(family: str) -> bool:
    return (family or "").strip().lower() in _CHAT_FAMILIES


def family_supports_album_groups(family: str) -> bool:
    return (family or "").strip().lower() in _MEDIA_FAMILIES


def family_supports_person_groups(family: str) -> bool:
    return family_supports_conversation_groups(family)


def person_browse_evidence_names() -> tuple[str, ...]:
    return _PERSON_BROWSE_EVIDENCE_NAMES


def person_browse_evidence_names_for_family(family: str) -> tuple[str, ...]:
    """Sibling evidence to merge for person/group identity.

    WhatsApp Messages merges only WhatsApp Deleted Messages (so each contact can
    show a live row + ``Name [deleted]``) without pulling SMS/Telegram.
    App-specific deleted boards merge live WhatsApp Messages the same way.
    Deleted-social boards merge other deleted sources only.
    """
    key = (family or "").strip().lower()
    if not key:
        return _PERSON_LIVE_EVIDENCE_NAMES
    if key in {"whatsapp_messages", "whatsapp_chats", "whatsapp_groups"}:
        # Pull WA deleted residuals so Open can show Name + Name [deleted].
        return ("WhatsApp Deleted Messages",)
    if key == "whatsapp_deleted_messages":
        # Already deleted-only; split_deleted labels each contact as Name [deleted].
        return ()
    if key in _APP_DELETED_FAMILIES:
        return ()
    if key in {"deleted_social", "deleted_chat_residuals"}:
        return _PERSON_DELETED_EVIDENCE_NAMES
    if key.endswith("_deleted") or "deleted_messages" in key:
        return ()
    return _PERSON_LIVE_EVIDENCE_NAMES


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _meta(row: dict[str, Any]) -> dict[str, Any]:
    meta = row.get("metadata") or {}
    return meta if isinstance(meta, dict) else {}


def _normalize_label(label: str) -> str:
    s = (label or "").strip().lower()
    s = re.sub(r"\(group\)|\(deleted\)|\(recovered\)", "", s)
    s = re.sub(r"\s*\[deleted\]\s*", " ", s, flags=re.I)
    s = s.replace("–", "-").replace("—", "-").replace("−", "-")
    s = re.sub(r"[@+]?", "", s)
    s = re.sub(r"[^\w\s.+-]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Collapse phone-like digits for matching.
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 8 and digits in re.sub(r"\D", "", label or ""):
        return digits[-12:]
    return s


def _looks_like_wa_jid(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v or "@" not in v:
        return False
    return any(
        v.endswith(suf)
        for suf in (
            "@s.whatsapp.net",
            "@g.us",
            "@lid",
            "@broadcast",
            "@newsletter",
        )
    ) or bool(re.match(r"^\d+@lid$", v))


_DELETED_PERSON_SUFFIX = "::deleted"


def _split_person_bucket_id(person_id: str) -> tuple[str, bool]:
    """Return (base_person_id, is_deleted_bucket)."""
    want = (person_id or "").strip()
    if want.endswith(_DELETED_PERSON_SUFFIX):
        return want[: -len(_DELETED_PERSON_SUFFIX)], True
    return want, False


def _person_bucket_id(base_pid: str, *, deleted: bool, split_deleted: bool) -> str:
    if split_deleted and deleted:
        return f"{base_pid}{_DELETED_PERSON_SUFFIX}"
    return base_pid


def family_splits_deleted_persons(family: str) -> bool:
    """WhatsApp (and WA-deleted) boards show live vs Name [deleted] as separate rows."""
    key = (family or "").strip().lower()
    return key in {
        "whatsapp_messages",
        "whatsapp_chats",
        "whatsapp_deleted_messages",
        "whatsapp_groups",
    } or key.startswith("whatsapp")


def _app_label(meta: dict[str, Any], row: dict[str, Any] | None = None) -> str:
    app = str(meta.get("social_app") or meta.get("application") or "").strip().lower()
    if not app:
        kind = str(meta.get("evidence_kind") or (row or {}).get("artifact_type") or "").lower()
        if "whatsapp" in kind:
            app = "whatsapp"
        elif "sms" in kind or "imessage" in kind:
            app = "sms"
        elif "telegram" in kind:
            app = "telegram"
        elif "signal" in kind:
            app = "signal"
        elif "instagram" in kind:
            app = "instagram"
        elif "facebook" in kind or "messenger" in kind:
            app = "facebook"
        elif "linkedin" in kind:
            app = "linkedin"
        else:
            app = "chat"
    pretty = {
        "whatsapp": "WhatsApp",
        "sms": "SMS",
        "imessage": "SMS",
        "telegram": "Telegram",
        "signal": "Signal",
        "instagram": "Instagram",
        "facebook": "Facebook",
        "messenger": "Facebook",
        "linkedin": "LinkedIn",
        "chat": "Chat",
    }
    return pretty.get(app, app.title())


def _is_message_row(row: dict[str, Any]) -> bool:
    meta = _meta(row)
    kind = str(meta.get("evidence_kind") or row.get("artifact_type") or "").lower()
    if kind in {
        "whatsapp_store",
        "sms_store",
        "notice",
        "conversation",
        "person",
        "group",
        "album",
    }:
        return False
    if kind.endswith("_store"):
        return False
    return True


def _is_deleted_row(row: dict[str, Any]) -> bool:
    meta = _meta(row)
    tags = [str(t).lower() for t in (row.get("tags") or [])]
    if meta.get("is_deleted") or meta.get("deleted_at"):
        return True
    if "deleted" in tags:
        return True
    recovery = meta.get("recovery") if isinstance(meta.get("recovery"), dict) else {}
    state = str(meta.get("recovery_state") or recovery.get("state") or "").lower()
    if state and state not in {"live", "current", ""}:
        return True
    kind = str(meta.get("evidence_kind") or "").lower()
    return "deleted" in kind or "residual" in kind


def _is_media_row(row: dict[str, Any]) -> bool:
    meta = _meta(row)
    if meta.get("media_name") or meta.get("media_artifact_id") or meta.get("thumbnail_base64"):
        return True
    mtype = str(meta.get("message_type") or "").lower()
    if mtype in {"image", "video", "audio", "document", "sticker", "gif", "ptt", "media"}:
        return True
    try:
        if int(meta.get("message_type") or 0) in {1, 2, 3, 8, 9, 13, 15, 20}:
            return True
    except (TypeError, ValueError):
        pass
    body = str(meta.get("body") or row.get("title") or "")
    return bool(_MEDIA_HINT.search(body))


def _is_call_row(row: dict[str, Any]) -> bool:
    meta = _meta(row)
    kind = str(meta.get("evidence_kind") or row.get("artifact_type") or "").lower()
    mtype = str(meta.get("message_type") or "").lower()
    if "call" in kind or "call" in mtype:
        return True
    body = str(meta.get("body") or row.get("title") or "")
    return bool(_CALL_HINT.search(body))


def _recovery_classification(recovery_state: str, *, deleted: bool, confidence: Any) -> str:
    state = (recovery_state or "").lower()
    if not deleted and not state:
        return "CURRENT"
    if "wal" in state:
        return "WAL_RECOVERED"
    if "freelist" in state:
        return "FREELIST_RECOVERED"
    if "historical" in state or "history" in state:
        return "HISTORICAL"
    if "fragment" in state or "residual" in state:
        return "FRAGMENT"
    if deleted:
        conf = str(confidence or "").lower()
        if "low" in conf or "medium" in conf:
            return "FRAGMENT"
        return "RECOVERED"
    return "CURRENT"


def _conv_key_from_row(row: dict[str, Any]) -> tuple[str, str, bool]:
    """Return (conversation_id, label, is_group) for a virtual message row."""
    meta = _meta(row)
    cid = str(meta.get("conversation_id") or "").strip()
    label = str(
        meta.get("conversation")
        or row.get("axiom_sub_category")
        or meta.get("sender")
        or "Unknown conversation"
    ).strip() or "Unknown conversation"
    jid = str(meta.get("chat_jid") or meta.get("remote_jid") or "").lower()
    is_group = bool(meta.get("is_group")) or jid.endswith("@g.us") or "(group)" in label.lower()
    if not cid:
        app = str(meta.get("social_app") or meta.get("evidence_kind") or "chat")
        digest = hashlib.sha1(f"{app}|{label.lower()}".encode("utf-8", errors="ignore")).hexdigest()[:16]
        cid = f"label:{digest}"
    return cid, label, is_group


def _person_key_from_row(row: dict[str, Any]) -> tuple[str, str, bool]:
    """Return (person_or_group_id, display_name, is_group).

    Groups stay conversation-scoped. 1:1 chats collapse to a person identity.
    For WhatsApp, prefer normalized contact/title so live ChatStorage rows and
    freelist residuals for the same person merge (chat-row ids are often missing
    on deleted residuals).
    """
    cid, label, is_group = _conv_key_from_row(row)
    meta = _meta(row)
    if is_group:
        gid = cid if cid.startswith("group:") else f"group:{cid}"
        return gid, label, True

    jid = str(meta.get("chat_jid") or meta.get("remote_jid") or "").strip().lower()
    peer = label
    sender = str(meta.get("sender") or "").strip()
    from_me = bool(meta.get("from_me"))
    if from_me or _normalize_label(sender) in _DEVICE_OWNER_ALIASES:
        peer = label
    elif sender and _normalize_label(sender) not in _DEVICE_OWNER_ALIASES:
        if not peer or peer.lower() in {"unknown", "unknown conversation", "chat"}:
            peer = sender

    app = str(meta.get("social_app") or meta.get("application") or "").lower()
    kind = str(meta.get("evidence_kind") or row.get("artifact_type") or "").lower()
    is_wa = "whatsapp" in app or "whatsapp" in kind

    # WhatsApp 1:1: name-first identity so live + deleted residuals align.
    # Use the same canonical name namespace as SMS/Telegram/Signal so an
    # examiner sees one person across apps when the recovered display identity
    # is the same.  App-specific conversation ids remain available in metadata.
    if is_wa:
        norm = _normalize_label(peer)
        if (
            norm
            and norm not in {"unknown", "unknown conversation", "chat", "me", "you", "status"}
            and not re.match(r"^chat[-_]?\d+$", norm)
            and not _looks_like_wa_jid(peer)
        ):
            digest = hashlib.sha1(f"person|{norm}".encode("utf-8", errors="ignore")).hexdigest()[:16]
            return f"person:{digest}", peer or label or "Unknown person", False

    # WhatsApp chat-row ids when name is missing.
    if cid.startswith("whatsapp:") or cid.startswith("whatsapp-ios:"):
        digest = hashlib.sha1(f"wa-chat|{cid}".encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"person:{digest}", peer or label or "Unknown person", False

    if _looks_like_wa_jid(jid) and not jid.endswith("@g.us"):
        digest = hashlib.sha1(f"jid|{jid}".encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"person:{digest}", peer or jid.split("@", 1)[0], False

    norm = _normalize_label(peer)
    digits = re.sub(r"\D", "", peer or "")
    if len(digits) >= 10:
        digest = hashlib.sha1(f"phone|{digits[-12:]}".encode("utf-8", errors="ignore")).hexdigest()[:16]
        return f"person:{digest}", peer or "Unknown person", False
    if not norm:
        norm = _normalize_label(cid) or "unknown"
    digest = hashlib.sha1(f"person|{norm}".encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"person:{digest}", peer or "Unknown person", False


def enrich_chat_row(row: dict[str, Any]) -> dict[str, Any]:
    """Attach application, recovery, provenance, and person/group ids for UI."""
    out = dict(row)
    meta = dict(_meta(row))
    pid, pname, is_group = _person_key_from_row(out)
    cid, clabel, _ = _conv_key_from_row(out)
    deleted = _is_deleted_row(out)
    from_me = bool(meta.get("from_me"))
    sender = str(meta.get("sender") or "unknown").strip() or "unknown"
    if from_me or _normalize_label(sender) in _DEVICE_OWNER_ALIASES:
        display = "Device Owner"
        sender_id = "PERSON-DEVICE-OWNER"
    else:
        display = sender
        sender_id = f"PERSON-{hashlib.sha1(_normalize_label(sender).encode()).hexdigest()[:10].upper()}"

    recovery_state = str(meta.get("recovery_state") or "").strip()
    if deleted and not recovery_state:
        recovery_state = "recovered"
    conf = out.get("confidence") if out.get("confidence") is not None else meta.get("confidence")
    classification = _recovery_classification(recovery_state, deleted=deleted, confidence=conf)
    conf_label = str(conf or ("high" if classification in {"CURRENT", "WAL_RECOVERED", "HISTORICAL"} else "medium"))
    if isinstance(conf, (int, float)):
        conf_label = "high" if conf >= 0.75 else "medium" if conf >= 0.4 else "low"

    app = _app_label(meta, out)
    # Stable per-message forensic record hash for the chat transcript UI.  This is
    # deliberately derived from immutable message/provenance fields rather than the
    # rendered title so the same evidence row keeps the same SHA-256 across views.
    record_hash = str(meta.get("record_hash_sha256") or "").strip()
    if not record_hash:
        hash_material = "\x1f".join(
            [
                str(meta.get("conversation_id") or cid or ""),
                str(meta.get("message_row_id") or meta.get("row_id") or meta.get("index") or out.get("id") or ""),
                str(meta.get("timestamp") or out.get("artifact_datetime") or ""),
                str(meta.get("sender") or ""),
                str(meta.get("original_content") or meta.get("body") or ""),
                str(meta.get("source_path") or out.get("source_path") or ""),
                str(meta.get("source_offset") or meta.get("offset") or ""),
            ]
        )
        record_hash = hashlib.sha256(hash_material.encode("utf-8", errors="ignore")).hexdigest()

    meta.update(
        {
            "application": app,
            "social_app": meta.get("social_app") or app.lower(),
            "person_id": pid,
            "base_person_id": pid,
            "person_name": pname,
            "conversation_id": cid,
            "conversation": meta.get("conversation") or clabel,
            "conversation_type": "group" if is_group else "direct",
            "is_group": is_group,
            "sender_display_name": display,
            "sender_identity_id": sender_id,
            "is_deleted": deleted,
            "is_current": not deleted,
            "message_type": meta.get("message_type")
            or ("media" if _is_media_row(out) else "call" if _is_call_row(out) else "text"),
            "recovery_state": recovery_state or None,
            "record_hash_sha256": record_hash,
            "recovery": {
                "state": recovery_state or ("current" if not deleted else "recovered"),
                "is_current": not deleted,
                "source": recovery_state or ("live_database" if not deleted else "recovered"),
                "confidence": str(conf_label).lower(),
                "classification": classification,
            },
            "provenance": {
                "source_file": meta.get("source_path") or out.get("source_path"),
                "source_offset": meta.get("source_offset") or meta.get("offset"),
                "parser": out.get("parser_version") or meta.get("parser"),
                "evidence_id": meta.get("source_artifact_id") or out.get("parent_artifact_id"),
                "record_hash_sha256": record_hash,
            },
        }
    )
    # Richer deleted preview when classification is available.
    # Keep carve/pipeline previews that already explain recovery (don't wipe attachments).
    existing_preview = str(meta.get("preview_body") or "")
    rich_deleted_preview = (
        existing_preview.startswith("WhatsApp Chat:")
        or existing_preview.startswith("Recovery:")
        or "RECOVERED / DELETED" in existing_preview
        or "Original content:" in existing_preview
    )
    # Surface recovered media/text when body was cleared by revoke.
    if deleted:
        body_now = str(meta.get("body") or "").strip()
        oc = str(meta.get("original_content") or "").strip()
        media_name = str(meta.get("media_name") or meta.get("media_filename") or "").strip()
        if (not body_now or body_now.startswith("🚫")) and oc:
            meta["body"] = oc[:8000]
            body_now = oc
        elif (not body_now or body_now.startswith("🚫")) and media_name:
            mtype = str(meta.get("message_type") or "ATTACHMENT").upper()
            if mtype.isdigit():
                mtype = "ATTACHMENT"
            label = {
                "1": "IMAGE",
                "2": "VIDEO",
                "3": "AUDIO",
                "8": "DOCUMENT",
                "IMAGE": "IMAGE",
                "VIDEO": "VIDEO",
                "AUDIO": "AUDIO",
                "DOCUMENT": "DOCUMENT",
            }.get(mtype, "ATTACHMENT")
            meta["body"] = f"[{label}] {media_name}"
            body_now = meta["body"]
        if not rich_deleted_preview:
            meta["preview_body"] = (
                f"{'GROUP' if is_group else 'PERSON'}: {pname}\n"
                f"Application: {app}\n"
                f"Time: {meta.get('timestamp') or out.get('artifact_datetime') or '—'}\n"
                f"From: {display}\n"
                f"Message:\n{body_now[:500] or '—'}\n\n"
                f"Recovery: {str(recovery_state or 'recovered').replace('_', ' ')}\n"
                f"Classification: {classification}\n"
                f"Confidence: {str(conf_label).title()}\n"
                f"Source:\n{meta.get('source_path') or out.get('source_path') or '—'}\n"
            )
            if media_name:
                meta["preview_body"] += f"\nAttachment: {media_name}\n"
                if meta.get("media_artifact_id"):
                    meta["preview_body"] += "Linked media: available (Open / Download)\n"
    out["metadata"] = meta
    tags = list(out.get("tags") or [])
    if deleted and "deleted" not in [str(t).lower() for t in tags]:
        tags.append("deleted")
    if is_group and "group" not in [str(t).lower() for t in tags]:
        tags.append("group")
    out["tags"] = tags
    return out


def filter_rows_by_message_filter(rows: list[dict[str, Any]], message_filter: str | None) -> list[dict[str, Any]]:
    mf = (message_filter or "all").strip().lower()
    if mf in {"", "all", "all_chats", "everything"}:
        return rows
    out: list[dict[str, Any]] = []
    for row in rows:
        if not _is_message_row(row):
            continue
        deleted = _is_deleted_row(row)
        if mf in {"current", "live", "active"}:
            if not deleted:
                out.append(row)
        elif mf in {"deleted", "recovered", "deleted_recovered", "deleted/recovered"}:
            if deleted:
                out.append(row)
        elif mf in {"media", "attachments"}:
            if _is_media_row(row):
                out.append(row)
        elif mf in {"calls", "call"}:
            if _is_call_row(row):
                out.append(row)
        else:
            out.append(row)
    return out


def group_message_rows_as_conversations(rows: list[dict[str, Any]], *, job_id: str) -> list[dict[str, Any]]:
    """Collapse flat message rows into conversation summary artifacts."""
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not _is_message_row(row):
            continue
        cid, label, is_group = _conv_key_from_row(row)
        meta = _meta(row)
        body = str(meta.get("original_content") or meta.get("body") or "")[:180]
        ts = str(row.get("artifact_datetime") or meta.get("timestamp") or "") or None
        deleted = _is_deleted_row(row)
        bucket = buckets.get(cid)
        if not bucket:
            buckets[cid] = {
                "id": f"ev-conv-{hashlib.sha1(cid.encode()).hexdigest()[:20]}",
                "job_id": job_id,
                "file_id": None,
                "parent_artifact_id": row.get("parent_artifact_id"),
                "artifact_type": "conversation",
                "axiom_category": "conversation",
                "axiom_category_label": "Conversations",
                "axiom_sub_category": "group" if is_group else "person",
                "title": label,
                "source_path": row.get("source_path"),
                "artifact_datetime": ts,
                "preview_uri": None,
                "storage_uri": None,
                "metadata": {
                    "evidence_kind": "conversation",
                    "conversation_id": cid,
                    "conversation": label,
                    "is_group": is_group,
                    "message_count": 1,
                    "deleted_count": 1 if deleted else 0,
                    "last_message": body,
                    "last_timestamp": ts,
                    "chat_jid": meta.get("chat_jid") or meta.get("remote_jid"),
                    "social_app": meta.get("social_app"),
                    "application": _app_label(meta, row),
                    "source_path": row.get("source_path"),
                    "source_artifact_id": meta.get("source_artifact_id"),
                    "preview_body": (
                        f"Conversation: {label}\n"
                        f"Type: {'Group' if is_group else 'Person / 1:1'}\n"
                        f"Messages: 1\n"
                        f"Last: {body or '—'}\n"
                        f"Time: {ts or '—'}\n"
                    ),
                },
                "tags": ["conversation", "group" if is_group else "person"],
                "examiner_comment": None,
                "parser_version": "conversation_group",
                "confidence": None,
                "created_at": _iso_now(),
            }
            continue
        m = bucket["metadata"]
        m["message_count"] = int(m.get("message_count") or 0) + 1
        if deleted:
            m["deleted_count"] = int(m.get("deleted_count") or 0) + 1
        prev_ts = str(m.get("last_timestamp") or "")
        if ts and (not prev_ts or ts > prev_ts):
            m["last_timestamp"] = ts
            m["last_message"] = body
            bucket["artifact_datetime"] = ts
        m["preview_body"] = (
            f"Conversation: {label}\n"
            f"Type: {'Group' if is_group else 'Person / 1:1'}\n"
            f"Messages: {m['message_count']:,}\n"
            f"Deleted/recovered: {int(m.get('deleted_count') or 0):,}\n"
            f"Last: {m.get('last_message') or '—'}\n"
            f"Time: {m.get('last_timestamp') or '—'}\n"
        )

    out = list(buckets.values())
    out.sort(
        key=lambda r: (
            str((r.get("metadata") or {}).get("last_timestamp") or ""),
            int((r.get("metadata") or {}).get("message_count") or 0),
        ),
        reverse=True,
    )
    return out


def group_message_rows_as_persons(
    rows: list[dict[str, Any]],
    *,
    job_id: str,
    split_deleted: bool = False,
) -> list[dict[str, Any]]:
    """Collapse messages into PERSON / GROUP identity summaries (cross-app).

    When ``split_deleted`` is True (WhatsApp), each contact becomes up to two rows:
    ``Name`` (live/current) and ``Name [deleted]`` (recovered/deleted only).
    """
    buckets: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not _is_message_row(raw):
            continue
        row = enrich_chat_row(raw)
        base_pid, label, is_group = _person_key_from_row(row)
        meta = _meta(row)
        body = str(meta.get("original_content") or meta.get("body") or "")[:180]
        body_l = body.lower()
        # Drop FTS schema / protobuf stanza noise from the Names "last message" line.
        if (
            "create virtual" in body_l
            or "create table" in body_l
            or "fts4" in body_l
            or "wa_tokenizer" in body_l
            or (
                ("@g.us" in body or "@s.whatsapp.net" in body or "@lid" in body)
                and " " not in body[:24]
                and len(body) > 40
                and not body.startswith("[")
                and not body.startswith("🚫")
            )
        ):
            media = str(meta.get("media_name") or "").strip()
            if media:
                body = f"[ATTACHMENT] {media}"[:180]
            elif body.startswith("🚫") or "deleted this message" in body_l:
                body = "Message deleted"
            else:
                body = ""
        ts = str(row.get("artifact_datetime") or meta.get("timestamp") or "") or None
        deleted = _is_deleted_row(row)
        app = str(meta.get("application") or _app_label(meta, row))
        sender = str(meta.get("sender_display_name") or meta.get("sender") or "")
        bucket_id = _person_bucket_id(base_pid, deleted=deleted, split_deleted=split_deleted)
        deleted_bucket = split_deleted and deleted
        display = f"{label} [deleted]" if deleted_bucket else label
        bucket = buckets.get(bucket_id)
        if not bucket:
            apps = {app}
            participants = {sender} if sender and sender != "Device Owner" else set()
            if sender == "Device Owner":
                participants.add("Device Owner")
            tags = ["group" if is_group else "person", "conversation"]
            if deleted_bucket:
                tags.append("deleted")
            buckets[bucket_id] = {
                "id": (
                    f"ev-{'group' if is_group else 'person'}-"
                    f"{hashlib.sha1(bucket_id.encode()).hexdigest()[:20]}"
                ),
                "job_id": job_id,
                "file_id": None,
                "parent_artifact_id": row.get("parent_artifact_id"),
                "artifact_type": "group" if is_group else "person",
                "axiom_category": "group" if is_group else "person",
                "axiom_category_label": "Groups" if is_group else "People",
                "axiom_sub_category": "group" if is_group else "person",
                "title": display,
                "source_path": row.get("source_path"),
                "artifact_datetime": ts,
                "preview_uri": None,
                "storage_uri": None,
                "metadata": {
                    "evidence_kind": "group" if is_group else "person",
                    "person_id": bucket_id,
                    "base_person_id": base_pid,
                    "person_name": display,
                    "person_name_base": label,
                    "deleted_bucket": deleted_bucket,
                    "is_deleted": deleted_bucket,
                    "conversation_id": meta.get("conversation_id"),
                    "conversation": meta.get("conversation") or label,
                    "is_group": is_group,
                    "message_count": 1,
                    "current_count": 0 if deleted else 1,
                    "deleted_count": 1 if deleted else 0,
                    "media_count": 1 if _is_media_row(row) else 0,
                    "call_count": 1 if _is_call_row(row) else 0,
                    "fragment_count": 1
                    if str((meta.get("recovery") or {}).get("classification") or "") == "FRAGMENT"
                    else 0,
                    "applications": sorted(apps),
                    "participants": sorted(participants),
                    "participant_count": len(participants),
                    "last_message": body,
                    "last_timestamp": ts,
                    "last_application": app,
                    "chat_jid": meta.get("chat_jid") or meta.get("remote_jid"),
                    "preview_body": "",
                },
                "tags": tags,
                "examiner_comment": None,
                "parser_version": "person_group",
                "confidence": None,
                "created_at": _iso_now(),
            }
            m = buckets[bucket_id]["metadata"]
            m["preview_body"] = _person_preview_body(m, display, is_group)
            continue

        m = bucket["metadata"]
        m["message_count"] = int(m.get("message_count") or 0) + 1
        if deleted:
            m["deleted_count"] = int(m.get("deleted_count") or 0) + 1
        else:
            m["current_count"] = int(m.get("current_count") or 0) + 1
        if _is_media_row(row):
            m["media_count"] = int(m.get("media_count") or 0) + 1
        if _is_call_row(row):
            m["call_count"] = int(m.get("call_count") or 0) + 1
        if str((meta.get("recovery") or {}).get("classification") or "") == "FRAGMENT":
            m["fragment_count"] = int(m.get("fragment_count") or 0) + 1
        apps = set(m.get("applications") or [])
        apps.add(app)
        m["applications"] = sorted(apps)
        parts = set(m.get("participants") or [])
        if sender:
            parts.add(sender)
        m["participants"] = sorted(parts)
        m["participant_count"] = len(parts)
        prev_ts = str(m.get("last_timestamp") or "")
        if ts and (not prev_ts or ts > prev_ts):
            m["last_timestamp"] = ts
            m["last_message"] = body
            m["last_application"] = app
            bucket["artifact_datetime"] = ts
        m["preview_body"] = _person_preview_body(m, display, is_group)

    out = list(buckets.values())
    out.sort(
        key=lambda r: (
            str((r.get("metadata") or {}).get("person_name_base") or r.get("title") or "").lower(),
            1 if (r.get("metadata") or {}).get("deleted_bucket") else 0,
            str((r.get("metadata") or {}).get("last_timestamp") or ""),
        ),
    )
    # Sort contacts A→Z but keep live before [deleted] for the same name; within
    # that, newest activity first for different contacts — re-sort by activity:
    out.sort(
        key=lambda r: (
            str((r.get("metadata") or {}).get("last_timestamp") or ""),
            int((r.get("metadata") or {}).get("message_count") or 0),
        ),
        reverse=True,
    )
    return out


def _person_preview_body(m: dict[str, Any], label: str, is_group: bool) -> str:
    apps = ", ".join(m.get("applications") or []) or "—"
    if is_group:
        return (
            f"GROUP: {label}\n"
            f"Applications: {apps}\n"
            f"Participants: {int(m.get('participant_count') or 0):,}\n"
            f"Messages: {int(m.get('message_count') or 0):,}\n"
            f"Current: {int(m.get('current_count') or 0):,}\n"
            f"Deleted/Recovered: {int(m.get('deleted_count') or 0):,}\n"
            f"Last: {m.get('last_message') or '—'}\n"
            f"Time: {m.get('last_timestamp') or '—'}\n"
        )
    return (
        f"PERSON: {label}\n"
        f"Applications: {apps}\n"
        f"Total artifacts: {int(m.get('message_count') or 0):,}\n"
        f"Current: {int(m.get('current_count') or 0):,}\n"
        f"Deleted/Recovered: {int(m.get('deleted_count') or 0):,}\n"
        f"Fragments: {int(m.get('fragment_count') or 0):,}\n"
        f"Last ({m.get('last_application') or '—'}): {m.get('last_message') or '—'}\n"
        f"Time: {m.get('last_timestamp') or '—'}\n"
    )


def filter_rows_for_conversation(rows: list[dict[str, Any]], conversation_id: str) -> list[dict[str, Any]]:
    """Keep message rows for one conversation; chronological oldest→newest."""
    want = (conversation_id or "").strip()
    if not want:
        return []
    kept: list[dict[str, Any]] = []
    for row in rows:
        if not _is_message_row(row):
            continue
        cid, _, _ = _conv_key_from_row(row)
        if cid == want:
            kept.append(enrich_chat_row(row))
    kept.sort(
        key=lambda r: str(
            r.get("artifact_datetime")
            or (r.get("metadata") or {}).get("timestamp")
            or ""
        )
    )
    return kept


def filter_rows_for_person(
    rows: list[dict[str, Any]],
    person_id: str,
    *,
    message_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Keep message rows for one person/group; apply tab filter; oldest→newest.

    ``person_id`` may end with ``::deleted`` for the WhatsApp ``Name [deleted]`` bucket.
    Never returns person/group summary rows.
    """
    want = (person_id or "").strip()
    if not want:
        return []
    base_id, deleted_bucket = _split_person_bucket_id(want)
    mf = (message_filter or "").strip().lower() or None

    # Bucket defaults: live/contact row → all messages; [deleted] row → deleted only.
    if not mf:
        mf = "deleted" if deleted_bucket else "all"
    elif mf == "all" and deleted_bucket:
        mf = "deleted"

    kept: list[dict[str, Any]] = []
    for row in rows:
        if not _is_message_row(row):
            continue
        # Defensive: summary rows must never appear inside a thread.
        kind = str((_meta(row).get("evidence_kind") or row.get("artifact_type") or "")).lower()
        if kind in {"person", "group", "conversation", "album", "notice"}:
            continue
        enriched = enrich_chat_row(row)
        pid, pname, _ = _person_key_from_row(enriched)
        meta = _meta(enriched)
        # Prefer explicit ids stamped during grouping / prior enrich.
        stamped = str(meta.get("base_person_id") or meta.get("person_id") or "").strip()
        stamped_base, _ = _split_person_bucket_id(stamped) if stamped else ("", False)
        if pid != base_id and stamped_base != base_id:
            continue
        if deleted_bucket and not _is_deleted_row(enriched):
            continue
        kept.append(enriched)

    kept = filter_rows_by_message_filter(kept, mf)
    kept.sort(
        key=lambda r: str(
            r.get("artifact_datetime")
            or (r.get("metadata") or {}).get("timestamp")
            or ""
        )
    )
    return kept


def build_thread_summary(rows: list[dict[str, Any]], *, person_id: str | None = None) -> dict[str, Any]:
    """Stats + participants for the person/group thread header."""
    if not rows and person_id:
        is_group = person_id.startswith("group:")
        return {
            "person_id": person_id,
            "is_group": is_group,
            "message_count": 0,
            "current_count": 0,
            "deleted_count": 0,
            "media_count": 0,
            "call_count": 0,
            "fragment_count": 0,
            "applications": [],
            "participants": [],
            "participant_count": 0,
        }
    label = ""
    is_group = False
    pid = person_id or ""
    apps: set[str] = set()
    participants: set[str] = set()
    current = deleted = media = calls = fragments = 0
    for row in rows:
        meta = _meta(row)
        if not pid:
            pid = str(meta.get("person_id") or "")
        if not label:
            label = str(meta.get("person_name") or meta.get("conversation") or row.get("title") or "")
        is_group = is_group or bool(meta.get("is_group"))
        apps.add(str(meta.get("application") or _app_label(meta, row)))
        sender = str(meta.get("sender_display_name") or meta.get("sender") or "").strip()
        if sender:
            participants.add(sender)
        if _is_deleted_row(row):
            deleted += 1
            if str((meta.get("recovery") or {}).get("classification") or "") == "FRAGMENT":
                fragments += 1
        else:
            current += 1
        if _is_media_row(row):
            media += 1
        if _is_call_row(row):
            calls += 1
    return {
        "person_id": pid,
        "person_name": label,
        "is_group": is_group,
        "message_count": len(rows),
        "current_count": current,
        "deleted_count": deleted,
        "media_count": media,
        "call_count": calls,
        "fragment_count": fragments,
        "applications": sorted(apps),
        "participants": sorted(participants),
        "participant_count": len(participants),
    }


def _album_key_from_path(path: str, *, family: str) -> tuple[str, str]:
    """Return (album_id, album_label) from a file path."""
    p = unquote((path or "").replace("\\", "/")).strip("/")
    if not p:
        return "album:unknown", "Unknown album"
    parts = [x for x in p.split("/") if x]
    low_parts = [x.lower() for x in parts]
    label_parts: list[str] = []
    for i, part in enumerate(parts):
        lp = low_parts[i]
        if lp in {
            "whatsapp images",
            "whatsapp video",
            "whatsapp audio",
            "whatsapp documents",
            "whatsapp animated gifs",
            "whatsapp voice notes",
            "whatsapp stickers",
            "media",
            "dcim",
            "camera",
            "pictures",
            "movies",
            "videos",
            "audio",
            "download",
            "downloads",
            "documents",
            ".trashed",
            "trash",
            "deleted_recovery",
        } or "whatsapp" in lp and "media" in lp:
            label_parts = parts[i : min(i + 2, len(parts) - 1)]
            break
    if not label_parts:
        label_parts = parts[-2:-1] if len(parts) >= 2 else parts[-1:]
    label = " / ".join(label_parts) if label_parts else "Files"
    parent = "/".join(parts[:-1]) if len(parts) > 1 else parts[0]
    if "/readable_artifacts/" in parent.lower():
        parent = "readable_artifacts/" + parent.lower().split("/readable_artifacts/", 1)[-1]
    digest = hashlib.sha1(f"{family}|{parent.lower()}".encode()).hexdigest()[:16]
    return f"album:{digest}", label


def group_file_rows_as_albums(rows: list[dict[str, Any]], *, job_id: str, family: str) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = str(row.get("source_path") or row.get("file_name") or row.get("title") or "")
        album_id, label = _album_key_from_path(path, family=family)
        size = int(row.get("size_bytes") or 0)
        ts = str(row.get("artifact_datetime") or "") or None
        bucket = buckets.get(album_id)
        if not bucket:
            buckets[album_id] = {
                "id": f"ev-album-{album_id.split(':', 1)[-1]}",
                "job_id": job_id,
                "file_id": None,
                "parent_artifact_id": None,
                "artifact_type": "album",
                "axiom_category": family,
                "axiom_category_label": "Albums",
                "axiom_sub_category": family,
                "title": label,
                "source_path": "/".join(path.replace("\\", "/").split("/")[:-1]) or path,
                "artifact_datetime": ts,
                "preview_uri": None,
                "storage_uri": None,
                "metadata": {
                    "evidence_kind": "album",
                    "album_id": album_id,
                    "album": label,
                    "file_count": 1,
                    "total_bytes": size,
                    "family": family,
                    "preview_body": (
                        f"Album / folder: {label}\n"
                        f"Files: 1\n"
                        f"Size: {size:,} bytes\n"
                        f"Family: {family}\n"
                    ),
                },
                "tags": ["album", family],
                "examiner_comment": None,
                "parser_version": "album_group",
                "confidence": None,
                "created_at": _iso_now(),
                "size_bytes": size,
            }
            continue
        m = bucket["metadata"]
        m["file_count"] = int(m.get("file_count") or 0) + 1
        m["total_bytes"] = int(m.get("total_bytes") or 0) + size
        bucket["size_bytes"] = m["total_bytes"]
        m["preview_body"] = (
            f"Album / folder: {label}\n"
            f"Files: {m['file_count']:,}\n"
            f"Size: {int(m['total_bytes']):,} bytes\n"
            f"Family: {family}\n"
        )
    out = list(buckets.values())
    out.sort(key=lambda r: int((r.get("metadata") or {}).get("file_count") or 0), reverse=True)
    return out


def filter_rows_for_album(rows: list[dict[str, Any]], album_id: str, *, family: str) -> list[dict[str, Any]]:
    want = (album_id or "").strip()
    if not want:
        return []
    kept = []
    for row in rows:
        path = str(row.get("source_path") or row.get("file_name") or "")
        aid, _ = _album_key_from_path(path, family=family)
        if aid == want:
            kept.append(row)
    kept.sort(key=lambda r: str(r.get("source_path") or r.get("title") or "").lower())
    return kept


def enrich_message_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Ensure conversation_id / chat_jid / is_group on extract records."""
    out = dict(rec)
    conversation = str(out.get("conversation") or out.get("chat") or "").strip()
    chat_jid = str(out.get("chat_jid") or out.get("remote_jid") or out.get("key_remote_jid") or "").strip()
    chat_row_id = out.get("chat_row_id") or out.get("conversation_row_id")
    social = str(out.get("social_app") or "chat")
    if out.get("conversation_id"):
        cid = str(out["conversation_id"])
    elif chat_row_id not in (None, "", 0, "0"):
        cid = f"{social}:{chat_row_id}"
    elif chat_jid:
        cid = f"{social}-jid:{chat_jid.lower()}"
    elif conversation:
        digest = hashlib.sha1(f"{social}|{conversation.lower()}".encode()).hexdigest()[:16]
        cid = f"label:{digest}"
    else:
        sender = str(out.get("sender") or "unknown")
        digest = hashlib.sha1(f"{social}|{sender.lower()}".encode()).hexdigest()[:16]
        cid = f"label:{digest}"
    is_group = bool(out.get("is_group")) or chat_jid.lower().endswith("@g.us") or "(group)" in conversation.lower()
    out["conversation_id"] = cid
    out["chat_jid"] = chat_jid or None
    out["is_group"] = is_group
    if conversation:
        out["conversation"] = conversation
    return out


def resolve_group_mode(family: str | None, group_by: str | None) -> str | None:
    """Return person | conversation | album | None (flat). Default person for chat families."""
    fam = (family or "").strip().lower()
    gb = (group_by or "").strip().lower()
    if gb in {"flat", "none", "off", "0", "false"}:
        return None
    if gb in {"person", "people", "contact", "contacts", "identity"}:
        return "person" if family_supports_person_groups(fam) else None
    if gb in {"conversation", "conversations", "chat", "thread"}:
        return "conversation" if family_supports_conversation_groups(fam) else None
    if gb in {"album", "albums", "folder", "folders"}:
        return "album" if family_supports_album_groups(fam) else None
    if not gb:
        if family_supports_person_groups(fam):
            return "person"
        if family_supports_album_groups(fam):
            return "album"
    return None


def apply_family_grouping(
    rows: list[dict[str, Any]],
    *,
    job_id: str,
    family: str,
    group_by: str | None = None,
    group_id: str | None = None,
    message_filter: str | None = None,
) -> tuple[list[dict[str, Any]], str | None, dict[str, Any] | None]:
    """
    Collapse rows into person/conversation/album summaries, or filter to one group.

    Returns (rows, active_mode, thread_summary).
    When group_id is set, returns the flat items inside that group (not summaries).
    """
    mode = resolve_group_mode(family, group_by)
    gid = (group_id or "").strip()
    split_deleted = family_splits_deleted_persons(family)
    if not mode:
        return rows, None, None
    if mode == "person":
        if gid:
            # Live WhatsApp contact row defaults to current; [deleted] to deleted.
            eff = message_filter
            if split_deleted and not (eff or "").strip():
                _, deleted_bucket = _split_person_bucket_id(gid)
                eff = "deleted" if deleted_bucket else "all"
            thread = filter_rows_for_person(rows, gid, message_filter=eff)
            # Summary over unfiltered person rows for tab badges.
            all_for_person = filter_rows_for_person(rows, gid, message_filter="all")
            summary = build_thread_summary(all_for_person, person_id=gid)
            return thread, "person", summary
        return (
            group_message_rows_as_persons(
                rows, job_id=job_id, split_deleted=split_deleted
            ),
            "person",
            None,
        )
    if mode == "conversation":
        if gid:
            thread = filter_rows_for_conversation(rows, gid)
            thread = filter_rows_by_message_filter(thread, message_filter)
            summary = build_thread_summary(
                filter_rows_for_conversation(rows, gid),
                person_id=None,
            )
            return thread, "conversation", summary
        return group_message_rows_as_conversations(rows, job_id=job_id), "conversation", None
    if mode == "album":
        if gid:
            return filter_rows_for_album(rows, gid, family=family), "album", None
        return group_file_rows_as_albums(rows, job_id=job_id, family=family), "album", None
    return rows, None, None
