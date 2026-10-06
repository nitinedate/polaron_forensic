"""WhatsApp Android msgstore — modern schema (2.21+) resolver with deleted recovery (V45).

Why this exists
---------------
``messaging.WhatsAppParser._parse_messages`` probes column names generically.
On the modern schema that silently degrades:

  * ``chat_row_id`` / ``sender_jid_row_id`` are integers — they were emitted as
    the conversation/sender instead of being resolved through ``chat -> jid``;
  * media moved to ``message_media`` (file_path, mime_type, file_length, …),
    so every message reported ``media_path = NULL``;
  * there is no ``is_deleted``/``revoke_timestamp`` column — "Delete for
    everyone" is ``message.message_type = 15`` plus a ``message_revoked`` row,
    so the deleted count was always 0.

What AXIOM shows for deleted WhatsApp content and where it really comes from:

  1. revoked rows (type 15 / message_revoked)                 -> flagged here
  2. text of a revoked/deleted message that someone *replied to* survives in
     ``message_quoted.text_data``                               -> recovered here
  3. text frequently survives in the FTS index content table
     (``message_ftsv2_content.c0`` keyed by docid = message._id,
     legacy ``messages_fts_content``)                           -> recovered here
  4. rows physically deleted ("Delete for me") live only in SQLite freelist /
     WAL pages -> ``mobile_acquire.sqlite_deleted.recover_sqlite_residuals``
     must run on the *decrypted* bytes (see messaging.py patch).

Everything yields ``NormalizedArtifact`` so the artifact UI / counts / report
pick it up unchanged.
"""

from __future__ import annotations

import sqlite3
import hashlib
from typing import Any, Iterator

from app.services.mobile_forensic.models import Confidence, InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import (
    column_name_map,
    epoch_to_iso,
    iter_query,
    table_names,
)
from app.services.mobile_forensic.plugins import ParseContext

PARSER_NAME = "whatsapp_parser"
PARSER_VERSION = "3.1.0-residual-candidates"

# message.message_type values (WhatsApp Android). Unknown codes are kept as type_<n>.
MESSAGE_TYPE_LABELS: dict[int, str] = {
    0: "text",
    1: "image",
    2: "audio",
    3: "video",
    4: "contact_vcard",
    5: "location",
    7: "system",
    8: "call",
    9: "document",
    10: "missed_call",
    11: "waiting_for_message",
    13: "gif",
    14: "deleted_contact",
    15: "revoked",          # "Deleted for everyone"
    16: "live_location",
    20: "sticker",
    23: "product",
    24: "group_invite",
    25: "product_catalog",
    26: "order",
    27: "payment",
    28: "payment_invite",
    30: "catalog",
    32: "status_text",
    37: "reaction",
    42: "view_once_image",
    43: "view_once_video",
    46: "poll_update",
    48: "keep_in_chat",
    64: "sticker_pack",
    66: "poll",
    68: "comment",
    82: "event",
    90: "edited_message",
}

REVOKED_TYPE = 15


def _q(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _scalar(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return {"binary_length": len(value), "hex_prefix": value[:24].hex()}
    return str(value)


def is_modern_msgstore(conn: sqlite3.Connection) -> bool:
    t = {n.lower() for n in table_names(conn)}
    if "message" not in t or "jid" not in t:
        return False
    cols = column_name_map(conn, "message")
    return "chat_row_id" in cols and "sender_jid_row_id" in cols


def _jid_display(jid_row: dict[str, Any] | None) -> dict[str, Any]:
    if not jid_row:
        return {"jid": None, "phone": None, "jid_type": None}
    raw = jid_row.get("raw_string") or ""
    user = jid_row.get("user") or (raw.split("@", 1)[0] if raw else None)
    server = jid_row.get("server") or (raw.split("@", 1)[1] if "@" in raw else None)
    jtype = {
        "s.whatsapp.net": "contact",
        "g.us": "group",
        "broadcast": "broadcast",
        "status": "status",
        "lid": "linked_identity",
        "newsletter": "channel",
    }.get(server or "", server)
    phone = user if user and user.isdigit() and server in ("s.whatsapp.net", None) else None
    return {"jid": raw or None, "phone": phone, "jid_type": jtype}


def _load_jids(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    cols = column_name_map(conn, "jid")
    sel = ", ".join(_q(c) for c in ("_id", "user", "server", "raw_string", "type") if c in cols)
    for r in iter_query(conn, f"SELECT {sel} FROM jid"):
        try:
            out[int(r["_id"])] = dict(r)
        except Exception:
            continue
    return out


def _load_chats(conn: sqlite3.Connection, jids: dict[int, dict[str, Any]]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    if "chat" not in {n.lower() for n in table_names(conn)}:
        return out
    cols = column_name_map(conn, "chat")
    wanted = ("_id", "jid_row_id", "subject", "created_timestamp", "archived", "hidden",
              "last_message_row_id", "unseen_message_count", "ephemeral_expiration")
    sel = ", ".join(_q(c) for c in wanted if c in cols)
    for r in iter_query(conn, f"SELECT {sel} FROM chat"):
        try:
            cid = int(r["_id"])
        except Exception:
            continue
        jid = jids.get(int(r.get("jid_row_id") or -1))
        info = _jid_display(jid)
        out[cid] = {
            "chat_row_id": cid,
            "subject": r.get("subject"),
            "created_timestamp": epoch_to_iso(r.get("created_timestamp")),
            "archived": r.get("archived"),
            "hidden": r.get("hidden"),
            **info,
            "display": r.get("subject") or info["jid"],
        }
    return out


def _load_media(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    if "message_media" not in {n.lower() for n in table_names(conn)}:
        return out
    cols = column_name_map(conn, "message_media")
    wanted = ("message_row_id", "file_path", "file_size", "file_length", "mime_type", "media_name",
              "media_caption", "media_duration", "file_hash", "enc_file_hash", "width", "height",
              "direct_path", "message_url", "media_key_timestamp")
    sel = ", ".join(_q(c) for c in wanted if c in cols)
    for r in iter_query(conn, f"SELECT {sel} FROM message_media"):
        try:
            out[int(r["message_row_id"])] = {k: _scalar(v) for k, v in r.items()}
        except Exception:
            continue
    return out


def _load_revoked(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    if "message_revoked" not in {n.lower() for n in table_names(conn)}:
        return out
    cols = column_name_map(conn, "message_revoked")
    sel = ", ".join(_q(c) for c in ("message_row_id", "revoked_key_id", "admin_jid_row_id") if c in cols)
    for r in iter_query(conn, f"SELECT {sel} FROM message_revoked"):
        try:
            out[int(r["message_row_id"])] = dict(r)
        except Exception:
            continue
    return out


def _load_quoted_text(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """key_id -> original text captured in a reply (survives revoke/delete)."""
    out: dict[str, dict[str, Any]] = {}
    if "message_quoted" not in {n.lower() for n in table_names(conn)}:
        return out
    cols = column_name_map(conn, "message_quoted")
    if "key_id" not in cols:
        return out
    wanted = ("message_row_id", "key_id", "text_data", "timestamp", "from_me", "sender_jid_row_id", "message_type")
    sel = ", ".join(_q(c) for c in wanted if c in cols)
    for r in iter_query(conn, f"SELECT {sel} FROM message_quoted"):
        kid = r.get("key_id")
        if not kid:
            continue
        txt = r.get("text_data")
        if txt and kid not in out:
            out[str(kid)] = {k: _scalar(v) for k, v in r.items()}
    return out


def _load_fts_text(conn: sqlite3.Connection) -> dict[int, str]:
    """docid (= message._id) -> text from the FTS shadow table."""
    out: dict[int, str] = {}
    names = {n.lower(): n for n in table_names(conn)}
    for cand in ("message_ftsv2_content", "message_fts_content", "messages_fts_content"):
        real = names.get(cand)
        if not real:
            continue
        cols = column_name_map(conn, real)
        text_col = cols.get("c0") or cols.get("c1")
        if not text_col or "docid" not in cols:
            continue
        for r in iter_query(conn, f"SELECT docid, {_q(text_col)} AS t FROM {_q(real)} WHERE {_q(text_col)} IS NOT NULL"):
            try:
                out[int(r["docid"])] = str(r["t"])
            except Exception:
                continue
        if out:
            break
    return out


def _load_edits(conn: sqlite3.Connection) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    if "message_edit_info" not in {n.lower() for n in table_names(conn)}:
        return out
    cols = column_name_map(conn, "message_edit_info")
    sel = ", ".join(_q(c) for c in ("message_row_id", "original_key_id", "edited_timestamp", "sender_timestamp") if c in cols)
    for r in iter_query(conn, f"SELECT {sel} FROM message_edit_info"):
        try:
            out[int(r["message_row_id"])] = dict(r)
        except Exception:
            continue
    return out


def _deleted_chat_jobs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    if "deleted_chat_job" not in {n.lower() for n in table_names(conn)}:
        return []
    return [dict(r) for r in iter_query(conn, "SELECT * FROM deleted_chat_job")]


def iter_modern_whatsapp(
    conn: sqlite3.Connection,
    item: InventoryItem,
    context: ParseContext,
    *,
    default_state: str,
    recovery_source: str,
) -> Iterator[NormalizedArtifact]:
    jids = _load_jids(conn)
    chats = _load_chats(conn, jids)
    media = _load_media(conn)
    revoked = _load_revoked(conn)
    quoted = _load_quoted_text(conn)
    fts = _load_fts_text(conn)
    edits = _load_edits(conn)
    chat_ids_present = set(chats)

    cols = column_name_map(conn, "message")
    wanted = ("_id", "chat_row_id", "from_me", "key_id", "sender_jid_row_id", "status", "timestamp",
              "received_timestamp", "receipt_server_timestamp", "message_type", "text_data", "starred",
              "origination_flags", "origin", "broadcast", "recipient_count", "message_add_on_flags")
    sel = ", ".join(_q(c) for c in wanted if c in cols)

    yielded_chats = 0
    for cid, chat in chats.items():
        yielded_chats += 1
        yield NormalizedArtifact.create(
            artifact_type="app_conversation",
            source_domain="messaging_apps",
            data={"application": "whatsapp", "artifact_family": "whatsapp_chats", **chat},
            timestamp_utc=chat.get("created_timestamp"),
            state=default_state,  # type: ignore[arg-type]
            recovery_source=recovery_source,
            source_path=item.path,
            source_table="chat",
            source_row_id=str(cid),
            source_sha256=item.sha256,
            parser=PARSER_NAME,
            parser_version=PARSER_VERSION,
            job_id=context.job_id,
            source_id=context.source_id,
        )

    for r in iter_query(conn, f"SELECT {sel} FROM message"):
        try:
            row_id = int(r["_id"])
        except Exception:
            continue
        cid = r.get("chat_row_id")
        try:
            cid = int(cid) if cid is not None else None
        except Exception:
            cid = None
        chat = chats.get(cid) if cid is not None else None
        sender = _jid_display(jids.get(int(r.get("sender_jid_row_id") or -1)))
        mtype = r.get("message_type")
        try:
            mtype_i = int(mtype) if mtype is not None else None
        except Exception:
            mtype_i = None
        type_label = MESSAGE_TYPE_LABELS.get(mtype_i, f"type_{mtype_i}") if mtype_i is not None else None

        body = _scalar(r.get("text_data"))
        is_revoked = mtype_i == REVOKED_TYPE or row_id in revoked
        chat_gone = cid is not None and cid not in chat_ids_present and bool(chats)
        recovered_from: list[str] = []
        key_id = str(r.get("key_id") or "")

        # Deleted-text recovery (AXIOM-style): quoted copy, then FTS shadow table.
        if not body and key_id and key_id in quoted:
            body = quoted[key_id].get("text_data")
            recovered_from.append("message_quoted")
        if not body and row_id in fts:
            body = fts[row_id]
            recovered_from.append("fts_content")

        if is_revoked:
            state = "database_deleted"
            rec_source = "revoked_for_everyone"
        elif chat_gone:
            state = "database_deleted"
            rec_source = "chat_deleted_orphan_message"
        else:
            state = default_state
            rec_source = recovery_source

        m = media.get(row_id) or {}
        edit = edits.get(row_id)
        data = {
            "application": "whatsapp",
            "artifact_family": "whatsapp_messages",
            "message_id": key_id or str(row_id),
            "conversation_id": chat.get("jid") if chat else (str(cid) if cid is not None else None),
            "conversation_name": chat.get("display") if chat else None,
            "conversation_type": chat.get("jid_type") if chat else None,
            "chat_row_id": cid,
            "sender": sender["jid"] if not r.get("from_me") else "me",
            "sender_phone": sender["phone"] if not r.get("from_me") else None,
            "from_me": _scalar(r.get("from_me")),
            "direction": "outgoing" if r.get("from_me") else "incoming",
            "body": body,
            "status": _scalar(r.get("status")),
            "message_type": mtype_i,
            "message_type_label": type_label,
            "starred": _scalar(r.get("starred")),
            "received_timestamp": epoch_to_iso(r.get("received_timestamp")),
            "server_receipt_timestamp": epoch_to_iso(r.get("receipt_server_timestamp")),
            "deleted_flag": 1 if (is_revoked or chat_gone) else 0,
            "revoked": is_revoked,
            "revoked_by_jid": _jid_display(jids.get(int((revoked.get(row_id) or {}).get("admin_jid_row_id") or -1)))["jid"]
            if row_id in revoked else None,
            "edited": bool(edit),
            "edited_timestamp": epoch_to_iso(edit.get("edited_timestamp")) if edit else None,
            "recovered_text_sources": recovered_from,
            "media_name": m.get("media_name"),
            "media_path": m.get("file_path"),
            "media_mime": m.get("mime_type"),
            "media_size": m.get("file_length") or m.get("file_size"),
            "media_caption": m.get("media_caption"),
            "media_duration": m.get("media_duration"),
            "media_hash": m.get("file_hash"),
            "media_width": m.get("width"),
            "media_height": m.get("height"),
            "has_attachment": bool(m.get("file_path") or m.get("media_name")),
        }
        conf = Confidence(
            label="HIGH" if not recovered_from else "MEDIUM",
            score=0.95 if not recovered_from else 0.75,
            validation=["modern_schema_join"] + [f"recovered:{s}" for s in recovered_from],
        )
        yield NormalizedArtifact.create(
            artifact_type="app_message",
            source_domain="messaging_apps",
            data=data,
            timestamp_utc=epoch_to_iso(r.get("timestamp")),
            state=state,  # type: ignore[arg-type]
            recovery_source=rec_source,
            source_path=item.path,
            source_table="message",
            source_row_id=str(row_id),
            source_sha256=item.sha256,
            parser=PARSER_NAME,
            parser_version=PARSER_VERSION,
            confidence=conf,
            job_id=context.job_id,
            source_id=context.source_id,
        )

    # Deleted whole-chat jobs (chat removed by the user; remnants may still be in freelist).
    for r in _deleted_chat_jobs(conn):
        yield NormalizedArtifact.create(
            artifact_type="app_conversation",
            source_domain="messaging_apps",
            data={
                "application": "whatsapp",
                "artifact_family": "whatsapp_chats",
                "deleted_chat_job": {k: _scalar(v) for k, v in r.items()},
                "note": "Chat deletion recorded by WhatsApp; message bodies may survive in SQLite freelist/WAL.",
            },
            state="database_deleted",  # type: ignore[arg-type]
            recovery_source="deleted_chat_job",
            source_path=item.path,
            source_table="deleted_chat_job",
            source_row_id=str(r.get("_id") or r.get("chat_row_id") or ""),
            source_sha256=item.sha256,
            parser=PARSER_NAME,
            parser_version=PARSER_VERSION,
            job_id=context.job_id,
            source_id=context.source_id,
        )

    # Calls (modern): call_log + call_log_participant_v2.
    names = {n.lower(): n for n in table_names(conn)}
    if "call_log" in names:
        ccols = column_name_map(conn, names["call_log"])
        wanted_c = ("_id", "jid_row_id", "from_me", "call_id", "timestamp", "video_call", "duration", "call_result", "bytes_transferred", "group_jid_row_id")
        csel = ", ".join(_q(c) for c in wanted_c if c in ccols)
        for r in iter_query(conn, f"SELECT {csel} FROM {_q(names['call_log'])}"):
            peer = _jid_display(jids.get(int(r.get("jid_row_id") or -1)))
            yield NormalizedArtifact.create(
                artifact_type="app_call",
                source_domain="messaging_apps",
                data={
                    "application": "whatsapp",
                    "artifact_family": "whatsapp_calls",
                    "call_id": _scalar(r.get("call_id")),
                    "peer_jid": peer["jid"],
                    "peer_phone": peer["phone"],
                    "direction": "outgoing" if r.get("from_me") else "incoming",
                    "video": bool(r.get("video_call")),
                    "duration_sec": _scalar(r.get("duration")),
                    "call_result": _scalar(r.get("call_result")),
                    "bytes_transferred": _scalar(r.get("bytes_transferred")),
                },
                timestamp_utc=epoch_to_iso(r.get("timestamp")),
                state=default_state,  # type: ignore[arg-type]
                recovery_source=recovery_source,
                source_path=item.path,
                source_table=names["call_log"],
                source_row_id=str(r.get("_id") or ""),
                source_sha256=item.sha256,
                parser=PARSER_NAME,
                parser_version=PARSER_VERSION,
                job_id=context.job_id,
                source_id=context.source_id,
            )


def iter_freelist_residuals(
    decrypted: bytes,
    item: InventoryItem,
    context: ParseContext,
    *,
    companions: dict[str, bytes] | None = None,
) -> Iterator[NormalizedArtifact]:
    """Carve retained free-page text from plaintext, with verifiable offsets."""
    from app.services.mobile_acquire.sqlite_deleted import iter_sqlite_residuals_bytes

    plain_sha256 = hashlib.sha256(decrypted).hexdigest()
    for idx, residual in enumerate(iter_sqlite_residuals_bytes(decrypted, companion_bytes=companions)):
        text = residual["text"]
        yield NormalizedArtifact.create(
            artifact_type="app_message",
            source_domain="messaging_apps",
            data={
                "application": "whatsapp",
                "artifact_family": "whatsapp_messages",
                "body": text,
                "deleted_flag": None,
                "is_deleted_candidate": True,
                "recovery_state": "sqlite_residual_candidate",
                "decrypted_sqlite_sha256": plain_sha256,
                "residual_offset": residual["offset"],
                "residual_byte_length": residual["byte_length"],
                "residual_page_number": residual["page_number"],
                "residual_source_kind": residual["source_kind"],
                "residual_source_component": residual["source_component"],
                "offset_scope": "decrypted_sqlite" if residual["source_component"] == "main" else "sqlite_companion",
                "note": "Unverified residual string carved from decrypted msgstore; a deleted message row and its metadata have not been established.",
            },
            state="freelist_candidate",
            recovery_source="sqlite_freelist_decrypted",
            source_path=item.path,
            source_table="<freelist>",
            source_row_id=f"freelist-{idx}",
            source_sha256=item.sha256,
            parser=PARSER_NAME,
            parser_version=PARSER_VERSION,
            confidence=Confidence(label="LOW", score=0.4, validation=["freelist_carve"]),
            job_id=context.job_id,
            source_id=context.source_id,
            artifact_id=NormalizedArtifact.make_stable_id(
                job_id=context.job_id, artifact_type="app_message", source_path=item.path,
                source_table="<freelist>", source_row_id=f"freelist-{idx}", state="database_deleted",
                data={"application": "whatsapp", "artifact_family": "whatsapp_messages"},
            ),
        )
