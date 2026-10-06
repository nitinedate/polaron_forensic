"""Human-readable chat / SMS extraction from SQLite messaging databases.

Used by the SQLite parser (persist parse results) and artifact preview
(inline readable body) for both mobile and disk jobs.
"""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any

# Default extract size for parsers / browse. Family Open can request up to 5000.
_MSG_LIMIT_DEFAULT = 2000


def _norm_path(path: str) -> str:
    return (path or "").replace("\\", "/").lower()


def infer_social_app(path: str) -> str | None:
    low = _norm_path(path)
    name = PurePosixPath(low).name
    checks = (
        (("whatsapp", "msgstore", "chatstorage", "extchatdatabase", "chatsearch"), "whatsapp"),
        (("telegram", "org.telegram"), "telegram"),
        (("signal", "org.thoughtcrime", "securesms"), "signal"),
        (("instagram", "com.instagram"), "instagram"),
        (("facebook", "messenger", "com.facebook"), "facebook"),
        (("linkedin", "com.linkedin"), "linkedin"),
        (("snapchat",), "snapchat"),
        (("discord",), "discord"),
        (("viber",), "viber"),
        (("wechat", "weixin"), "wechat"),
        (("skype",), "skype"),
        (("slack",), "slack"),
        (("teams", "com.microsoft.teams"), "teams"),
        (("mmssms.db", "/sms.db", "sms.db", "imessage", "chat.db"), "sms"),
    )
    for markers, app in checks:
        if any(m in low or name == m for m in markers):
            return app
    return None


def is_messaging_sqlite(path: str) -> bool:
    return infer_social_app(path) is not None


def _ts_to_iso(value: Any) -> str | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            if s.isdigit():
                value = int(s)
            else:
                return s[:64]
        n = float(value)
        if n > 1e14:  # µs
            n = n / 1_000_000.0
        elif n > 1e11:  # ms
            n = n / 1000.0
        # Apple Core Data / Cocoa absolute time (seconds since 2001-01-01)
        if 0 < n < 1e10 and n < 3_000_000_000:
            # Heuristic: WhatsApp Android often uses unix seconds; iOS Z* uses Cocoa.
            # Prefer unix when year lands in 2008–2100; else try Cocoa.
            dt_unix = datetime.fromtimestamp(n, tz=timezone.utc)
            if 2008 <= dt_unix.year <= 2100:
                return dt_unix.isoformat().replace("+00:00", "Z")
            dt_cocoa = datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=n)
            if 2008 <= dt_cocoa.year <= 2100:
                return dt_cocoa.isoformat().replace("+00:00", "Z")
            return dt_unix.isoformat().replace("+00:00", "Z")
        if n > 3_000_000_000:
            dt = datetime.fromtimestamp(n / 1000.0 if n > 1e12 else n, tz=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None
    return None


def _table_columns(cur: sqlite3.Cursor, table: str) -> dict[str, str]:
    cur.execute(f'PRAGMA table_info("{table}")')
    return {str(r[1]).lower(): str(r[1]) for r in cur.fetchall()}


def _pick(cols: dict[str, str], candidates: tuple[str, ...]) -> str | None:
    for c in candidates:
        if c in cols:
            return cols[c]
    return None


def _extract_from_table(
    cur: sqlite3.Cursor,
    table: str,
    *,
    path: str,
    app: str,
    limit: int,
    record_type: str,
) -> list[dict[str, Any]]:
    cols = _table_columns(cur, table)
    if not cols:
        return []
    text_col = _pick(
        cols,
        (
            "ztext",
            "text_data",  # modern Android WhatsApp msgstore.message
            "text",
            "body",
            "message",
            "data",
            "content",
            "msg",
            "snippet",
            "c0docs_content",  # FTS
            "c0content",
            "message_text",
        ),
    )
    if not text_col:
        return []
    sender_col = _pick(
        cols,
        (
            "zfromjid",
            "sender",
            "from_id",
            "fromid",
            "key_remote_jid",
            "remote_resource",
            "address",
            "handle",
            "chat_id",
            "conversation_id",
            "jid",
            "author",
        ),
    )
    ts_col = _pick(
        cols,
        (
            "zmessagedate",
            "timestamp",
            "time",
            "date",
            "message_timestamp",
            "date_sent",
            "date_received",
            "created_at",
            "sort_id",
        ),
    )
    order = f' ORDER BY "{ts_col}" DESC' if ts_col else ""
    sel = f'SELECT "{text_col}"'
    if sender_col:
        sel += f', "{sender_col}"'
    if ts_col:
        sel += f', "{ts_col}"'
    sel += f' FROM "{table}" WHERE "{text_col}" IS NOT NULL AND length(CAST("{text_col}" AS TEXT)) > 0{order} LIMIT ?'
    try:
        cur.execute(sel, (limit,))
        rows = cur.fetchall()
    except sqlite3.Error:
        return []

    out: list[dict[str, Any]] = []
    for row in rows:
        body = str(row[0] or "").strip()
        if not body or body.startswith("blob") or len(body) < 1:
            continue
        # Skip obvious binary / base64 garbage dumps
        if "\x00" in body:
            continue
        body = body[:4000]
        idx = 1
        sender = "unknown"
        if sender_col:
            sender = str(row[idx] or "unknown").strip() or "unknown"
            idx += 1
        ts = None
        if ts_col:
            ts = _ts_to_iso(row[idx] if len(row) > idx else None)
        label = app.replace("_", " ").title()
        out.append(
            {
                "record_type": record_type,
                "social_app": app,
                "text_body": body,
                "body": body,
                "sender": sender,
                "timestamp": ts,
                "table": table,
                "source": path,
                "text": f"{label} · {sender}: {body[:240]}",
            }
        )
    return out


_WA_TABLES = (
    "ZWAMESSAGE",
    "messages",
    "message",
    "msg",
    "chat_messages",
    "messages_quotes",
    "docs_content",
)
_SMS_TABLES = ("message", "messages", "sms", "pdu", "chat_message")
_GENERIC_TABLES = (
    "messages",
    "message",
    "msg",
    "chat_messages",
    "dialogs",
    "channel_messages",
    "conversation_messages",
)

# Modern Android WhatsApp message_type → examiner label (when no caption).
_WA_TYPE_LABELS = {
    0: None,  # text
    1: "[Image]",
    2: "[Audio]",
    3: "[Video]",
    4: "[Contact]",
    5: "[Location]",
    9: "[Document]",
    13: "[GIF]",
    15: "[Sticker]",
    20: "[Sticker]",
    62: None,  # often long text / template with text_data
}

# Skip system / call plumbing rows that are not conversation content.
_WA_SKIP_TYPES = frozenset({7, 90, 99, 81, 116, 23, 36})


def _format_wa_jid(raw: str | None, user: str | None = None) -> str:
    raw_s = (raw or "").strip()
    if raw_s.endswith("@g.us"):
        return raw_s.split("@", 1)[0] + " (group)"
    if raw_s.endswith("@lid"):
        # Linked-device opaque id — not a dialable phone number.
        return (user or raw_s.split("@", 1)[0] or raw_s)[:24]
    if raw_s.endswith("@s.whatsapp.net") or raw_s.endswith("@c.us"):
        num = raw_s.split("@", 1)[0]
        if num.isdigit() and len(num) >= 10:
            return f"+{num}"
        return num or raw_s
    if user and str(user).isdigit() and 10 <= len(str(user)) <= 15:
        return f"+{user}"
    return raw_s or (user or "")


def extract_chat_sessions_from_connection(
    cur: sqlite3.Cursor,
    path: str,
    *,
    limit: int = 5000,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List chat/person rows only (ZWACHATSESSION / chat) — not every message.

    Used by Artifacts Open so chats appear without extracting 100k messages.
    """
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 400")
        tables = [str(r[0]) for r in cur.fetchall()]
    except sqlite3.Error:
        return []
    lower_map = {t.lower(): t for t in tables}
    ios = _extract_whatsapp_ios_sessions(
        cur, path, tables=lower_map, limit=limit, offset=offset
    )
    if ios:
        return ios
    modern = _extract_whatsapp_modern_sessions(
        cur, path, tables=lower_map, limit=limit, offset=offset
    )
    if modern:
        return modern
    return []


def count_chat_sessions_from_connection(
    cur: sqlite3.Cursor,
    path: str,
    *,
    groups_only: bool = False,
) -> int:
    """COUNT(*) of WhatsApp chat sessions (optional groups-only)."""
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 400")
        tables = [str(r[0]) for r in cur.fetchall()]
    except sqlite3.Error:
        return 0
    lower_map = {t.lower(): t for t in tables}
    chat_t = lower_map.get("zwachatsession") or lower_map.get("zwachat")
    jid_col = None
    if chat_t:
        cols = _table_columns(cur, chat_t)
        jid_col = _pick(cols, ("zcontactjid", "zpartnerjid", "zsessionid"))
    else:
        chat_t = lower_map.get("chat")
        if chat_t:
            cols = _table_columns(cur, chat_t)
            jid_col = _pick(cols, ("jid_row_id",))
    if not chat_t:
        return 0
    where = ""
    if groups_only and jid_col and (lower_map.get("zwachatsession") or lower_map.get("zwachat")):
        where = f' WHERE lower(cast("{jid_col}" as text)) LIKE \'%@g.us\''
    elif groups_only and lower_map.get("jid") and jid_col:
        jid_t = lower_map.get("jid")
        try:
            cur.execute(
                f'SELECT COUNT(*) FROM "{chat_t}" c '
                f'JOIN "{jid_t}" j ON j."_id" = c."{jid_col}" '
                f"WHERE lower(cast(j.\"raw_string\" as text)) LIKE '%@g.us'"
            )
            row = cur.fetchone()
            return int(row[0] or 0) if row else 0
        except sqlite3.Error:
            return 0
    try:
        cur.execute(f'SELECT COUNT(*) FROM "{chat_t}"{where}')
        row = cur.fetchone()
        return int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return 0


def extract_chat_sessions_from_bytes(
    data: bytes,
    path: str,
    *,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    if not data or not data[:16].startswith(b"SQLite format"):
        return []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            return extract_chat_sessions_from_connection(
                conn.cursor(), path, limit=limit or 5000, offset=0
            )
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


def _extract_whatsapp_ios_sessions(
    cur: sqlite3.Cursor,
    path: str,
    *,
    tables: dict[str, str],
    limit: int,
    offset: int = 0,
) -> list[dict[str, Any]]:
    chat_t = tables.get("zwachatsession") or tables.get("zwachat")
    if not chat_t:
        return []
    cols = _table_columns(cur, chat_t)
    pk = _pick(cols, ("z_pk", "rowid")) or "Z_PK"
    name_col = _pick(cols, ("zpartnername", "zcontactname", "zsessionid"))
    jid_col = _pick(cols, ("zcontactjid", "zpartnerjid", "zsessionid"))
    ts_col = _pick(cols, ("zlastmessagedate", "zmessagedate", "zsessiondate"))
    count_col = _pick(cols, ("zmessagecounter", "zunreadcount", "zchatsessionunreadcount"))
    hidden_col = _pick(cols, ("zhidden", "zarchived", "zremoved"))
    if not name_col and not jid_col:
        return []
    aligned = [pk]
    for col in (name_col, jid_col, ts_col, count_col, hidden_col):
        if col and col not in aligned:
            aligned.append(col)
    order = f' ORDER BY "{ts_col}" DESC' if ts_col else ""
    select_cols = ", ".join(f'"{c}"' for c in aligned)
    try:
        cur.execute(
            f'SELECT {select_cols} FROM "{chat_t}"{order} LIMIT ? OFFSET ?',
            (max(int(limit), 1), max(int(offset), 0)),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        data = {aligned[i]: row[i] for i in range(min(len(aligned), len(row)))}
        chat_id = data.get(pk)
        name = str(data.get(name_col) or "").strip() if name_col else ""
        jid = str(data.get(jid_col) or "").strip() if jid_col else ""
        hidden = False
        if hidden_col:
            try:
                hidden = int(data.get(hidden_col) or 0) != 0
            except (TypeError, ValueError):
                hidden = bool(data.get(hidden_col))
        label = name or _format_wa_jid(jid) or (f"chat-{chat_id}" if chat_id is not None else "Unknown chat")
        is_group = jid.lower().endswith("@g.us") or "(group)" in label.lower()
        msg_count = 0
        if count_col:
            try:
                msg_count = int(data.get(count_col) or 0)
            except (TypeError, ValueError):
                msg_count = 0
        ts = _ts_to_iso(data.get(ts_col)) if ts_col else None
        preview = f"[Chat session] {label}"
        if msg_count:
            preview = f"[Chat session] {label} · {msg_count:,} messages"
        out.append(
            {
                "record_type": "whatsapp_message",
                "social_app": "whatsapp",
                "text_body": preview,
                "body": preview,
                "sender": label,
                "conversation": label,
                "chat": label,
                "conversation_id": f"whatsapp-ios:{chat_id}" if chat_id is not None else None,
                "chat_row_id": chat_id,
                "chat_jid": jid or None,
                "is_group": is_group,
                "timestamp": ts,
                "message_type": 0,
                "from_me": False,
                "is_deleted": False,
                "session_row": True,
                "message_count": msg_count,
                "hidden": hidden,
                "table": chat_t,
                "source": path,
                "text": f"WhatsApp · {label}",
            }
        )
    return out


def _extract_whatsapp_modern_sessions(
    cur: sqlite3.Cursor,
    path: str,
    *,
    tables: dict[str, str],
    limit: int,
    offset: int = 0,
) -> list[dict[str, Any]]:
    chat_t = tables.get("chat")
    if not chat_t:
        return []
    cols = _table_columns(cur, chat_t)
    if not cols:
        return []
    pk = _pick(cols, ("_id", "chat_row_id")) or "_id"
    subject = _pick(cols, ("subject", "display_name", "name"))
    jid_row = _pick(cols, ("jid_row_id",))
    ts_col = _pick(cols, ("sort_timestamp", "last_message_timestamp", "timestamp"))
    jid_t = tables.get("jid")
    jid_map: dict[int, tuple[str, str]] = {}
    if jid_t and jid_row:
        try:
            cur.execute(f'SELECT "_id", "raw_string", "user" FROM "{jid_t}"')
            for jid, raw, user in cur.fetchall():
                jid_map[int(jid)] = (str(raw or ""), str(user or ""))
        except (sqlite3.Error, ValueError, TypeError):
            pass
    aligned = [pk]
    for col in (subject, jid_row, ts_col):
        if col and col not in aligned:
            aligned.append(col)
    order = f' ORDER BY "{ts_col}" DESC' if ts_col else ""
    select_cols = ", ".join(f'"{c}"' for c in aligned)
    try:
        cur.execute(
            f'SELECT {select_cols} FROM "{chat_t}"{order} LIMIT ? OFFSET ?',
            (max(int(limit), 1), max(int(offset), 0)),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        data = {aligned[i]: row[i] for i in range(min(len(aligned), len(row)))}
        chat_id = data.get(pk)
        try:
            chat_id_int = int(chat_id) if chat_id is not None else 0
        except (TypeError, ValueError):
            chat_id_int = 0
        subj = str(data.get(subject) or "").strip() if subject else ""
        raw_jid = ""
        user = ""
        if jid_row and data.get(jid_row) is not None:
            try:
                raw_jid, user = jid_map.get(int(data.get(jid_row)), ("", ""))
            except (TypeError, ValueError):
                raw_jid, user = "", ""
        label = subj or _format_wa_jid(raw_jid, user) or (
            f"chat-{chat_id}" if chat_id is not None else "Unknown chat"
        )
        is_group = raw_jid.lower().endswith("@g.us") or "(group)" in label.lower()
        ts = _ts_to_iso(data.get(ts_col)) if ts_col else None
        preview = f"[Chat session] {label}"
        out.append(
            {
                "record_type": "whatsapp_message",
                "social_app": "whatsapp",
                "text_body": preview,
                "body": preview,
                "sender": label,
                "conversation": label,
                "chat": label,
                "conversation_id": f"whatsapp:{chat_id_int}" if chat_id_int else None,
                "chat_row_id": chat_id_int or chat_id,
                "chat_jid": raw_jid or None,
                "is_group": is_group,
                "timestamp": ts,
                "message_type": 0,
                "from_me": False,
                "is_deleted": False,
                "session_row": True,
                "table": chat_t,
                "source": path,
                "text": f"WhatsApp · {label}",
            }
        )
    return out


def _extract_whatsapp_modern(
    cur: sqlite3.Cursor,
    path: str,
    *,
    limit: int,
    deleted_only: bool = False,
    chat_row_id: Any = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Android msgstore schema: message.text_data + chat/jid joins."""
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        lower_map = {str(r[0]).lower(): str(r[0]) for r in cur.fetchall()}
    except sqlite3.Error:
        return []
    if "message" not in lower_map:
        return []
    msg_t = lower_map["message"]
    cols = _table_columns(cur, msg_t)
    if "text_data" not in cols and "timestamp" not in cols:
        return []

    chat_t = lower_map.get("chat")
    jid_t = lower_map.get("jid")
    has_chat = bool(chat_t and "chat_row_id" in cols)
    has_jid = bool(jid_t)

    # Build resolver maps (small tables).
    chat_label: dict[int, str] = {}
    chat_jid: dict[int, str] = {}
    if has_chat:
        try:
            if has_jid:
                cur.execute(
                    f'''SELECT c."_id", c."subject", j."raw_string", j."user"
                        FROM "{chat_t}" c
                        LEFT JOIN "{jid_t}" j ON j."_id" = c."jid_row_id"'''
                )
                for cid, subject, raw, user in cur.fetchall():
                    label = (subject or "").strip() or _format_wa_jid(raw, user) or f"chat-{cid}"
                    chat_label[int(cid)] = label
                    chat_jid[int(cid)] = _format_wa_jid(raw, user) or label
            else:
                cur.execute(f'SELECT "_id", "subject" FROM "{chat_t}"')
                for cid, subject in cur.fetchall():
                    chat_label[int(cid)] = (subject or "").strip() or f"chat-{cid}"
        except sqlite3.Error:
            pass

    jid_label: dict[int, str] = {}
    if has_jid:
        try:
            cur.execute(f'SELECT "_id", "raw_string", "user" FROM "{jid_t}"')
            for jid, raw, user in cur.fetchall():
                jid_label[int(jid)] = _format_wa_jid(raw, user) or str(jid)
        except sqlite3.Error:
            pass

    extra_where = ""
    if chat_row_id is not None:
        try:
            extra_where = f' AND m."chat_row_id" = {int(chat_row_id)}'
        except (TypeError, ValueError):
            extra_where = ' AND m."chat_row_id" = 0'
    if deleted_only:
        del_col = _pick(cols, ("deleted", "is_deleted", "status"))
        if del_col == "status":
            extra_where += f' AND lower(cast(m."{del_col}" as text)) IN (\'deleted\',\'revoked\')'
        elif del_col:
            extra_where += f' AND CAST(m."{del_col}" AS INTEGER) != 0'
        else:
            return []
    select = (
        f'SELECT m."_id", m."chat_row_id", m."from_me", m."sender_jid_row_id", '
        f'm."timestamp", m."message_type", m."text_data" '
        f'FROM "{msg_t}" m '
        f'WHERE m."chat_row_id" IS NOT NULL AND m."chat_row_id" > 0{extra_where} '
        f'ORDER BY m."timestamp" DESC '
        f'LIMIT ? OFFSET ?'
    )
    try:
        pull = max(int(limit), 1)
        cur.execute(select, (pull, max(int(offset), 0)))
        rows = cur.fetchall()
    except sqlite3.Error:
        return []

    media_by_msg: dict[Any, str] = {}
    # message_media / message_media_v2 often hold file names for image/video rows.
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tnames = {str(r[0]).lower(): str(r[0]) for r in cur.fetchall()}
        for cand in ("message_media", "message_media_v2"):
            real = tnames.get(cand)
            if not real:
                continue
            cols = _table_columns(cur, real)
            msg_col = _pick(cols, ("message_row_id", "message_id", "_id"))
            name_col = _pick(
                cols,
                ("file_path", "original_file_name", "file_name", "media_name", "mime_type"),
            )
            if not msg_col or not name_col:
                continue
            try:
                cur.execute(
                    f'SELECT "{msg_col}", "{name_col}" FROM "{real}" '
                    f'WHERE "{name_col}" IS NOT NULL LIMIT 20000'
                )
                for mid, fname in cur.fetchall():
                    s = str(fname or "").replace("\\", "/").strip()
                    if not s:
                        continue
                    base = s.rsplit("/", 1)[-1]
                    if "." in base:
                        media_by_msg[mid] = base
            except sqlite3.Error:
                continue
            break
    except sqlite3.Error:
        pass

    out: list[dict[str, Any]] = []
    for row in rows:
        _id, chat_row_id, from_me, sender_jid_row_id, ts_raw, msg_type, text_data = row
        try:
            mtype = int(msg_type) if msg_type is not None else -1
        except (TypeError, ValueError):
            mtype = -1
        if mtype in _WA_SKIP_TYPES:
            continue
        body = (str(text_data).strip() if text_data is not None else "")
        # Contact-card payloads are not conversation text (were showing as fake messages).
        if mtype == 4:
            continue
        media_name = media_by_msg.get(_id)
        placeholder = _WA_TYPE_LABELS.get(mtype)
        if not body:
            if placeholder is None and not media_name:
                continue
            body = placeholder or "[Media]"
        elif placeholder and mtype not in {0, 62}:
            # Keep caption; prefix media kind for clarity.
            body = f"{placeholder} {body}"
        if media_name and mtype in {1, 3, 9, 13, 15, 20}:
            if media_name.lower() not in body.lower():
                body = f"{body} {media_name}".strip() if body not in {"[Image]", "[Video]", "[Document]", "[GIF]", "[Sticker]"} else f"{placeholder or '[IMAGE]'} {media_name}"

        # Drop ultra-short contact-name-only noise with no chat context
        if len(body) < 2:
            continue

        chat_id = int(chat_row_id or 0)
        conversation = chat_label.get(chat_id) or chat_jid.get(chat_id) or f"chat-{chat_id}"
        jid_raw = chat_jid.get(chat_id) or ""
        if from_me in (1, True, "1"):
            sender = "Me"
        else:
            sender = jid_label.get(int(sender_jid_row_id or 0)) or conversation
        ts = _ts_to_iso(ts_raw)
        out.append(
            {
                "record_type": "whatsapp_message",
                "social_app": "whatsapp",
                "text_body": body[:4000],
                "body": body[:4000],
                "sender": sender,
                "conversation": conversation,
                "chat": conversation,
                "conversation_id": f"whatsapp:{chat_id}",
                "chat_row_id": chat_id,
                "chat_jid": jid_raw or None,
                "is_group": str(jid_raw).lower().endswith("@g.us") or "(group)" in conversation.lower(),
                "timestamp": ts,
                "message_type": mtype,
                "media_name": media_name,
                "media_filename": media_name,
                "from_me": bool(from_me in (1, True, "1")),
                "table": msg_t,
                "source": path,
                "message_row_id": _id,
                "text": f"WhatsApp · {conversation} · {sender}: {body[:240]}",
            }
        )
        if len(out) >= limit:
            break
    return out


def _extract_whatsapp_ios(
    cur: sqlite3.Cursor,
    path: str,
    *,
    limit: int,
    tables: dict[str, str],
    deleted_only: bool = False,
    chat_row_id: Any = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """iOS ChatStorage.sqlite — ZWAMESSAGE (+ optional ZWAMEDIAITEM filename).

    Recovers *revoked / "You deleted this message"* rows via ``ZMESSAGETYPE = 14``
    (Delete for Everyone placeholders still present in ChatStorage).

    Important: do **not** treat ``ZFLAGS & 0x1000000`` as revoke — on modern iOS
    WhatsApp that bit is set on nearly every live message and caused mass
    false positives.
    """
    msg_t = tables.get("zwamessage")
    if not msg_t:
        return []
    cols = _table_columns(cur, msg_t)
    text_col = _pick(cols, ("ztext", "text"))
    ts_col = _pick(cols, ("zmessagedate", "zsentdate"))
    from_col = _pick(cols, ("zfromjid", "ztojid"))
    to_col = _pick(cols, ("ztojid",))
    is_from_me = _pick(cols, ("zisfromme", "zfromme"))
    media_ref = _pick(cols, ("zmediaitem",))
    flags_col = _pick(cols, ("zflags", "flags"))
    msg_type_col = _pick(cols, ("zmessagetype", "zmessagetyp", "messagetype"))
    status_col = _pick(cols, ("zmessagestatus", "zstatus", "message_status"))
    deleted_flag_col = _pick(
        cols,
        (
            "zismissagefrommedeleted",
            "zisdeleted",
            "zdeleted",
            "zisfrommedeleted",
            "deleted",
            "is_deleted",
        ),
    )
    stanza_col = _pick(cols, ("zstanzaid", "stanza_id", "zmessageid"))
    pk_col = _pick(cols, ("z_pk", "rowid")) or "Z_PK"
    if not text_col and not media_ref and not msg_type_col:
        return []

    # Delete-for-Everyone placeholder type in iOS / macOS ChatStorage.ZWAMESSAGE.
    # Empirically verified against WhatsApp UI "You deleted this message" rows.
    _REVOKE_MSG_TYPES = {14}

    media_names: dict[Any, str] = {}
    media_titles: dict[Any, str] = {}
    media_peer: dict[Any, str] = {}
    media_t = tables.get("zwamediaitem")
    if media_t:
        mcols = _table_columns(cur, media_t)
        mpk = _pick(mcols, ("z_pk", "rowid")) or "Z_PK"
        mpath = _pick(
            mcols,
            ("zmedialocalpath", "zmediaurl", "zthumbnaillocalpath", "zxmppthumbpath"),
        )
        mtitle = _pick(mcols, ("ztitle", "title"))
        mpeer = _pick(mcols, ("zvcardname", "zauthorname"))
        try:
            sel = [f'"{mpk}"']
            if mpath:
                sel.append(f'"{mpath}"')
            if mtitle:
                sel.append(f'"{mtitle}"')
            if mpeer:
                sel.append(f'"{mpeer}"')
            # Cap media index — full table scans on large ChatStorage stall Open.
            media_lim = 80_000 if deleted_only or chat_row_id is not None else 40_000
            cur.execute(f'SELECT {", ".join(sel)} FROM "{media_t}" LIMIT {int(media_lim)}')
            for row in cur.fetchall():
                mid = row[0]
                idx = 1
                if mpath:
                    s = str(row[idx] or "").replace("\\", "/").strip()
                    idx += 1
                    if s:
                        base = s.rsplit("/", 1)[-1]
                        if "." in base or base.upper().startswith("IMG"):
                            media_names[mid] = base
                if mtitle:
                    t = str(row[idx] or "").strip()
                    idx += 1
                    if t:
                        media_titles[mid] = t
                if mpeer:
                    p = str(row[idx] or "").strip()
                    if p:
                        media_peer[mid] = p
        except sqlite3.Error:
            pass

    chat_label: dict[Any, str] = {}
    chat_t = tables.get("zwachat") or tables.get("zwachatsession")
    if chat_t:
        ccols = _table_columns(cur, chat_t)
        cpk = _pick(ccols, ("z_pk", "rowid")) or "Z_PK"
        cname = _pick(ccols, ("zpartnername", "zcontactjid", "zsessionid"))
        if cname:
            try:
                cur.execute(f'SELECT "{cpk}", "{cname}" FROM "{chat_t}" LIMIT 5000')
                for cid, name in cur.fetchall():
                    chat_label[cid] = str(name or "").strip() or f"chat-{cid}"
            except sqlite3.Error:
                pass

    chat_fk = _pick(cols, ("zchat", "zchatsession"))
    # Keep SELECT column list and name map aligned 1:1 (skip duplicate physical cols).
    col_order: list[str] = []
    for col in (
        text_col,
        ts_col,
        from_col,
        to_col,
        is_from_me,
        media_ref,
        chat_fk,
        flags_col,
        msg_type_col,
        status_col,
        deleted_flag_col,
        stanza_col,
    ):
        if col and col not in col_order:
            col_order.append(col)
    sel_parts = [f'"{pk_col}"'] + [f'"{c}"' for c in col_order]
    order = f' ORDER BY "{ts_col}" DESC' if ts_col else ""
    select_sql = f'SELECT {", ".join(sel_parts)} FROM "{msg_t}"'

    def _fetch_rows(extra_where: str, lim: int, off: int = 0) -> list[tuple[Any, ...]]:
        try:
            where = f" WHERE {extra_where}" if extra_where else ""
            cur.execute(
                f"{select_sql}{where}{order} LIMIT ? OFFSET ?",
                (lim, max(int(off), 0)),
            )
            return list(cur.fetchall())
        except sqlite3.Error:
            return []

    clauses: list[str] = []
    if chat_row_id is not None and chat_fk:
        try:
            clauses.append(f'"{chat_fk}" = {int(chat_row_id)}')
        except (TypeError, ValueError):
            clauses.append(f'"{chat_fk}" = {int(0)}')
    if deleted_only:
        del_parts: list[str] = []
        if msg_type_col:
            del_parts.append(f'"{msg_type_col}" = 14')
        if deleted_flag_col:
            del_parts.append(f'CAST("{deleted_flag_col}" AS INTEGER) != 0')
        if del_parts:
            clauses.append("(" + " OR ".join(del_parts) + ")")
        else:
            # No deleted columns — do not scan the live message table.
            return []
    where_sql = " AND ".join(clauses)

    if deleted_only:
        rows = _fetch_rows(where_sql, max(int(limit), 1), offset)
    else:
        rows = _fetch_rows(where_sql, max(int(limit), 1), offset)
        if msg_type_col and chat_row_id is None and int(offset or 0) == 0:
            revoke_rows = _fetch_rows(f'"{msg_type_col}" = 14', max(int(limit), 1), 0)
            seen_pk = {r[0] for r in rows}
            for r in revoke_rows:
                if r[0] not in seen_pk:
                    rows.append(r)
                    seen_pk.add(r[0])

    out: list[dict[str, Any]] = []
    seen_out_pk: set[Any] = set()

    def _read(row: tuple[Any, ...]) -> dict[str, Any]:
        data: dict[str, Any] = {"pk": row[0]}
        for i, name in enumerate(col_order, start=1):
            data[name] = row[i]
        return data

    def _is_jid_like(text: str) -> bool:
        low = text.lower()
        if " " in text.strip():
            return False
        return (
            "@s.whatsapp.net" in low
            or low.endswith("@g.us")
            or low.endswith("@lid")
            or low.endswith("@broadcast")
        )

    for row in rows:
        raw = _read(row)
        pk = raw.get("pk")
        if pk in seen_out_pk:
            continue
        body = str(raw.get(text_col) or "").strip() if text_col else ""
        # Type-14 rows sometimes store a peer JID in ZTEXT — not message content.
        if body and _is_jid_like(body):
            body = ""
        ts_raw = raw.get(ts_col) if ts_col else None
        from_me = False
        if is_from_me:
            from_me = raw.get(is_from_me) in (1, True, "1")
        sender_raw = raw.get(from_col) if from_col else None
        if from_me and to_col and to_col in raw:
            sender_raw = raw.get(to_col) or sender_raw
        media_id = raw.get(media_ref) if media_ref else None
        chat_id = raw.get(chat_fk) if chat_fk else None
        flags_val = raw.get(flags_col) if flags_col else 0
        try:
            flags_int = int(flags_val or 0)
        except (TypeError, ValueError):
            flags_int = 0
        msg_type_val = raw.get(msg_type_col) if msg_type_col else None
        try:
            msg_type_int = int(msg_type_val) if msg_type_val is not None else None
        except (TypeError, ValueError):
            msg_type_int = None
        del_flag_val = raw.get(deleted_flag_col) if deleted_flag_col else None
        try:
            del_flag_int = int(del_flag_val or 0)
        except (TypeError, ValueError):
            del_flag_int = 0

        revoked = msg_type_int in _REVOKE_MSG_TYPES
        flagged_deleted = bool(deleted_flag_col) and del_flag_int != 0
        is_deleted = revoked or flagged_deleted

        media_name = media_names.get(media_id) if media_id is not None else None
        media_title = media_titles.get(media_id) if media_id is not None else None
        peer_hint = media_peer.get(media_id) if media_id is not None else None
        # Revoke placeholders keep a media-item FK for metadata; live path is usually cleared.
        if is_deleted:
            media_name = None
        is_media_type = msg_type_int in {1, 2, 3, 8, 9, 13, 15, 20}
        if not body and not media_name and not is_deleted and not (is_media_type and media_title):
            continue
        if media_name and not body:
            body = f"[IMAGE] {media_name}"
        elif media_name and "[IMAGE]" not in body.upper() and body.startswith("http"):
            body = f"[IMAGE] {media_name}"

        conversation = chat_label.get(chat_id) or ""
        if from_me:
            sender = "Me"
        else:
            sender = str(sender_raw or conversation or "unknown").strip() or "unknown"
        ts = _ts_to_iso(ts_raw)
        conv_label = conversation or sender

        recovery_state = ""
        if is_deleted:
            # WhatsApp UI placeholder; original body is usually cleared from ZTEXT.
            if not body:
                body = (
                    "🚫 You deleted this message"
                    if from_me
                    else "🚫 This message was deleted"
                )
            recovery_state = "whatsapp_revoke_type14" if revoked else "whatsapp_deleted_flag"

        rec = {
            "record_type": "whatsapp_message_deleted" if is_deleted else "whatsapp_message",
            "social_app": "whatsapp",
            "text_body": body[:4000],
            "body": body[:4000],
            "sender": sender,
            "conversation": conv_label,
            "chat": conv_label,
            "conversation_id": f"whatsapp-ios:{chat_id}" if chat_id is not None else None,
            "chat_row_id": chat_id,
            "chat_jid": str(sender_raw or peer_hint or "") if (sender_raw or peer_hint) else None,
            "is_group": "(group)" in conv_label.lower()
            or str(sender_raw or "").lower().endswith("@g.us"),
            "timestamp": ts,
            "message_type": 1 if media_name else (msg_type_int or 0),
            "media_name": media_name,
            "media_filename": media_name,
            "media_title": media_title,
            "media_peer_jid": peer_hint,
            "from_me": bool(from_me),
            "is_deleted": bool(is_deleted),
            "deleted": bool(is_deleted),
            "status": "deleted" if is_deleted else None,
            "recovery_state": recovery_state or None,
            "flags": flags_int if flags_col else None,
            "stanza_id": str(raw.get(stanza_col) or "") if stanza_col else None,
            "table": msg_t,
            "source": path,
            "message_row_id": pk,
            "text": f"WhatsApp · {conv_label} · {sender}: {body[:240]}",
        }
        # For live image/video rows without a file basename, still mark as media via type.
        if not is_deleted and not media_name and msg_type_int in {1, 2, 3, 8, 15} and media_title:
            rec["media_name"] = {
                1: "image.jpg",
                2: "video.mp4",
                3: "audio.opus",
                8: "document",
                15: "sticker.webp",
            }.get(msg_type_int or 0, "attachment")
            rec["media_filename"] = rec["media_name"]
            if not body:
                rec["body"] = f"[IMAGE] {rec['media_name']}"
                rec["text_body"] = rec["body"]
        out.append(rec)
        seen_out_pk.add(pk)

    deleted_msgs = [m for m in out if m.get("is_deleted")]
    if deleted_msgs:
        _recover_deleted_text_from_indexes(cur, path, deleted_msgs)
        _recover_ios_revoke_originals(cur, path, deleted_msgs)
    # Carve inline JPEG thumbs for live + deleted media (files often absent from extract).
    _attach_media_thumbnails(cur, path, out)
    live_msgs = [m for m in out if not m.get("is_deleted")]
    # Always retain revoke placeholders; fill remaining budget with live messages.
    keep_del = deleted_msgs[: max(500, min(len(deleted_msgs), limit))]
    keep_live = live_msgs[:limit]
    merged = keep_live + keep_del
    merged.sort(key=lambda m: str(m.get("timestamp") or ""), reverse=True)
    return merged


def _carve_sqlite_jpeg_thumbnail(db_bytes: bytes, title: str) -> bytes | None:
    """Carve a JPEG thumbnail stored near a ZWAMEDIAITEM title on a SQLite page.

    Prefer the first valid JPEG in a tight window after the title — a wide scan
    often picks an unrelated later thumb (wrong aspect / wrong message).
    """
    needle = (title or "").strip().encode("ascii", errors="ignore")
    if len(needle) < 8 or not db_bytes:
        return None
    pos = db_bytes.find(needle)
    if pos < 0:
        return None

    def _first_jpeg(window: bytes) -> bytes | None:
        start = 0
        while True:
            i = window.find(b"\xff\xd8\xff", start)
            if i < 0:
                return None
            j = window.find(b"\xff\xd9", i + 2)
            if j < 0:
                return None
            blob = window[i : j + 2]
            # WhatsApp chat thumbs are typically 0.5–8 KB; reject huge false spans.
            if 200 <= len(blob) <= 64_000:
                return blob
            start = i + 3

    # Tight window first (same SQLite cell / nearby record).
    for radius in (8_000, 20_000, 80_000):
        blob = _first_jpeg(db_bytes[pos : pos + radius])
        if blob:
            return blob
    # Rare: thumbnail slightly before the title token on the same page.
    return _first_jpeg(db_bytes[max(0, pos - 8_000) : pos + 20_000])


def _attach_media_thumbnails(
    cur: sqlite3.Cursor,
    path: str,
    messages: list[dict[str, Any]],
    *,
    max_live: int = 200,
) -> None:
    """Attach base64 JPEG thumbs carved from ChatStorage for media / revoke rows."""
    import base64

    deleted = [m for m in messages if m.get("is_deleted") and m.get("media_title")]
    live = [
        m
        for m in messages
        if not m.get("is_deleted")
        and m.get("media_title")
        and (
            m.get("media_name")
            or int(m.get("message_type") or 0) in {1, 2, 3, 8, 9, 13, 15, 20}
        )
    ][:max_live]
    need = [m for m in (deleted + live) if not m.get("thumbnail_base64")]
    if not need:
        return
    db_bytes = _sqlite_main_bytes(cur, path)
    if not db_bytes:
        return
    cache: dict[str, str | None] = {}
    for msg in need:
        title = str(msg.get("media_title") or "").strip()
        if title not in cache:
            blob = _carve_sqlite_jpeg_thumbnail(db_bytes, title)
            cache[title] = base64.b64encode(blob).decode("ascii") if blob else None
        b64 = cache[title]
        if not b64:
            continue
        msg["thumbnail_base64"] = b64
        msg["thumbnail_content_type"] = "image/jpeg"
        msg["preview_quality"] = msg.get("preview_quality") or "chat_thumbnail_only"
        # Always expose a downloadable name — deleted revoke rows often keep only the thumb.
        if not msg.get("media_name"):
            title_stub = re.sub(r"[^A-Za-z0-9._-]+", "", title)[:16] or "media"
            ext = "pdf" if "pdf" in str(msg.get("mime_recovered") or "").lower() else "jpg"
            msg["media_name"] = msg.get("media_filename") or f"recovered-{title_stub}.{ext}"
            msg["media_filename"] = msg["media_name"]


def _recover_ios_revoke_originals(
    cur: sqlite3.Cursor,
    path: str,
    deleted_msgs: list[dict[str, Any]],
) -> None:
    """Carve original media/text remnants for type-14 revoke rows from DB pages.

    WhatsApp clears ZTEXT / ZMEDIALOCALPATH on Delete-for-Everyone, but prior cell
    bytes often remain near the media-item ZTITLE on the same SQLite page.
    """
    import re

    db_bytes = _sqlite_main_bytes(cur, path)
    if not db_bytes:
        return

    title_re = re.compile(rb"(?<![A-Fa-f0-9])[A-Fa-f0-9]{16,40}(?![A-Fa-f0-9])")
    media_re = re.compile(
        rb"Media/[A-Za-z0-9@._\-/]+\.(?:jpg|jpeg|png|webp|gif|mp4|mov|pdf|docx?|xlsx?|pptx?|zip|rar|opus|m4a|mp3|aac|thumb|url)",
        re.I,
    )
    mime_re = re.compile(
        rb"(?:image|video|audio|application)/(?:jpeg|jpg|png|webp|gif|mp4|pdf|octet-stream|zip|x-zip-compressed|ogg|opus|vcard|wav)",
        re.I,
    )
    url_re = re.compile(rb"https://mmg\.whatsapp\.net/[^\x00\s\"'<>]{20,400}")

    def _jid_token(value: str | None) -> str:
        s = str(value or "").strip().lower()
        if not s:
            return ""
        return s.split("@", 1)[0]

    for msg in deleted_msgs:
        title = str(msg.get("media_title") or "").strip()
        if len(title) < 8:
            continue
        needle = title.encode("ascii", errors="ignore")
        if not needle:
            continue
        pos = db_bytes.find(needle)
        if pos < 0:
            continue
        window = db_bytes[pos : pos + 750]
        next_titles = list(title_re.finditer(window[len(needle) :]))
        end = len(window)
        peer = _jid_token(msg.get("media_peer_jid") or msg.get("chat_jid"))
        for m in next_titles:
            abs_start = len(needle) + m.start()
            # Title + peer JID occupy the start of the record; cut at later titles.
            if abs_start > len(needle) + 64:
                end = abs_start
                break
        chunk = window[:end]
        chunk_txt = chunk.decode("latin-1", errors="ignore")

        # Prefer a Media/ path whose folder matches this chat peer; otherwise take the
        # first path in this record window (LID folder names often differ from ZVCARDNAME).
        # Prefer real media over .thumb placeholders.
        media_candidates = [
            mp.decode("ascii", errors="ignore") for mp in media_re.findall(chunk)
        ]
        real_media = [
            p for p in media_candidates if not p.lower().endswith((".thumb", ".thumb.webp"))
        ]
        prefer_list = real_media or media_candidates
        media_path = None
        if peer:
            for p in prefer_list:
                if peer in p.lower():
                    media_path = p
                    break
        if not media_path and prefer_list:
            media_path = prefer_list[0]
        if not media_path and media_candidates:
            media_path = media_candidates[0]

        mime = None
        mm = mime_re.search(chunk)
        if mm:
            mime = mm.group(0).decode("ascii", errors="ignore").lower()

        orig_name = None
        pre = re.search(
            rb"([A-Za-z0-9._\- ]{3,120}\.(?:pdf|zip|docx?|xlsx?|pptx?|jpg|jpeg|png|mp4))Media/",
            chunk,
            re.I,
        )
        if pre:
            after = chunk[pre.end() - 6 : pre.end() + 180]
            path_m = media_re.search(after) or media_re.search(chunk[pre.start() :])
            path_s = path_m.group(0).decode("ascii", errors="ignore") if path_m else ""
            # Accept filename when it sits immediately before a Media/ path in this window.
            if path_s and (not media_candidates or path_s in media_candidates or path_s == media_path):
                cand = pre.group(1).decode("ascii", errors="ignore").strip()
                if len(cand) > 2 and cand[0].islower() and cand[1].isupper():
                    cand = cand[1:]
                # Avoid attributing another chat's file when path peer conflicts hard
                # and we already have a better peer-matching media_path.
                path_peer_ok = (not peer) or (peer in path_s.lower()) or (media_path == path_s)
                if path_peer_ok or not media_path:
                    orig_name = cand
                    if not media_path:
                        media_path = path_s
        if not orig_name and media_path:
            orig_name = media_path.rsplit("/", 1)[-1]

        media_url = None
        um = url_re.search(chunk)
        if um and media_path:
            media_url = um.group(0).decode("ascii", errors="ignore")[:300]

        # Only accept Media/ paths from this record window (avoid later chats on the page).
        if media_path and len(chunk) > 1600 and chunk.find(media_path.encode("ascii", errors="ignore")) > 1500:
            media_path = None
            if orig_name and not re.search(r"\.(pdf|zip|docx?|xlsx?|pptx?|jpe?g|png|mp4)$", orig_name, re.I):
                orig_name = None

        mime_only = bool(mime) and (
            (peer and peer in chunk_txt.lower())
            or bool(msg.get("media_peer_jid") or msg.get("chat_jid") or msg.get("to_jid"))
        )
        if not media_path and not mime_only and not orig_name:
            continue

        label = None
        if mime:
            if mime.startswith("image/"):
                label = "IMAGE"
            elif mime.startswith("video/"):
                label = "VIDEO"
            elif mime.startswith("audio/"):
                label = "AUDIO"
            elif "pdf" in mime:
                label = "DOCUMENT"
            elif "zip" in mime:
                label = "FILE"
            else:
                label = "ATTACHMENT"
        elif media_path or orig_name:
            ext = (media_path or orig_name or "").rsplit(".", 1)[-1].lower()
            label = {
                "jpg": "IMAGE",
                "jpeg": "IMAGE",
                "png": "IMAGE",
                "webp": "IMAGE",
                "gif": "IMAGE",
                "mp4": "VIDEO",
                "mov": "VIDEO",
                "pdf": "DOCUMENT",
                "zip": "FILE",
                "opus": "AUDIO",
                "m4a": "AUDIO",
                "mp3": "AUDIO",
            }.get(ext, "ATTACHMENT")
        if not label:
            continue

        title_stub = re.sub(r"[^A-Za-z0-9._-]+", "", title)[:20] or "media"
        if not orig_name and not media_path and mime:
            ext = {
                "IMAGE": "jpg",
                "VIDEO": "mp4",
                "AUDIO": "opus",
                "DOCUMENT": "pdf",
                "FILE": "zip",
            }.get(label, "bin")
            if "pdf" in (mime or ""):
                ext = "pdf"
            elif "zip" in (mime or ""):
                ext = "zip"
            display = f"recovered-{title_stub}.{ext}"
        else:
            display = orig_name or (
                media_path.rsplit("/", 1)[-1] if media_path else f"recovered-{title_stub}.bin"
            )
        recovered_body = f"[{label}] {display}"
        ts = str(msg.get("timestamp") or "").strip()
        # Lead with recovered content + timestamp so list/preview show what was deleted.
        if ts:
            body = f"{recovered_body}\nDeleted at: {ts}"
        else:
            body = recovered_body
        placeholder = (
            "🚫 You deleted this message"
            if msg.get("from_me")
            else "🚫 This message was deleted"
        )
        body = f"{body}\n({placeholder})"
        msg["body"] = body[:4000]
        msg["text_body"] = body[:4000]
        msg["media_name"] = display
        msg["media_filename"] = display
        msg["media_path_recovered"] = media_path
        msg["media_url_recovered"] = media_url
        msg["mime_recovered"] = mime
        msg["original_content"] = recovered_body
        msg["recovery_state"] = "whatsapp_revoke_carved"
        if not media_path:
            msg["preview_quality"] = "chat_thumbnail_only"
            msg["original_missing_from_extract"] = True
        msg["message_type"] = {
            "IMAGE": 1,
            "VIDEO": 2,
            "AUDIO": 3,
            "DOCUMENT": 8,
            "FILE": 8,
        }.get(label, 0) or msg.get("message_type")
        msg["text"] = (
            f"WhatsApp · {msg.get('conversation') or ''} · {msg.get('sender')}: {body[:240]}"
        )

    # Text-only Delete-for-Everyone: original ZTEXT is gone, but leftover page
    # bytes near the stanza id / row id often still hold the unread body.
    still_empty = [
        m
        for m in deleted_msgs
        if _is_placeholder_or_empty(str(m.get("text_body") or m.get("body") or ""))
        and not m.get("original_content")
    ]
    if still_empty and db_bytes:
        for msg in still_empty:
            token = str(msg.get("stanza_id") or "").strip()
            carved = ""
            if len(token) >= 12:
                carved = _carve_chat_text_near_token(db_bytes, token)
            if not carved:
                continue
            clean, residue = _split_whatsapp_carve_text(carved)
            if clean:
                carved = clean
                if residue:
                    msg["protocol_residue"] = residue
            if _is_whatsapp_protocol_noise(carved):
                continue
            placeholder = (
                "🚫 You deleted this message"
                if msg.get("from_me")
                else "🚫 This message was deleted"
            )
            body = f"{carved}\n({placeholder})"
            msg["body"] = body[:4000]
            msg["text_body"] = body[:4000]
            msg["original_content"] = carved
            msg["recovery_state"] = "whatsapp_revoke_text_carve"
            msg["text"] = (
                f"WhatsApp · {msg.get('conversation') or ''} · {msg.get('sender')}: {carved[:240]}"
            )


def _is_placeholder_or_empty(body: str) -> bool:
    t = (body or "").strip().lower()
    if not t:
        return True
    return "deleted this message" in t or t.startswith("🚫")


_PLACEHOLDER_MARKERS = (
    "(🚫 you deleted this message)",
    "(🚫 this message was deleted)",
    "(you deleted this message)",
    "(this message was deleted)",
)

# Group/user JID local-part may be digits or digits-digits (legacy @g.us).
_JID_LEAD_RE = re.compile(
    r"^(?P<jid>~?(?:\d{5,20}(?:-\d{5,20})?)@(?:g\.us|lid|s\.whatsapp\.net|c\.us))",
    re.I,
)

# After the JID: optional base64 (must include '='), optional hex/stanza id, then human text.
# Requiring '=' stops the base64 class from swallowing English words like "Thank".
_IDS_THEN_CHAT_RE = re.compile(
    r"^(?P<ids>(?:[A-Za-z0-9+/]{4,}={1,2})?(?:3EB0[0-9A-Fa-f]{8,36}|[0-9A-Fa-f]{16,40})?)"
    r"(?P<chat>\s*[A-Za-z].+)$",
    re.S,
)


def _strip_placeholder_wrappers(text: str) -> tuple[str, str]:
    """Return (core, placeholder_suffix_if_any)."""
    s = (text or "").strip()
    if not s:
        return "", ""
    low = s.lower()
    for marker in _PLACEHOLDER_MARKERS:
        idx = low.find(marker)
        if idx >= 0:
            core = s[:idx].strip()
            suffix = s[idx:].strip()
            return core, suffix
    return s, ""


def _find_prose_start_after_ids(blob: str) -> int | None:
    """Index where human chat begins after base64/hex residue (may have no space)."""
    if not blob:
        return None
    # base64? + hex/stanza, then immediately a letter (Thank you… / on 23rd…).
    m = re.match(
        r"^(?:[A-Za-z0-9+/]{4,}={1,2})?(?:3EB0[0-9A-Fa-f]{8,36}|[0-9A-Fa-f]{16,40})(?=[A-Za-z])",
        blob,
    )
    if m:
        return m.end()
    # Fallback: hex/base64 run then Capitalized word with no space.
    m = re.search(r"[0-9A-Fa-f+/=]([A-Z][a-z]{2,}\b)", blob)
    if m:
        return m.start(1)
    # Space then letter.
    m = re.search(r"\s+([A-Za-z].*)$", blob, re.S)
    if m:
        return m.start(1)
    return None


def _looks_like_prose_chat(chat: str) -> bool:
    """True for recovered human text (not leftover hex/base64)."""
    c = (chat or "").strip()
    if len(c) < 3:
        return False
    if re.fullmatch(r"[0-9A-Fa-f+/=_-]+", c):
        return False
    letters = sum(1 for ch in c if ch.isalpha())
    if letters < 3:
        return False
    if " " in c:
        return True
    # Single word messages still need lowercase letters (Thank / Ok / Hi).
    return bool(re.search(r"[a-z]{2,}", c))


def _split_whatsapp_carve_text(text: str) -> tuple[str, str]:
    """Split carved payload into (human_chat_text, protocol_residue).

    Freelist often concatenates group JID + base64/hex onto the real message, sometimes
    with no space::

      9199…-1492…@g.usCPzFopgGIAA=3EB09178…B9Thank you Soooo Much Chitra…
      1203…@g.usC03j…==433D…BFE11 on 23rd of June 2025 English evaluation is there
    """
    core, _suffix = _strip_placeholder_wrappers(text)
    s = core.strip()
    if not s:
        return "", ""
    # Carve noise sometimes wraps the JID: "[1203…@g.us…]" / "[9199…-1492…@g.us…]"
    if re.match(r"^[\(\[\{<]*~?\d{5,}(?:-\d{5,})?@", s):
        s = re.sub(r"^[\s\[\(\{<]+", "", s)
        s = re.sub(r"[\s\]\)\}>]+$", "", s).strip()
        if not s:
            return "", ""
    # If a preview blob was passed, only split the Original content section.
    if "Original content:" in s:
        after = s.split("Original content:", 1)[1]
        after = re.split(
            r"\n\s*(?:Protocol residue|Recovery status|\[ATTACHMENT\]|⚠)",
            after,
            maxsplit=1,
        )[0].strip()
        return _split_whatsapp_carve_text(after)

    jm = _JID_LEAD_RE.match(s)
    if jm:
        jid = jm.group("jid")
        after = s[jm.end() :]
        im = _IDS_THEN_CHAT_RE.match(after)
        if im and _looks_like_prose_chat(im.group("chat") or ""):
            ids = im.group("ids") or ""
            chat = (im.group("chat") or "").strip()
            if ids and (
                re.search(r"[+/=]", ids)
                or re.search(r"3EB0|[0-9A-Fa-f]{12,}", ids)
                or len(ids) >= 8
            ):
                return chat, (jid + ids).strip()
            if not ids:
                return chat, jid
        start = _find_prose_start_after_ids(after)
        if start is not None and start < len(after):
            residue = (jid + after[:start]).strip()
            chat = after[start:].strip()
            if _looks_like_prose_chat(chat):
                return chat, residue
        # JID present but no recoverable prose — whole payload is residue.
        return "", (jid + after).strip() if after else jid

    # Hex / base64 blob then prose (no JID), space optional.
    start = _find_prose_start_after_ids(s)
    if start is not None and start >= 12:
        residue = s[:start].strip()
        chat = s[start:].strip()
        if _looks_like_prose_chat(chat) and re.search(r"\d", residue) and (
            re.search(r"[+/=]", residue)
            or sum(c.isupper() for c in residue) >= 3
            or re.fullmatch(r"[0-9A-Fa-f]+", residue)
        ):
            return chat, residue

    m2 = re.match(
        r"^(?P<residue>[A-Za-z0-9+/=_-]{16,})(?:\s+(?P<chat>[A-Za-z].+))$",
        s,
        re.S,
    )
    if m2:
        residue = m2.group("residue")
        chat = m2.group("chat").strip()
        if _looks_like_prose_chat(chat) and re.search(r"\d", residue) and (
            re.search(r"[+/=]", residue)
            or sum(c.isupper() for c in residue) >= 3
            or re.fullmatch(r"[0-9A-Fa-f]+", residue)
        ):
            return chat, residue
    return s, ""


def _is_whatsapp_protocol_noise(text: str) -> bool:
    """True when nothing usable remains after stripping JID/hash residue."""
    clean, residue = _split_whatsapp_carve_text(text)
    if clean:
        # Recovered prose after a protocol prefix is NOT noise.
        letters = sum(1 for c in clean if c.isalpha())
        if letters >= 3 or (" " in clean and len(clean) >= 4):
            return False
    s = (clean or "").strip()
    if not s:
        # Pure residue / empty after strip.
        core, _ = _strip_placeholder_wrappers(text)
        s = core.strip()
        if residue and not clean:
            return True
    if not s:
        return True
    if "\x00" in s:
        return True
    # Group / user / LID identifiers still present (unsplit leftovers).
    if re.search(r"@g\.us|@s\.whatsapp\.net|@lid|@c\.us", s, re.I):
        return True
    if re.fullmatch(r"~?\d{8,20}", s):
        return True
    if re.fullmatch(r"(?i)(?:recovered[-_])?[0-9a-f]{12,40}(?:\.jpe?g|\.png|\.pdf|\.mp4|\.zip)?", s):
        return True
    compact = re.sub(r"\s+", "", s)
    if len(compact) >= 16 and " " not in s.strip():
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", compact):
            has_b64 = bool(re.search(r"[+/=]", compact)) or (
                sum(c.isupper() for c in compact) >= 2 and sum(c.isdigit() for c in compact) >= 2
            )
            if has_b64 or re.fullmatch(r"[0-9A-Fa-f]{16,}", compact):
                return True
    if re.search(r"\d{10,}@g\.us[A-Za-z0-9+/=]{6,}[0-9A-Fa-f]{8,}", s):
        return True
    if " " not in s and len(s) >= 16:
        hexish = sum(1 for c in s if c in "0123456789abcdefABCDEF")
        if hexish / len(s) >= 0.85:
            return True
    return False


def _carve_chat_text_near_token(db_bytes: bytes, token: str) -> str:
    """Pull a nearby printable chat string for an unread / revoked message."""
    needle = token.encode("utf-8", errors="ignore")
    if len(needle) < 4 or not db_bytes:
        return ""
    pos = db_bytes.find(needle)
    if pos < 0:
        pos = db_bytes.find(token.encode("ascii", errors="ignore"))
    if pos < 0:
        return ""
    # Only look after the token — bytes before it are usually the previous live row.
    window = db_bytes[pos + len(needle) : pos + len(needle) + 700]
    # Prefer UTF-8 runs; fall back to latin-1 printable.
    candidates: list[str] = []
    buf = bytearray()
    for b in window:
        if 32 <= b < 127 or b in (9, 10, 13):
            buf.append(b)
            continue
        if buf:
            s = buf.decode("ascii", errors="ignore").strip()
            if s:
                candidates.append(s)
            buf.clear()
    if buf:
        s = buf.decode("ascii", errors="ignore").strip()
        if s:
            candidates.append(s)
    skip = {
        "this message was deleted",
        "you deleted this message",
        "sqlite format 3",
    }

    def _score(cand: str) -> tuple[int, int]:
        """Higher is better: prefer natural language over ids."""
        clean, _res = _split_whatsapp_carve_text(cand)
        use = clean or cand
        letters = sum(1 for c in use if c.isalpha())
        spaces = use.count(" ")
        words = len([w for w in re.split(r"\s+", use) if len(w) >= 2])
        score = letters + spaces * 8 + words * 12
        if clean and _res:
            score += 20  # prefer candidates that yield recoverable prose
        if re.search(r"[.!?]$", use):
            score += 5
        return (score, len(use))

    best = ""
    best_score = (-1, -1)
    for cand in candidates:
        low = cand.lower()
        if low in skip or "deleted this message" in low:
            continue
        if token.lower() in low:
            continue
        clean, _res = _split_whatsapp_carve_text(cand)
        use = clean.strip() if clean else cand.strip()
        if not use or _is_whatsapp_protocol_noise(use if clean else cand):
            continue
        if " " not in use and len(use) < 8:
            continue
        if len(use) < 4 or len(use) > 400:
            continue
        if use.count("/") + use.count("ZWA") > 3:
            continue
        letters = sum(1 for c in use if c.isalpha())
        if letters < 3:
            continue
        if " " not in use and letters < max(8, int(len(use) * 0.6)):
            continue
        sc = _score(cand)
        if sc > best_score:
            best_score = sc
            best = use
    if best and _is_whatsapp_protocol_noise(best):
        return ""
    return best[:400]


def _sqlite_main_bytes(cur: sqlite3.Cursor, path: str) -> bytes | None:
    """Read main DB file bytes for page-level carving (capped)."""
    db_path = ""
    try:
        for r in cur.execute("PRAGMA database_list").fetchall():
            if str(r[1] or "") == "main" and r[2]:
                db_path = str(r[2])
                break
    except Exception:
        db_path = ""
    if not db_path or not os.path.isfile(db_path):
        if path and os.path.isfile(path):
            db_path = path
        else:
            return None
    try:
        size = os.path.getsize(db_path)
        with open(db_path, "rb") as fh:
            return fh.read(min(size, 512 * 1024 * 1024))
    except OSError:
        return None


def extract_chat_messages_from_connection(
    cur: sqlite3.Cursor,
    path: str,
    *,
    limit: int | None = None,
    deleted_only: bool = False,
    chat_row_id: Any = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Extract readable chat/SMS rows from an open SQLite cursor."""
    app = infer_social_app(path) or "chat"
    lim = max(int(limit or _MSG_LIMIT_DEFAULT), 1)
    off = max(int(offset or 0), 0)
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 400")
        tables = [str(r[0]) for r in cur.fetchall()]
    except sqlite3.Error:
        return []
    lower_map = {t.lower(): t for t in tables}

    if app == "whatsapp":
        # Prefer modern Android msgstore (message.text_data + chat/jid).
        modern = _extract_whatsapp_modern(
            cur,
            path,
            limit=lim,
            deleted_only=deleted_only,
            chat_row_id=chat_row_id,
            offset=off,
        )
        if modern:
            return modern
        ios = _extract_whatsapp_ios(
            cur,
            path,
            limit=lim,
            tables=lower_map,
            deleted_only=deleted_only,
            chat_row_id=chat_row_id,
            offset=off,
        )
        if ios:
            return ios
        prefer = _WA_TABLES
        record_type = "whatsapp_message"
    elif app == "sms":
        prefer = _SMS_TABLES
        record_type = "sms_message"
    else:
        prefer = _GENERIC_TABLES
        record_type = "chat_message"

    records: list[dict[str, Any]] = []
    seen_bodies: set[str] = set()
    for cand in prefer:
        real = lower_map.get(cand.lower())
        if not real:
            continue
        # Avoid FTS shadow / metadata tables that yield token junk.
        if real.lower() in {"metadata", "message_ftsv2", "message_ftsv2_content"}:
            continue
        for rec in _extract_from_table(
            cur, real, path=path, app=app, limit=lim, record_type=record_type
        ):
            key = f"{rec.get('sender')}|{rec.get('text_body')[:120]}"
            if key in seen_bodies:
                continue
            seen_bodies.add(key)
            records.append(rec)
            if len(records) >= lim:
                return records

    # Fallback: any table with a text-like column and message-ish name
    if not records:
        for t in tables:
            tl = t.lower()
            if tl in {"metadata", "message_ftsv2", "message_ftsv2_content", "chat"}:
                continue
            if not any(x in tl for x in ("message", "msg", "sms", "docs_content", "zwamessage")):
                continue
            for rec in _extract_from_table(
                cur, t, path=path, app=app, limit=min(lim, 80), record_type=record_type
            ):
                key = f"{rec.get('sender')}|{rec.get('text_body')[:120]}"
                if key in seen_bodies:
                    continue
                seen_bodies.add(key)
                records.append(rec)
                if len(records) >= lim:
                    return records
    return records


def count_chat_messages_from_connection(
    cur: sqlite3.Cursor,
    path: str,
    *,
    deleted_only: bool = False,
    chat_row_id: Any = None,
) -> int:
    """COUNT of WhatsApp message rows for a thread (or all chats)."""
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 400")
        tables = [str(r[0]) for r in cur.fetchall()]
    except sqlite3.Error:
        return 0
    lower_map = {t.lower(): t for t in tables}
    if "message" in lower_map:
        msg_t = lower_map["message"]
        cols = _table_columns(cur, msg_t)
        where = ['m."chat_row_id" IS NOT NULL', 'm."chat_row_id" > 0']
        if chat_row_id is not None and "chat_row_id" in cols:
            try:
                where.append(f'm."chat_row_id" = {int(chat_row_id)}')
            except (TypeError, ValueError):
                where.append('m."chat_row_id" = 0')
        if deleted_only:
            del_col = _pick(cols, ("deleted", "is_deleted", "status"))
            if del_col == "status":
                where.append(f'lower(cast(m."{del_col}" as text)) IN (\'deleted\',\'revoked\')')
            elif del_col:
                where.append(f'CAST(m."{del_col}" AS INTEGER) != 0')
            else:
                return 0
        try:
            cur.execute(
                f'SELECT COUNT(*) FROM "{msg_t}" m WHERE ' + " AND ".join(where)
            )
            row = cur.fetchone()
            return int(row[0] or 0) if row else 0
        except sqlite3.Error:
            return 0
    msg_t = lower_map.get("zwamessage")
    if not msg_t:
        return 0
    cols = _table_columns(cur, msg_t)
    chat_fk = _pick(cols, ("zchat", "zchatsession"))
    msg_type_col = _pick(cols, ("zmessagetype",))
    deleted_flag_col = _pick(cols, ("zismessagefrommedeleted", "zdeleted"))
    clauses: list[str] = []
    if chat_row_id is not None and chat_fk:
        try:
            clauses.append(f'"{chat_fk}" = {int(chat_row_id)}')
        except (TypeError, ValueError):
            clauses.append(f'"{chat_fk}" = 0')
    if deleted_only:
        del_parts: list[str] = []
        if msg_type_col:
            del_parts.append(f'"{msg_type_col}" = 14')
        if deleted_flag_col:
            del_parts.append(f'CAST("{deleted_flag_col}" AS INTEGER) != 0')
        if not del_parts:
            return 0
        clauses.append("(" + " OR ".join(del_parts) + ")")
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    try:
        cur.execute(f'SELECT COUNT(*) FROM "{msg_t}"{where}')
        row = cur.fetchone()
        return int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return 0


def extract_chat_messages_from_bytes(
    data: bytes,
    path: str,
    *,
    limit: int | None = None,
    deleted_only: bool = False,
    chat_row_id: Any = None,
) -> list[dict[str, Any]]:
    """Open SQLite bytes read-only and extract human-readable chat rows."""
    if not data or not data[:16].startswith(b"SQLite format"):
        return []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        return extract_chat_messages_from_path(
            tmp_path, path, limit=limit, deleted_only=deleted_only, chat_row_id=chat_row_id
        )
    except Exception:
        return []
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def extract_chat_messages_from_path(
    db_path: str,
    source_path: str,
    *,
    limit: int | None = None,
    deleted_only: bool = False,
    chat_row_id: Any = None,
    sessions_only: bool = False,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Read an on-disk SQLite file (cached ChatStorage) without re-downloading."""
    if not db_path or not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            if sessions_only:
                return extract_chat_sessions_from_connection(
                    cur, source_path, limit=limit or 5000, offset=offset
                )
            return extract_chat_messages_from_connection(
                cur,
                source_path,
                limit=limit,
                deleted_only=deleted_only,
                chat_row_id=chat_row_id,
                offset=offset,
            )
        finally:
            conn.close()
    except Exception:
        return []


def extract_deleted_chat_summaries_from_path(
    db_path: str,
    source_path: str,
    *,
    limit: int = 5_000,
) -> list[dict[str, Any]]:
    """Fast per-chat deleted counts from ChatStorage/msgstore (Names list).

    Avoids loading every revoke row + media index — SQL GROUP BY only.
    """
    if not db_path or not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        cur = conn.cursor()
        tables = {str(r[0]).lower(): str(r[0]) for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        ios = _extract_ios_deleted_chat_summaries(
            cur, source_path, tables=tables, limit=limit
        )
        if ios:
            return ios
        return _extract_android_deleted_chat_summaries(
            cur, source_path, tables=tables, limit=limit
        )
    except Exception:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _extract_ios_deleted_chat_summaries(
    cur: sqlite3.Cursor,
    path: str,
    *,
    tables: dict[str, str],
    limit: int,
) -> list[dict[str, Any]]:
    msg_t = tables.get("zwamessage")
    chat_t = tables.get("zwachat") or tables.get("zwachatsession")
    if not msg_t or not chat_t:
        return []
    mcols = _table_columns(cur, msg_t)
    ccols = _table_columns(cur, chat_t)
    chat_fk = _pick(mcols, ("zchat", "zchatsession"))
    msg_type_col = _pick(mcols, ("zmessagetype", "zmessagetyp", "messagetype"))
    deleted_flag_col = _pick(
        mcols,
        (
            "zismissagefrommedeleted",
            "zisdeleted",
            "zdeleted",
            "zisfrommedeleted",
            "deleted",
            "is_deleted",
        ),
    )
    ts_col = _pick(mcols, ("zmessagedate", "zsentdate"))
    cpk = _pick(ccols, ("z_pk", "rowid")) or "Z_PK"
    cname = _pick(ccols, ("zpartnername", "zcontactname", "zsessionid"))
    cjid = _pick(ccols, ("zcontactjid", "zpartnerjid", "zsessionid"))
    if not chat_fk or (not msg_type_col and not deleted_flag_col):
        return []
    del_parts: list[str] = []
    if msg_type_col:
        del_parts.append(f'm."{msg_type_col}" = 14')
    if deleted_flag_col:
        del_parts.append(f'CAST(m."{deleted_flag_col}" AS INTEGER) != 0')
    where_del = " OR ".join(del_parts)
    name_expr = f'c."{cname}"' if cname else "NULL"
    jid_expr = f'c."{cjid}"' if cjid else "NULL"
    ts_expr = f'MAX(m."{ts_col}")' if ts_col else "NULL"
    sql = (
        f'SELECT c."{cpk}", {name_expr}, {jid_expr}, COUNT(*), {ts_expr} '
        f'FROM "{msg_t}" m '
        f'JOIN "{chat_t}" c ON m."{chat_fk}" = c."{cpk}" '
        f"WHERE ({where_del}) "
        f'GROUP BY c."{cpk}" '
        f"ORDER BY {ts_expr if ts_col else 'COUNT(*)'} DESC "
        f"LIMIT ?"
    )
    try:
        cur.execute(sql, (max(int(limit), 1),))
        rows = cur.fetchall()
    except sqlite3.Error:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        chat_id, name, jid, cnt, ts_raw = row[0], row[1], row[2], row[3], row[4]
        label = str(name or "").strip() or _format_wa_jid(str(jid or "")) or (
            f"chat-{chat_id}" if chat_id is not None else "Unknown"
        )
        jid_s = str(jid or "").strip()
        out.append(
            {
                "conversation": label,
                "sender": label,
                "chat_jid": jid_s or None,
                "chat_row_id": chat_id,
                "conversation_id": f"whatsapp-ios:{chat_id}" if chat_id is not None else None,
                "is_group": jid_s.lower().endswith("@g.us") or "(group)" in label.lower(),
                "deleted_count": int(cnt or 0),
                "timestamp": _ts_to_iso(ts_raw) if ts_raw is not None else None,
                "source": path,
                "social_app": "whatsapp",
                "is_deleted": True,
                "body": f"{int(cnt or 0)} deleted/recovered messages",
                "text_body": f"{int(cnt or 0)} deleted/recovered messages",
            }
        )
    return out


def _extract_android_deleted_chat_summaries(
    cur: sqlite3.Cursor,
    path: str,
    *,
    tables: dict[str, str],
    limit: int,
) -> list[dict[str, Any]]:
    msg_t = tables.get("message")
    chat_t = tables.get("chat")
    jid_t = tables.get("jid")
    if not msg_t or not chat_t:
        return []
    mcols = _table_columns(cur, msg_t)
    ccols = _table_columns(cur, chat_t)
    chat_fk = _pick(mcols, ("chat_row_id", "chat_id"))
    status_col = _pick(mcols, ("status", "message_status"))
    ts_col = _pick(mcols, ("timestamp", "receipt_timestamp", "received_timestamp"))
    # Android often marks revoke with status=8 or message_type specific values.
    msg_type_col = _pick(mcols, ("message_type", "type"))
    cpk = _pick(ccols, ("_id", "rowid")) or "_id"
    cjid_fk = _pick(ccols, ("jid_row_id", "jid_id"))
    if not chat_fk:
        return []
    del_parts: list[str] = []
    if status_col:
        # Common revoke/delete statuses observed across WA Android versions.
        del_parts.append(f'm."{status_col}" IN (8, 10, 12)')
    if msg_type_col:
        del_parts.append(f'm."{msg_type_col}" IN (15, 64)')
    if not del_parts:
        return []
    where_del = " OR ".join(del_parts)
    # Resolve subject/jid when jid table exists.
    if jid_t and cjid_fk:
        jcols = _table_columns(cur, jid_t)
        jpk = _pick(jcols, ("_id", "rowid")) or "_id"
        juser = _pick(jcols, ("user", "raw_string", "jid"))
        jraw = _pick(jcols, ("raw_string", "jid", "user"))
        label_expr = f'COALESCE(j."{juser}", j."{jraw}", \'chat-\' || c."{cpk}")' if juser or jraw else f"'chat-' || c.\"{cpk}\""
        jid_expr = f'j."{jraw}"' if jraw else "NULL"
        join_jid = f'LEFT JOIN "{jid_t}" j ON c."{cjid_fk}" = j."{jpk}"'
    else:
        label_expr = f"'chat-' || c.\"{cpk}\""
        jid_expr = "NULL"
        join_jid = ""
    ts_expr = f'MAX(m."{ts_col}")' if ts_col else "NULL"
    sql = (
        f'SELECT c."{cpk}", {label_expr}, {jid_expr}, COUNT(*), {ts_expr} '
        f'FROM "{msg_t}" m '
        f'JOIN "{chat_t}" c ON m."{chat_fk}" = c."{cpk}" '
        f"{join_jid} "
        f"WHERE ({where_del}) "
        f'GROUP BY c."{cpk}" '
        f"ORDER BY {ts_expr if ts_col else 'COUNT(*)'} DESC "
        f"LIMIT ?"
    )
    try:
        cur.execute(sql, (max(int(limit), 1),))
        rows = cur.fetchall()
    except sqlite3.Error:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        chat_id, name, jid, cnt, ts_raw = row[0], row[1], row[2], row[3], row[4]
        label = str(name or "").strip() or (f"chat-{chat_id}" if chat_id is not None else "Unknown")
        jid_s = str(jid or "").strip()
        out.append(
            {
                "conversation": label,
                "sender": label,
                "chat_jid": jid_s or None,
                "chat_row_id": chat_id,
                "conversation_id": f"whatsapp:{chat_id}" if chat_id is not None else None,
                "is_group": jid_s.lower().endswith("@g.us") or "(group)" in label.lower(),
                "deleted_count": int(cnt or 0),
                "timestamp": _ts_to_iso(ts_raw) if ts_raw is not None else None,
                "source": path,
                "social_app": "whatsapp",
                "is_deleted": True,
                "body": f"{int(cnt or 0)} deleted/recovered messages",
                "text_body": f"{int(cnt or 0)} deleted/recovered messages",
            }
        )
    return out


def format_chat_preview_body(messages: list[dict[str, Any]], *, path: str, max_msgs: int = 40) -> str:
    """Build a plain-text preview body for examiners."""
    app = infer_social_app(path) or "chat"
    lines = [
        f"{app.replace('_', ' ').title()} chat database (human-readable extract)",
        f"Path: {path}",
        f"Messages shown: {min(len(messages), max_msgs)} of {len(messages)}",
        "",
    ]
    if not messages:
        lines.append(
            "No plaintext message rows were recovered from this SQLite file.\n"
            "The database may be encrypted, schema-unknown, or contain only binary blobs.\n"
            "Use Open in new tab to download the raw database."
        )
        return "\n".join(lines)
    for rec in messages[:max_msgs]:
        sender = rec.get("sender") or "unknown"
        chat = rec.get("conversation") or rec.get("chat") or ""
        ts = rec.get("timestamp") or "—"
        body = rec.get("text_body") or rec.get("body") or ""
        head = f"[{ts}] {chat} · {sender}" if chat else f"[{ts}] {sender}"
        lines.append(head)
        lines.append(str(body))
        lines.append("")
    return "\n".join(lines)


def _is_useful_recovered_text(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 2:
        return False
    low = t.lower()
    if "deleted this message" in low or t.startswith("🚫"):
        return False
    if t.startswith("{") and any(k in low for k in ("\"code\":", "bizintegrity")):
        return False
    try:
        from app.services.mobile_acquire.sqlite_deleted import _is_schema_or_index_junk

        if _is_schema_or_index_junk(t):
            return False
    except Exception:
        if any(
            tok in low
            for tok in (
                "create virtual table",
                "create table",
                "using fts",
                "wa_tokenizer",
                "tokenize=",
            )
        ):
            return False
    return True


def extract_searchable_message_texts_from_path(db_path: str, source_path: str) -> list[dict[str, Any]]:
    """Pull candidate original bodies from ChatSearch FTS or notification stores."""
    if not db_path or not os.path.exists(db_path):
        return []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        cur = conn.cursor()
        low_path = _norm_path(source_path) + " " + _norm_path(db_path)
        if "notification" in low_path or "pushstore" in low_path:
            kind = "whatsapp_notification"
        else:
            kind = "whatsapp_search_index"
        return _extract_searchable_texts(cur, source_path, recovery_state=kind)
    except Exception:
        return []
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _extract_searchable_texts(
    cur: sqlite3.Cursor,
    source: str,
    *,
    recovery_state: str,
) -> list[dict[str, Any]]:
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 300")
        tables = [str(r[0]) for r in cur.fetchall()]
    except sqlite3.Error:
        return []
    out: list[dict[str, Any]] = []
    prefer = (
        "docs_content",
        "c0docs_content",
        "metadata",
        "message_ftsv2_content",
        "ZWAMESSAGEDATAITEM",
        "notifications",
        "notification",
        "records",
        "record",
    )
    lower_map = {t.lower(): t for t in tables}
    skip_live = {
        "zwamessage",
        "message",
        "messages",
        "msg",
        "chat_messages",
        "messages_quotes",
    }
    ordered = [lower_map[p.lower()] for p in prefer if p.lower() in lower_map]
    for t in tables:
        tl = t.lower()
        if tl in skip_live:
            continue
        if t not in ordered and any(
            x in tl
            for x in ("docs_content", "notification", "fts", "message_text", "alert")
        ):
            ordered.append(t)
    seen: set[str] = set()
    for table in ordered[:20]:
        cols = _table_columns(cur, table)
        text_col = _pick(
            cols,
            (
                "c0docs_content",
                "c0content",
                "docs_content",
                "text",
                "body",
                "message",
                "content",
                "title",
                "subtitle",
                "alert",
                "ztext",
                "data",
            ),
        )
        if not text_col:
            continue
        ts_col = _pick(cols, ("timestamp", "date", "zmessagedate", "time", "created_at"))
        jid_col = _pick(cols, ("jid", "chat_jid", "zfromjid", "sender", "bundle_id", "app"))
        sel = [f'"{text_col}"']
        extra = []
        if ts_col:
            extra.append(ts_col)
            sel.append(f'"{ts_col}"')
        if jid_col:
            extra.append(jid_col)
            sel.append(f'"{jid_col}"')
        try:
            cur.execute(
                f'SELECT {", ".join(sel)} FROM "{table}" '
                f'WHERE "{text_col}" IS NOT NULL AND length(CAST("{text_col}" AS TEXT)) > 1 '
                f"LIMIT 8000"
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            continue
        for row in rows:
            raw = str(row[0] or "").strip()
            # Notification blobs sometimes embed JSON / plist alert text.
            if raw.startswith("bplist") or (raw[:1] in "{<" and "whatsapp" in raw.lower()):
                extracted = _alert_body_from_blob(raw)
                raw = extracted or raw
            if not _is_useful_recovered_text(raw):
                continue
            if "whatsapp" in (jid_col or "") and jid_col:
                pass
            key = raw[:180]
            if key in seen:
                continue
            seen.add(key)
            ts = None
            jid = None
            idx = 1
            if ts_col:
                ts = _ts_to_iso(row[idx]) if idx < len(row) else None
                idx += 1
            if jid_col and idx < len(row):
                jid = str(row[idx] or "").strip() or None
            if jid and "whatsapp" not in jid.lower() and recovery_state == "whatsapp_notification":
                # Keep rows without bundle filter when the file itself is a WhatsApp pushstore.
                if "whatsapp" not in (jid or "").lower() and "net.whatsapp" not in (jid or "").lower():
                    if len(raw) < 8:
                        continue
            out.append(
                {
                    "text": raw[:4000],
                    "timestamp": ts,
                    "chat_jid": jid,
                    "source": source,
                    "table": table,
                    "recovery_state": recovery_state,
                }
            )
            if len(out) >= 12_000:
                return out
    return out


def _alert_body_from_blob(raw: str) -> str | None:
    """Best-effort alert/body extraction from JSON or XML-ish notification payloads."""
    if not raw:
        return None
    for pat in (
        r'"body"\s*:\s*"([^"\\]{2,400})"',
        r'"alert"\s*:\s*"([^"\\]{2,400})"',
        r"<string>([^<]{2,400})</string>",
        r"alert[^a-zA-Z]{0,20}([^\x00]{4,200})",
    ):
        m = re.search(pat, raw)
        if m:
            text = m.group(1).strip()
            if _is_useful_recovered_text(text) and "aps" not in text.lower():
                return text
    return None


def match_deleted_original_text(
    deleted: dict[str, Any],
    corpus: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Match a revoke/unread placeholder to a ChatSearch or notification body."""
    if not corpus:
        return None
    want_ts = str(deleted.get("timestamp") or "")
    want_jid = str(deleted.get("chat_jid") or "").lower()
    want_name = str(deleted.get("conversation") or deleted.get("sender") or "").strip().lower()
    jid_token = want_jid.split("@", 1)[0] if want_jid else ""
    best: tuple[int, dict[str, Any]] | None = None
    for rec in corpus:
        text = str(rec.get("text") or "").strip()
        if not _is_useful_recovered_text(text):
            continue
        score = 1
        rec_jid = str(rec.get("chat_jid") or "").lower()
        if jid_token and jid_token in rec_jid:
            score += 5
        if want_name and want_name[:12] and want_name[:12] in (text.lower() + " " + rec_jid):
            score += 2
        rec_ts = str(rec.get("timestamp") or "")
        if want_ts and rec_ts:
            try:
                a = datetime.fromisoformat(want_ts.replace("Z", "+00:00"))
                b = datetime.fromisoformat(rec_ts.replace("Z", "+00:00"))
                delta = abs((a - b).total_seconds())
                if delta <= 90:
                    score += 6
                elif delta <= 15 * 60:
                    score += 3
            except Exception:
                if want_ts[:19] == rec_ts[:19]:
                    score += 6
        if rec.get("recovery_state") == "whatsapp_notification":
            score += 1
        if best is None or score > best[0]:
            best = (score, rec)
    if not best or best[0] < 3:
        return None
    return best[1]


def _recover_deleted_text_from_indexes(
    cur: sqlite3.Cursor,
    path: str,
    deleted_msgs: list[dict[str, Any]],
) -> None:
    """Use FTS / data-item tables in the same DB to restore unread deleted bodies."""
    pending = [
        m
        for m in deleted_msgs
        if _is_placeholder_or_empty(str(m.get("text_body") or m.get("body") or ""))
        and not m.get("original_content")
    ]
    if not pending:
        return
    corpus = _extract_searchable_texts(cur, path, recovery_state="whatsapp_search_index")
    if not corpus:
        return
    for msg in pending:
        hit = match_deleted_original_text(msg, corpus)
        if not hit:
            continue
        original = str(hit.get("text") or "").strip()
        if not original:
            continue
        if _is_whatsapp_protocol_noise(original):
            continue
        placeholder = (
            "🚫 You deleted this message"
            if msg.get("from_me")
            else "🚫 This message was deleted"
        )
        body = f"{original}\n({placeholder})"
        msg["body"] = body[:4000]
        msg["text_body"] = body[:4000]
        msg["original_content"] = original
        msg["recovery_state"] = hit.get("recovery_state") or "whatsapp_search_index"
        msg["text"] = (
            f"WhatsApp · {msg.get('conversation') or ''} · {msg.get('sender')}: {original[:240]}"
        )
