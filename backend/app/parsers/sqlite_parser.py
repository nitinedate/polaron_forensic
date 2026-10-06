"""SQLite parser — tables + browser history / WhatsApp message extraction."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import PurePosixPath
from typing import Any

_WHATSAPP_MSG_LIMIT = 30  # legacy default; prefer _whatsapp_msg_limit()


def _whatsapp_msg_limit() -> int:
    from app.config import get_settings

    return max(int(getattr(get_settings(), "parse_whatsapp_msg_limit", 500) or 500), 1)


def _sqlite_write_cap() -> int:
    from app.config import get_settings

    return max(int(getattr(get_settings(), "parse_sqlite_max_bytes", 512_000_000) or 512_000_000), 1_000_000)


_BROWSER_MARKERS = ("chrome", "edge", "brave", "chromium", "opera", "vivaldi", "ebwebview", "firefox", "mozilla")
_BROWSER_DB_NAMES = frozenset({
    "history", "favicons", "top sites", "web data", "visited links", "places.sqlite", "cookies", "login data",
})


def _browser_url_limit() -> int:
    from app.config import get_settings

    return max(int(get_settings().browser_url_parse_limit or 5000), 1)


def _path_lower(path: str) -> str:
    return path.replace("\\", "/").lower()


def _is_browser_history(path: str) -> bool:
    p = _path_lower(path)
    name = PurePosixPath(p).name
    return name == "history" and any(x in p for x in _BROWSER_MARKERS)


def _is_browser_login_data(path: str) -> bool:
    p = _path_lower(path)
    return PurePosixPath(p).name == "login data" and any(x in p for x in _BROWSER_MARKERS)


def _browser_login_time(raw: Any) -> str | None:
    try:
        return _chrome_epoch_to_iso(int(raw or 0))
    except Exception:
        return None


def _extract_browser_login_accounts(cur: sqlite3.Cursor, path: str) -> list[dict[str, Any]]:
    """Extract account identities from Chromium Login Data without exposing secrets."""
    records: list[dict[str, Any]] = []
    try:
        cur.execute("PRAGMA table_info(logins)")
        cols = {str(row[1]) for row in cur.fetchall()}
    except sqlite3.Error:
        return records
    if not cols or "username_value" not in cols:
        return records
    origin_col = "origin_url" if "origin_url" in cols else ("action_url" if "action_url" in cols else None)
    if not origin_col:
        return records
    time_col = "date_last_used" if "date_last_used" in cols else ("date_created" if "date_created" in cols else None)
    select = f'SELECT "{origin_col}", username_value' + (f', "{time_col}"' if time_col else '') + ' FROM logins WHERE username_value IS NOT NULL AND length(username_value) > 0 LIMIT 5000'
    try:
        cur.execute(select)
        rows = cur.fetchall()
    except sqlite3.Error:
        return records
    seen: set[tuple[str, str]] = set()
    for row in rows:
        url = str(row[0] or "").strip()
        account = str(row[1] or "").strip()
        if not account:
            continue
        key = (url.lower(), account.lower())
        if key in seen:
            continue
        seen.add(key)
        when = _browser_login_time(row[2]) if time_col and len(row) > 2 else None
        records.append({
            "record_type": "browser_login_account",
            "url": url[:2000] or None,
            "account": account[:320],
            "event_time": when,
            "source": path,
            "text": f"Browser saved-login account: {account}" + (f" for {url}" if url else ""),
        })
    return records


def _is_firefox_places(path: str) -> bool:
    p = _path_lower(path)
    return PurePosixPath(p).name == "places.sqlite" or ("/firefox/" in p and p.endswith("places.sqlite"))


def _is_browser_url_db(path: str) -> bool:
    p = _path_lower(path)
    name = PurePosixPath(p).name
    if name in _BROWSER_DB_NAMES and any(x in p for x in _BROWSER_MARKERS):
        return True
    return False


def _is_whatsapp_db(path: str) -> bool:
    p = _path_lower(path)
    name = PurePosixPath(p).name
    return (
        "whatsapp" in p
        or name in {
            "msgstore.db",
            "messages.db",
            "wa.db",
            "chatstorage.sqlite",
            "extchatdatabase.sqlite",
            "chatsearchv5f.sqlite",
        }
        or "chatstorage" in name
        or "extchat" in name
    )


def _is_sms_db(path: str) -> bool:
    p = _path_lower(path)
    name = PurePosixPath(p).name
    return (
        name in {"mmssms.db", "sms.db", "chat.db"}
        or "/sms.db" in p
        or "mmssms" in p
        or ("imessage" in p and name.endswith(".db"))
    )


def _chrome_epoch_to_iso(micro: int) -> str | None:
    # Chrome time: microseconds since 1601-01-01
    if not micro or micro < 0:
        return None
    try:
        from datetime import datetime, timedelta, timezone

        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micro)
        if dt.year < 1990 or dt.year > 2100:
            return None
        return dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _extract_browser_urls(cur: sqlite3.Cursor, path: str) -> list[dict[str, Any]]:
    limit = _browser_url_limit()
    records: list[dict[str, Any]] = []
    try:
        cur.execute(
            """SELECT u.url, u.title, u.visit_count, v.visit_time
               FROM urls u
               LEFT JOIN visits v ON v.url = u.id
               WHERE u.url IS NOT NULL AND length(u.url) > 7
               ORDER BY COALESCE(v.visit_time, 0) DESC, u.visit_count DESC
               LIMIT ?""",
            (limit,),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        try:
            cur.execute(
                """SELECT url, title, visit_count, last_visit_time
                   FROM urls WHERE url IS NOT NULL AND length(url) > 7
                   ORDER BY last_visit_time DESC LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            return records

    seen: set[str] = set()
    for row in rows:
        url = (row[0] or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        title = (row[1] or "").strip() if len(row) > 1 else ""
        visits = row[2] if len(row) > 2 else None
        when = None
        if len(row) > 3 and isinstance(row[3], int):
            when = _chrome_epoch_to_iso(row[3])
        rec = {
            "record_type": "browser_url",
            "url": url[:2000],
            "title": title[:500] if title else None,
            "visit_count": visits,
            "last_visit": when,
            "source": path,
            "text": f"Visited URL: {url}" + (f" ({title})" if title else "") + (f" at {when}" if when else ""),
        }
        records.append(rec)
    if records:
        records.insert(0, {
            "record_type": "browser_history_summary",
            "url_count_sampled": len(records),
            "source": path,
            "text": f"Browser history from {path}: {len(records)} recent URLs sampled",
        })
    return records


def _extract_firefox_urls(cur: sqlite3.Cursor, path: str) -> list[dict[str, Any]]:
    limit = _browser_url_limit()
    records: list[dict[str, Any]] = []
    try:
        cur.execute(
            """SELECT p.url, p.title, p.visit_count, h.visit_date
               FROM moz_places p
               LEFT JOIN moz_historyvisits h ON h.place_id = p.id
               WHERE p.url IS NOT NULL AND length(p.url) > 7
               ORDER BY COALESCE(h.visit_date, 0) DESC
               LIMIT ?""",
            (limit,),
        )
        rows = cur.fetchall()
    except sqlite3.Error:
        return records
    seen: set[str] = set()
    for row in rows:
        url = (row[0] or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        title = (row[1] or "").strip() if len(row) > 1 else ""
        when = None
        if len(row) > 3 and isinstance(row[3], int):
            # Firefox: microseconds since Unix epoch
            try:
                from datetime import datetime, timezone

                when = datetime.fromtimestamp(row[3] / 1_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                when = None
        records.append({
            "record_type": "browser_url",
            "url": url[:2000],
            "title": title[:500] if title else None,
            "visit_count": row[2] if len(row) > 2 else None,
            "last_visit": when,
            "source": path,
            "text": f"Visited URL: {url}" + (f" ({title})" if title else ""),
        })
    return records


def _extract_browser_url_inventory(data: bytes, path: str) -> list[dict[str, Any]]:
    """Favicons / Web Data / Top Sites — reuse shared inventory extractor."""
    from app.services.browser_url_inventory import extract_url_records_from_sqlite

    limit = _browser_url_limit()
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rec in extract_url_records_from_sqlite(data, path):
        url = (rec.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        records.append({
            "record_type": "browser_url",
            "url": url[:2000],
            "visit_count": rec.get("visit_count"),
            "source": path,
            "text": f"Browser URL: {url}",
        })
        if len(records) >= limit:
            break
    if records:
        records.insert(0, {
            "record_type": "browser_history_summary",
            "url_count_sampled": len(records),
            "source": path,
            "text": f"Browser URLs from {path}: {len(records)} URLs sampled",
        })
    return records


def _wa_ts_to_iso(raw) -> str | None:
    """Best-effort WhatsApp timestamp → ISO (handles s / ms / FILETIME-ish)."""
    if raw is None:
        return None
    try:
        n = float(raw)
    except (TypeError, ValueError):
        s = str(raw).strip()
        return s[:32] if s else None
    try:
        from datetime import datetime, timezone

        if n > 1e17:  # 100ns FILETIME-like
            n = (n / 10_000_000) - 11644473600
        elif n > 1e12:
            n = n / 1000.0
        if n < 1e9:
            return None
        return datetime.fromtimestamp(n, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _extract_whatsapp_deleted(cur: sqlite3.Cursor, path: str, tables: list[str]) -> list[dict[str, Any]]:
    """Recover deleted WhatsApp rows from dedicated tables or status flags."""
    records: list[dict[str, Any]] = []
    lower_map = {t.lower(): t for t in tables}
    deleted_tables = (
        "deleted_messages",
        "message_deleted",
        "deleted_chat_messages",
        "zwamessagedeleted",
        "message_deletes",
    )
    for cand in deleted_tables:
        real = lower_map.get(cand)
        if not real:
            continue
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{real}"')
            n = int(cur.fetchone()[0] or 0)
            records.append({
                "record_type": "whatsapp_summary",
                "table": real,
                "deleted_message_count": n,
                "is_deleted": True,
                "social_app": "whatsapp",
                "recovery_state": "social_deleted",
                "source": path,
                "text": f"WhatsApp deleted messages table '{real}': {n} rows in {path}",
            })
            cur.execute(f'PRAGMA table_info("{real}")')
            cols = {str(r[1]).lower(): str(r[1]) for r in cur.fetchall()}
            text_col = next((cols[c] for c in ("text", "body", "message", "data", "ztext") if c in cols), None)
            ts_col = next(
                (cols[c] for c in ("timestamp", "time", "date", "message_timestamp", "zmessagedate", "deleted_at") if c in cols),
                None,
            )
            if text_col:
                sel = f'SELECT "{text_col}"' + (f', "{ts_col}"' if ts_col else "") + f' FROM "{real}" LIMIT 40'
                cur.execute(sel)
                for row in cur.fetchall():
                    body = str(row[0] or "")[:500].strip()
                    if not body:
                        continue
                    deleted_at = _wa_ts_to_iso(row[1]) if ts_col and len(row) > 1 else None
                    records.append({
                        "record_type": "whatsapp_message_deleted",
                        "text_body": body,
                        "deleted_at": deleted_at,
                        "is_deleted": True,
                        "social_app": "whatsapp",
                        "recovery_state": "social_deleted",
                        "source": path,
                        "text": f"Deleted WhatsApp message: {body}",
                    })
        except sqlite3.Error:
            continue

    # Live tables with an explicit deleted / revoke marker.
    # iOS ChatStorage: Delete-for-Everyone uses ZMESSAGETYPE=14 placeholders.
    # Do NOT use ZFLAGS & 0x1000000 — that bit is set on nearly all modern rows.
    for tbl in ("messages", "message", "msg", "chat_messages", "ZWAMESSAGE"):
        real = lower_map.get(tbl.lower())
        if not real:
            continue
        try:
            cur.execute(f'PRAGMA table_info("{real}")')
            cols = {str(r[1]).lower(): str(r[1]) for r in cur.fetchall()}
            flag_col = next(
                (
                    cols[c]
                    for c in (
                        "deleted",
                        "is_deleted",
                        "zismissagefrommedeleted",
                        "zisdeleted",
                        "zdeleted",
                    )
                    if c in cols
                ),
                None,
            )
            msg_type_col = cols.get("zmessagetype") or cols.get("messagetype")
            text_col = next(
                (cols[c] for c in ("text", "body", "message", "data", "ztext") if c in cols),
                None,
            )
            ts_col = next(
                (
                    cols[c]
                    for c in ("timestamp", "time", "date", "message_timestamp", "zmessagedate")
                    if c in cols
                ),
                None,
            )
            from_me_col = next(
                (cols[c] for c in ("zisfromme", "from_me", "key_from_me") if c in cols),
                None,
            )
            where_parts: list[str] = []
            if flag_col:
                where_parts.append(f'CAST("{flag_col}" AS INTEGER) != 0')
            if msg_type_col and real.lower() == "zwamessage":
                where_parts.append(f'CAST("{msg_type_col}" AS INTEGER) = 14')
            if not where_parts:
                continue
            where = " OR ".join(f"({w})" for w in where_parts)
            cur.execute(f'SELECT COUNT(*) FROM "{real}" WHERE {where}')
            n = int(cur.fetchone()[0] or 0)
            if n <= 0:
                continue
            records.append({
                "record_type": "whatsapp_summary",
                "table": real,
                "deleted_message_count": n,
                "is_deleted": True,
                "social_app": "whatsapp",
                "recovery_state": "social_deleted",
                "source": path,
                "text": f"WhatsApp flagged-deleted / revoked rows in '{real}': {n}",
            })
            sel_cols: list[str] = []
            if text_col:
                sel_cols.append(f'"{text_col}"')
            if ts_col:
                sel_cols.append(f'"{ts_col}"')
            if from_me_col:
                sel_cols.append(f'"{from_me_col}"')
            if not sel_cols:
                continue
            cur.execute(
                f'SELECT {", ".join(sel_cols)} FROM "{real}" WHERE {where} LIMIT 500'
            )
            for row in cur.fetchall():
                body = str(row[0] or "").strip() if text_col else ""
                idx = 1 if text_col else 0
                deleted_at = None
                if ts_col and len(row) > idx:
                    deleted_at = _wa_ts_to_iso(row[idx])
                    idx += 1
                from_me = False
                if from_me_col and len(row) > idx:
                    from_me = row[idx] in (1, True, "1")
                # Peer JIDs sometimes sit in ZTEXT on type-14 rows — not content.
                body_l = body.lower()
                if body and " " not in body and (
                    "@s.whatsapp.net" in body_l
                    or body_l.endswith("@g.us")
                    or body_l.endswith("@lid")
                ):
                    body = ""
                if not body:
                    body = (
                        "🚫 You deleted this message"
                        if from_me
                        else "🚫 This message was deleted"
                    )
                records.append({
                    "record_type": "whatsapp_message_deleted",
                    "text_body": body[:2000],
                    "body": body[:2000],
                    "deleted_at": deleted_at,
                    "timestamp": deleted_at,
                    "from_me": from_me,
                    "sender": "Me" if from_me else "unknown",
                    "is_deleted": True,
                    "social_app": "whatsapp",
                    "recovery_state": "whatsapp_revoke_type14",
                    "source": path,
                    "text": f"Deleted WhatsApp message: {body[:240]}",
                })
        except sqlite3.Error:
            continue
    return records


def _infer_social_app_from_path(path: str) -> str | None:
    low = (path or "").replace("\\", "/").lower()
    for marker, app in (
        ("whatsapp", "whatsapp"),
        ("msgstore", "whatsapp"),
        ("chatstorage", "whatsapp"),
        ("telegram", "telegram"),
        ("signal", "signal"),
        ("instagram", "instagram"),
        ("facebook", "facebook"),
        ("messenger", "facebook"),
        ("snapchat", "snapchat"),
        ("discord", "discord"),
        ("viber", "viber"),
        ("wechat", "wechat"),
        ("linkedin", "linkedin"),
        ("skype", "skype"),
        ("slack", "slack"),
        ("teams", "teams"),
    ):
        if marker in low:
            return app
    return None


def _extract_social_deleted(cur: sqlite3.Cursor, path: str, tables: list[str]) -> list[dict[str, Any]]:
    """Generic deleted-row recovery for messaging apps (Telegram/Signal/…/WhatsApp)."""
    app = _infer_social_app_from_path(path)
    if not app:
        return []
    # WhatsApp has a richer dedicated extractor — still emit generic summaries here for
    # shared deleted_* table names found in multi-app dumps.
    records: list[dict[str, Any]] = []
    lower_map = {t.lower(): t for t in tables}
    deleted_tables = (
        "deleted_messages",
        "message_deleted",
        "deleted_chat_messages",
        "messages_deleted",
        "deleted_dialogs",
        "hidden_messages",
    )
    for cand in deleted_tables:
        real = lower_map.get(cand)
        if not real:
            continue
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{real}"')
            n = int(cur.fetchone()[0] or 0)
            if n <= 0:
                continue
            records.append({
                "record_type": "social_message_deleted",
                "table": real,
                "deleted_message_count": n,
                "is_deleted": True,
                "social_app": app,
                "recovery_state": "social_deleted",
                "source": path,
                "text": f"{app.title()} deleted table '{real}': {n} rows in {path}",
            })
            cur.execute(f'PRAGMA table_info("{real}")')
            cols = {str(r[1]).lower(): str(r[1]) for r in cur.fetchall()}
            text_col = next(
                (cols[c] for c in ("text", "body", "message", "data", "content", "ztext") if c in cols),
                None,
            )
            ts_col = next(
                (
                    cols[c]
                    for c in ("timestamp", "time", "date", "message_timestamp", "deleted_at", "zmessagedate")
                    if c in cols
                ),
                None,
            )
            if not text_col:
                continue
            sel = f'SELECT "{text_col}"' + (f', "{ts_col}"' if ts_col else "") + f' FROM "{real}" LIMIT 40'
            cur.execute(sel)
            for row in cur.fetchall():
                body = str(row[0] or "")[:500].strip()
                if not body:
                    continue
                deleted_at = _wa_ts_to_iso(row[1]) if ts_col and len(row) > 1 else None
                records.append({
                    "record_type": "social_message_deleted",
                    "text_body": body,
                    "deleted_at": deleted_at,
                    "is_deleted": True,
                    "social_app": app,
                    "recovery_state": "social_deleted",
                    "source": path,
                    "text": f"Deleted {app} message: {body}",
                })
        except sqlite3.Error:
            continue
    return records


def _extract_whatsapp(cur: sqlite3.Cursor, path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 200")
        tables = [r[0] for r in cur.fetchall()]
    except sqlite3.Error:
        tables = []
    records.extend(_extract_whatsapp_deleted(cur, path, tables))
    records.extend(_extract_social_deleted(cur, path, tables))
    try:
        from app.services.chat_message_extract import extract_chat_messages_from_connection

        live = extract_chat_messages_from_connection(
            cur, path, limit=_whatsapp_msg_limit()
        )
        records.extend(live)
        if live:
            records.insert(
                0,
                {
                    "record_type": "whatsapp_summary",
                    "message_count": len(live),
                    "source": path,
                    "text": f"WhatsApp readable messages extracted: {len(live)} from {path}",
                },
            )
            return records
    except Exception:
        pass
    # Fallback: classic Android/Desktop table names
    for tbl in ("ZWAMESSAGE", "messages", "message", "msg", "chat_messages", "docs_content"):
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{tbl}"')
            count = cur.fetchone()[0]
            records.append({
                "record_type": "whatsapp_summary",
                "table": tbl,
                "message_count": count,
                "source": path,
                "text": f"WhatsApp messages table '{tbl}': {count} rows in {path}",
            })
            try:
                cur.execute(f'PRAGMA table_info("{tbl}")')
                cols = {r[1].lower() for r in cur.fetchall()}
                text_col = next(
                    (c for c in ("ztext", "text", "body", "message", "data", "c0docs_content") if c in cols),
                    None,
                )
                ts_col = next(
                    (c for c in ("zmessagedate", "timestamp", "time", "date", "message_timestamp") if c in cols),
                    None,
                )
                if text_col:
                    q = (
                        f'SELECT "{text_col}"'
                        + (f', "{ts_col}"' if ts_col else "")
                        + f' FROM "{tbl}" WHERE "{text_col}" IS NOT NULL LIMIT {_whatsapp_msg_limit()}'
                    )
                    cur.execute(q)
                    for row in cur.fetchall():
                        body = str(row[0])[:500].strip()
                        if not body:
                            continue
                        records.append({
                            "record_type": "whatsapp_message",
                            "text_body": body,
                            "body": body,
                            "source": path,
                            "text": f"WhatsApp message: {body}",
                        })
            except sqlite3.Error:
                pass
            break
        except sqlite3.Error:
            continue
    return records


def _extract_messaging_live(cur: sqlite3.Cursor, path: str) -> list[dict[str, Any]]:
    """SMS / Telegram / Signal / LinkedIn / … live plaintext messages."""
    from app.services.chat_message_extract import extract_chat_messages_from_connection

    return extract_chat_messages_from_connection(cur, path, limit=_whatsapp_msg_limit())


def parse_sqlite(data: bytes, path: str) -> list[dict[str, Any]]:
    if not data[:16].startswith(b"SQLite format"):
        return []

    records: list[dict[str, Any]] = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            # Always write the full buffer — forensic History/chat DBs must not be truncated.
            # Callers must only pass full-read data for forensic paths (see _read_budget_for_path).
            tmp.write(data)
            tmp_path = tmp.name
        if len(data) > _sqlite_write_cap():
            # Soft warning only — still parsed fully; operators see size in results.
            records.append({
                "format": "sqlite3",
                "path": path,
                "size_bytes": len(data),
                "large_db": True,
                "text": f"Large SQLite {path} ({len(data):,} bytes) — full parse",
            })
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 100")
        tables = [r[0] for r in cur.fetchall()]
        for tbl in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}"')
                count = cur.fetchone()[0]
                records.append({"table": tbl, "row_count": count, "database": path})
            except sqlite3.Error:
                records.append({"table": tbl, "row_count": None, "database": path})

        if _is_browser_history(path):
            records.extend(_extract_browser_urls(cur, path))
        elif _is_browser_login_data(path):
            records.extend(_extract_browser_login_accounts(cur, path))
        elif _is_firefox_places(path):
            records.extend(_extract_firefox_urls(cur, path))
        elif _is_browser_url_db(path):
            records.extend(_extract_browser_url_inventory(data, path))
        elif _is_whatsapp_db(path):
            records.extend(_extract_whatsapp(cur, path))
        elif _is_sms_db(path) or _infer_social_app_from_path(path):
            # Live plaintext rows + deleted residuals for SMS / Telegram / Signal / LinkedIn / …
            try:
                records.extend(_extract_messaging_live(cur, path))
            except Exception:
                pass
            records.extend(_extract_social_deleted(cur, path, tables))

        conn.close()
    except Exception:
        records.append({"format": "sqlite3", "size_bytes": len(data), "path": path})
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if not records:
        records.append({"format": "sqlite3", "size_bytes": len(data), "path": path})
    return records
