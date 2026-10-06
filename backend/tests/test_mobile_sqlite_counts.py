"""Tests for modern iOS WhatsApp SQLite counting."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from app.services.mobile_forensic.sqlite_counts import (
    analyze_mail_db,
    analyze_whatsapp_db,
    count_ios_manifest_whatsapp_media,
)


def _db_with(tables: dict[str, list[tuple]]) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        path = tmp.name
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    for name, rows in tables.items():
        if not rows:
            cur.execute(f'CREATE TABLE "{name}" (id INTEGER)')
            continue
        cols = rows[0]
        cur.execute(f'CREATE TABLE "{name}" ({", ".join(f"{c} TEXT" for c in cols)})')
        for row in rows[1:]:
            placeholders = ", ".join("?" for _ in row)
            cur.execute(f'INSERT INTO "{name}" VALUES ({placeholders})', row)
    conn.commit()
    conn.close()
    data = Path(path).read_bytes()
    Path(path).unlink(missing_ok=True)
    return data


def test_chatsearch_docs_content_counts_messages():
    data = _db_with(
        {
            "docs_content": [("id", "c0"), ("1", "hello"), ("2", "world"), ("3", "group")],
            "metadata": [("docid",), ("1",), ("2",), ("3",)],
        }
    )
    out = analyze_whatsapp_db(data, "whatsapp/fts/ChatSearchV5f.sqlite")
    assert out["messages"] == 3
    assert out["source_table"]["messages"] == "docs_content"


def test_extchat_thread_messages_and_groups():
    data = _db_with(
        {
            "thread_messages": [
                ("id", "chat_jid"),
                ("1", "alice@s.whatsapp.net"),
                ("2", "bob@s.whatsapp.net"),
                ("3", "family@g.us"),
                ("4", "family@g.us"),
            ],
            "group_metadata": [("group_metadata_id", "group_jid"), ("1", "family@g.us")],
        }
    )
    out = analyze_whatsapp_db(data, "whatsapp/ExtChatDB/ExtChatDatabase.sqlite")
    assert out["messages"] == 4
    assert out["chats"] >= 3
    assert out["groups"] >= 1


def test_callhistory_zwacdcallevent():
    data = _db_with(
        {
            "ZWACDCALLEVENT": [("Z_PK",), ("1",), ("2",)],
            "ZWACDCALLEVENTPARTICIPANT": [("Z_PK",), ("1",), ("2",), ("3",)],
        }
    )
    out = analyze_whatsapp_db(data, "whatsapp/CallHistory.sqlite")
    assert out["calls"] == 2
    # Participant table must NOT inflate groups
    assert out["groups"] == 0


def test_gmail_pane_archives_record():
    data = _db_with({"record": [("id",), ("1",), ("2",), ("3",)]})
    out = analyze_mail_db(data, "mail/pane_archives.sqlite3")
    assert out["emails"] == 3


def test_ios_chatstorage_counts_type14_deleted_without_flag_column():
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
        path = tmp.name
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER, ZMESSAGETYPE INTEGER, ZTEXT TEXT, ZMEDIAITEM INTEGER)"
    )
    conn.executemany(
        "INSERT INTO ZWAMESSAGE VALUES (?,?,?,?)",
        [(1, 0, "live", None), (2, 14, None, 9), (3, 14, None, 10), (4, 0, "ok", None)],
    )
    conn.commit()
    conn.close()
    data = Path(path).read_bytes()
    Path(path).unlink(missing_ok=True)
    out = analyze_whatsapp_db(data, "whatsapp/ChatStorage.sqlite")
    assert out["messages"] == 4
    assert out["deleted_messages"] == 2


def test_ios_manifest_counts_whatsapp_media_rows():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        path = tmp.name
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)")
    conn.executemany(
        "INSERT INTO Files VALUES (?,?,?,1)",
        [
            ("a", "AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "Message/Media/x.jpg"),
            ("b", "AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"),
            ("c", "HomeDomain", "Library/SMS/sms.db"),
        ],
    )
    conn.commit()
    conn.close()
    data = Path(path).read_bytes()
    Path(path).unlink(missing_ok=True)
    assert count_ios_manifest_whatsapp_media(data) == 1


def test_android_message_type_is_not_treated_as_ios_revoke():
    data = _db_with(
        {
            "message": [
                ("_id", "messagetype", "text_data"),
                ("1", "14", "not-an-ios-revoke"),
                ("2", "0", "hello"),
            ]
        }
    )
    out = analyze_whatsapp_db(data, "com.whatsapp/databases/msgstore.db")
    assert out["messages"] == 2
    assert out["deleted_messages"] == 0
