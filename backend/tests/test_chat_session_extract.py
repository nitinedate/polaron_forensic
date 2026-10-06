"""Fast WhatsApp session / deleted-only extract (no full message dump)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from app.services.chat_message_extract import (
    extract_chat_messages_from_path,
    extract_chat_sessions_from_connection,
)


def _ios_chatstorage(path: Path) -> None:
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE ZWACHATSESSION (Z_PK INTEGER PRIMARY KEY, ZPARTNERNAME TEXT, "
        "ZCONTACTJID TEXT, ZLASTMESSAGEDATE REAL, ZMESSAGECOUNTER INTEGER)"
    )
    cur.execute(
        "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER PRIMARY KEY, ZTEXT TEXT, ZMESSAGEDATE REAL, "
        "ZFROMJID TEXT, ZTOJID TEXT, ZISFROMME INTEGER, ZCHAT INTEGER, "
        "ZMESSAGETYPE INTEGER, ZISMESSAGEFROMMEDELETED INTEGER, ZSTANZAID TEXT)"
    )
    cur.execute(
        "CREATE TABLE docs_content (c0docs_content TEXT, timestamp REAL, jid TEXT)"
    )
    cur.executemany(
        "INSERT INTO ZWACHATSESSION VALUES (?,?,?,?,?)",
        [
            (1, "Alice", "15551234567@s.whatsapp.net", 700_000_000.0, 12),
            (2, "Family", "120363@g.us", 700_000_100.0, 40),
        ],
    )
    cur.executemany(
        "INSERT INTO ZWAMESSAGE VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            (10, "hello live", 700_000_000.0, "15551234567@s.whatsapp.net", None, 0, 1, 0, 0, "live-1"),
            (11, None, 700_000_050.0, "15551234567@s.whatsapp.net", None, 0, 1, 14, 0, "rev-unread-1"),
            (12, "group hi", 700_000_100.0, "15550001111@s.whatsapp.net", None, 0, 2, 0, 0, "grp-1"),
            (13, "gone", 700_000_110.0, None, "15551234567@s.whatsapp.net", 1, 1, 0, 1, "del-me-1"),
        ],
    )
    cur.execute(
        "INSERT INTO docs_content VALUES (?,?,?)",
        ("Meet me at the gate tonight", 700_000_050.0, "15551234567@s.whatsapp.net"),
    )
    conn.commit()
    conn.close()


def test_extract_chat_sessions_respects_limit_offset(tmp_path: Path) -> None:
    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    conn = sqlite3.connect(db_path)
    try:
        first = extract_chat_sessions_from_connection(
            conn.cursor(), str(db_path), limit=1, offset=0
        )
        second = extract_chat_sessions_from_connection(
            conn.cursor(), str(db_path), limit=1, offset=1
        )
        from app.services.chat_message_extract import count_chat_sessions_from_connection

        total = count_chat_sessions_from_connection(conn.cursor(), str(db_path))
    finally:
        conn.close()
    assert len(first) == 1
    assert len(second) == 1
    assert first[0]["conversation"] != second[0]["conversation"]
    assert total == 2


def test_extract_chat_sessions_ios(tmp_path: Path) -> None:
    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    conn = sqlite3.connect(db_path)
    try:
        rows = extract_chat_sessions_from_connection(
            conn.cursor(), str(db_path), limit=50
        )
    finally:
        conn.close()
    assert len(rows) == 2
    names = {r["conversation"] for r in rows}
    assert "Alice" in names
    assert "Family" in names
    assert all(r.get("session_row") for r in rows)


def test_extract_deleted_only_skips_live(tmp_path: Path) -> None:
    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    rows = extract_chat_messages_from_path(
        str(db_path),
        "App/WhatsApp/ChatStorage.sqlite",
        limit=50,
        deleted_only=True,
    )
    assert rows
    assert all(r.get("is_deleted") for r in rows)
    bodies = " ".join(str(r.get("text_body") or r.get("body") or "") for r in rows)
    assert "hello live" not in bodies
    assert "group hi" not in bodies


def test_extract_one_chat_row(tmp_path: Path) -> None:
    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    rows = extract_chat_messages_from_path(
        str(db_path),
        "App/WhatsApp/ChatStorage.sqlite",
        limit=50,
        chat_row_id=1,
    )
    assert rows
    assert all(int(r.get("chat_row_id") or 0) == 1 for r in rows)
    assert not any("group hi" in str(r.get("text_body") or "") for r in rows)


def test_deleted_recovers_original_from_search_index(tmp_path: Path) -> None:
    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    rows = extract_chat_messages_from_path(
        str(db_path),
        "App/WhatsApp/ChatStorage.sqlite",
        limit=50,
        deleted_only=True,
    )
    bodies = " ".join(str(r.get("original_content") or r.get("text_body") or "") for r in rows)
    assert "Meet me at the gate tonight" in bodies


def test_group_sessions_marked(tmp_path: Path) -> None:
    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    conn = sqlite3.connect(db_path)
    try:
        rows = extract_chat_sessions_from_connection(conn.cursor(), str(db_path), limit=50)
    finally:
        conn.close()
    groups = [r for r in rows if r.get("is_group")]
    assert len(groups) == 1
    assert groups[0]["conversation"] == "Family"


def test_count_ios_groups_uses_contact_jid(tmp_path: Path) -> None:
    from app.services.mobile_forensic.sqlite_counts import analyze_whatsapp_db

    db_path = tmp_path / "ChatStorage.sqlite"
    _ios_chatstorage(db_path)
    analyzed = analyze_whatsapp_db(db_path.read_bytes(), str(db_path))
    assert analyzed["groups"] >= 1
