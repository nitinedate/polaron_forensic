"""Modern Android msgstore.message.text_data extraction."""
from __future__ import annotations

import sqlite3
import tempfile

from app.services.chat_message_extract import extract_chat_messages_from_bytes


def _build_msgstore() -> bytes:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, agent INT, device INT, type INT, raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INT, hidden INT, subject TEXT, created_timestamp INT);
        CREATE TABLE message (
          _id INTEGER PRIMARY KEY, chat_row_id INT, from_me INT, key_id TEXT,
          sender_jid_row_id INT, status INT, broadcast INT, recipient_count INT,
          participant_hash TEXT, origination_flags INT, origin INT, timestamp INT,
          received_timestamp INT, receipt_server_timestamp INT, message_type INT,
          text_data TEXT, starred INT, lookup_tables INT, message_add_on_flags INT,
          view_mode INT, sort_id INT, translated_text TEXT, view_replies_thread_id INT
        );
        INSERT INTO jid VALUES (1, '919999999999', 's.whatsapp.net', 0, 0, 0, '919999999999@s.whatsapp.net');
        INSERT INTO jid VALUES (2, '120363', 'g.us', 0, 0, 1, '120363@g.us');
        INSERT INTO jid VALUES (3, '918888888888', 's.whatsapp.net', 0, 0, 0, '918888888888@s.whatsapp.net');
        INSERT INTO chat VALUES (1, 1, 0, NULL, 1);
        INSERT INTO chat VALUES (2, 2, 0, 'School Group', 1);
        -- real text
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (10, 1, 0, 'k1', 3, 1767079048000, 0, 'Phone karo bhai');
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (11, 2, 1, 'k2', 0, 1767079058000, 0, 'Tomorrow is a Holiday');
        -- contact card (must be skipped)
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (12, 1, 0, 'k3', 3, 1767079068000, 4, 'tokarshi bhawanji');
        -- system (skip)
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (13, 2, 1, 'k4', 0, 1767079078000, 7, 'Office ');
        -- image with caption
        INSERT INTO message (_id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, message_type, text_data)
        VALUES (14, 1, 0, 'k5', 3, 1767079088000, 1, 'see this photo');
        """
    )
    # dump to bytes via tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    import os

    os.close(fd)
    disk = sqlite3.connect(path)
    conn.backup(disk)
    disk.close()
    conn.close()
    with open(path, "rb") as f:
        data = f.read()
    os.unlink(path)
    return data


def test_modern_whatsapp_extracts_conversations_not_contact_names():
    data = _build_msgstore()
    path = "/data/data/com.whatsapp/databases/msgstore.db"
    msgs = extract_chat_messages_from_bytes(data, path, limit=50)
    bodies = [m.get("text_body") for m in msgs]
    assert "Phone karo bhai" in bodies
    assert "Tomorrow is a Holiday" in bodies
    assert "tokarshi bhawanji" not in bodies
    assert "Office " not in bodies
    assert any("see this photo" in (b or "") for b in bodies)
    # Chat / sender context present
    holiday = next(m for m in msgs if m.get("text_body") == "Tomorrow is a Holiday")
    assert holiday.get("conversation") == "School Group"
    assert holiday.get("sender") == "Me"
    phone = next(m for m in msgs if m.get("text_body") == "Phone karo bhai")
    assert phone.get("timestamp")
    assert "+918888888888" in str(phone.get("sender") or "")
