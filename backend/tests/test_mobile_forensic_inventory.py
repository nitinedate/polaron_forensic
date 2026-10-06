"""Mobile forensic inventory — AXIOM-style WhatsApp SQLite counts (disk path not used)."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.mobile_forensic.sqlite_counts import analyze_whatsapp_db
from app.services.mobile_forensic.inventory import _map_axiom_name_to_key, count_mobile_axiom_artifact


def _make_msgstore() -> bytes:
    path = Path(tempfile.mkstemp(suffix=".db")[1])
    try:
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, text TEXT)")
        cur.executemany("INSERT INTO message(text) VALUES (?)", [("hi",), ("yo",), ("bye",)])
        cur.execute("CREATE TABLE chat (id INTEGER PRIMARY KEY, jid TEXT, subject TEXT)")
        cur.executemany(
            "INSERT INTO chat(jid, subject) VALUES (?, ?)",
            [("x@s.whatsapp.net", None), ("g@g.us", "Family")],
        )
        cur.execute("CREATE TABLE call_log (id INTEGER PRIMARY KEY)")
        cur.execute("INSERT INTO call_log DEFAULT VALUES")
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def test_analyze_whatsapp_db_counts_message_chat_call() -> None:
    data = _make_msgstore()
    out = analyze_whatsapp_db(data, "msgstore.db")
    assert out["messages"] == 3
    assert out["chats"] == 2
    assert out["calls"] == 1
    assert out["groups"] >= 1


def test_axiom_name_mapping_whatsapp_families() -> None:
    assert _map_axiom_name_to_key("WhatsApp Messages - Android") == "whatsapp_messages"
    assert _map_axiom_name_to_key("WhatsApp Chats - Android") == "whatsapp_chats"
    assert _map_axiom_name_to_key("WhatsApp Calls") == "whatsapp_calls"
    assert _map_axiom_name_to_key("WhatsApp Contacts - Android") == "whatsapp_contacts"
    assert _map_axiom_name_to_key("WhatsApp Groups - Android") == "whatsapp_groups"
    assert _map_axiom_name_to_key("WhatsApp Media - Android") == "whatsapp_media"
    assert _map_axiom_name_to_key("WhatsApp Encrypted Backups - Android") == "whatsapp_encrypted_backups"
    assert _map_axiom_name_to_key("Android SMS") == "sms"


def test_count_mobile_uses_snapshot_not_disk() -> None:
    db = MagicMock()
    snap = {
        "platform": "Android",
        "total_files": 10,
        "counts": {"whatsapp_messages": 42, "sms": 0},
        "samples": {},
        "limitations": ["No WhatsApp msgstore"],
        "db_paths": {"whatsapp": ["logical/msgstore.db"], "sms": [], "call_logs": []},
    }
    with patch("app.services.mobile_forensic.inventory.is_mobile_job", return_value=True), patch(
        "app.services.mobile_forensic.inventory.build_mobile_inventory_snapshot",
        return_value=snap,
    ):
        result = count_mobile_axiom_artifact(db, "job-1", artifact_name="WhatsApp Messages - Android")
    assert result["count"] == 42
    assert result["domain"] == "artifact_record"
    assert "msgstore" in (result["sample_paths"][0] if result["sample_paths"] else "")
