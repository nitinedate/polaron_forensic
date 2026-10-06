from __future__ import annotations

import sqlite3
from pathlib import Path

from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers.files_media import FilesMediaParser
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
from app.services.mobile_forensic.plugins import ParseContext
from app.services.mobile_forensic.recovery.analyzers import SqliteHistoryAnalyzer


def _make_whatsapp_db(path: Path, rows: int) -> bytes:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """CREATE TABLE message (
                   _id INTEGER PRIMARY KEY,
                   timestamp INTEGER,
                   text_data TEXT,
                   from_me INTEGER,
                   sender TEXT,
                   chat_id TEXT,
                   key_id TEXT,
                   status INTEGER,
                   message_type INTEGER,
                   is_deleted INTEGER DEFAULT 0,
                   media_name TEXT,
                   media_url TEXT,
                   media_mime_type TEXT,
                   media_file_length INTEGER
               )"""
        )
        conn.executemany(
            """INSERT INTO message
               (_id, timestamp, text_data, from_me, sender, chat_id, key_id, status, message_type, is_deleted)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    i,
                    1_700_000_000_000 + i,
                    f"message-{i}",
                    i % 2,
                    f"user-{i % 7}@s.whatsapp.net",
                    "group-1@g.us",
                    f"KEY-{i}",
                    1,
                    0,
                    1 if i == rows else 0,
                )
                for i in range(1, rows + 1)
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return path.read_bytes()


def test_whatsapp_parser_has_no_5000_row_cap(tmp_path: Path):
    db_bytes = _make_whatsapp_db(tmp_path / "msgstore.db", 5501)
    item = InventoryItem(
        path="data/data/com.whatsapp/databases/msgstore.db",
        size=len(db_bytes),
        extension=".db",
        sha256="abc123",
    )
    ctx = ParseContext(
        job_id="00000000-0000-0000-0000-000000000001",
        source_id="SRC-1",
        platform="Android",
        read_bytes=lambda _path, **_kwargs: db_bytes,
    )

    artifacts = list(WhatsAppParser().parse(item, ctx))
    messages = [a for a in artifacts if a.data.get("artifact_family") == "whatsapp_messages"]

    assert len(messages) == 5501
    assert messages[-1].data["message_id"] == "KEY-5501"
    assert messages[-1].forensic["state"] == "database_deleted"


def test_normalized_artifact_id_is_stable_for_same_source_row():
    kwargs = dict(
        artifact_type="app_message",
        source_domain="messaging_apps",
        data={"message_id": "ABC", "body": "hello"},
        source_path="data/data/com.whatsapp/databases/msgstore.db",
        source_table="message",
        source_row_id="42",
        job_id="00000000-0000-0000-0000-000000000001",
    )
    a = NormalizedArtifact.create(**kwargs)
    b = NormalizedArtifact.create(**kwargs)
    assert a.artifact_id == b.artifact_id
    assert a.artifact_id.startswith("MOB-")


def test_wal_presence_is_recovery_source_not_recovered_record():
    item = InventoryItem(
        path="data/data/com.whatsapp/databases/msgstore.db-wal",
        size=4096,
        extension=".db-wal",
        sha256="wal-sha",
    )
    ctx = ParseContext(
        job_id="00000000-0000-0000-0000-000000000001",
        source_id="SRC-1",
        platform="Android",
    )
    artifacts = list(SqliteHistoryAnalyzer().analyze([item], [], ctx))
    assert len(artifacts) == 1
    assert artifacts[0].artifact_type == "sqlite_wal_source"
    assert artifacts[0].forensic["state"] == "unverified"
    assert artifacts[0].forensic["recovery_source"] == "sqlite_wal_source"


def test_whatsapp_deleted_document_is_classified_and_preserved():
    item = InventoryItem(
        path="sdcard/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/Trash/report.pdf",
        size=12345,
        extension=".pdf",
        mime_hint="application/pdf",
        sha256="doc-sha",
    )
    ctx = ParseContext(
        job_id="00000000-0000-0000-0000-000000000001",
        source_id="SRC-1",
        platform="Android",
    )
    artifacts = list(FilesMediaParser().parse(item, ctx))
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_type == "document"
    assert art.data["artifact_family"] == "whatsapp_media"
    assert art.data["whatsapp_media_type"] == "document"
    assert art.forensic["state"] == "filesystem_recovered"


def test_sqlite_residual_carver_has_no_5000_string_ceiling():
    from app.services.mobile_acquire.sqlite_deleted import _carve_bytes

    blob = b"\x00".join(
        f"deleted chat residual candidate number {i:05d}".encode("utf-8")
        for i in range(6001)
    )
    carved = _carve_bytes(blob)
    assert len(carved) == 6001
    assert carved[-1].endswith("06000")
