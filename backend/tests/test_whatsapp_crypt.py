"""WhatsApp key-file parsing and fail-closed crypt decrypt."""

from __future__ import annotations

from app.services.mobile_forensic.sqlite_counts import (
    _is_whatsapp_msgstore_crypt,
    whatsapp_key_gap_text,
)
from app.services.mobile_forensic.whatsapp_crypt import (
    cipher_key_from_material,
    looks_like_sqlite,
    try_decrypt_whatsapp_crypt,
)


def test_cipher_key_from_whatsapp_keyfile() -> None:
    # V45: the 158-byte Android key file holds the AES-256 key in its LAST 32
    # bytes (offset 126). Offset 30 is the crypt12 "t1" header checksum; the
    # pre-V45 reader used it as the key and could never decrypt a real backup.
    keyfile = b"\xff" * 30 + b"\x11" * 32 + b"\xff" * 64 + bytes(range(32))
    assert len(keyfile) == 158
    assert cipher_key_from_material(keyfile) == bytes(range(32))
    assert cipher_key_from_material(b"\x00" * 30 + bytes(range(32)) + b"\xff" * 96) == b"\xff" * 32
    assert cipher_key_from_material(bytes(range(32))) == bytes(range(32))
    assert cipher_key_from_material(bytes(range(32)).hex()) == bytes(range(32))
    assert cipher_key_from_material("not-hex") is None
    assert cipher_key_from_material(b"short") is None
    assert cipher_key_from_material(b"run-as: package not debuggable\n") is None


def test_decrypt_passthrough_sqlite() -> None:
    payload = b"SQLite format 3\x00" + b"\x00" * 80
    assert looks_like_sqlite(payload)
    assert try_decrypt_whatsapp_crypt(payload, "aa" * 32) == payload


def test_decrypt_fail_closed_without_usable_key() -> None:
    blob = b"\x00" * 200
    assert try_decrypt_whatsapp_crypt(blob, None) is None
    assert try_decrypt_whatsapp_crypt(blob, "zz") is None
    assert try_decrypt_whatsapp_crypt(blob, "ab" * 32) is None


def test_intake_key_status_and_material() -> None:
    from app.services.mobile_forensic.integrity import forensic_key_status_from_disk_source

    status = forensic_key_status_from_disk_source(
        {"whatsapp_key_hex": "ab" * 32, "case_intake": {}}
    )
    assert status["whatsapp_key_hex_set"] is True
    assert status["ios_backup_password_set"] is False


def test_discover_whatsapp_key_uses_disk_source_hex() -> None:
    from unittest.mock import MagicMock, patch

    from app.services.mobile_forensic.sqlite_counts import discover_whatsapp_key_hex

    db = MagicMock()
    db_row = {"disk_source": {"whatsapp_key_hex": "11" * 32}}
    with patch("app.services.mobile_forensic.sqlite_counts.fetchone", return_value=db_row), patch(
        "app.services.mobile_forensic.sqlite_counts.fetchall", return_value=[]
    ):
        found = discover_whatsapp_key_hex(db, "job-1")
    assert found == "11" * 32


def test_crypt_preview_theme_is_not_chat() -> None:
    from unittest.mock import MagicMock, patch

    from app.services.artifact_preview import (
        _is_whatsapp_media_crypt_name,
        _is_whatsapp_msgstore_crypt_name,
        _whatsapp_crypt_preview_body,
    )

    theme = (
        "WhatsApp/Backups/Payment Backgrounds/006_travel_theme.webp.crypt14"
    )
    assert _is_whatsapp_media_crypt_name(theme)
    assert not _is_whatsapp_msgstore_crypt_name(theme)
    assert _is_whatsapp_msgstore_crypt_name("WhatsApp/Databases/msgstore.db.crypt14")

    with patch(
        "app.services.mobile_forensic.sqlite_counts.discover_whatsapp_key_hex",
        return_value=None,
    ):
        body = _whatsapp_crypt_preview_body(MagicMock(), "job-1", theme, b"\x00" * 80)
    assert "NOT a chat database" in body
    assert "ChatStorage.sqlite / msgstore.db from the same dump" not in body


def test_msgstore_crypt_not_theme_sidecar() -> None:
    assert _is_whatsapp_msgstore_crypt(
        "sdcard/WhatsApp/Databases/msgstore.db.crypt14"
    )
    assert _is_whatsapp_msgstore_crypt(
        "WhatsApp/Databases/msgstore-2026-09-13.1.db.crypt14"
    )
    assert not _is_whatsapp_msgstore_crypt(
        "WhatsApp/Backups/022_cricket_punjab_theme.webp.crypt14"
    )
    assert not _is_whatsapp_msgstore_crypt("WhatsApp/Media/IMG.jpg")


def test_key_gap_explains_run_as_stub() -> None:
    text = whatsapp_key_gap_text(
        backup_count=15,
        key_size=45,
        key_head=b"run-as: package ",
        empty_android_backup=True,
    )
    assert "15" in text
    assert "run-as" in text
    assert "whatsapp.ab" in text
    assert "158" in text
