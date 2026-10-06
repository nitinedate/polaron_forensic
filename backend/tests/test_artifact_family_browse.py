from app.services.artifact_evidence_browse import evidence_browse_mode, _looks_like_chat_body
from app.services.artifact_family_browse import (
    family_evidence_artifact_name,
    family_where_sql,
    filter_evidence_rows_for_family,
)


def test_deleted_photos_filter():
    sql, params = family_where_sql("deleted_photos")
    assert "trashed" in sql.lower() or ".trashed" in sql.lower() or "is_deleted" in sql
    assert "jpg" in sql.lower() or "jpeg" in sql.lower()
    assert params == {}


def test_whatsapp_filter_prefers_chat_dbs_not_apk():
    sql, params = family_where_sql("whatsapp_messages")
    assert "msgstore" in sql.lower()
    assert "apk" in sql.lower()  # exclusion
    assert "/data/app/" in sql.lower() or "data/app" in sql.lower()
    assert params == {}
    assert family_evidence_artifact_name("whatsapp_chats") == "WhatsApp Chats"
    assert family_evidence_artifact_name("whatsapp_deleted_messages") == "WhatsApp Deleted Messages"
    assert family_evidence_artifact_name("contacts") == "Contacts"
    assert evidence_browse_mode("WhatsApp Deleted Messages") == "whatsapp_deleted_message"
    assert evidence_browse_mode("Contacts") == "contact"


def test_encrypted_whatsapp_backups_list_msgstore_crypt_not_media():
    sql, params = family_where_sql("whatsapp_encrypted_backups")
    assert "msgstore" in sql.lower()
    assert ".crypt" in sql.lower()
    assert "webp" not in sql.lower()
    assert params == {}
    assert evidence_browse_mode("WhatsApp Encrypted Backups") is None


def test_empty_family():
    sql, params = family_where_sql("")
    assert sql == ""
    assert params == {}


def test_facebook_filter_excludes_apk_dex():
    sql, _ = family_where_sql("facebook")
    assert "dalvik-cache" in sql.lower() or "databases" in sql.lower()
    assert "apk" in sql.lower() or "dex" in sql.lower() or "art" in sql.lower()
    assert "com.facebook.orca" in sql.lower() or "databases" in sql.lower()


def test_strip_runtime_junk_drops_facebook_dex():
    from app.services.artifact_family_browse import is_runtime_junk_row, strip_runtime_junk

    rows = [
        {
            "title": "appmanager@facebook-appmanager.apk@classes.dex",
            "source_path": "vivo.zip/Dump/data/dalvik-cache/arm64/...",
        },
        {
            "title": "threads_db2",
            "file_name": "threads_db2",
            "source_path": "/data/data/com.facebook.orca/databases/threads_db2",
        },
    ]
    assert is_runtime_junk_row(rows[0])
    assert not is_runtime_junk_row(rows[1])
    kept = strip_runtime_junk(rows, family="facebook")
    assert len(kept) == 1
    assert kept[0]["title"] == "threads_db2"


def test_binary_preview_never_hex_for_elf_dex():
    from app.services.artifact_preview import _binary_preview_text

    elf = b"\x7fELF" + b"\x00" * 64
    text = _binary_preview_text(
        elf, path="vivo.zip/Dump/data/dalvik-cache/arm64/appmanager@facebook-appmanager.apk@classes.dex"
    )
    assert "Offset" not in text
    assert "Hex" not in text or "hex dump" not in text.lower()
    assert "not conversation" in text.lower() or "runtime binary" in text.lower()


def test_whatsapp_contacts_not_message_browse():
    assert evidence_browse_mode("WhatsApp Contacts") is None
    assert evidence_browse_mode("WhatsApp Calls") is None
    assert evidence_browse_mode("WhatsApp Chats") == "whatsapp_message"
    assert evidence_browse_mode("WhatsApp Groups - iOS") == "whatsapp_group"
    assert evidence_browse_mode("WhatsApp Chats - iOS") == "whatsapp_message"
    assert family_evidence_artifact_name("whatsapp_contacts") is None
    assert not _looks_like_chat_body('{"code":417,"detail":"Failed to deliver BizIntegrityQuery"}')
    assert _looks_like_chat_body("Meet me at 5pm tomorrow")


def test_filter_evidence_drops_apk_stores():
    rows = [
        {
            "title": "alice: hello",
            "artifact_type": "whatsapp_message",
            "metadata": {"evidence_kind": "whatsapp_message"},
        },
        {
            "title": "base.apk",
            "source_path": "/data/app/com.whatsapp/base.apk",
            "metadata": {"evidence_kind": "whatsapp_store"},
        },
        {
            "title": "msgstore.db",
            "source_path": "/data/data/com.whatsapp/databases/msgstore.db",
            "metadata": {"evidence_kind": "whatsapp_store"},
        },
    ]
    out = filter_evidence_rows_for_family("whatsapp_chats", rows)
    titles = [r["title"] for r in out]
    assert "alice: hello" in titles
    assert "msgstore.db" in titles
    assert "base.apk" not in titles


def test_deleted_family_keeps_only_deleted_message_rows():
    rows = [
        {
            "title": "alice: secret",
            "artifact_type": "whatsapp_deleted_message",
            "metadata": {"evidence_kind": "whatsapp_deleted_message", "is_deleted": True},
        },
        {
            "title": "bob: live",
            "artifact_type": "whatsapp_message",
            "metadata": {"evidence_kind": "whatsapp_message", "is_deleted": False},
        },
        {
            "title": "carved_deleted_residuals.json",
            "artifact_type": "whatsapp_store",
            "metadata": {"evidence_kind": "whatsapp_store"},
        },
    ]
    out = filter_evidence_rows_for_family("whatsapp_deleted_messages", rows)
    assert len(out) == 1
    assert out[0]["title"] == "alice: secret"


def test_whatsapp_chats_filter_drops_sms_paths():
    rows = [
        {
            "title": "alice: hi",
            "artifact_type": "whatsapp_message",
            "source_path": ".../ChatStorage.sqlite",
            "metadata": {"evidence_kind": "whatsapp_message", "social_app": "whatsapp"},
        },
        {
            "title": "unknown: Dear SBI",
            "artifact_type": "sms_message",
            "source_path": ".../sms_imessage/.../sms.db",
            "metadata": {
                "evidence_kind": "chat_message",
                "social_app": "sms",
                "preview_body": "App: SMS / iMessage\nMessage:\nDear SBI",
            },
        },
    ]
    out = filter_evidence_rows_for_family("whatsapp_chats", rows)
    assert len(out) == 1
    assert out[0]["title"] == "alice: hi"


def test_looks_like_chat_body_rejects_schema_junk():
    assert not _looks_like_chat_body("WAMessageDataItem")
    assert not _looks_like_chat_body("919820647005@s.whatsapp.net")
    assert _looks_like_chat_body("Bring the documents also tomorrow")


def test_contacts_family_sql_targets_addressbook():
    sql, _ = family_where_sql("contacts")
    assert "addressbook" in sql.lower()
    assert "shadow" in sql.lower()  # exclusion
    assert "%contacts%" not in sql.lower() or "addressbook" in sql.lower()


def test_email_attachments_family_excludes_webkit():
    sql, _ = family_where_sql("email_attachments")
    assert "webkit" in sql.lower()
    assert "observations.db" in sql.lower()
