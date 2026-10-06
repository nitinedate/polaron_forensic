"""Tests for plain-language mobile report findings helpers."""

from app.services.mobile_report_llm import (
    evidence_summary_for_llm,
    looks_too_technical,
    plain_fallback_observations,
    strip_technical_noise,
)


def test_strip_paths_and_db_names():
    raw = (
        "Found chats in /data/data/com.whatsapp/databases/msgstore.db "
        "and freelist WAL carve at offset 12"
    )
    clean = strip_technical_noise(raw)
    assert "msgstore" not in clean.lower()
    assert "/data/data/" not in clean
    assert "freelist" not in clean.lower()


def test_evidence_brief_has_no_paths():
    brief = evidence_summary_for_llm(
        inventory={"pictures": 120, "whatsapp_messages": 40, "audio": 3},
        payment_hits=[
            {
                "file_path": "/WhatsApp/Media/IMG_001.jpg",
                "content": "Google Pay paid 500 to merchant",
            }
        ],
        rag_snippets=["path: /private/var/mobile/foo chat about money transfer"],
    )
    assert "photos/images" in brief
    assert "Google Pay" in brief
    assert "/WhatsApp/" not in brief
    assert "/private/var/" not in brief


def test_looks_too_technical():
    assert looks_too_technical("IndexedDB LevelDB protobuf dump")
    assert not looks_too_technical(
        "### 3. Observations\n- The phone’s chats were reviewed for money talk.\n"
        "- About 100 photos were checked for payment screens."
    )


def test_plain_fallback():
    text = plain_fallback_observations({"pictures": 10, "whatsapp_chats": 5, "deleted_files": 2})
    assert "### 3. Observations" in text
    assert "msgstore" not in text.lower()
    assert "/" not in text or "plain terms" in text.lower()
