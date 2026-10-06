"""Unit tests for WhatsApp protocol-noise rejection in text carve."""
from app.services.chat_message_extract import (
    _carve_chat_text_near_token,
    _is_whatsapp_protocol_noise,
    _split_whatsapp_carve_text,
)


def test_protocol_noise_detects_jid_hash_blob():
    blob = "120363145874501505@g.usCPLZ2rYGIABIAZABAA==F82B61CC74F2A2B6491F5BB6F814"
    assert _is_whatsapp_protocol_noise(blob)
    assert _is_whatsapp_protocol_noise(blob + "\n(🚫 You deleted this message)")


def test_split_glued_hyphen_jid_no_space():
    mixed = (
        "919987072547-1492870671@g.usCPzFopgGIAA=3EB09178D000EC4750B9"
        "Thank you Soooo Much Chitra for updating each everything details! "
        "You are the best volunteer"
    )
    clean, residue = _split_whatsapp_carve_text(mixed)
    assert clean.startswith("Thank you Soooo Much Chitra")
    assert residue.startswith("919987072547-1492870671@g.us")
    assert "Thank" not in residue
    assert "@g.us" not in clean
    assert not _is_whatsapp_protocol_noise(mixed)


def test_split_keeps_message_moves_residue():
    mixed = (
        "120363291849526806@g.usC03jxcIGTABIAZABAA==433D3A714589C89935D41051A2BFE11 "
        "on 23rd of June 2025 English evaluation is there"
    )
    clean, residue = _split_whatsapp_carve_text(mixed)
    assert clean == "on 23rd of June 2025 English evaluation is there"
    assert residue.startswith("120363291849526806@g.us")
    assert not _is_whatsapp_protocol_noise(mixed)


def test_split_preview_body_original_section():
    preview = (
        "Conversation: 7th STD\nSender: X\n\nOriginal content:\n"
        "[919987072547-1492870671@g.usCPzFopgGIAA=3EB09178D000EC4750B9"
        "Thank you Soooo Much Chitra]\n\nProtocol residue: leftover"
    )
    clean, residue = _split_whatsapp_carve_text(preview)
    assert clean.startswith("Thank you Soooo Much Chitra")
    assert "@g.us" not in clean
    assert "919987072547" in residue


def test_split_bracket_wrapped_jid():
    mixed = (
        "[120363291849526806@g.usC03jxcIGTABIAZABAA==433D3A714589C89935D41051A2BFE11"
        "on 23rd of June 2025 English evaluation is there]"
    )
    clean, residue = _split_whatsapp_carve_text(mixed)
    assert "English evaluation" in clean
    assert "@g.us" not in clean


def test_carve_rejects_jid_blob_prefers_prose():
    token = "3EB0DEADBEEFCAFE1234"
    window = (
        token.encode()
        + b"\x00\x01"
        + b"120363145874501505@g.usCPLZ2rYGIABIAZABAA==F82B61CC74F2A2B6491F5BB6F814"
        + b"\x00\x02"
        + b"Please share the final invoice tonight"
        + b"\x00"
    )
    db = b"\x00" * 100 + window + b"\x00" * 50
    carved = _carve_chat_text_near_token(db, token)
    assert carved == "Please share the final invoice tonight"


def test_carve_splits_mixed_candidate():
    token = "3EB0MIXEDMSG0001"
    mixed = (
        b"120363291849526806@g.usC03jxcIGTABIAZABAA==433D3A714589C89935D41051A2BFE11 "
        b"on 23rd of June 2025 English evaluation is there"
    )
    window = token.encode() + b"\x00" + mixed + b"\x00"
    carved = _carve_chat_text_near_token(window, token)
    assert carved == "on 23rd of June 2025 English evaluation is there"


def test_carve_returns_empty_when_only_noise():
    token = "3EB0ONLYNOISE0001"
    window = token.encode() + b"\x00" + b"85852839493722@lidABCDEF==DEADBEEF" + b"\x00"
    carved = _carve_chat_text_near_token(window, token)
    assert carved == ""
