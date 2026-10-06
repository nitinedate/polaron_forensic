from pathlib import Path

from app.services.mobile_forensic.inventory import _map_axiom_name_to_key

ROOT = Path(__file__).resolve().parents[1]


def test_deleted_mobile_catalog_name_mapping_expanded():
    assert _map_axiom_name_to_key("WhatsApp Deleted Messages - Android") == "whatsapp_deleted_messages"
    assert _map_axiom_name_to_key("Telegram Deleted Messages") == "telegram_deleted"
    assert _map_axiom_name_to_key("Signal Deleted Messages") == "signal_deleted"
    assert _map_axiom_name_to_key("Instagram Deleted Messages") == "instagram_deleted"
    assert _map_axiom_name_to_key("Facebook Messenger Deleted Messages") == "facebook_deleted"
    assert _map_axiom_name_to_key("Viber Deleted Messages") == "viber_deleted"
    assert _map_axiom_name_to_key("WeChat Deleted Messages") == "wechat_deleted"
    assert _map_axiom_name_to_key("LINE Deleted Messages") == "line_deleted"
    assert _map_axiom_name_to_key("TikTok Deleted Messages") == "tiktok_deleted"
    assert _map_axiom_name_to_key("LinkedIn Deleted Messages") == "linkedin_deleted"
    assert _map_axiom_name_to_key("Deleted SMS Messages") == "sms_deleted"


def test_mobile_board_does_not_emit_vendor_brand_in_public_note_or_fallback():
    src = (ROOT / "app/routers/jobs.py").read_text(encoding="utf-8")
    public_block = src[src.index('def mobile_artifact_board'):src.index('@router.get("/jobs/{job_id}/mobile/normalized-artifacts")')]
    assert 'Counts use AXIOM-style' not in public_block
    assert 'AXIOM catalog artifact (mobile)' not in public_block
    assert 'if n <= 0:' not in public_block


def test_mobile_board_frontend_sanitizes_backend_strings():
    src = (ROOT.parent / "frontend/src/components/forensic/MobileArtifactBoard.tsx").read_text(encoding="utf-8")
    assert 'stripVendorBranding(data.note)' in src
    assert 'stripVendorBranding(row.label)' in src
    assert 'stripVendorBranding(row.category)' in src
    assert 'stripVendorBranding(row.description)' in src


def test_generic_deleted_flag_detection_and_registry_expanded():
    from app.services.mobile_forensic.parsers.messaging import _row_is_explicitly_deleted
    from app.services.mobile_forensic.plugins import get_plugin_registry, reset_plugin_registry_for_tests

    assert _row_is_explicitly_deleted("messages", {"is_deleted": 1})
    assert _row_is_explicitly_deleted("deleted_messages", {"is_deleted": 0})
    assert not _row_is_explicitly_deleted("messages", {"is_deleted": 0, "body": "live"})

    reset_plugin_registry_for_tests()
    names = {p.name for p in get_plugin_registry().parsers}
    for expected in {
        "instagram_parser", "snapchat_parser", "discord_parser", "viber_parser",
        "wechat_parser", "line_parser", "tiktok_parser", "linkedin_parser",
    }:
        assert expected in names
