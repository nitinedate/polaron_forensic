"""Tests for canonical catalog category labels."""

from app.services.catalog_categories import (
    EMAIL_CALENDAR_CATEGORY,
    canonical_category,
    dedupe_subcategories,
    is_email_calendar_category,
    norm_category_key,
)


def test_canonical_email_calendar_variants() -> None:
    assert canonical_category("Email and Calendar") == EMAIL_CALENDAR_CATEGORY
    assert canonical_category("Email & Calendar") == EMAIL_CALENDAR_CATEGORY
    assert canonical_category("email and calendar") == EMAIL_CALENDAR_CATEGORY
    assert canonical_category("EMAIL AND CALENDAR") == EMAIL_CALENDAR_CATEGORY


def test_norm_category_key_treats_ampersand_and_and_equally() -> None:
    assert norm_category_key("Email & Calendar") == "email and calendar"
    assert norm_category_key("Email and Calendar") == "email and calendar"


def test_is_email_calendar_category() -> None:
    assert is_email_calendar_category("Email and Calendar")
    assert is_email_calendar_category("Email & Calendar")


def test_dedupe_subcategories_merges_counts() -> None:
    merged = dedupe_subcategories([
        {"key": "AX-1", "label": "Email Attachments", "count": 7},
        {"key": "RPT-ART-006", "label": "Email Attachments", "count": 3, "critical": True},
    ])
    assert len(merged) == 1
    assert merged[0]["count"] == 7
    assert merged[0]["key"] == "RPT-ART-006"
