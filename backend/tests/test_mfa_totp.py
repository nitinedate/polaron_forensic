"""MFA TOTP code normalization."""

from app.services.security import normalize_totp_code


def test_normalize_totp_code_strips_spaces_and_dashes() -> None:
    assert normalize_totp_code("747 345") == "747345"
    assert normalize_totp_code("747-345") == "747345"
    assert normalize_totp_code(" 747345 ") == "747345"


def test_normalize_totp_code_empty() -> None:
    assert normalize_totp_code("") == ""
    assert normalize_totp_code("abc") == ""
