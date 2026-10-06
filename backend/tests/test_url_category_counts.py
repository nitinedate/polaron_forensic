"""Tests for domain-aware URL category counting."""

from app.services.url_category_counts import (
    classify_url_category,
    count_url_records,
    is_malware_phishing_url,
    url_matches_domains,
    _SOCIAL_MEDIA_SUFFIXES,
    _WEB_CHAT_SUFFIXES,
)


def test_web_chat_domain_match() -> None:
    assert url_matches_domains("https://web.whatsapp.com/send?phone=1", _WEB_CHAT_SUFFIXES)
    assert classify_url_category("https://zoom.us/j/123") == "web chat urls"
    assert classify_url_category("https://discord.com/api/webhooks/1") == "web chat urls"


def test_social_domain_match() -> None:
    assert url_matches_domains("https://www.instagram.com/p/abc", _SOCIAL_MEDIA_SUFFIXES)
    assert classify_url_category("https://www.facebook.com/profile") == "social media urls"
    assert classify_url_category("https://teams.microsoft.com/l/chat/0") == "social media urls"
    assert classify_url_category("https://api.twitter.com/oauth/access_token") == "social media urls"


def test_internal_urls_excluded() -> None:
    assert classify_url_category("http://lhhrms/LiLavatiWebSmart/Login.aspx") is None
    assert classify_url_category("file:///C:/test.pdf") is None


def test_malware_phishing_keyword() -> None:
    assert is_malware_phishing_url("https://evil.example/secure-login-steal")
    assert classify_url_category("https://evil.example/secure-login-steal") == "malware/phishing urls"


def test_count_url_records_uses_visit_count() -> None:
    urls = [
        {"url": "https://web.whatsapp.com/", "visit_count": 4},
        {"url": "https://www.bing.com/search?q=test", "visit_count": 2},
    ]
    assert count_url_records(urls, category="web chat urls", count_visits=True) == 4
    assert count_url_records(urls, category="web chat urls", count_visits=False) == 1
