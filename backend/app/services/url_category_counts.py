"""Domain-aware browser URL category counting (Web Chat, Social Media, Malware/Phishing)."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_FACEBOOK_SUFFIXES = frozenset({"facebook.com", "fb.com", "fb.me", "m.facebook.com", "graph.facebook.com"})

_CLOUD_SUFFIXES = frozenset(
    {
        "drive.google.com",
        "docs.google.com",
        "dropbox.com",
        "onedrive.live.com",
        "1drv.com",
        "sharepoint.com",
        "mega.nz",
        "mega.io",
        "box.com",
        "icloud.com",
        "wetransfer.com",
        "mediafire.com",
        "sync.com",
        "pcloud.com",
        "acronis.com",
        "cloud.acronis.com",
        "in01-cloud.acronis.com",
        "skydrive.live.com",
    }
)

_WEB_CHAT_SUFFIXES = frozenset(
    {
        "web.whatsapp.com",
        "whatsapp.com",
        "discord.com",
        "discordapp.com",
        "cdn.discordapp.com",
        "slack.com",
        "telegram.org",
        "t.me",
        "messenger.com",
        "signal.org",
        "web.telegram.org",
        "chat.google.com",
        "meet.google.com",
        "zoom.us",
        "skype.com",
        "web.skype.com",
        "teams.live.com",
        "chatsvcagg.teams.microsoft.com",
    }
)

# Preserve the product/reference mapping: Teams is reported under Social Media URLs.
_SOCIAL_MEDIA_SUFFIXES = frozenset(
    {
        "instagram.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "api.twitter.com",
        "tiktok.com",
        "youtube.com",
        "youtu.be",
        "reddit.com",
        "pinterest.com",
        "snapchat.com",
        "threads.net",
        "tumblr.com",
        "vk.com",
        "weibo.com",
        "teams.microsoft.com",
        "presence.teams.microsoft.com",
        "yammer.com",
        "glassdoor.com",
        "quora.com",
    }
)

_PORNOGRAPHY_SUFFIXES = frozenset(
    {
        "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
        "redtube.com", "youporn.com", "spankbang.com", "brazzers.com",
        "porn.com", "tube8.com", "tnaflix.com", "beeg.com",
    }
)

_DATING_SUFFIXES = frozenset(
    {
        "tinder.com", "bumble.com", "hinge.co", "okcupid.com",
        "match.com", "pof.com", "plentyoffish.com", "eharmony.com",
        "happn.com", "grindr.com", "her.com", "badoo.com",
        "zoosk.com", "coffee-meets-bagel.com", "coffeemeetsbagel.com",
    }
)

_PHISHING_KEYWORDS = (
    "phish",
    "login-verify",
    "secure-login",
    "account-verify",
    "credential-steal",
    "malware",
    "trojan",
    "microsft",
    "goggle.",
    "paypa1",
)


def _host_suffix(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""
    return host


def url_matches_domains(url: str, suffixes: frozenset[str]) -> bool:
    host = _host_suffix(url)
    if not host:
        return False
    for suffix in suffixes:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def is_internal_or_non_public_url(url: str) -> bool:
    low = (url or "").lower()
    if low.startswith(("file:", "about:", "chrome:", "edge:", "data:")):
        return True
    host = _host_suffix(url)
    if not host:
        return True
    if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
        return True
    if re.match(r"^(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.", host):
        return True
    if host.endswith(".local") or host.endswith(".lan"):
        return True
    return False


def is_malware_phishing_url(url: str) -> bool:
    if is_internal_or_non_public_url(url):
        return False
    low = url.lower()
    if any(kw in low for kw in _PHISHING_KEYWORDS):
        return True
    return url_matches_domains(url, frozenset({"phishing.com", "login.microsoftonline.com.phishing"}))


def classify_url_category(url: str) -> str | None:
    if not url or is_internal_or_non_public_url(url):
        return None
    if url_matches_domains(url, _WEB_CHAT_SUFFIXES):
        return "web chat urls"
    if url_matches_domains(url, _FACEBOOK_SUFFIXES | _SOCIAL_MEDIA_SUFFIXES):
        return "social media urls"
    if url_matches_domains(url, _PORNOGRAPHY_SUFFIXES):
        return "pornography urls"
    if url_matches_domains(url, _DATING_SUFFIXES):
        return "dating site urls"
    if is_malware_phishing_url(url):
        return "malware/phishing urls"
    return None


def count_url_records(
    urls: list[dict],
    *,
    category: str,
    count_visits: bool = True,
    allowed_origins: set[str] | frozenset[str] | None = None,
) -> int:
    """Count URLs or visit events from normalized browser_url dicts."""
    target = category.strip().lower()
    total = 0
    for row in urls:
        if allowed_origins is not None:
            origin = str(row.get("record_origin") or "browser_history")
            if origin not in allowed_origins:
                continue
        url = str(row.get("url") or "")
        cat = classify_url_category(url)
        if cat != target:
            continue
        if count_visits:
            visits = row.get("visit_count")
            try:
                total += max(int(visits or 0), 1)
            except (TypeError, ValueError):
                total += 1
        else:
            total += 1
    return total
