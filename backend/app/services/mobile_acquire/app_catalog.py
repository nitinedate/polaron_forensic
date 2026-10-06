"""Catalog of social, messaging and mail apps for acquisition/materialisation.

This is a living keyword/package map — not a warranty that every future OS build
exposes every app the same way. Acquisition pulls *all* matching backup domains
and shared-storage trees; analysis materialises DBs for catalogued apps.
"""

from __future__ import annotations

# domain/path substrings (case-insensitive) → examiner-facing category
IOS_DOMAIN_CATEGORIES: dict[str, str] = {
    # Messaging / social
    "whatsapp": "whatsapp",
    "telegram": "telegram",
    "instagram": "instagram",
    "facebook": "facebook",
    "messenger": "facebook",
    "snapchat": "snapchat",
    "tiktok": "tiktok",
    "musical.ly": "tiktok",
    "twitter": "twitter",
    "x.x": "twitter",
    "com.atebits.tweetie": "twitter",
    "linkedin": "linkedin",
    "discord": "discord",
    "signal": "signal",
    "viber": "viber",
    "line": "line",
    "wechat": "wechat",
    "tencent.xin": "wechat",
    "kakaotalk": "kakaotalk",
    "skype": "skype",
    "teams": "teams",
    "slack": "slack",
    "reddit": "reddit",
    "pinterest": "pinterest",
    "tumblr": "tumblr",
    "threads": "threads",
    "bereal": "bereal",
    "clubhouse": "clubhouse",
    "imo": "imo",
    "botim": "botim",
    "truecaller": "truecaller",
    "sharechat": "sharechat",
    "moj": "moj",
    "josh": "josh",
    "snap": "snapchat",
    # Mail
    "apple.mobilemail": "mail",
    "mobilemail": "mail",
    "gmail": "mail",
    "google.gmail": "mail",
    "googlemobile": "mail",
    "outlook": "mail",
    "microsoft.office.outlook": "mail",
    "hotmail": "mail",
    "yahoo.mail": "mail",
    "protonmail": "mail",
    "spark": "mail",
    "airmail": "mail",
    "newton": "mail",
    "superhuman": "mail",
    # Native comms
    "mobilesms": "sms_imessage",
    "library/sms": "sms_imessage",
    "addressbook": "contacts",
    "callhistory": "calls",
}

# Prefer these relative-path suffixes when materialising from a domain.
IOS_DB_SUFFIXES: tuple[str, ...] = (
    ".sqlite",
    ".sqlite3",
    ".db",
    ".sqlitedb",
    ".storedata",
    ".sql",
)

ANDROID_SOCIAL_PACKAGES: tuple[str, ...] = (
    "com.whatsapp",
    "com.whatsapp.w4b",
    "org.telegram.messenger",
    "org.telegram.messenger.web",
    "com.instagram.android",
    "com.facebook.katana",
    "com.facebook.orca",
    "com.facebook.mlite",
    "com.snapchat.android",
    "com.zhiliaoapp.musically",  # TikTok
    "com.ss.android.ugc.trill",
    "com.twitter.android",
    "com.linkedin.android",
    "com.discord",
    "org.thoughtcrime.securesms",  # Signal
    "com.viber.voip",
    "jp.naver.line.android",
    "com.tencent.mm",  # WeChat
    "com.skype.raider",
    "com.microsoft.teams",
    "com.Slack",
    "com.reddit.frontpage",
    "com.google.android.gm",
    "com.microsoft.office.outlook",
    "com.yahoo.mobile.client.android.mail",
    "ch.protonmail.android",
    "com.google.android.apps.messaging",
    "com.samsung.android.messaging",
)

ANDROID_SHARED_EXTRA: tuple[str, ...] = (
    "/sdcard/Android/media/com.facebook.katana",
    "/sdcard/Android/media/com.facebook.orca",
    "/sdcard/Android/media/com.snapchat.android",
    "/sdcard/Android/media/com.zhiliaoapp.musically",
    "/sdcard/Android/media/com.twitter.android",
    "/sdcard/Android/media/com.discord",
    "/sdcard/Android/media/org.thoughtcrime.securesms",
    "/sdcard/Android/media/com.viber.voip",
    "/sdcard/Android/media/com.google.android.gm",
    "/sdcard/Android/media/com.microsoft.office.outlook",
    "/sdcard/Android/data/com.facebook.katana",
    "/sdcard/Android/data/com.facebook.orca",
    "/sdcard/Android/data/com.instagram.android",
    "/sdcard/Android/data/com.snapchat.android",
    "/sdcard/Android/data/com.zhiliaoapp.musically",
    "/sdcard/Android/data/com.twitter.android",
    "/sdcard/Android/data/com.google.android.gm",
    "/sdcard/Android/data/com.microsoft.office.outlook",
    "/sdcard/Snapchat",
    "/sdcard/TikTok",
    "/sdcard/Facebook",
    "/sdcard/Instagram",
    "/sdcard/Discord",
    "/sdcard/Signal",
    "/sdcard/Viber",
    "/sdcard/Download/Telegram",
    "/sdcard/Download/WhatsApp",
    "/sdcard/DCIM/.trashed",
    "/sdcard/DCIM/.trash",
    "/sdcard/Pictures/.trashed",
    "/sdcard/.Trash",
    "/sdcard/.trashed",
    "/sdcard/WhatsApp/Media",
    "/sdcard/WhatsApp/Media/.Statuses",
    "/sdcard/Android/media/com.whatsapp/WhatsApp",
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Media",
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
    "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business",
)


def category_for_ios_domain(domain: str, relative_path: str = "") -> str | None:
    blob = f"{domain} {relative_path}".lower()
    for needle, category in IOS_DOMAIN_CATEGORIES.items():
        if needle in blob:
            return category
    return None


def is_db_path(relative_path: str) -> bool:
    low = (relative_path or "").lower()
    return any(low.endswith(suf) for suf in IOS_DB_SUFFIXES)
