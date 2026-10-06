"""Phase 1-40 handbook evidence scope — extensions, special names, and extensionless paths.

Reference: Forensic_All_Artifacts_Discovery_Attachments_and_Counting_Handbook.pdf
(parser 40.0.0, 164 deterministic policies).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

HANDBOOK_PARSER_VERSION = "40.0.0"

# §5–§29 — file extensions cited across Windows, browser, email, mobile, media, network, containers.
HANDBOOK_EVIDENCE_EXTENSIONS: frozenset[str] = frozenset({
    # Windows / OS
    ".evtx", ".evt", ".log", ".etl", ".pf", ".reg", ".dat", ".hve",
    ".automaticdestinations-ms", ".customdestinations-ms", ".lnk", ".url", ".website",
    # Registry / DB
    ".sqlite", ".sqlite3", ".db", ".edb", ".mdb", ".accdb", ".sst", ".ldb",
    # Text / config / data
    ".txt", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".md", ".ini", ".cfg", ".conf",
    ".yaml", ".yml", ".ps1", ".bat", ".vbs", ".js", ".properties", ".env", ".toml",
    # Email / mailbox (§7)
    ".eml", ".emlx", ".msg", ".pst", ".ost", ".mbox", ".dbx", ".ics", ".vcf",
    # Documents (§8–9)
    ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".rtf",
    ".odt", ".ods", ".odp", ".one", ".pub",
    # Media (§29)
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".heif", ".ico", ".jfif",
    ".cr2", ".nef", ".dng", ".raw", ".arw", ".orf",
    ".mp3", ".wav", ".wma", ".m4a", ".aac", ".flac", ".ogg", ".mid", ".midi",
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg", ".m4v", ".3gp", ".webm", ".ts",
    ".psd", ".psb", ".pdd",
    # Archives / containers (§26)
    ".zip", ".7z", ".rar", ".cab", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".dmg", ".tc", ".hc", ".luks",
    # Network (§27)
    ".pcap", ".pcapng", ".cap",
    # Memory / volatile (§25)
    ".dmp", ".mdmp", ".vmem", ".lime", ".core", ".raw", ".img",
    # Security / crypto
    ".pem", ".key", ".pfx", ".p12", ".kdbx", ".wallet",
    # Mobile / Apple / chat crypto / packages
    ".plist", ".storedata", ".tracev3", ".jsonlz4",
    ".apk", ".xapk", ".apks", ".ipa", ".appx", ".msix",
    ".crypt", ".crypt12", ".crypt14", ".crypt15", ".mcrypt1",
    ".wab", ".wab~", ".nomedia",
    ".pages", ".numbers", ".key", ".webarchive", ".pkpass",
    ".oxps", ".xps", ".wps", ".wpd", ".epub", ".mobi",
    ".thumbs", ".db-wal", ".db-shm", ".db-journal",
    ".bak", ".old", ".tmp", ".cache", ".blob", ".bin",
    ".amr", ".opus", ".caf", ".aae", ".livephoto",
    ".sketch", ".fig", ".drawio",
})

# §31 Extensionless and special-name quick reference (+ chapter-specific basenames).
HANDBOOK_SPECIAL_BASENAMES: frozenset[str] = frozenset({
    # Windows registry / setup / memory
    "sam", "system", "software", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve",
    "setupapi.dev.log", "setupapi.app.log", "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    "log1", "log2",
    # NTFS metadata (small metadata files only — not full $MFT enumeration here)
    "$logfile", "$usnjrnl",
    # Chromium (§6, §31)
    "history", "cookies", "web data", "login data", "favicons", "top sites", "shortcuts",
    "bookmarks", "bookmarks.bak", "preferences", "secure preferences",
    "current session", "current tabs", "last session", "last tabs",
    "network persistent state", "transportsecurity", "transport security",
    # Firefox
    "places.sqlite", "cookies.sqlite", "formhistory.sqlite", "webappsstore.sqlite",
    "sessionstore.js", "sessionstore.json", "sessionstore.jsonlz4",
    "recovery.jsonlz4", "previous.jsonlz4",
    # LevelDB
    "current",
    # Apple Mail (§7)
    "envelope index", "manifest.db",
    # Thunderbird (§7)
    "global-messages-db.sqlite", "profiles.ini", "prefs.js",
    # Linux (§31)
    "passwd", "group", "crontab", "secure", "auth.log",
    ".bash_history", ".zsh_history", "fish_history",
    # Android (§8)
    "packages.xml", "bt_config.conf", "bt_config.bak",
    "mmssms.db", "telephony.db", "sms.db", "calllog.db", "contacts2.db",
    "external.db", "internal.db", "media.db",
    "wificonfigstore.xml", "wifi_config.xml",
    # iOS (§9)
    "info.plist", "status.plist", "manifest.plist",
    "sms.db", "callhistory.storedata", "call_history.db",
    "addressbook.sqlitedb", "addressbook.db",
    # Chat / collaboration stores
    "msgstore.db", "wa.db", "chatstorage.sqlite", "cache4.db",
    "com.apple.launchservices.quarantineeventsv2",
})

# Path substring markers — extensionless files under these trees are evidence candidates.
HANDBOOK_EVIDENCE_PATH_MARKERS: tuple[str, ...] = (
    "/users/",
    "/documents and settings/",
    "/appdata/",
    "/programdata/",
    "/windows/system32/config/",
    "/windows/system32/winevt/",
    "/windows/prefetch/",
    "/windows/inf/",
    "/$recycle.bin/",
    "/recycle.bin/",
    # Email / mailbox (§7)
    "/library/mail/",
    "/mail downloads/",
    "/containers/com.apple.mail/",
    "/thunderbird/",
    "/outlook/",
    "/microsoft/outlook/",
    "/windows mail/",
    "/maildir/",
    "/mail/cur/",
    "/mail/new/",
    "/local folders/",
    "/content.outlook/",
    "/inetcache/content.outlook/",
    # Browser
    "/user data/",
    "/mozilla/firefox/profiles/",
    "/ebwebview/",
    "/local storage/",
    "/indexeddb/",
    "/session storage/",
    "/leveldb/",
    # Chat / collaboration
    "/discord/",
    "/slack/",
    "/microsoft/teams/",
    "/msteams/",
    "/whatsapp/",
    "/telegram/",
    "/signal/",
    "/skype/",
    "/zoom/",
    # Cloud sync
    "/onedrive/",
    "/dropbox/",
    "/google drive/",
    "/icloud/",
    "/icloud drive/",
    # Mobile extraction trees (Android / iOS / UFED)
    "/data/data/",
    "/android/data/",
    "/storage/emulated/",
    "/sdcard/",
    "/dump/",
    "/mediastore/",
    "/shared_prefs/",
    "/databases/",
    "/files/whatsapp/",
    "/com.whatsapp/",
    "/com.telegram/",
    "/com.facebook/",
    "/com.signal/",
    "/mobile/",
    "/ios/",
    "/applications/",
    "/var/mobile/",
    "/private/var/mobile/",
    "/home/",
    "/root/",
)

_EXTENSIONLESS_PATH_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"/maildir/(cur|new)/", re.I),
    re.compile(r"/thunderbird/.+/mail/", re.I),
    re.compile(r"/library/mail/v\d+/.+/messages/", re.I),
    re.compile(r"/library/mail downloads/", re.I),
    re.compile(r"/local/microsoft/outlook/", re.I),
    re.compile(r"/content\.outlook/", re.I),
    re.compile(r"/(cur|new)/[^/]+$", re.I),
)

_RECYCLE_I_PREFIX = re.compile(r"/\$recycle\.bin/[^/]+/\$i", re.I)
_MANIFEST_PREFIX = re.compile(r"^manifest-", re.I)
_FIREFOX_SESSION_RE = re.compile(r"/recovery\.|/previous\.", re.I)
_ANDROID_WIFI_RE = re.compile(r"wifi[^/]*\.xml$", re.I)
_CRON_RE = re.compile(r"(^|/)(cron\.d/|spool/cron/)", re.I)


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").strip().lower()


def _basename(path: str) -> str:
    return PurePosixPath(_norm(path)).name


def _ext(path: str) -> str:
    return PurePosixPath(_norm(path)).suffix.lower()


def matches_handbook_special_basename(path: str) -> bool:
    base = _basename(path)
    if not base:
        return False
    if base in HANDBOOK_SPECIAL_BASENAMES:
        return True
    if _MANIFEST_PREFIX.match(base):
        return True
    if _RECYCLE_I_PREFIX.search(_norm(path)):
        return True
    if _FIREFOX_SESSION_RE.search(_norm(path)):
        return True
    if _ANDROID_WIFI_RE.search(_norm(path)):
        return True
    if _CRON_RE.search(_norm(path)):
        return True
    if base.startswith("$i") and "$recycle.bin/" in _norm(path):
        return True
    # WhatsApp crypt key is extensionless "key" (or encrypted_backup.key).
    # Keep it even when a UFED dump uses an atypical parent path.
    if base in {"key", "encrypted_backup.key"} and (
        "whatsapp" in _norm(path) or _norm(path).endswith("/files/key")
    ):
        return True
    return False


def matches_handbook_extensionless_path(path: str) -> bool:
    """Extensionless (or dotted-but-not-typed) evidence under handbook/mobile trees.

    Keeps small Chromium/Firefox/LevelDB/mail/maildir/Android shared_prefs files even
    when they have no conventional extension — these are often the only copy of chat/account state.
    """
    p = _norm(path)
    if not p:
        return False
    # Maildir / Thunderbird / Apple Mail message files use dots in the basename (not extensions).
    if any(pat.search(p) for pat in _EXTENSIONLESS_PATH_RES):
        return True
    if not any(marker in p for marker in HANDBOOK_EVIDENCE_PATH_MARKERS):
        return False
    ext = _ext(p)
    # True extensionless
    if not ext:
        return True
    # Numeric / UUID-looking "extensions" (e.g. file.12345, msg.uuid) under evidence trees
    if ext[1:].isdigit() or (len(ext) > 20 and all(c.isalnum() or c in "-_" for c in ext[1:])):
        return True
    return False


def is_handbook_evidence_path(path: str) -> bool:
    """True when path matches handbook extension, special name, or extensionless rules."""
    if not path:
        return False
    if matches_handbook_special_basename(path):
        return True
    from app.services.mobile_forensic.crypt_formats import is_crypt_file
    if is_crypt_file(path):
        return True
    if _ext(path) in HANDBOOK_EVIDENCE_EXTENSIONS:
        return True
    if matches_handbook_extensionless_path(path):
        return True
    p = _norm(path)
    if any(marker in p for marker in HANDBOOK_EVIDENCE_PATH_MARKERS):
        ext = _ext(path)
        if ext in HANDBOOK_EVIDENCE_EXTENSIONS:
            return True
    return False


def handbook_text_index_extensions() -> frozenset[str]:
    """Extensions worth RAG text embedding (handbook text/log/json/xml/email family)."""
    return frozenset({
        ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".md",
        ".ini", ".cfg", ".conf", ".yaml", ".yml", ".ps1", ".bat", ".reg", ".vbs",
        ".eml", ".emlx", ".msg", ".ics", ".vcf", ".rtf",
        ".js", ".ts", ".py", ".java", ".c", ".cpp", ".h", ".cs", ".php",
        ".properties", ".env", ".toml", ".plist",
    })
