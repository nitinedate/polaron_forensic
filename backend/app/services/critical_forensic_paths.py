"""Shared critical forensic paths for disk extraction, materialization, parse, and RAG."""

from __future__ import annotations

from pathlib import PurePosixPath

# Registry hive basenames (no extension) and key EVTX / profile files.
CRITICAL_HIVE_BASENAMES: frozenset[str] = frozenset({
    "sam",
    "system",
    "software",
    "security",
    "default",
    "ntuser.dat",
    "usrclass.dat",
    "amcache.hve",
})

CRITICAL_EVTX_SUFFIXES: tuple[str, ...] = (
    "winevt/logs/security.evtx",
    "winevt/logs/system.evtx",
    "winevt/logs/application.evtx",
)

# Canonical config hive paths — fetched from disk when absent from tar index.
CRITICAL_CONFIG_HIVE_PATHS: tuple[str, ...] = (
    "Windows/System32/config/SOFTWARE",
    "Windows/System32/config/SYSTEM",
    "Windows/System32/config/SAM",
    "Windows/System32/config/SECURITY",
    "Windows/System32/config/DEFAULT",
)

# Allow large registry hives through extraction size cap (2 GiB).
# Enterprise SOFTWARE hives commonly exceed 512 MiB — never drop them.
CRITICAL_HIVE_MAX_BYTES: int = 2 * 1024 * 1024 * 1024

# Forensic containers (browser History, PST/OST, chat DBs) waived from extract_max_file_bytes.
FORENSIC_CONTAINER_EXTENSIONS: frozenset[str] = frozenset({
    ".pst", ".ost", ".edb", ".sqlite", ".sqlite3", ".db", ".hve",
})
# Photos / video / audio keep original bytes (download original size).
FORENSIC_MEDIA_EXTENSIONS: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif",
    ".webp", ".raw", ".cr2", ".nef", ".dng", ".ico",
    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".m4v", ".3gp",
    ".wav", ".mp3", ".m4a", ".aac", ".ogg", ".flac", ".amr",
})
FORENSIC_CONTAINER_BASENAMES: frozenset[str] = frozenset({
    "history", "places.sqlite", "login data", "web data", "cookies",
    "favicons", "top sites", "msgstore.db", "wa.db", "messages.db",
    "activitiescache.db", "srudb.dat",
    "chatstorage.sqlite", "manifest.db", "sms.db", "contacts.db",
})

# SQL fragment — use as: f"... AND ({CRITICAL_PATH_SQL})"
CRITICAL_PATH_SQL = """
file_path ILIKE 'Windows/System32/config/SAM'
OR file_path ILIKE 'Windows/System32/config/SOFTWARE'
OR file_path ILIKE 'Windows/System32/config/SYSTEM'
OR file_path ILIKE 'Windows/System32/config/SECURITY'
OR file_path ILIKE 'Windows/System32/config/DEFAULT'
OR file_path ILIKE 'Windows/AppCompat/Programs/Amcache.hve'
OR file_path ILIKE 'Users/%/NTUSER.DAT'
OR file_path ILIKE 'Users/%/AppData/Local/Microsoft/Windows/UsrClass.dat'
OR file_path ILIKE 'Windows/System32/winevt/Logs/Security.evtx'
OR file_path ILIKE 'Windows/System32/winevt/Logs/System.evtx'
OR file_path ILIKE 'Windows/System32/winevt/Logs/Application.evtx'
OR file_path ILIKE 'Windows/System32/config/SYSTEM'
OR file_path ILIKE '%/config/SAM'
OR file_path ILIKE '%/config/SOFTWARE'
OR file_path ILIKE '%/config/SYSTEM'
OR file_path ILIKE '%/config/SECURITY'
"""

# Parse-priority SQL (artifact_parse / forensic_inventory).
FORENSIC_PARSE_PATH_SQL = """
(
  file_path ILIKE '%/History'
  OR file_path ILIKE '%/Favicons'
  OR file_path ILIKE '%/Top Sites'
  OR file_path ILIKE '%/Visited Links'
  OR file_path ILIKE '%/Cookies'
  OR file_path ILIKE '%/Login Data'
  OR file_path ILIKE '%/Bookmarks'
  OR file_path ILIKE '%/Preferences'
  OR file_path ILIKE '%Web Data'
  OR file_path ILIKE '%WebCache%'
  OR file_path ILIKE '%places.sqlite'
  OR file_path ILIKE '%cookies.sqlite'
  OR file_path ILIKE '%/User Data/%'
  OR file_path ILIKE '%/Mozilla/Firefox/Profiles/%'
  OR file_path ILIKE '%/EBWebView/%'
  OR file_path ILIKE '%WhatsApp%'
  OR file_path ILIKE '%msgstore%'
  OR file_path ILIKE '%Discord%'
  OR file_path ILIKE '%Slack%'
  OR file_path ILIKE '%Telegram%'
  OR file_path ILIKE '%Microsoft/Teams%'
  OR file_path ILIKE '%/Teams/%'
  OR file_path ILIKE '%Zoom%'
  OR file_path ILIKE '%Skype%'
  OR file_path ILIKE '%Signal%'
  OR file_path ILIKE '%/Local Storage/%'
  OR file_path ILIKE '%/IndexedDB/%'
  OR file_path ILIKE '%/leveldb/%'
  OR file_path ILIKE '%Thunderbird%'
  OR file_path ILIKE '%Outlook%'
  OR file_path ILIKE '%/Recent/%'
  OR file_path ILIKE '%Jump Lists%'
  OR file_path ILIKE '%ActivitiesCache.db%'
  OR file_path ILIKE '%SRUM%'
  OR file_path ILIKE '%.eml'
  OR file_path ILIKE '%.pst'
  OR file_path ILIKE '%.ost'
  OR file_path ILIKE '%.msg'
  OR file_path ILIKE '%.automaticDestinations-ms'
  OR file_path ILIKE '%.customDestinations-ms'
  OR file_path ILIKE '%.lnk'
  OR file_path ILIKE '%setupapi.dev.log'
  OR file_path ILIKE '%/config/SYSTEM'
  OR file_path ILIKE '%/config/SOFTWARE'
  OR file_path ILIKE '%/config/SAM'
  OR file_path ILIKE '%/config/SECURITY'
  OR file_path ILIKE '%/config/DEFAULT'
  OR file_path ILIKE '%Amcache.hve'
  OR file_path ILIKE '%Security.evtx'
  OR file_path ILIKE '%System.evtx'
  OR file_path ILIKE '%Application.evtx'
  OR file_path ILIKE '%NTUSER.DAT'
  OR file_path ILIKE '%UsrClass.dat'
  OR file_path ILIKE '%/Prefetch/%'
  OR file_path ILIKE '%/Winevt/Logs/%'
  OR lower(replace(file_path,'\\','/')) LIKE '%/$recycle.bin/%'
  OR lower(replace(file_path,'\\','/')) LIKE '$recycle.bin/%'
  OR lower(replace(file_path,'\\','/')) LIKE '%/recycle.bin/%'
  OR lower(replace(file_path,'\\','/')) LIKE 'recycle.bin/%'
)
"""

# Human-readable catalog for operators / report appendix.
CRITICAL_FORENSIC_CATALOG: list[dict[str, str]] = [
    {
        "path": "Windows/System32/config/SOFTWARE",
        "purpose": "OS version, Product Key/ID, Install Date, ProfileList, installed programs",
        "rag": "Parse → windows_os + profile_list → __forensic__/windows_os",
    },
    {
        "path": "Windows/System32/config/SYSTEM",
        "purpose": "Computer name, last shutdown, USB, environment, processor",
        "rag": "Parse → computer_name, last_shutdown → __forensic__/windows_os",
    },
    {
        "path": "Windows/System32/config/SAM",
        "purpose": "Local user accounts, last logon, password last set",
        "rag": "Parse → sam_user → __forensic__/windows_user_profiles",
    },
    {
        "path": "Windows/System32/config/SECURITY",
        "purpose": "Security policy / LSA secrets (supplemental account evidence)",
        "rag": "Parse → registry keys",
    },
    {
        "path": "Windows/System32/config/DEFAULT",
        "purpose": "Default user hive baseline",
        "rag": "Parse → registry keys",
    },
    {
        "path": "Users/*/NTUSER.DAT",
        "purpose": "Per-user registry, last-write timeline",
        "rag": "Parse → ntuser_hive → user timeline",
    },
    {
        "path": "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "purpose": "Per-user class registry (ComDlg, MUICache)",
        "rag": "Parse → registry keys",
    },
    {
        "path": "Windows/AppCompat/Programs/Amcache.hve",
        "purpose": "Program execution / install inventory",
        "rag": "Parse → execution artifacts",
    },
    {
        "path": "Windows/System32/winevt/Logs/Security.evtx",
        "purpose": "Logon 4624, password change 4723/4724",
        "rag": "Parse → security_event → user timeline",
    },
    {
        "path": "Windows/System32/winevt/Logs/System.evtx",
        "purpose": "System / device connect events",
        "rag": "Parse → system events",
    },
    {
        "path": "Windows/System32/winevt/Logs/Application.evtx",
        "purpose": "Application errors and installs",
        "rag": "Parse → application events",
    },
]


def _norm_path(path: str) -> str:
    return (path or "").replace("\\", "/").strip().lower()


def is_critical_forensic_path(path: str) -> bool:
    low = _norm_path(path)
    if not low:
        return False
    # Windows Recycle Bin $I descriptors are extensionless and historically could be
    # skipped by phase-1 materialization. Treat the entire Recycle Bin tree as a
    # critical forensic source so report recreation can backfill old jobs from the
    # disk index without requiring a new acquisition.
    if (
        low.startswith("$recycle.bin/")
        or low.startswith("recycle.bin/")
        or "/$recycle.bin/" in low
        or "/recycle.bin/" in low
    ):
        return True
    name = PurePosixPath(low).name
    if name in CRITICAL_HIVE_BASENAMES:
        return True
    if name.endswith(".evtx") and any(low.endswith(sfx) for sfx in CRITICAL_EVTX_SUFFIXES):
        return True
    if "/config/" in low and name in CRITICAL_HIVE_BASENAMES:
        return True
    if low.endswith("/ntuser.dat") or low.endswith("/usrclass.dat"):
        return True
    if "amcache.hve" in low:
        return True
    return False


def is_critical_evtx_path(path: str) -> bool:
    low = _norm_path(path)
    return bool(low) and low.endswith(".evtx") and any(low.endswith(sfx) for sfx in CRITICAL_EVTX_SUFFIXES)


def is_forensic_full_read_path(path: str) -> bool:
    """True when parse must read the entire object — never apply 64 KiB metadata truncation.

    Covers registry hives, key EVTX, browser/chat SQLite, email containers, jump lists,
    prefetch, LNK, SetupAPI, SRUM, and other FORENSIC_PARSE_PATH markers.
    """
    low = _norm_path(path)
    if not low:
        return False
    if is_critical_forensic_path(path) or is_critical_evtx_path(path):
        return True
    name = PurePosixPath(low).name
    if name in FORENSIC_CONTAINER_BASENAMES or name in CRITICAL_HIVE_BASENAMES:
        return True
    if name.endswith(tuple(FORENSIC_CONTAINER_EXTENSIONS)):
        return True
    markers = (
        "/history", "/favicons", "/top sites", "/visited links", "/cookies",
        "/login data", "/bookmarks", "/web data", "places.sqlite", "cookies.sqlite",
        "/user data/", "/mozilla/firefox/profiles/", "/ebwebview/",
        "whatsapp", "msgstore", "discord", "slack", "telegram", "teams",
        "zoom", "skype", "signal", "thunderbird", "outlook",
        "activitiescache.db", "srum", "srudb",
        ".eml", ".pst", ".ost", ".msg",
        ".automaticdestinations-ms", ".customdestinations-ms", ".lnk",
        "setupapi.dev.log", "/prefetch/", "/winevt/logs/", "$recycle.bin/", "recycle.bin/", "/$recycle.bin/", "/recycle.bin/",
        "/config/software", "/config/system", "/config/sam",
        "/config/security", "/config/default", "amcache.hve",
        "ntuser.dat", "usrclass.dat",
    )
    return any(m in low for m in markers)


def is_forensic_extract_waived(path: str) -> bool:
    """True when extract must not drop the file solely for exceeding extract_max_file_bytes."""
    if is_forensic_full_read_path(path):
        return True
    low = _norm_path(path)
    if any(
        seg in low
        for seg in (
            "/ios_image/",
            "/ios_backup/",
            "/readable_artifacts/",
            "/afc_media/",
        )
    ) or low.startswith(("ios_image/", "ios_backup/", "readable_artifacts/", "afc_media/")):
        return True
    name = PurePosixPath(low).name
    return any(name.endswith(ext) for ext in FORENSIC_MEDIA_EXTENSIONS)


def filter_critical_entries(entries: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for e in entries:
        path = (e.get("path") or "").replace("\\", "/")
        if not path or path in seen:
            continue
        if is_critical_forensic_path(path):
            seen.add(path)
            out.append(e)
    return out


def missing_critical_hive_names(entries: list[dict]) -> list[str]:
    """Return required config hive basenames absent from disk index entries."""
    present = {_norm_path(e.get("path") or "").rsplit("/", 1)[-1] for e in entries}
    required = ("software", "system", "sam", "security")
    return [h for h in required if h not in present]
