"""Phase 1-40 AXIOM artifact scope — evidence paths, noise filtering, parser join sidecars.

Reference: Forensic Counting Engine Phase 1-40 Artifact Reference Manual (parser 40.0.0).
Filters low-value files at materialize while preserving SQLite WAL/SHM/journal, LevelDB
MANIFEST/CURRENT/log, Registry LOG1/LOG2, and other sidecars required for parser joins.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from app.services.critical_forensic_paths import is_critical_forensic_path
from app.services.extract_filters import (
    FORENSIC_BROWSER_DB_NAMES,
    FORENSIC_SPECIAL_NAMES,
    matches_forensic_include,
)
from app.services.forensic_handbook_scope import (
    HANDBOOK_EVIDENCE_EXTENSIONS,
    HANDBOOK_SPECIAL_BASENAMES,
    is_handbook_evidence_path,
    matches_handbook_extensionless_path,
)

# Direct extension handlers — handbook §3.1 + report Section B extensions.
PHASE1_EVIDENCE_EXTENSIONS: frozenset[str] = frozenset({
    *HANDBOOK_EVIDENCE_EXTENSIONS,
    ".evt", ".sqlite3", ".nsf", ".docm", ".xlsm", ".srs",
}) | frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".heif", ".ico",
    ".mp3", ".wav", ".wma", ".m4a", ".aac", ".flac", ".ogg", ".mid", ".midi", ".amr", ".opus", ".caf",
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg", ".m4v", ".3gp", ".webm",
    ".psd", ".psb", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods",
    ".zip", ".7z", ".rar", ".cab", ".iso", ".vhd", ".vhdx", ".pcap", ".pcapng",
    ".kdbx", ".wallet", ".pem", ".key", ".pfx", ".p12",
    ".eml", ".emlx", ".mbox", ".pf", ".lnk", ".ldb", ".sst", ".edb",
    ".automaticdestinations-ms", ".customdestinations-ms", ".pst", ".ost", ".msg",
    # Mobile packages / WhatsApp crypto / Apple docs (even when tiny)
    ".apk", ".xapk", ".ipa", ".crypt", ".crypt12", ".crypt14", ".crypt15", ".wab",
    ".pages", ".numbers", ".webarchive", ".pkpass", ".nomedia",
    ".bak", ".old", ".cache", ".blob",
})

# Extensionless / special-name sources — handbook §31 + Appendix A.
PHASE1_SPECIAL_BASENAMES: frozenset[str] = frozenset({
    # Chromium browser profile / session
    "bookmarks", "preferences", "secure preferences",
    "current session", "current tabs", "last session", "last tabs",
    "network persistent state", "transportsecurity", "transport security",
    # Firefox
    "sessionstore.js", "sessionstore.json", "sessionstore.jsonlz4", "webappsstore.sqlite",
    "places.sqlite", "formhistory.sqlite",
    # Registry hives (extensionless)
    "sam", "system", "software", "security", "default", "ntuser.dat", "usrclass.dat", "amcache.hve",
    # SetupAPI / Windows
    "setupapi.dev.log", "setupapi.app.log", "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    # LevelDB metadata
    "current",
    # Apple Mail / Maildir / mobile
    "envelope index", "manifest.db", "packages.xml",
    "msgstore.db", "wa.db", "chatstorage.sqlite", "cache4.db", "contacts2.db", "mmssms.db",
    # Android config
    "wificonfigstore.xml", "wifi_config.xml", "bt_config.conf", "bt_config.bak",
    # Linux / macOS
    "passwd", "group", "crontab", "auth.log", "secure",
    ".bash_history", ".zsh_history", "fish_history",
    "com.apple.launchservices.quarantineeventsv2",
    # Thunderbird
    "global-messages-db.sqlite", "profiles.ini", "prefs.js",
}) | HANDBOOK_SPECIAL_BASENAMES | FORENSIC_BROWSER_DB_NAMES | FORENSIC_SPECIAL_NAMES
# Known mobile / messaging DB basenames (parent for SQLite sidecar joins).
PHASE1_MOBILE_DB_BASENAMES: frozenset[str] = frozenset({
    "msgstore.db", "wa.db", "chatstorage.sqlite", "cache4.db", "contacts2.db", "mmssms.db",
    "manifest.db", "envelope index", "webappsstore.sqlite", "places.sqlite",
})

SQLITE_SIDECAR_SUFFIXES: tuple[str, ...] = ("-wal", "-shm", "-journal")

LEVELDB_PATH_MARKERS: tuple[str, ...] = (
    "/leveldb/",
    "/local storage/",
    "/indexeddb/",
    "/session storage/",
)

# Recycle Bin $I metadata — extensionless prefix per manual.
_RECYCLE_I_PREFIX = re.compile(r"/\$recycle\.bin/[^/]+/\$i", re.I)

# Firefox session recovery files — recovery.* / previous.*
_FIREFOX_SESSION_RE = re.compile(r"/recovery\.|/previous\.", re.I)

# Android wifi*.xml
_ANDROID_WIFI_RE = re.compile(r"wifi[^/]*\.xml$", re.I)

# Maildir cur/new (extensionless messages)
_MAILDIR_RE = re.compile(r"/(cur|new)/[^/]+$", re.I)

# Cron paths
_CRON_RE = re.compile(r"(^|/)(cron\.d/|spool/cron/)", re.I)


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").strip().lower()


def _basename(path: str) -> str:
    return PurePosixPath(_norm(path)).name


def _ext(path: str) -> str:
    return PurePosixPath(_norm(path)).suffix.lower()


def matches_phase1_special_basename(path: str) -> bool:
    """True for extensionless or special-name evidence sources from Phase 1-40 manual."""
    p = _norm(path)
    base = _basename(p)
    if not base:
        return False
    if base in PHASE1_SPECIAL_BASENAMES:
        return True
    if base.startswith("manifest-"):
        return True
    if _RECYCLE_I_PREFIX.search(p):
        return True
    if _FIREFOX_SESSION_RE.search(p):
        return True
    if _ANDROID_WIFI_RE.search(p):
        return True
    if _MAILDIR_RE.search(p):
        return True
    if _CRON_RE.search(p):
        return True
    if base.startswith("$i") and "$recycle.bin/" in p:
        return True
    return False


def sqlite_sidecar_parent_basename(path: str) -> str | None:
    """Return parent DB basename when path is a SQLite sidecar (-wal/-shm/-journal)."""
    base = _basename(path)
    for suf in SQLITE_SIDECAR_SUFFIXES:
        if base.endswith(suf):
            return base[: -len(suf)]
    return None


def is_parser_join_sidecar(path: str) -> bool:
    """Keep parser companion files even when they look like noise (WAL, MANIFEST, LOG1, etc.)."""
    p = _norm(path)
    base = _basename(p)

    # Registry hive transaction logs (Phase 7 — YARP replay joins).
    if base in ("log1", "log2") and "/config/" in p:
        return True

    # LevelDB / Electron metadata and write logs.
    if base == "current" or base.startswith("manifest-"):
        if any(marker in p for marker in LEVELDB_PATH_MARKERS):
            return True
    if base.endswith(".log") and any(marker in p for marker in LEVELDB_PATH_MARKERS):
        return True

    parent = sqlite_sidecar_parent_basename(path)
    if not parent:
        return False

    if parent in PHASE1_SPECIAL_BASENAMES or parent in PHASE1_MOBILE_DB_BASENAMES:
        return True
    if parent in FORENSIC_BROWSER_DB_NAMES:
        return True

    # Generic SQLite sidecars under user/browser evidence trees.
    if any(marker in p for marker in ("/user data/", "/mozilla/firefox/profiles/", "/outlook/", "/thunderbird/")):
        return True
    if parent.endswith(".sqlite") or parent.endswith(".db") or parent.endswith(".sqlite3"):
        if matches_forensic_include(p) or matches_phase1_special_basename(p):
            return True
    return False


def is_phase1_evidence_path(path: str) -> bool:
    """True when a path is in Phase 1-40 forensic evidence scope (before noise-only exclusion)."""
    if is_critical_forensic_path(path):
        return True
    if is_parser_join_sidecar(path):
        return True
    if matches_phase1_special_basename(path):
        return True
    if matches_handbook_extensionless_path(path):
        return True
    from app.services.mobile_forensic.crypt_formats import is_crypt_file
    if is_crypt_file(path):
        return True
    if _ext(path) in PHASE1_EVIDENCE_EXTENSIONS:
        return True
    if is_handbook_evidence_path(path):
        return True
    return matches_forensic_include(path)


def should_materialize_path(path: str, *, enabled: bool = True) -> tuple[bool, str | None]:
    """Return (include, skip_reason) for job_artifacts materialization."""
    if not enabled:
        return True, None
    if not path:
        return False, "empty_path"
    if is_phase1_evidence_path(path):
        return True, None
    return False, "phase1_noise"


# SQL fragment — extend parse-priority queries so sidecars are not marked skipped.
PHASE1_PARSE_SIDECAR_SQL = """
(
  lower(file_name) IN ('log1', 'log2', 'current')
  OR lower(file_name) LIKE 'manifest-%'
  OR lower(file_name) LIKE '%-wal'
  OR lower(file_name) LIKE '%-shm'
  OR lower(file_name) LIKE '%-journal'
  OR (
    lower(file_name) LIKE '%.log'
    AND (
      file_path ILIKE '%/leveldb/%'
      OR file_path ILIKE '%/Local Storage/%'
      OR file_path ILIKE '%/IndexedDB/%'
    )
  )
)
"""


def phase1_scope_summary() -> dict[str, int | list[str]]:
    """Operator/debug snapshot of configured scope sizes."""
    return {
        "evidence_extensions": len(PHASE1_EVIDENCE_EXTENSIONS),
        "special_basenames": len(PHASE1_SPECIAL_BASENAMES),
        "sqlite_sidecar_suffixes": list(SQLITE_SIDECAR_SUFFIXES),
        "leveldb_markers": list(LEVELDB_PATH_MARKERS),
    }
