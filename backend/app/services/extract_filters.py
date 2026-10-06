"""Path and size filters to skip low-value or unreadable files before disk read.

Modes:
  full       — extract nearly everything (minimal NTFS skips only)
  defensible — court-safe default: forensic evidence + uncertain/user files (when in doubt, keep)
  forensic   — encyclopedia / RAG evidence set (skips WinSxS DLL noise)
  fast       — aggressive include-hints only

OS-aware: Windows forensic mode keeps user/registry/event/media evidence while
dropping WinSxS/DriverStore binary noise. Media counts can still use full-disk
enumeration via media_inventory without extracting every binary.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from app.services.forensic_handbook_scope import (
    HANDBOOK_EVIDENCE_EXTENSIONS,
    is_handbook_evidence_path,
    matches_handbook_extensionless_path,
)
from app.services.extract_noise import NoiseLedger, NoisePolicy, classify_noise, policy_for_mode
from app.services.os_artifact_scope import matches_os_scope

# Minimal skips — truly unreadable / metadata-only NTFS structures.
ALWAYS_SKIP_PREFIXES_MINIMAL: tuple[str, ...] = (
    "$extend/",
)

# Broader skips used when EXTRACT_SKIP_SYSTEM_PATHS=true (non-forensic modes).
ALWAYS_SKIP_PREFIXES_BROAD: tuple[str, ...] = (
    "$extend/",
    "$recycle.bin/",
    "windows/winsxs/",
    "windows/system32/logfiles/",
    "windows/system32/driverstore/filerepository/",
    "windows/system32/wbem/",
    "windows/softwaredistribution/",
    "windows/servicing/",
    "windows/assembly/",
    "program files/windowsapps/",
    "program files (x86)/windowsapps/",
    "windows/system32/config/regback/",
)

# Trees that are huge and mostly binary noise for RAG — keep only forensic extensions.
FORENSIC_NOISE_PREFIXES: tuple[str, ...] = (
    "windows/winsxs/",
    "windows/system32/driverstore/",
    "windows/system32/drivers/",
    "windows/syswow64/",
    "windows/assembly/",
    "windows/microsoft.net/",
    "windows/servicing/",
    "windows/softwaredistribution/",
    "windows/installer/",
    "windows/fonts/",
    "windows/speech/",
    "windows/systemui/",
    "windows/resources/",
    "windows/schemas/",
    "windows/systemresources/",
    "windows/appcompat/programs/",
    "windows/system32/catroot",
    "windows/system32/catroot2",
    "windows/system32/spool/",
    "windows/system32/sru/",  # keep .dat via extensions below — prefix alone not enough
    "program files/windows defender advanced threat protection/",
    "program files/common files/microsoft shared/",
    "programdata/package cache/",
    "programdata/microsoft/windows defender/",
    "programdata/microsoft/microsoft defender/",
    "programdata/microsoft/windows/wer/reportqueue/",
)

# Always keep these trees wholesale (minus empty / oversized handled elsewhere).
FORENSIC_KEEP_PREFIXES = (
    "users/",
    "documents and settings/",
    "windows/system32/config/",
    "windows/system32/winevt/",
    "windows/system32/logfiles/",
    "windows/prefetch/",
    "windows/media/",
    "windows/inf/",
    "windows/appcompat/programs/amcache.hve",
    "$recycle.bin/",
    "recycle.bin/",
    "programdata/microsoft/windows/start menu/",
    "programdata/microsoft/windows/caches/",
    "programdata/microsoft/search/",
    "programdata/microsoft/diagnosis/",
    "programdata/microsoft/event viewer/",
    "programdata/microsoft/network/",
    "programdata/microsoft/user account pictures/",
    "programdata/microsoft/wlansvc/",
    "inetpub/",
    "perflogs/",
)

MOBILE_FORENSIC_PREFIXES = (
    "data/data/",
    "android/data/",
    "dump/",
    "media/",
    "mnt/",
    "storage/emulated/",
    "storage/self/",
    "sdcard/",
    "tombstones/",
    "anr/",
    "log/",
    "logs/",
    "accounts/",
    "contacts/",
    "sms/",
    "mms/",
    "ios_image/",
    "ios_backup/",
    "readable_artifacts/",
    "afc_media/",
    "house_arrest/",
)


def _is_mobile_forensic_path(path: str) -> bool:
    p = _norm(path)
    if _starts_with_any(p, MOBILE_FORENSIC_PREFIXES):
        return True
    if any(seg in p for seg in ("/com.android.", "/com.google.android.", "/com.whatsapp.", "/com.facebook.")):
        return True
    base = PurePosixPath(p).name.lower()
    if base.endswith((".pas", ".ufd", ".ufdx")):
        return True
    if base.startswith("installedappslist"):
        return True
    # Members inside portable packages (.zip/.pas/.ufd) — same forensic keep rules as disk.
    if any(f".{ext}/" in p for ext in ("zip", "pas", "ufd")) and any(
        seg in p
        for seg in (
            "/dump/",
            "/data/data/",
            "/android/data/",
            "/02_original_extraction/",
            "/whatsapp/",
            "/com.whatsapp",
            "/sms/",
            "/media/",
            "/dcim/",
            "/ios_backup/",
            "/ios_image/",
            "/afc_media/",
            "/shared_storage/",
            "/readable_artifacts/",
            "_sealed/",
        )
    ):
        return True
    return False


def matches_mobile_forensic_include(path: str, name: str | None = None) -> bool:
    if is_handbook_evidence_path(path):
        return True
    if matches_handbook_extensionless_path(path):
        return True
    if _is_mobile_forensic_path(path):
        return True
    p = _norm(path)
    base = (name or PurePosixPath(p).name).lower()
    ext = _ext(base)
    if ext in FORENSIC_EXTENSIONS:
        return True
    if ext in {".txt", ".xml", ".json", ".plist", ".prop", ".conf", ".log", ".csv", ".db", ".sqlite", ".sqlite3"}:
        return True
    if ext in {".jpg", ".jpeg", ".png", ".webp", ".mp4", ".3gp", ".amr", ".m4a", ".vcf"}:
        return True
    return False

# Fast mode path hints (also used as forensic keep hints).
FAST_INCLUDE_HINTS: tuple[str, ...] = (
    "/users/",
    "/documents and settings/",
    "/appdata/",
    "ntuser.dat",
    "usrclass.dat",
    "/programdata/",
    "/inetpub/",
    "/recycler/",
    "/$recycle.bin/",
    "/windows/system32/config/",
    "/windows/system32/winevt/",
    "/windows/prefetch/",
    "/windows/media/",
    "/windowsapps/",
)

# High-value extensions for forensic encyclopedia / Media / Documents / OS artifacts.
FORENSIC_EXTENSIONS: frozenset[str] = frozenset({
    *HANDBOOK_EVIDENCE_EXTENSIONS,
    # Legacy aliases retained for extract filter parity
    ".docm", ".xlsm", ".one", ".pub", ".dbx", ".sqlite3", ".nsf", ".srs",
    ".cr2", ".nef", ".dng", ".raw",
}) | frozenset({
    # Logs / OS
    ".evtx", ".evt", ".log", ".etl", ".dmp", ".mdmp", ".hdmp", ".pf", ".reg",
    ".automaticdestinations-ms", ".customdestinations-ms",
    # Text / config / data
    ".txt", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".dat", ".db", ".sqlite", ".mdb", ".accdb", ".edb",
    # Email / chat / browser-ish
    ".eml", ".emlx", ".msg", ".pst", ".ost", ".mbox", ".dbx",
    ".ldb",  # LevelDB (Discord, Slack, Electron apps)
    # Documents
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".ods",
    # Security / crypto
    ".pem", ".key", ".pfx", ".p12", ".kdbx", ".wallet",
    # Media (Axiom Media Explorer parity for extracted set)
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".heif", ".ico", ".jfif",
    ".mp3", ".wav", ".wma", ".m4a", ".aac", ".flac", ".ogg", ".mid", ".midi", ".amr", ".opus", ".caf",
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg", ".m4v", ".3gp", ".webm", ".ts",
    ".psd", ".psb",
    # Shortcuts / jump-list adjacent
    ".lnk", ".url", ".website",
    # Disk / archive that often hold evidence
    ".zip", ".7z", ".rar", ".cab", ".iso", ".vhd", ".vhdx",
    # Network / memory / containers (handbook §25–§27)
    ".pcap", ".pcapng", ".cap", ".vmem", ".lime", ".core", ".raw", ".img",
    ".tar", ".gz", ".tgz", ".dmg", ".vmdk", ".qcow2", ".tc", ".hc", ".luks",
    ".ics", ".vcf", ".plist", ".storedata", ".tracev3", ".jsonlz4",
    # Mobile / WhatsApp / Apple iWork (include tiny files)
    ".apk", ".xapk", ".ipa", ".crypt", ".crypt12", ".crypt14", ".crypt15", ".wab",
    ".pages", ".numbers", ".webarchive", ".pkpass", ".nomedia",
    ".bak", ".old", ".cache", ".blob",
})

FAST_EXTENSIONS = FORENSIC_EXTENSIONS

# Binary noise under Windows / Program Files — skip unless path is otherwise kept.
SYSTEM_BINARY_EXTENSIONS: frozenset[str] = frozenset({
    ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".ax", ".efi", ".mui", ".mun",
    ".nls", ".tlb", ".winmd", ".com", ".scr", ".ime", ".tsp", ".ttf", ".ttc", ".otf",
    ".fon", ".cat", ".mum", ".msp", ".msu", ".cab", ".bin", ".pyd", ".so",
})

# User-profile subpaths that are rarely useful for encyclopedia RAG.
USER_NOISE_SUBSTRINGS: tuple[str, ...] = (
    "/appdata/local/temp/",
    "/appdata/local/microsoft/windows/inetcache/",
    "/appdata/local/microsoft/windows/webcache/",
    "/appdata/local/microsoft/windows/temporary internet files/",
    "/appdata/local/pip/",
    "/appdata/local/nuget/",
    "/appdata/local/yarn/",
    "/appdata/local/pnpm/",
    "/appdata/local/crashdumps/",
    "/appdata/local/d3dscache/",
    "/appdata/local/iconcache.db",
    "/appdata/local/microsoft/windows/explorer/iconcache",
    "/appdata/local/microsoft/windows/explorer/thumbcache_",  # keep via media_inventory CMMM; files still large
    "/appdata/roaming/code/cache/",
    "/appdata/roaming/code/cacheddata/",
)

# Browser DB basenames — never treat as cache noise even under /cache/ paths.
FORENSIC_BROWSER_DB_NAMES: frozenset[str] = frozenset({
    "history", "cookies", "web data", "login data", "favicons", "top sites",
    "visited links", "places.sqlite", "cookies.sqlite", "bookmarks", "bookmarks.bak",
    "preferences", "shortcuts", "current session", "current tabs", "webcachev01.dat",
    "network action predictor", "transport security", "relevant sites",
})

# App / browser evidence paths that bypass user-noise filters (chat, email, web apps).
FORENSIC_USER_EVIDENCE_HINTS: tuple[str, ...] = (
    "/user data/",
    "/internet explorer/",
    "/ebwebview/",
    "/local storage/",
    "/indexeddb/",
    "/session storage/",
    "/leveldb/",
    "/discord/",
    "/slack/",
    "/telegram/",
    "/microsoft/teams/",
    "/zoom/",
    "/skype/",
    "/signal/",
    "/whatsapp/",
    "/element/",
    "/wire/",
    "/viber/",
    "/thunderbird/",
    "/outlook/",
    "/mail/",
    "/onedrive/",
    "/dropbox/",
    "/google drive/",
    "/recent/",
    "/automaticdestinations-ms",
    "/customdestinations-ms",
    "/jump lists/",
    "/activitiescache.db",
    "/srum",
    "/webcachev01.dat",
)

_CACHE_SEGMENTS = (
    "/cache/",
    "/code cache/",
    "/gpucache/",
    "/cache2/",
    "/blob_storage/",
    "/service worker/cachestorage/",
)

# Under Firefox/Chrome keep history DBs but skip cache folders — use path checks in matcher.

REGISTRY_HIVE_NAMES: frozenset[str] = frozenset({
    "sam", "system", "software", "security", "default", "ntuser.dat", "usrclass.dat",
    "amcache.hve", "bbirectives.hiv", "components", "elam", "bcd-template",
})

FORENSIC_SPECIAL_NAMES: frozenset[str] = frozenset({
    "setupapi.dev.log", "setupapi.app.log", "pagefile.sys", "hiberfil.sys", "swapfile.sys",
    "wpsettings.dat", "activitiescache.db", "srum*.dat", "srudb.dat",
    "places.sqlite", "cookies.sqlite", "web data", "history", "loginvault.vdf",
    "favicons", "top sites", "visited links", "login data", "cookies", "bookmarks",
    "bookmarks.bak", "preferences", "shortcuts", "current session", "current tabs",
    "webcachev01.dat", "certtransparency", "network action predictor",
    "ntds.dit", "system.sav", "software.sav",
}) | FORENSIC_BROWSER_DB_NAMES


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def _starts_with_any(path: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if path.startswith(prefix) or f"/{prefix}" in f"/{path}/":
            return True
    return False


def _ext(name: str) -> str:
    return PurePosixPath(name).suffix.lower()


def resolve_skip_system_paths(
    *,
    mode: str,
    extract_skip_system_paths: bool,
    os_family: str | None = None,
) -> tuple[bool, str]:
    """Decide whether broad system-path skips apply (legacy full/fast).

    Forensic mode uses its own include logic — skip_system flag is unused there.
    """
    mode_l = (mode or "full").strip().lower()
    family = (os_family or "unknown").strip().lower()

    if mode_l == "forensic":
        return False, "forensic_mode_selective_include"

    if mode_l == "defensible":
        return False, "defensible_mode_selective_include"

    if mode_l == "fast":
        return True, "fast_mode_broad_skip"

    if family == "windows" and mode_l == "full":
        return False, "windows_full_keep_system_paths"

    if extract_skip_system_paths:
        return True, "extract_skip_system_paths_env"

    return False, "full_mode_minimal_skip"


def matches_skip_prefix(
    path: str,
    *,
    skip_system_paths: bool = False,
    os_family: str | None = None,
    mode: str | None = None,
) -> bool:
    p = _norm(path)
    if not p:
        return True
    if p.startswith("$") and not p.startswith("$recycle"):
        return True

    mode_l = (mode or "").strip().lower()
    if mode_l in ("forensic", "defensible"):
        return _starts_with_any(p, ALWAYS_SKIP_PREFIXES_MINIMAL)

    family = (os_family or "").strip().lower()
    if family == "windows" and mode_l != "fast":
        # Legacy: never skip critical trees in full mode.
        never_skip = (
            "program files/windowsapps/",
            "program files (x86)/windowsapps/",
            "windows/winsxs/",
            "windows/system32/logfiles/",
            "windows/system32/winevt/",
            "windows/system32/config/",
            "windows/prefetch/",
            "windows/media/",
            "windows/systemresources/",
            "users/",
            "programdata/",
            "documents and settings/",
        )
        if _starts_with_any(p, never_skip):
            return False

    prefixes = ALWAYS_SKIP_PREFIXES_BROAD if skip_system_paths else ALWAYS_SKIP_PREFIXES_MINIMAL
    return _starts_with_any(p, prefixes)


def matches_fast_include(path: str, name: str | None = None) -> bool:
    p = _norm(path)
    base = (name or PurePosixPath(p).name).lower()
    if base in REGISTRY_HIVE_NAMES:
        return True
    for hint in FAST_INCLUDE_HINTS:
        if hint in f"/{p}/" or p.endswith(hint.strip("/")):
            return True
    if _ext(base) in FAST_EXTENSIONS:
        return True
    return False


def _is_forensic_user_evidence_path(p: str) -> bool:
    if any(seg in p for seg in _CACHE_SEGMENTS):
        base = PurePosixPath(p).name.lower()
        if base not in FORENSIC_BROWSER_DB_NAMES:
            return False
    return any(h in p for h in FORENSIC_USER_EVIDENCE_HINTS)


def _is_regenerable_user_noise(p: str) -> bool:
    """Cache and package trees whose contents can be rebuilt and carry no case facts."""
    return any(
        s in p
        for s in (
            "/inetcache/",
            "/temporary internet files/",
            "/webcache/",
            "/d3dscache/",
            "/iconcache",
            "/thumbcache_",
            "/appdata/local/pip/",
            "/appdata/local/nuget/",
            "/appdata/local/yarn/",
            "/appdata/local/pnpm/",
            "/crashdumps/",
            "/dawngraphitecache/",
            "/dawnwebgpucache/",
        )
    )


def _is_user_noise(p: str) -> bool:
    if _is_forensic_user_evidence_path(p):
        return False
    if any(s in p for s in USER_NOISE_SUBSTRINGS):
        return True
    # Firefox — skip cache/thumbnail trees only; keep places.sqlite and profile DBs.
    if "/mozilla/firefox/profiles/" in p:
        if any(
            x in p
            for x in (
                "/cache2/",
                "/startupcache/",
                "/thumbnails/",
                "/safebrowsing/",
                "/glamor/",
            )
        ):
            return True
        return False
    # Browser disk caches (any profile — not only Default)
    browser_markers = ("/chrome/", "/edge/", "/chromium/", "/brave-browser/", "/opera/", "/vivaldi/")
    base = PurePosixPath(p).name.lower()
    if any(m in p for m in browser_markers):
        if base in FORENSIC_BROWSER_DB_NAMES or _ext(p) in FORENSIC_EXTENSIONS:
            return False
        if any(
            seg in p
            for seg in _CACHE_SEGMENTS
            + (
                "/dawngraphitecache/",
                "/dawnwebgpucache/",
            )
        ):
            return True
    if "/code cache/" in p or "/gpucache/" in p:
        return True
    return False


def _special_name_match(base: str) -> bool:
    if base in REGISTRY_HIVE_NAMES or base in FORENSIC_SPECIAL_NAMES:
        return True
    if base.startswith("sru") and base.endswith(".dat"):
        return True
    if base.endswith(".automaticdestinations-ms") or base.endswith(".customdestinations-ms"):
        return True
    if base.startswith("thumbcache_") or base.startswith("iconcache_"):
        return True
    return False


def matches_forensic_include(path: str, name: str | None = None, *, os_family: str | None = None) -> bool:
    """Return True if path is worth extracting for forensic encyclopedia / RAG."""
    family = (os_family or "").strip().lower()
    # Strong mobile trees must never bleed into a known disk-OS extraction just
    # because the handbook/OS catalog contains WhatsApp or generic mobile path
    # hints.  Evidence with an explicit forensic extension (for example .db) is
    # still admitted by the normal disk rules below.
    normalized = _norm(path)
    mobile_base = (name or PurePosixPath(normalized).name).lower()
    if family and family not in ("android", "ios") and _is_mobile_forensic_path(path) and not _ext(mobile_base):
        return False

    # OS scope packs are ADDITIVE and evaluated first: they may only ever widen
    # coverage, never veto a hit made by the handbook rules below. On an
    # unidentified image `matches_os_scope` falls back to the union of all packs
    # so we over-collect rather than lose evidence.
    if matches_os_scope(path, os_family=os_family, name=name):
        return True

    if family in ("android", "ios"):
        return matches_mobile_forensic_include(path, name)

    # Disk / unknown OS: handbook + Windows forensic rules only (no mobile path bleed).
    if is_handbook_evidence_path(path):
        return True
    if matches_handbook_extensionless_path(path):
        return True

    p = _norm(path)
    base = (name or PurePosixPath(p).name).lower()
    ext = _ext(base)

    if _special_name_match(base):
        return True

    # User profiles — keep evidence, drop temp/cache noise
    if p.startswith("users/") or p.startswith("documents and settings/"):
        if _is_user_noise(p):
            # Still keep media / docs / DBs that landed in cache paths
            return ext in FORENSIC_EXTENSIONS or _special_name_match(base)
        return True

    # High-value OS / evidence trees
    if _starts_with_any(p, FORENSIC_KEEP_PREFIXES):
        return True

    # Recycle bin
    if "$recycle.bin/" in p or p.startswith("recycle.bin/"):
        return True

    # Noise trees — media/docs/logs only (not every DLL)
    if _starts_with_any(p, FORENSIC_NOISE_PREFIXES):
        return ext in FORENSIC_EXTENSIONS

    # WindowsApps / Program Files — keep media + configs + installers metadata, skip binaries
    if p.startswith("program files/") or p.startswith("program files (x86)/") or p.startswith("programdata/"):
        if ext in FORENSIC_EXTENSIONS or _special_name_match(base):
            return True
        if base in {"appxmanifest.xml", "appxblockmap.xml", "desktop.ini", "readme.txt"}:
            return True
        if ext in SYSTEM_BINARY_EXTENSIONS:
            return False
        # Keep small-ish non-binary artifacts (licenses, configs)
        if ext in {".txt", ".xml", ".json", ".html", ".htm", ".ini", ".config", ".dll.config"}:
            return True
        return False

    # Rest of Windows\ — skip system binaries; keep forensic extensions
    if p.startswith("windows/"):
        if ext in SYSTEM_BINARY_EXTENSIONS:
            return False
        return ext in FORENSIC_EXTENSIONS or _special_name_match(base)

    # Other roots (recovery, EFI, etc.) — extensions only
    if ext in FORENSIC_EXTENSIONS or _special_name_match(base):
        return True
    return False


def matches_defensible_include(
    path: str,
    name: str | None = None,
    *,
    size_bytes: int = 0,
    uncertain_max_bytes: int = 4_194_304,
    os_family: str | None = None,
) -> bool:
    """Court-defensible include: forensic hits + uncertain files in evidence-relevant paths.

    When classification is unclear, prefer extraction over loss — especially under user
    profiles, ProgramData, and small unknown artifacts in system trees.
    """
    if matches_forensic_include(path, name, os_family=os_family):
        return True

    p = _norm(path)
    base = (name or PurePosixPath(p).name).lower()
    ext = _ext(base)
    cap = max(int(uncertain_max_bytes or 0), 0)

    if _special_name_match(base):
        return True

    # User profiles — keep real documents and extensionless unknowns (a dropper
    # with no extension in Temp is still evidence). Do not re-include regenerable
    # cache bodies that the forensic rules already classified as noise.
    if p.startswith("users/") or p.startswith("documents and settings/"):
        if _is_user_noise(p):
            if ext in FORENSIC_EXTENSIONS or _special_name_match(base):
                return True
            if any(seg in p for seg in _CACHE_SEGMENTS) or _is_regenerable_user_noise(p):
                return False
        if ext in SYSTEM_BINARY_EXTENSIONS and size_bytes > 524_288:
            return False
        return True

    if _starts_with_any(p, FORENSIC_KEEP_PREFIXES):
        return True

    if "$recycle.bin/" in p or p.startswith("recycle.bin/"):
        return True

    # ProgramData / Program Files — keep configs, unknown, small binaries (possible droppers)
    if p.startswith("programdata/") or p.startswith("program files/") or p.startswith("program files (x86)/"):
        if ext in SYSTEM_BINARY_EXTENSIONS and size_bytes > 1_048_576:
            return False
        if not ext or ext not in SYSTEM_BINARY_EXTENSIONS:
            return True
        if cap <= 0 or size_bytes <= cap:
            return True
        return False

    # System noise trees — keep forensic types + small unknown (renamed malware, steganography)
    if _starts_with_any(p, FORENSIC_NOISE_PREFIXES):
        if not ext and (cap <= 0 or size_bytes <= cap):
            return True
        if ext and ext not in SYSTEM_BINARY_EXTENSIONS and (cap <= 0 or size_bytes <= cap):
            return True
        return False

    # Rest of Windows\ — skip large system binaries only
    if p.startswith("windows/"):
        if ext in SYSTEM_BINARY_EXTENSIONS and size_bytes > 524_288:
            return False
        if not ext and (cap <= 0 or size_bytes <= min(cap, 2_097_152)):
            return True
        return bool(ext) or size_bytes <= cap

    # Other volume roots — include when uncertain and reasonably sized
    if cap <= 0 or size_bytes <= cap:
        return True
    return ext in FORENSIC_EXTENSIONS or _special_name_match(base)


def should_extract_node(
    path: str,
    size_bytes: int,
    *,
    mode: str,
    max_file_bytes: int,
    min_file_bytes: int = 0,
    skip_system_paths: bool | None = None,
    os_family: str | None = None,
    uncertain_max_bytes: int = 4_194_304,
) -> tuple[bool, str | None]:
    """Return (include, skip_reason)."""
    if size_bytes < min_file_bytes:
        return False, "empty"

    from app.services.critical_forensic_paths import (
        CRITICAL_HIVE_MAX_BYTES,
        is_critical_forensic_path,
        is_forensic_extract_waived,
    )

    if is_critical_forensic_path(path) or is_forensic_extract_waived(path):
        # Forensic hives/containers: only hard-cap at CRITICAL_HIVE_MAX_BYTES (2 GiB).
        if CRITICAL_HIVE_MAX_BYTES > 0 and size_bytes > CRITICAL_HIVE_MAX_BYTES:
            return False, "too_large"
    elif max_file_bytes > 0 and size_bytes > max_file_bytes:
        return False, "too_large"

    mode_l = (mode or "full").strip().lower()
    if skip_system_paths is None:
        skip_system_paths = mode_l == "fast"

    # A curated scope-pack hit outranks the generic skip lists. Without this,
    # ALWAYS_SKIP_PREFIXES_MINIMAL ("$extend/") silently discarded $UsnJrnl:$J —
    # the change journal — in *every* extraction mode.
    in_os_scope = matches_os_scope(path, os_family=os_family)

    if not in_os_scope and matches_skip_prefix(
        path,
        skip_system_paths=bool(skip_system_paths),
        os_family=os_family,
        mode=mode_l,
    ):
        return False, "system_path"

    if mode_l == "defensible":
        if not matches_defensible_include(
            path,
            uncertain_max_bytes=uncertain_max_bytes,
            size_bytes=size_bytes,
            os_family=os_family,
        ):
            return False, "defensible_filter"
        return True, None

    if mode_l == "forensic":
        if matches_forensic_include(path, os_family=os_family):
            return True, None
        # Keep even tiny unknown files — prefs, sidecars, crypto headers, ads.
        if size_bytes <= 8192:
            return True, None
        return False, "forensic_filter"

    if mode_l == "fast" and not matches_fast_include(path):
        return False, "fast_filter"
    return True, None


def should_extract_node_v2(
    path: str,
    size_bytes: int,
    *,
    mode: str,
    max_file_bytes: int,
    min_file_bytes: int = 0,
    skip_system_paths: bool | None = None,
    os_family: str | None = None,
    uncertain_max_bytes: int = 4_194_304,
    noise_policy: NoisePolicy | None = None,
    noise_ledger: NoiseLedger | None = None,
    content_hash: str | None = None,
    seen_hashes: set[str] | None = None,
) -> tuple[bool, str | None]:
    """should_extract_node plus evidentiary-value noise suppression.

    Order is deliberate and must not be rearranged: inclusion is decided FIRST,
    and only files the include rules did not claim are offered to the noise
    filter. A scope-pack artifact can therefore never be dropped as noise.
    """
    include, reason = should_extract_node(
        path,
        size_bytes,
        mode=mode,
        max_file_bytes=max_file_bytes,
        min_file_bytes=min_file_bytes,
        skip_system_paths=skip_system_paths,
        os_family=os_family,
        uncertain_max_bytes=uncertain_max_bytes,
    )
    if not include:
        return False, reason

    policy = noise_policy if noise_policy is not None else policy_for_mode(mode)
    verdict = classify_noise(
        path,
        size_bytes=size_bytes,
        os_family=os_family,
        policy=policy,
        content_hash=content_hash,
        seen_hashes=seen_hashes,
    )
    if verdict.is_noise:
        if noise_ledger is not None:
            noise_ledger.record(verdict, path, size_bytes)
        return False, f"noise:{verdict.rule_id}"
    return True, None


def filter_policy_summary(
    *,
    mode: str,
    extract_skip_system_paths: bool,
    os_info: dict[str, Any] | None,
) -> dict[str, Any]:
    family = (os_info or {}).get("family") or "unknown"
    mode_l = (mode or "full").strip().lower()
    skip, reason = resolve_skip_system_paths(
        mode=mode_l,
        extract_skip_system_paths=extract_skip_system_paths,
        os_family=family,
    )
    return {
        "os_family": family,
        "os_confidence": (os_info or {}).get("confidence"),
        "extract_mode": mode_l,
        "skip_system_paths": skip,
        "policy_reason": reason,
        "forensic_noise_prefixes": list(FORENSIC_NOISE_PREFIXES) if mode_l in ("forensic", "defensible") else [],
        "forensic_keep_prefixes": list(FORENSIC_KEEP_PREFIXES) if mode_l in ("forensic", "defensible") else [],
        "include_uncertain": mode_l == "defensible",
    }
