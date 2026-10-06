"""Parser plugin registry for forensic artifacts."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Callable
from app.parsers.communications import parse_communications_file

from app.parsers.email_mime_parser import is_extensionless_email_candidate, parse_email_file
from app.parsers.evtx import parse_evtx
from app.parsers.jumplist import parse_jump_list
from app.parsers.lnk import parse_lnk
from app.parsers.mft import parse_mft_metadata
from app.parsers.prefetch import parse_prefetch
from app.parsers.recycle_bin import is_recycle_bin_i_path, parse_recycle_bin_i
from app.parsers.registry import parse_registry_hive
from app.parsers.sqlite_parser import parse_sqlite
from app.parsers.trash_info import is_trash_info_path, parse_trash_info

from app.parsers.setupapi import parse_setupapi_log

PARSER_VERSION = "2.12.0"

# Extensionless / special SQLite DBs common in browser & chat forensics
_SQLITE_BASENAMES = frozenset({
    "history",
    "cookies",
    "web data",
    "login data",
    "favicons",
    "top sites",
    "visited links",
    "bookmarks",
    "preferences",
    "shortcuts",
    "current session",
    "current tabs",
    "places.sqlite",
    "cookies.sqlite",
    "msgstore.db",
    "wa.db",
    "messages.db",
    "chat.db",
    "conversations.db",
})

_CHAT_APP_MARKERS = (
    "whatsapp",
    "discord",
    "slack",
    "telegram",
    "skype",
    "signal",
    "teams",
    "zoom",
)


def parse_text_file(data: bytes) -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-16" if data.startswith((b"\xff\xfe",b"\xfe\xff")) else "utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return [{"line_count": len(lines), "text": text, "preview": "\n".join(lines[:20])}]


def parse_file_metadata(path: str, data: bytes) -> list[dict[str, Any]]:
    """Fallback so every extracted file becomes searchable evidence."""
    head = data[:4096]
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    ratio = (printable / len(head)) if head else 0.0
    text_preview = ""
    if ratio >= 0.75 and head:
        text_preview = head.decode("utf-8", errors="replace")[:8000]
    magic = head[:16].hex() if head else ""
    return [{
        "record_type": "file_metadata",
        "path": path,
        "size_bytes": len(data),
        "magic_hex": magic,
        "text_preview": text_preview,
        "text": text_preview or f"File {path} ({len(data)} bytes)",
        "preview": text_preview[:500] if text_preview else f"binary file {path}",
    }]


PARSERS: dict[str, Callable[..., list[dict[str, Any]]]] = {
    ".evtx": lambda d, p: parse_evtx(d, p),
    ".dat": lambda d, p: parse_registry_hive(d, p) if d.startswith(b'regf') else parse_communications_file(d, p),
    ".sqlite": lambda d, p: parse_sqlite(d, p),
    ".db": lambda d, p: parse_sqlite(d, p),
    ".txt": lambda d, p: parse_text_file(d),
    ".log": lambda d, p: parse_text_file(d),
    ".csv": lambda d, p: parse_text_file(d),
    ".json": lambda d, p: parse_text_file(d),
    ".xml": lambda d, p: parse_text_file(d),
    ".html": lambda d, p: parse_text_file(d),
    ".htm": lambda d, p: parse_text_file(d),
    ".md": lambda d, p: parse_text_file(d),
    ".ini": lambda d, p: parse_text_file(d),
    ".cfg": lambda d, p: parse_text_file(d),
    ".conf": lambda d, p: parse_text_file(d),
    ".yaml": lambda d, p: parse_text_file(d),
    ".yml": lambda d, p: parse_text_file(d),
    ".ps1": lambda d, p: parse_text_file(d),
    ".bat": lambda d, p: parse_text_file(d),
    ".reg": lambda d, p: parse_text_file(d),
    ".eml": lambda d, p: parse_email_file(d, p) or parse_text_file(d),
    ".emlx": lambda d, p: parse_email_file(d, p) or parse_text_file(d),
    ".mbox":parse_communications_file,
    ".mbx":parse_communications_file,
    ".msg":parse_communications_file,
    ".plist":parse_communications_file,
    ".bplist":parse_communications_file,
    ".jsonl":parse_communications_file,
    ".ndjson":parse_communications_file,
    ".bin":parse_communications_file,
    ".pb":parse_communications_file,
    ".protobuf":parse_communications_file,
    ".blob":parse_communications_file,
    ".pf": lambda d, p: parse_prefetch(d, p),
    ".lnk": lambda d, p: parse_lnk(d, p),
    ".automaticdestinations-ms": lambda d, p: parse_jump_list(d, p),
    ".customdestinations-ms": lambda d, p: parse_jump_list(d, p),
}

REGISTRY_NAMES = frozenset({
    "sam", "system", "software", "security", "default",
    "ntuser.dat", "usrclass.dat", "amcache.hve",
})


def select_parser(path: str) -> tuple[str, Callable[..., list[dict[str, Any]]]] | None:
    norm = path.replace("\\", "/")
    ext = PurePosixPath(norm).suffix.lower()
    name = PurePosixPath(norm).name.lower()

    # Special forensic files before generic extension routing.
    if is_recycle_bin_i_path(norm) or (
        name.startswith("$i") and ("$recycle.bin" in norm.lower() or "recycle" in norm.lower())
    ):
        return "recycle_bin", lambda d, p: parse_recycle_bin_i(d, p)
    if is_trash_info_path(norm) or name.endswith(".trashinfo"):
        return "trash_info", lambda d, p: parse_trash_info(d, p)
    if name == "setupapi.dev.log" or name.startswith("setupapi.dev") or (
        "setupapi.dev" in name and name.endswith(".log")
    ):
        return "setupapi", lambda d, p: parse_setupapi_log(d, p)
    if "automaticdestinations" in name or "customdestinations" in name or ext in {
        ".automaticdestinations-ms",
        ".customdestinations-ms",
    }:
        return "jumplist", lambda d, p: parse_jump_list(d, p)
    if name in REGISTRY_NAMES or ext == ".hve":
        return "registry", lambda d, p: parse_registry_hive(d, p)
    if name in _SQLITE_BASENAMES:
        return "sqlite", lambda d, p: parse_sqlite(d, p)
    if name == "history" or (
        "/user data/" in norm.lower()
        and name in {"history", "cookies", "web data", "login data", "favicons", "top sites"}
    ):
        return "sqlite", lambda d, p: parse_sqlite(d, p)
    if any(app in norm.lower() for app in _CHAT_APP_MARKERS) and (
        ext in {".db", ".sqlite", ".sqlite3"} or name.endswith(".db") or name in _SQLITE_BASENAMES
    ):
        return "sqlite", lambda d, p: parse_sqlite(d, p)
    if "whatsapp" in norm.lower() and (ext in {".db", ".sqlite"} or name.endswith(".db")):
        return "sqlite", lambda d, p: parse_sqlite(d, p)
    if not ext and name in ("hosts", "lmhosts", "services", "protocol", "networks"):
        return ".txt", PARSERS[".txt"]
    if "$mft" in name or name.startswith("$"):
        return "mft", lambda d, p: parse_mft_metadata(p, len(d))
    if ext in PARSERS:
        return ext, PARSERS[ext]
    return None


def run_parser(path: str, data: bytes) -> tuple[str, list[dict[str, Any]]]:
    sel = select_parser(path)
    if not sel:
        # Extensionless RFC822 messages are common in Apple Mail, Maildir, browser
        # downloads and forensic exports.  Detect them by structured headers before
        # falling back to generic file metadata so EML evidence is searchable.
        if is_extensionless_email_candidate(data):
            records = parse_email_file(data, path)
            if records:
                return "email_mime", records
        if data[:16].startswith(b"SQLite format"):
            return "sqlite", parse_sqlite(data, path)
        meta = parse_mft_metadata(path, len(data))
        if meta and any(k in meta[0] for k in ("user_profile", "ntfs_system", "installed_software_path")):
            return "mft", meta
        # Never leave extracted files as empty/no_parser — index metadata + text sniff.
        return "file_meta", parse_file_metadata(path, data)
    key, fn = sel
    records = fn(data, path)
    if not records:
        return "file_meta", parse_file_metadata(path, data)
    return key, records
