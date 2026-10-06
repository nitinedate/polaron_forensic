"""Path-based encyclopedia classification for job artifacts.

The previous matcher used substring checks against prose in ``file_extensions``,
which mis-tagged thousands of files (e.g. ``.ini`` → WFS-NTFS-0005 /$AttrDef).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

# Stable forensic taxonomy — mix of real encyclopedia IDs + extended IDs we seed.
# Order matters: first match wins.
_PATH_RULES: list[tuple[re.Pattern[str], str]] = [
    # Registry hives
    (re.compile(r"(^|/)windows/system32/config/system$", re.I), "WRG-HIVE-0001"),
    (re.compile(r"(^|/)windows/system32/config/software$", re.I), "WRG-HIVE-0002"),
    (re.compile(r"(^|/)windows/system32/config/sam$", re.I), "WRG-HIVE-0003"),
    (re.compile(r"(^|/)windows/system32/config/security$", re.I), "WRG-HIVE-0004"),
    (re.compile(r"(^|/)windows/system32/config/default$", re.I), "WRG-HIVE-0005"),
    (re.compile(r"(^|/)windows/system32/config/components$", re.I), "WRG-HIVE-0012"),
    (re.compile(r"(^|/)windows/system32/config/elam$", re.I), "WRG-HIVE-0011"),
    (re.compile(r"(^|/)ntuser\.dat$", re.I), "WRG-HIVE-0006"),
    (re.compile(r"/ntuser\.dat$", re.I), "WRG-HIVE-0006"),
    (re.compile(r"usrclass\.dat$", re.I), "WRG-HIVE-0007"),
    (re.compile(r"amcache\.hve$", re.I), "WRG-HIVE-0008"),
    (re.compile(r"syscache\.hve$", re.I), "WRG-HIVE-0009"),
    (re.compile(r"/config/regback/", re.I), "WRG-HIVE-0015"),
    (re.compile(r"\.log[12]$", re.I), "WRG-HIVE-0013"),
    # Event logs
    (re.compile(r"\.evtx$", re.I), "WRG-EVT-0001"),
    (re.compile(r"/winevt/logs/", re.I), "WRG-EVT-0001"),
    # Prefetch / execution
    (re.compile(r"/prefetch/.*\.pf$", re.I), "WRX-PRE-0001"),
    (re.compile(r"\.pf$", re.I), "WRX-PRE-0001"),
    # Shell / LNK / jump lists / thumbs
    (re.compile(r"\.lnk$", re.I), "WFS-SHL-0001"),
    (re.compile(r"\.automaticdestinations-ms$", re.I), "WFS-SHL-0002"),
    (re.compile(r"\.customdestinations-ms$", re.I), "WFS-SHL-0002"),
    (re.compile(r"thumbcache_.*\.db$", re.I), "WFS-SHL-0006"),
    (re.compile(r"iconcache_.*\.db$", re.I), "WFS-SHL-0007"),
    (re.compile(r"(^|/)thumbs\.db$", re.I), "WFS-SHL-0005"),
    (re.compile(r"(^|/)desktop\.ini$", re.I), "WFS-SHL-0004"),
    # Recycle bin
    (re.compile(r"\$recycle\.bin/.*/\$i", re.I), "WFS-RB-0001"),
    (re.compile(r"\$recycle\.bin/.*/\$r", re.I), "WFS-RB-0002"),
    (re.compile(r"\$recycle\.bin/", re.I), "WFS-RB-0001"),
    (re.compile(r"(^|/)recycler/", re.I), "WFS-RB-0003"),
    # VSS
    (re.compile(r"system volume information", re.I), "WFS-VSC-0001"),
    # SetupAPI / USB
    (re.compile(r"setupapi(\.dev)?\.log$", re.I), "WRG-USB-0001"),
    # Browser — Chrome / Edge / Firefox / IE
    (re.compile(r"/google/chrome/.*/user data/.*/history$", re.I), "BRW-CHR-0001"),
    (re.compile(r"/google/chrome/.*/history$", re.I), "BRW-CHR-0001"),
    (re.compile(r"/microsoft/edge/.*/user data/.*/history$", re.I), "BRW-EDG-0001"),
    (re.compile(r"/microsoft/edge/.*/history$", re.I), "BRW-EDG-0001"),
    (re.compile(r"/microsoft/edge/.*/web data$", re.I), "BRW-EDG-0002"),
    (re.compile(r"/google/chrome/.*/web data$", re.I), "BRW-CHR-0002"),
    (re.compile(r"/google/chrome/.*/cookies$", re.I), "BRW-CHR-0003"),
    (re.compile(r"/microsoft/edge/.*/cookies$", re.I), "BRW-EDG-0003"),
    (re.compile(r"/google/chrome/.*/login data$", re.I), "BRW-CHR-0004"),
    (re.compile(r"/google/chrome/.*/favicons$", re.I), "BRW-CHR-0005"),
    (re.compile(r"/google/chrome/.*/top sites$", re.I), "BRW-CHR-0006"),
    (re.compile(r"/microsoft/edge/.*/favicons$", re.I), "BRW-EDG-0004"),
    (re.compile(r"/microsoft/edge/.*/top sites$", re.I), "BRW-EDG-0005"),
    (re.compile(r"/microsoft/edge/.*/login data$", re.I), "BRW-EDG-0006"),
    (re.compile(r"places\.sqlite$", re.I), "BRW-FF-0001"),
    (re.compile(r"cookies\.sqlite$", re.I), "BRW-FF-0002"),
    (re.compile(r"/mozilla/firefox/", re.I), "BRW-FF-0003"),
    (re.compile(r"/internet explorer/", re.I), "BRW-IE-0001"),
    (re.compile(r"/webview/.*/history$", re.I), "BRW-WEBVIEW-0001"),
    (re.compile(r"/ebwebview/.*/history$", re.I), "BRW-WEBVIEW-0001"),
    # Chat / messaging desktop apps
    (re.compile(r"/discord/", re.I), "CHAT-DSC-0001"),
    (re.compile(r"/slack/", re.I), "CHAT-SLK-0001"),
    (re.compile(r"/telegram/", re.I), "CHAT-TGM-0001"),
    (re.compile(r"/microsoft/teams/", re.I), "CHAT-TEA-0001"),
    (re.compile(r"/skype/", re.I), "CHAT-SKP-0001"),
    (re.compile(r"/signal/", re.I), "CHAT-SIG-0001"),
    (re.compile(r"/local storage/", re.I), "CHAT-ELEC-0001"),
    (re.compile(r"/indexeddb/", re.I), "CHAT-ELEC-0001"),
    (re.compile(r"/leveldb/", re.I), "CHAT-ELEC-0001"),
    # Email / Outlook
    (re.compile(r"\.pst$", re.I), "EML-PST-0001"),
    (re.compile(r"\.ost$", re.I), "EML-OST-0001"),
    (re.compile(r"\.eml$", re.I), "EML-EML-0001"),
    (re.compile(r"\.msg$", re.I), "EML-MSG-0001"),
    (re.compile(r"/outlook files/", re.I), "EML-PST-0001"),
    # Chat / WhatsApp
    (re.compile(r"msgstore.*\.db", re.I), "CHAT-WA-0001"),
    (re.compile(r"whatsapp", re.I), "CHAT-WA-0001"),
    # SQLite / DB generally under AppData
    (re.compile(r"\.sqlite3?$", re.I), "WRX-SQL-0001"),
    (re.compile(r"(^|/)history$", re.I), "BRW-CHR-0001"),
    # Documents
    (re.compile(r"\.(docx?|xlsx?|pptx?|rtf|odt|ods)$", re.I), "DOC-OFFICE-0001"),
    (re.compile(r"\.pdf$", re.I), "DOC-PDF-0001"),
    (re.compile(r"\.(jpe?g|png|gif|bmp|webp|tif{1,2})$", re.I), "DOC-IMAGE-0001"),
    (re.compile(r"\.(mp4|avi|mkv|mov|wmv|mp3|wav)$", re.I), "DOC-MEDIA-0001"),
    (re.compile(r"\.(txt|log|csv|json|xml|yml|yaml|ini|cfg|conf|md)$", re.I), "DOC-TEXT-0001"),
    (re.compile(r"\.(htm|html|mht|mhtml)$", re.I), "DOC-WEB-0001"),
    # Executables / libraries
    (re.compile(r"\.(exe|dll|sys|ocx|cpl|drv|mui)$", re.I), "SYS-BIN-0001"),
    (re.compile(r"\.(msi|msp|cab|msu)$", re.I), "SYS-INSTALL-0001"),
    (re.compile(r"\.(ps1|bat|cmd|vbs|js|wsf)$", re.I), "SYS-SCRIPT-0001"),
    # User profile / Windows / Program roots (broad, last)
    (re.compile(r"^users/[^/]+/documents/", re.I), "USR-DOCS-0001"),
    (re.compile(r"^users/[^/]+/downloads/", re.I), "USR-DL-0001"),
    (re.compile(r"^users/[^/]+/desktop/", re.I), "USR-DESK-0001"),
    (re.compile(r"^users/[^/]+/appdata/", re.I), "USR-APPDATA-0001"),
    (re.compile(r"^users/", re.I), "USR-PROFILE-0001"),
    (re.compile(r"^windows/system32/", re.I), "SYS-WIN32-0001"),
    (re.compile(r"^windows/syswow64/", re.I), "SYS-WIN32-0001"),
    (re.compile(r"^windows/", re.I), "SYS-WINDOWS-0001"),
    (re.compile(r"^program files( \(x86\))?/", re.I), "SYS-PROGRAMFILES-0001"),
    (re.compile(r"^programdata/", re.I), "SYS-PROGRAMDATA-0001"),
]

_EXTENDED_ENCYCLOPEDIA: list[dict[str, str]] = [
    {"artifact_id": "WRG-EVT-0001", "artifact_name": "Windows Event Log (.evtx)", "category": "Event Logs", "section": "Windows"},
    {"artifact_id": "WRX-PRE-0001", "artifact_name": "Prefetch (.pf)", "category": "Execution", "section": "Windows"},
    {"artifact_id": "WRX-SQL-0001", "artifact_name": "SQLite database", "category": "Databases", "section": "Application"},
    {"artifact_id": "WRG-USB-0001", "artifact_name": "SetupAPI device install log", "category": "USB / Devices", "section": "Windows"},
    {"artifact_id": "BRW-CHR-0001", "artifact_name": "Chrome browser history", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-CHR-0002", "artifact_name": "Chrome Web Data", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-CHR-0003", "artifact_name": "Chrome cookies", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-CHR-0004", "artifact_name": "Chrome Login Data", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-CHR-0005", "artifact_name": "Chrome Favicons", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-CHR-0006", "artifact_name": "Chrome Top Sites", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-EDG-0001", "artifact_name": "Edge browser history", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-EDG-0002", "artifact_name": "Edge Web Data", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-EDG-0003", "artifact_name": "Edge cookies", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-EDG-0004", "artifact_name": "Edge Favicons", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-EDG-0005", "artifact_name": "Edge Top Sites", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-EDG-0006", "artifact_name": "Edge Login Data", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-FF-0001", "artifact_name": "Firefox places.sqlite", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-FF-0002", "artifact_name": "Firefox cookies.sqlite", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-FF-0003", "artifact_name": "Firefox profile data", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-IE-0001", "artifact_name": "Internet Explorer data", "category": "Browser", "section": "Web"},
    {"artifact_id": "BRW-WEBVIEW-0001", "artifact_name": "Embedded WebView history", "category": "Browser", "section": "Web"},
    {"artifact_id": "EML-PST-0001", "artifact_name": "Outlook PST mailbox", "category": "Email", "section": "Communication"},
    {"artifact_id": "EML-OST-0001", "artifact_name": "Outlook OST mailbox", "category": "Email", "section": "Communication"},
    {"artifact_id": "EML-EML-0001", "artifact_name": "Email message (.eml)", "category": "Email", "section": "Communication"},
    {"artifact_id": "EML-MSG-0001", "artifact_name": "Outlook message (.msg)", "category": "Email", "section": "Communication"},
    {"artifact_id": "CHAT-WA-0001", "artifact_name": "WhatsApp message store", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-DSC-0001", "artifact_name": "Discord application data", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-SLK-0001", "artifact_name": "Slack application data", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-TGM-0001", "artifact_name": "Telegram application data", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-TEA-0001", "artifact_name": "Microsoft Teams data", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-SKP-0001", "artifact_name": "Skype application data", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-SIG-0001", "artifact_name": "Signal application data", "category": "Chat", "section": "Communication"},
    {"artifact_id": "CHAT-ELEC-0001", "artifact_name": "Electron app local storage", "category": "Chat", "section": "Communication"},
    {"artifact_id": "DOC-OFFICE-0001", "artifact_name": "Office documents", "category": "Documents", "section": "User Files"},
    {"artifact_id": "DOC-PDF-0001", "artifact_name": "PDF documents", "category": "Documents", "section": "User Files"},
    {"artifact_id": "DOC-IMAGE-0001", "artifact_name": "Image files", "category": "Media", "section": "User Files"},
    {"artifact_id": "DOC-MEDIA-0001", "artifact_name": "Audio / video files", "category": "Media", "section": "User Files"},
    {"artifact_id": "DOC-TEXT-0001", "artifact_name": "Text / log / config files", "category": "Documents", "section": "User Files"},
    {"artifact_id": "DOC-WEB-0001", "artifact_name": "HTML / web page files", "category": "Documents", "section": "User Files"},
    {"artifact_id": "SYS-BIN-0001", "artifact_name": "Windows binaries (EXE/DLL/SYS)", "category": "System", "section": "Windows"},
    {"artifact_id": "SYS-INSTALL-0001", "artifact_name": "Installer packages", "category": "System", "section": "Windows"},
    {"artifact_id": "SYS-SCRIPT-0001", "artifact_name": "Scripts (PS1/BAT/JS/VBS)", "category": "System", "section": "Windows"},
    {"artifact_id": "USR-DOCS-0001", "artifact_name": "User Documents folder", "category": "User Profile", "section": "Windows"},
    {"artifact_id": "USR-DL-0001", "artifact_name": "User Downloads folder", "category": "User Profile", "section": "Windows"},
    {"artifact_id": "USR-DESK-0001", "artifact_name": "User Desktop folder", "category": "User Profile", "section": "Windows"},
    {"artifact_id": "USR-APPDATA-0001", "artifact_name": "User AppData", "category": "User Profile", "section": "Windows"},
    {"artifact_id": "USR-PROFILE-0001", "artifact_name": "User profile files", "category": "User Profile", "section": "Windows"},
    {"artifact_id": "SYS-WIN32-0001", "artifact_name": "Windows System32 / SysWOW64", "category": "System", "section": "Windows"},
    {"artifact_id": "SYS-WINDOWS-0001", "artifact_name": "Windows directory files", "category": "System", "section": "Windows"},
    {"artifact_id": "SYS-PROGRAMFILES-0001", "artifact_name": "Program Files", "category": "System", "section": "Windows"},
    {"artifact_id": "SYS-PROGRAMDATA-0001", "artifact_name": "ProgramData", "category": "System", "section": "Windows"},
    {"artifact_id": "FS-GENERIC-0001", "artifact_name": "Other extracted file", "category": "File System", "section": "General"},
]


def ensure_extended_encyclopedia(db) -> int:
    """Seed extended forensic categories used by the path classifier."""
    n = 0
    for row in _EXTENDED_ENCYCLOPEDIA:
        execute(
            db,
            """INSERT INTO public.encyclopedia_artifacts
               (artifact_id, artifact_name, volume, section, category, operating_system,
                default_paths, file_extensions, evidence_value, search_text)
               VALUES (:aid, :name, 'Extended', :sec, :cat, 'Windows',
                       '', '', 'medium', :search)
               ON CONFLICT (artifact_id) DO UPDATE SET
                 artifact_name=EXCLUDED.artifact_name,
                 category=EXCLUDED.category,
                 section=EXCLUDED.section,
                 updated_at=NOW()""",
            {
                "aid": row["artifact_id"],
                "name": row["artifact_name"],
                "sec": row["section"],
                "cat": row["category"],
                "search": f"{row['artifact_id']} {row['artifact_name']} {row['category']}",
            },
        )
        n += 1
    return n


def _parse_extension_tokens(file_extensions: str | None) -> set[str]:
    """Extract real extension tokens from encyclopedia field (ignore prose)."""
    if not file_extensions:
        return set()
    text = file_extensions.lower()
    tokens: set[str] = set()
    for m in re.finditer(r"(?:\*\.)?(\.[a-z0-9]{1,12})\b", text):
        tokens.add(m.group(1))
    # Also accept bare tokens like "lnk" only when listed as short tokens
    for part in re.split(r"[,;/|]+", text):
        p = part.strip().lower()
        if re.fullmatch(r"\.[a-z0-9]{1,12}", p):
            tokens.add(p)
        elif re.fullmatch(r"[a-z0-9]{1,8}", p) and p not in {
            "ntfs", "mft", "fat", "exfat", "refs", "ole", "ini", "guid", "key", "text",
            "data", "file", "files", "table", "index", "binary", "sparse", "slack",
        }:
            tokens.add(f".{p}")
    return tokens


def match_encyclopedia_id(path: str, enc_cache: list[dict] | None = None) -> str | None:
    """Return best encyclopedia artifact_id for a relative forensic path."""
    norm = path.replace("\\", "/").strip("/")
    low = norm.lower()
    name = PurePosixPath(low).name
    ext = PurePosixPath(low).suffix.lower()

    for pat, aid in _PATH_RULES:
        if pat.search(low) or pat.search(f"/{low}"):
            return aid

    # Conservative encyclopedia path / exact-extension match (no prose substrings).
    if enc_cache:
        for row in enc_cache:
            paths = (row.get("default_paths") or "").lower()
            if name and len(name) >= 3 and name in paths and ("\\" in paths or "/" in paths or "%" in paths):
                # Prefer path hints that look like filesystem locations
                if any(tok in paths for tok in ("system32", "users", "appdata", "prefetch", "recycle", name)):
                    return row["artifact_id"]
        if ext:
            for row in enc_cache:
                tokens = _parse_extension_tokens(row.get("file_extensions"))
                if ext in tokens:
                    return row["artifact_id"]

    return "FS-GENERIC-0001"


def load_encyclopedia_cache(db) -> list[dict]:
    rows = fetchall(
        db,
        "SELECT artifact_id, file_extensions, default_paths, artifact_name, category FROM public.encyclopedia_artifacts",
        {},
    )
    return [dict(r) for r in rows]


def encyclopedia_label_map(db) -> dict[str, str]:
    rows = fetchall(
        db,
        "SELECT artifact_id, artifact_name, category FROM public.encyclopedia_artifacts",
        {},
    )
    out: dict[str, str] = {}
    for r in rows:
        aid = r["artifact_id"]
        name = r.get("artifact_name") or aid
        cat = r.get("category") or ""
        out[aid] = f"{name}" if not cat else f"{name} ({cat})"
    for row in _EXTENDED_ENCYCLOPEDIA:
        out.setdefault(row["artifact_id"], f"{row['artifact_name']} ({row['category']})")
    return out


def reclassify_job_artifacts(db, job_id: str, *, batch_size: int = 2000) -> dict[str, Any]:
    """Re-apply path classifier to every artifact for a job (fixes unmatched + bad tags)."""
    ensure_extended_encyclopedia(db)
    enc_cache = load_encyclopedia_cache(db)
    total = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:j", {"j": job_id})
    total_n = int(total["c"]) if total else 0
    updated = 0
    matched = 0
    last_id = "00000000-0000-0000-0000-000000000000"
    while True:
        rows = fetchall(
            db,
            """SELECT id, file_path, encyclopedia_artifact_id
               FROM job_artifacts
               WHERE job_id=:j AND id > :last
               ORDER BY id LIMIT :lim""",
            {"j": job_id, "last": last_id, "lim": batch_size},
        )
        if not rows:
            break
        for r in rows:
            last_id = str(r["id"])
            new_id = match_encyclopedia_id(r["file_path"] or "", enc_cache)
            if new_id:
                matched += 1
            if new_id != r.get("encyclopedia_artifact_id"):
                execute(
                    db,
                    """UPDATE job_artifacts
                       SET encyclopedia_artifact_id=:aid, updated_at=NOW()
                       WHERE id=:id""",
                    {"aid": new_id, "id": r["id"]},
                )
                updated += 1
        db.commit()
    unmatched = fetchone(
        db,
        """SELECT count(*) c FROM job_artifacts
           WHERE job_id=:j AND (encyclopedia_artifact_id IS NULL OR encyclopedia_artifact_id='FS-GENERIC-0001')""",
        {"j": job_id},
    )
    return {
        "status": "ok",
        "total": total_n,
        "matched": matched,
        "updated": updated,
        "generic_or_null": int(unmatched["c"]) if unmatched else 0,
    }
