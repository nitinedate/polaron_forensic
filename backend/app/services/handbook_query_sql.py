"""SQL WHERE fragments aligned with forensic_handbook_scope (Phase 1-40).

Used by artifact browse, export, counting, and MIME inventory queries so indexed
handbook extensions and extensionless mail/browser/mobile paths are included.
"""

from __future__ import annotations

from app.services.forensic_handbook_scope import (
    HANDBOOK_EVIDENCE_EXTENSIONS,
    HANDBOOK_SPECIAL_BASENAMES,
)

# Media groups — handbook §29 + AXIOM media_inventory parity.
HANDBOOK_PICTURE_EXTS: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".heif", ".ico", ".jfif",
    ".cr2", ".nef", ".dng", ".raw", ".arw", ".orf", ".svg", ".emf", ".wmf", ".jpe", ".tga", ".dib",
}) & HANDBOOK_EVIDENCE_EXTENSIONS | frozenset({".svg", ".emf", ".wmf", ".jpe", ".tga", ".dib"})

HANDBOOK_AUDIO_EXTS: frozenset[str] = frozenset({
    ".mp3", ".wav", ".wma", ".m4a", ".aac", ".flac", ".ogg", ".mid", ".midi",
    ".aiff", ".aif", ".opus", ".amr", ".ra", ".ram", ".cda", ".ac3", ".ape", ".mka", ".dts", ".mp2", ".mpa",
}) & HANDBOOK_EVIDENCE_EXTENSIONS | frozenset({
    ".aiff", ".aif", ".opus", ".amr", ".ra", ".ram", ".cda", ".ac3", ".ape", ".mka", ".dts", ".mp2", ".mpa",
})

HANDBOOK_VIDEO_EXTS: frozenset[str] = frozenset({
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg", ".m4v", ".3gp", ".webm", ".ts",
    ".mts", ".vob", ".asf", ".m2ts", ".divx", ".f4v", ".ogv", ".rm", ".rmvb", ".3g2", ".wtv", ".dvr-ms",
}) & HANDBOOK_EVIDENCE_EXTENSIONS | frozenset({
    ".mts", ".vob", ".asf", ".m2ts", ".divx", ".f4v", ".ogv", ".rm", ".rmvb", ".3g2", ".wtv", ".dvr-ms",
})

HANDBOOK_PHOTOSHOP_EXTS: frozenset[str] = frozenset({".psd", ".psb", ".pdd"})

HANDBOOK_DOCUMENT_EXTS: frozenset[str] = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx",
    ".rtf", ".odt", ".ods", ".odp", ".one", ".pub", ".csv", ".txt",
}) & HANDBOOK_EVIDENCE_EXTENSIONS

HANDBOOK_EMAIL_EXTS: frozenset[str] = frozenset({
    ".eml", ".emlx", ".msg", ".pst", ".ost", ".mbox", ".dbx", ".ics", ".vcf",
}) & HANDBOOK_EVIDENCE_EXTENSIONS

HANDBOOK_NETWORK_CONTAINER_EXTS: frozenset[str] = frozenset({
    ".pcap", ".pcapng", ".cap", ".vmem", ".lime", ".core", ".raw", ".img",
    ".tar", ".gz", ".tgz", ".bz2", ".xz", ".dmg", ".vmdk", ".qcow2", ".tc", ".hc", ".luks",
}) & HANDBOOK_EVIDENCE_EXTENSIONS


def _norm_ext(ext: str) -> str:
    e = (ext or "").strip().lower()
    if not e:
        return ""
    return e if e.startswith(".") else f".{e}"


def escape_sqlalchemy_literal(value: str) -> str:
    """Escape ``:name`` bind markers inside static SQL fragments for sqlalchemy.text()."""
    return (value or "").replace(":", "\\:")


def sql_ilike_contains(literal: str) -> str:
    """Safe ILIKE ``%literal%`` clause for sqlalchemy.text() (Maildir ``:2,S`` etc.)."""
    return f"file_path ILIKE '{escape_sqlalchemy_literal(f'%{literal}%')}'"


def sql_extension_match(
    extensions: frozenset[str] | list[str] | set[str],
    *,
    include_path_ilike: bool = True,
) -> str:
    """Match extension column and optional path suffix (basename fallback)."""
    exts = sorted({_norm_ext(e) for e in extensions if _norm_ext(e)})
    if not exts:
        return "FALSE"
    quoted = ", ".join(f"'{e}'" for e in exts)
    parts = [f"lower(coalesce(extension,'')) IN ({quoted})"]
    if include_path_ilike:
        for e in exts:
            parts.append(f"file_path ILIKE '%{e}'")
        parts.append(
            "lower(regexp_replace(coalesce(file_name, ''), "
            "'^.*(\\.[a-z0-9]+)$', '\\1')) IN ({quoted})".format(quoted=quoted)
        )
    return "(" + " OR ".join(parts) + ")"


def sql_special_basename_match(*, max_items: int = 64) -> str:
    """Match handbook special basenames (History, Cookies, registry hives, etc.)."""
    bases = sorted(HANDBOOK_SPECIAL_BASENAMES)[:max_items]
    if not bases:
        return "FALSE"
    quoted = ", ".join(f"'{b}'" for b in bases)
    parts = [
        f"lower(coalesce(file_name,'')) IN ({quoted})",
        "lower(coalesce(file_name,'')) LIKE 'manifest-%'",
        "file_path ILIKE '%/$Recycle.Bin/%/$I%'",
        "file_path ILIKE '%/recovery.%'",
        "file_path ILIKE '%/previous.%'",
    ]
    return "(" + " OR ".join(parts) + ")"


_NORMALIZED_MAIL_PATH_SQL = "lower(replace(coalesce(file_path,''), '\\', '/'))"

# Extensionless mail / mailbox message files (§7, §31).
EXTENSIONLESS_MAIL_WHERE = f"""
(
  {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/maildir/%/cur/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/maildir/%/new/%'
  OR (
    {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/thunderbird/%/mail/%'
    AND lower(coalesce(file_name,'')) NOT IN (
      'global-messages-db.sqlite','foldercache.json','xulstore.json','prefs.js','profiles.ini'
    )
    AND {_NORMALIZED_MAIL_PATH_SQL} NOT LIKE '%.msf'
    AND {_NORMALIZED_MAIL_PATH_SQL} NOT LIKE '%.sqlite'
  )
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/library/mail/v%/%/messages/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/library/mail/%/messages/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/mail downloads/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/local/microsoft/outlook/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/content.outlook/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%content.outlook%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/inetcache/content.outlook/%'
)
"""

# Canonical RFC822 / EML evidence set.
#
# IMPORTANT: count, browse and MIME parsing all use this same predicate.  Earlier
# builds could count an extensionless MIME-validated message while the Artifact
# browser filtered only on ``.eml/.emlx``.  That produced the exact bad state
# "EML(X) Files = 1" with "0 matching" evidence rows.
#
# ``EML_RFC822_ANY_WHERE`` includes derived Outlook->EML rows because they must be
# parsed for body/attachment access.  ``EML_EMLX_FILE_WHERE`` excludes those
# derived rows from the EML(X) catalog so Outlook messages are not double-counted.
EML_RFC822_ANY_WHERE = f"""
(
  {sql_extension_match(['.eml', '.emlx'])}
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/library/mail/%/messages/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/mail downloads/%.eml%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/containers/com.apple.mail/%/messages/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/maildir/%/cur/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/maildir/%/new/%'
  OR lower(coalesce(metadata->>'resolved_content_type','')) = 'message/rfc822'
  OR lower(coalesce(metadata->>'content_type','')) = 'message/rfc822'
  OR lower(coalesce(metadata->>'detected_extension','')) IN ('.eml', '.emlx')
  OR lower(coalesce(metadata->>'normalized_filename','')) LIKE '%.eml'
  OR lower(coalesce(metadata->>'normalized_filename','')) LIKE '%.emlx'
  OR coalesce(metadata->>'email_mime_validated','false') IN ('true','1','t')
)
"""

EML_EMLX_FILE_WHERE = f"""
(
  {EML_RFC822_ANY_WHERE.strip()}
)
AND coalesce(metadata->>'derived_from_mailbox','false') NOT IN ('true','1','t')
"""

MBOX_EMAIL_WHERE = f"""
(
  {sql_extension_match(['.mbox'])}
  OR file_path ILIKE '%/Thunderbird/%/Mail/%'
  OR file_path ILIKE '%/Maildir/%'
  OR file_path ILIKE '%/maildir/%'
)
"""

EMAIL_ATTACHMENT_WHERE = f"""
(
  file_path ILIKE '%/Attachments/%'
  OR file_path ILIKE '%/Attachment/%'
  OR file_path ILIKE '%Content.Outlook%'
  OR file_path ILIKE '%/Olk/%Attachment%'
  OR file_path ILIKE '%/Mail/Local Folders/%'
  OR file_path ILIKE '%Thunderbird%/Mail/%'
  OR file_path ILIKE '%/INBOX/%'
  OR file_path ILIKE '%Olk%Attachment%'
  OR file_path ILIKE '%/Microsoft/Windows/INetCache/Content.Outlook/%'
  OR file_path ILIKE '%/Local/Microsoft/Outlook/%'
  OR file_path ILIKE '%/AppData/Local/Microsoft/Outlook/%'
  OR file_path ILIKE '%/Windows Mail/%'
  OR file_path ILIKE '%windowscommunicationsapps%Attachments%'
  OR file_path ILIKE '%/Maildir/%'
  OR file_path ILIKE '%/maildir/%'
  OR file_path ILIKE '%/Library/Mail/%'
  OR file_path ILIKE '%/Mail Downloads/%'
  OR (file_path ILIKE '%/Olk/%' AND file_path ILIKE '%attach%')
  OR {sql_ilike_contains(':2,S')}
  OR {sql_ilike_contains(':2,PS')}
)
AND file_path NOT ILIKE '%.db'
AND file_path NOT ILIKE '%.sqlite'
AND file_path NOT ILIKE '%.xml'
AND file_path NOT ILIKE '%.ini'
AND file_path NOT ILIKE '%.dat'
AND file_path NOT ILIKE '%.srs'
AND size_bytes > 64
"""

OUTLOOK_EMAIL_WHERE = f"""
(
  {sql_extension_match(['.msg', '.pst', '.ost'])}
  OR file_path ILIKE '%/Outlook Files/%'
  OR file_path ILIKE '%/Microsoft/Outlook/%'
  OR file_path ILIKE '%/Local/Microsoft/Outlook/%'
  OR (file_path ILIKE '%/Olk/%' AND file_path NOT ILIKE '%Attachment%')
  OR file_path ILIKE '%/Content.Outlook/%'
)
"""

WEB_RELATED_WHERE = f"""
(
  {sql_special_basename_match()}
  OR file_path ILIKE '%/History'
  OR file_path ILIKE '%/Cookies'
  OR file_path ILIKE '%/Web Data'
  OR file_path ILIKE '%/Favicons'
  OR file_path ILIKE '%/Top Sites'
  OR file_path ILIKE '%/Login Data'
  OR file_path ILIKE '%/Bookmarks'
  OR file_path ILIKE '%/Downloads/%'
  OR file_path ILIKE '%places.sqlite'
  OR file_path ILIKE '%/User Data/%'
  OR file_path ILIKE '%/EBWebView/%'
  OR file_path ILIKE '%/Mozilla/Firefox/Profiles/%'
  OR file_path ILIKE '%sessionstore%'
  OR file_path ILIKE '%/leveldb/%'
  OR file_path ILIKE '%/Local Storage/%'
  OR file_path ILIKE '%/IndexedDB/%'
  OR file_path ILIKE '%/Session Storage/%'
  OR encyclopedia_artifact_id ~ '^(BRW-)'
)
AND file_path NOT ILIKE '%/Cache/%'
AND file_path NOT ILIKE '%/Code Cache/%'
"""

# AXIOM Logfile Analysis — system/event logs only (never generic .txt documents).
LOGFILE_ANALYSIS_WHERE = f"""
(
  {sql_extension_match(['.log', '.evtx', '.etl'], include_path_ilike=False)}
  OR file_path ILIKE '%/winevt/Logs/%'
  OR file_path ILIKE '%/Windows/Logs/%'
  OR file_path ILIKE '%/Panther/%'
  OR file_path ILIKE '%/PerfLogs/%'
  OR file_path ILIKE '%/WDI/LogFiles/%'
  OR file_path ILIKE '%Windows Error Reporting%'
  OR file_path ILIKE '%/WER/%'
  OR file_path ILIKE '%DiagTrack%'
  OR file_path ILIKE '%AppCompat%'
  OR file_path ILIKE '%/CBSLogs/%'
  OR file_path ILIKE '%/Logs/TWindows%'
  OR file_path ILIKE '%/Logs/RecEnv%'
  OR file_path ILIKE '%/System32/LogFiles/%'
  OR file_path ILIKE '%/System32/LogFiles/WMI/%'
  OR file_name ILIKE 'setupapi.dev.log'
  OR file_path ILIKE '%/Windows/INF/setupapi%'
  OR file_name ILIKE '%SRUDB%'
  OR file_path ILIKE '%auth.log%'
  OR file_path ILIKE '%/cron.d/%'
  OR file_path ILIKE '%/spool/cron/%'
  OR encyclopedia_artifact_id = 'WRG-EVT-0001'
)
"""

EXTENSIONLESS_EML_CANDIDATE_WHERE = f"""
(
  {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/desktop/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/documents/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/downloads/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/temp/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%appdata%local%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%appdata%roaming%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/library/mail/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/maildir/%'
  OR {_NORMALIZED_MAIL_PATH_SQL} LIKE '%/thunderbird/%/mail/%'
  OR ({EXTENSIONLESS_MAIL_WHERE.strip()})
)
AND lower(coalesce(extension,'')) NOT IN (
  '.eml','.emlx','.pst','.ost','.msg','.mbox',
  '.exe','.dll','.msi','.zip','.7z','.rar','.db','.sqlite'
)
AND size_bytes > 128
AND size_bytes <= 104857600
"""

_MEDIA_MAP: dict[str, frozenset[str]] = {
    "picture": HANDBOOK_PICTURE_EXTS,
    "pictures": HANDBOOK_PICTURE_EXTS,
    "audio": HANDBOOK_AUDIO_EXTS,
    "video": HANDBOOK_VIDEO_EXTS,
    "videos": HANDBOOK_VIDEO_EXTS,
    "photoshop": HANDBOOK_PHOTOSHOP_EXTS,
    "photoshop files": HANDBOOK_PHOTOSHOP_EXTS,
}


def sql_media_where(kind: str) -> str:
    exts = _MEDIA_MAP.get((kind or "").strip().lower())
    if not exts:
        return "FALSE"
    return sql_extension_match(exts)


def sql_document_where(extensions: list[str] | None = None) -> str:
    exts = extensions or sorted(HANDBOOK_DOCUMENT_EXTS)
    return sql_extension_match(exts)


def sql_handbook_path_markers_for_tokens(tokens: list[str]) -> str:
    """Path-marker ILIKE clauses for artifact name tokens (chat, mail, browser, cloud)."""
    markers = (
        "discord", "slack", "telegram", "whatsapp", "signal", "skype", "zoom", "teams",
        "thunderbird", "outlook", "maildir", "mail", "chrome", "firefox", "edge",
        "onedrive", "dropbox", "google drive", "leveldb", "indexeddb",
    )
    parts: list[str] = []
    token_set = {t.lower() for t in tokens if len(t) > 3}
    for marker in markers:
        if any(marker in t or t in marker for t in token_set):
            parts.append(f"file_path ILIKE '%{marker}%'")
    return " OR ".join(parts) if parts else ""


def sql_handbook_evidence_fallback(name: str, *, category: str = "") -> str:
    """Targeted handbook fallback: named artifact SQL, tokens, path markers, extensionless mail."""
    import re

    norm = re.sub(r"\s+", " ", (name or "").strip().lower())
    cat = (category or "").strip().lower()
    parts: list[str] = []

    media = _MEDIA_MAP.get(norm)
    if media:
        parts.append(sql_extension_match(media))

    if norm in {"eml(x) files", "eml files"}:
        parts.append(EML_EMLX_FILE_WHERE.strip())
    elif norm == "mbox emails":
        parts.append(MBOX_EMAIL_WHERE.strip())
    elif norm in {"email attachments", "email attachment"}:
        parts.append(EMAIL_ATTACHMENT_WHERE.strip())
    elif norm in {"outlook emails", "outlook 11 emails"}:
        parts.append(OUTLOOK_EMAIL_WHERE.strip())
    elif norm in {"web related files"}:
        parts.append(WEB_RELATED_WHERE.strip())
    elif norm in {"logfile analysis", "$logfile analysis"}:
        parts.append(LOGFILE_ANALYSIS_WHERE.strip())
    elif "document" in norm or cat == "documents":
        doc_key = norm.replace("microsoft ", "")
        from app.services.catalog_aligned_counts import document_extensions_for

        doc_exts = document_extensions_for(norm) or document_extensions_for(doc_key)
        if doc_exts:
            parts.append(sql_document_where(doc_exts))
        else:
            parts.append(sql_document_where())

    if any(k in norm for k in ("pcap", "network capture", "packet capture")):
        parts.append(sql_extension_match({".pcap", ".pcapng", ".cap"}))
    if any(k in norm for k in ("memory dump", "vmem", "crash dump", "hiberfil")):
        parts.append(sql_extension_match({".dmp", ".mdmp", ".vmem", ".hiberfil.sys"}))
    if any(k in norm for k in ("disk image", "container", "vmdk", "aff", "e01")):
        parts.append(sql_extension_match(HANDBOOK_NETWORK_CONTAINER_EXTS))

    # AND-match meaningful tokens only — OR on "windows"/"files" matches ~entire disk.
    _hb_stop = {
        "file", "files", "data", "related", "analysis", "windows", "microsoft",
        "system", "user", "users", "program", "programs", "device", "devices",
        "media", "other", "items", "list", "lists", "record", "records",
        "log", "logs", "event", "events", "message", "messages", "chat",
        "document", "documents", "office", "history", "cache", "account", "accounts",
    }
    tokens = [
        t for t in re.split(r"[^a-z0-9]+", norm)
        if len(t) > 3 and t not in _hb_stop
    ][:4]
    if len(tokens) >= 2:
        parts.append(
            "(" + " AND ".join(f"(file_path ILIKE '%{t}%' OR file_name ILIKE '%{t}%')" for t in tokens) + ")"
        )
    elif len(tokens) == 1:
        parts.append(f"(file_path ILIKE '%{tokens[0]}%' OR file_name ILIKE '%{tokens[0]}%')")

    marker_sql = sql_handbook_path_markers_for_tokens(tokens)
    if marker_sql:
        parts.append(f"({marker_sql})")

    mailish = "mail" in cat or "calendar" in cat or any(
        t in norm for t in ("mail", "eml", "mbox", "outlook", "thunderbird", "calendar", "ics")
    )
    if mailish:
        parts.append(EXTENSIONLESS_MAIL_WHERE.strip())
        parts.append(sql_extension_match(HANDBOOK_EMAIL_EXTS))

    browserish = any(t in norm for t in ("browser", "chrome", "firefox", "edge", "cookie", "history", "web"))
    if browserish or norm in {"web related files"}:
        parts.append(sql_special_basename_match())

    if not parts:
        return "FALSE"

    return " OR ".join(f"({p.strip()})" for p in parts if p and p.strip() != "FALSE")
