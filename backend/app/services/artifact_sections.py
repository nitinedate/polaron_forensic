"""Axiom-style forensic artifact sections for Q&A and RAG grounding.

Groups job artifacts into human-readable report sections (Connected Devices,
Application Usages, Communication, Documents, …) so Ollama / hybrid retrieval
can answer inventory questions from structured section facts — not random chunks.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("artifact_sections")


def _count_ext(db, job_id: str, extensions: list[str]) -> int:
    from app.services.axiom_aligned_counts import count_document_file_occurrences

    return count_document_file_occurrences(db, job_id, extensions)


def _sample_ext(db, job_id: str, extensions: list[str], limit: int = 8) -> list[str]:
    exts = [e if e.startswith(".") else f".{e}" for e in extensions]
    exts = [e.lower() for e in exts]
    rows = fetchall(
        db,
        """SELECT file_path FROM job_artifacts
           WHERE job_id=:j AND lower(coalesce(extension,'')) = ANY(:e)
           ORDER BY size_bytes DESC NULLS LAST LIMIT :lim""",
        {"j": job_id, "e": exts, "lim": limit},
    )
    return [r["file_path"] for r in rows]


def _count_path(db, job_id: str, patterns: list[str]) -> int:
    if not patterns:
        return 0
    clauses = " OR ".join(f"file_path ILIKE :p{i}" for i in range(len(patterns)))
    params: dict[str, Any] = {"j": job_id}
    for i, p in enumerate(patterns):
        params[f"p{i}"] = p
    row = fetchone(
        db,
        f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j AND ({clauses})",
        params,
    )
    return int(row["c"]) if row else 0


def _collect_usb_devices(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_usb_devices, collect_usb_usage_events

    devices = collect_usb_devices(db, job_id)
    usage = collect_usb_usage_events(db, job_id)
    # Axiom "USB Devices Count" = Enum\\USB + USBSTOR registry instances.
    count = len(devices) or int(usage.get("unique_device_count") or 0)
    samples = [d.get("device_name") for d in devices[:8] if d.get("device_name")]
    if not samples:
        samples = [e.get("device_id") for e in (usage.get("events") or [])[:5] if e.get("device_id")]
    return {
        "count": count,
        "usage_events": int(usage.get("usage_event_count") or 0),
        "samples": samples,
        "description": (
            "External USB devices recovered from SYSTEM\\Enum\\USB + USBSTOR "
            "(Axiom USB Devices). Usage events come from SetupAPI install/connect logs."
        ),
    }


def _collect_phone_devices(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_phone_usage

    phone = collect_phone_usage(db, job_id)
    devices = phone.get("devices") or []
    return {
        "count": int(phone.get("unique_device_count") or len(devices) or 0),
        "usage_events": int(phone.get("usage_event_count") or 0),
        "samples": [d.get("device_name") for d in devices[:8] if d.get("device_name")],
        "description": (
            "Microsoft Your Phone / CrossDevice linked devices and portable MTP/WPD "
            "phone pairings (Axiom Your Phone Device)."
        ),
    }


def _collect_rdp(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_rdp_connections

    rdp = collect_rdp_connections(db, job_id)
    return {
        "count": int(rdp.get("count") or 0),
        "samples": rdp.get("samples") or [],
        "description": (
            "Remote Desktop connection artifacts from Terminal Server Client Servers/MRU "
            "in NTUSER.DAT (Axiom RDP) — not RDP DLL file counts."
        ),
    }


def _collect_feature_usage(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_feature_usage_artifacts

    feat = collect_feature_usage_artifacts(db, job_id)
    return {
        "count": int(feat.get("count") or 0),
        "samples": feat.get("samples") or [],
        "description": (
            "Feature Usage registry entries, Prefetch, and Jump Lists "
            "(File Explorer / app launch activity)."
        ),
    }


def _collect_ms_programs(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_installed_programs

    prog = collect_installed_programs(db, job_id)
    count = int(prog.get("microsoft_count") or 0)
    samples = prog.get("samples_ms") or []
    # Fallback to Program Files folders only if Uninstall not yet parsed
    if count == 0:
        rows = fetchall(
            db,
            """SELECT DISTINCT split_part(file_path, '/', 2) AS prod
               FROM job_artifacts WHERE job_id=:j AND (
                 file_path ILIKE 'Program Files/Microsoft%'
                 OR file_path ILIKE 'Program Files (x86)/Microsoft%'
               ) LIMIT 40""",
            {"j": job_id},
        )
        samples = [r["prod"] for r in rows if r.get("prod")]
        count = len(samples)
    return {
        "count": count,
        "samples": samples[:12],
        "description": (
            "Microsoft applications from SOFTWARE Uninstall registry "
            "(Axiom Installed Microsoft Programs)."
        ),
    }


def _collect_non_ms_programs(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_installed_programs

    prog = collect_installed_programs(db, job_id)
    count = int(prog.get("non_microsoft_count") or 0)
    samples = prog.get("samples_non_ms") or []
    if count == 0:
        rows = fetchall(
            db,
            """SELECT DISTINCT split_part(file_path, '/', 2) AS prod
               FROM job_artifacts WHERE job_id=:j AND (
                 file_path ILIKE 'Program Files/%' OR file_path ILIKE 'Program Files (x86)/%'
               )
               AND file_path NOT ILIKE 'Program Files/Microsoft%'
               AND file_path NOT ILIKE 'Program Files (x86)/Microsoft%'
               AND file_path NOT ILIKE 'Program Files/Windows%'
               AND file_path NOT ILIKE 'Program Files (x86)/Windows%'
               AND file_path NOT ILIKE 'Program Files/Common Files%'
               AND file_path NOT ILIKE 'Program Files (x86)/Common Files%'
               LIMIT 200""",
            {"j": job_id},
        )
        samples = [r["prod"] for r in rows if r.get("prod")]
        count = len(samples)
    return {
        "count": count,
        "samples": samples[:20],
        "description": (
            "Non-Microsoft applications from SOFTWARE Uninstall registry "
            "(Axiom Installed Programs Non-Microsoft)."
        ),
    }


def _collect_defender(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_defender_logs

    d = collect_defender_logs(db, job_id)
    return {
        "count": int(d.get("count") or 0),
        "samples": d.get("samples") or [],
        "description": (
            "Windows Defender log artifacts (MPLog / Defender Operational channels) — "
            "not definition or cache binaries."
        ),
    }


def _filter_urls(urls: list[dict], patterns: list[re.Pattern[str]]) -> list[dict]:
    out = []
    for u in urls:
        url = (u.get("url") or "").lower()
        if any(p.search(url) for p in patterns):
            out.append(u)
    return out


def _collect_web_chat(db, job_id: str) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import count_url_visit_occurrences
    from app.services.browser_url_inventory import collect_job_browser_url_records
    from app.services.url_category_counts import classify_url_category

    count = count_url_visit_occurrences(db, job_id, "web chat urls")
    records = collect_job_browser_url_records(db, job_id)
    samples = [
        r.get("url")
        for r in records
        if str(r.get("record_origin") or "browser_history") == "browser_history"
        and classify_url_category(str(r.get("url") or "")) == "web chat urls"
    ][:10]
    return {
        "count": count,
        "samples": samples,
        "description": (
            "Links to web-based chat platforms (e.g. WhatsApp Web, Messenger, Teams) "
            "indicating chat usage."
        ),
    }


def _collect_social(db, job_id: str) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import count_url_visit_occurrences
    from app.services.browser_url_inventory import collect_job_browser_url_records
    from app.services.url_category_counts import classify_url_category

    count = count_url_visit_occurrences(db, job_id, "social media urls")
    records = collect_job_browser_url_records(db, job_id)
    samples = [
        r.get("url")
        for r in records
        if str(r.get("record_origin") or "browser_history") == "browser_history"
        and classify_url_category(str(r.get("url") or "")) == "social media urls"
    ][:10]
    return {
        "count": count,
        "samples": samples,
        "description": (
            "URLs linking to social platforms such as Instagram, Facebook, LinkedIn, Twitter/X, Reddit, etc."
        ),
    }


def _collect_malware_urls(db, job_id: str) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import count_url_visit_occurrences
    from app.services.browser_url_inventory import collect_job_browser_url_records
    from app.services.url_category_counts import is_malware_phishing_url

    count = count_url_visit_occurrences(db, job_id, "malware/phishing urls")
    records = collect_job_browser_url_records(db, job_id)
    hits = [r for r in records if str(r.get("record_origin") or "browser_history") == "browser_history" and is_malware_phishing_url(str(r.get("url") or ""))]
    return {
        "count": count,
        "samples": [h.get("url") for h in hits[:10]],
        "description": "Links designed to steal information or install harmful software on your device.",
    }


def _collect_pornography_urls(db, job_id: str) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import count_url_visit_occurrences
    from app.services.browser_url_inventory import collect_job_browser_url_records
    from app.services.url_category_counts import classify_url_category
    count = count_url_visit_occurrences(db, job_id, "pornography urls")
    records = collect_job_browser_url_records(db, job_id)
    samples = [r.get("url") for r in records if str(r.get("record_origin") or "browser_history") == "browser_history" and classify_url_category(str(r.get("url") or "")) == "pornography urls"][:10]
    return {"count": count, "samples": samples, "description": "Browser-history visits to adult/pornography sites."}


def _collect_dating_urls(db, job_id: str) -> dict[str, Any]:
    from app.services.axiom_aligned_counts import count_url_visit_occurrences
    from app.services.browser_url_inventory import collect_job_browser_url_records
    from app.services.url_category_counts import classify_url_category
    count = count_url_visit_occurrences(db, job_id, "dating site urls")
    records = collect_job_browser_url_records(db, job_id)
    samples = [r.get("url") for r in records if str(r.get("record_origin") or "browser_history") == "browser_history" and classify_url_category(str(r.get("url") or "")) == "dating site urls"][:10]
    return {"count": count, "samples": samples, "description": "Browser-history visits to online dating platforms."}


def _doc_collector(exts: list[str], description: str) -> Callable:
    def _inner(db, job_id: str) -> dict[str, Any]:
        from app.services.axiom_aligned_counts import count_document_occurrences_axiom

        count = count_document_occurrences_axiom(db, job_id, exts)
        return {
            "count": count,
            "samples": _sample_ext(db, job_id, exts),
            "extensions": exts,
            "description": description,
        }

    return _inner


def _collect_email_calendar_item(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.email_inventory import collect_email_artifact

    data = collect_email_artifact(db, job_id, title)
    return {
        "count": int(data.get("count") or 0),
        "samples": data.get("samples") or [],
        "description": f"Email & Calendar — {title}.",
    }


def _make_email_collector(title: str) -> Callable:
    def _inner(db, job_id: str) -> dict[str, Any]:
        return _collect_email_calendar_item(db, job_id, title)

    return _inner


def _collect_encryption_item(db, job_id: str, title: str) -> dict[str, Any]:
    from app.services.encryption_inventory import collect_encryption_artifact

    data = collect_encryption_artifact(db, job_id, title)
    return {
        "count": int(data.get("count") or 0),
        "samples": data.get("samples") or [],
        "description": f"Encryption & Credentials — {title}.",
    }


def _make_encryption_collector(title: str) -> Callable:
    def _inner(db, job_id: str) -> dict[str, Any]:
        return _collect_encryption_item(db, job_id, title)

    return _inner


_ENCRYPTION_ITEMS: list[tuple[str, str]] = [
    ("encrypted_files", "Encrypted Files"),
    ("windows_stored_credentials", "Windows Stored Credentials"),
    ("encryption_tools", "Encryption / Anti-forensics Tools"),
]

_EMAIL_CALENDAR_ITEMS: list[tuple[str, str]] = [
    ("email_attachments", "Email Attachments"),
    ("eml_files", "EML(X) Files"),
    ("windows_mail", "Windows Mail"),
    ("outlook_emails", "Outlook Emails"),
    ("outlook_tasks", "Outlook Tasks"),
    ("outlook_contacts", "Outlook Contacts"),
    ("outlook_appointments", "Outlook Appointments"),
    ("calendar_ics", "Calendar Events (ICS)"),
    ("mbox_emails", "MBOX Emails"),
    ("gmail_webmail", "Gmail Webmail"),
    ("gmail_fragments", "Gmail Fragments"),
    ("offline_gmail", "Offline Gmail"),
    ("hotmail_webmail", "Hotmail Webmail"),
    ("gmx_webmail", "GMX Webmail"),
    ("yahoo_webmail", "Yahoo! Webmail"),
    ("hushmail_fragments", "Hushmail Fragments"),
    ("hushmail_inbox", "Hushmail Inbox"),
    ("mail_ru", "Mail.ru"),
    ("outlook_web_inbox", "Outlook Web App Email Inbox"),
    ("outlook_webmail_inbox", "Outlook Webmail Inbox"),
]


def _collect_email(db, job_id: str) -> dict[str, Any]:
    """Legacy Communication rollup — EML/MBOX + Outlook mail artifacts."""
    from app.services.email_inventory import count_eml_files, count_outlook_emails, count_mbox_emails

    eml = count_eml_files(db, job_id)
    outlook = count_outlook_emails(db, job_id)
    mbox = count_mbox_emails(db, job_id)
    count = max(
        int(eml.get("count") or 0) + int(outlook.get("count") or 0),
        int(mbox.get("count") or 0),
    )
    samples = (eml.get("samples") or []) + (outlook.get("samples") or [])
    return {
        "count": count,
        "samples": samples[:8],
        "description": "Email containers and messages (PST/OST/EML/MSG/MBOX) found on the disk image.",
    }


def _collect_whatsapp(db, job_id: str) -> dict[str, Any]:
    from app.services.forensic_inventory import collect_whatsapp_artifacts

    info = collect_whatsapp_artifacts(db, job_id)
    return {
        "count": int(info.get("file_count") or 0),
        "samples": (info.get("files") or [])[:8],
        "description": "WhatsApp message stores and related chat databases.",
    }


def _collect_deleted_files(db, job_id: str) -> dict[str, Any]:
    from app.services.deleted_evidence import count_deleted_job_artifacts

    info = count_deleted_job_artifacts(db, job_id)
    samples = [
        s.get("title") or s.get("file_name") or s.get("file_path")
        for s in (info.get("samples") or [])
    ][:10]
    return {
        "count": int(info.get("deleted_files") or 0),
        "samples": samples,
        "description": (
            "Deleted files of any type (Recycle Bin, trash, .trashed-*, freelist). "
            "Deletion dates appear in brackets on artifact titles when recovered."
        ),
    }


def _collect_deleted_whatsapp(db, job_id: str) -> dict[str, Any]:
    from app.services.deleted_evidence import count_deleted_job_artifacts
    from app.services.forensic_inventory import collect_whatsapp_artifacts

    wa = collect_whatsapp_artifacts(db, job_id)
    deleted = count_deleted_job_artifacts(db, job_id)
    count = max(int(wa.get("deleted_message_count") or 0), int(deleted.get("deleted_whatsapp") or 0))
    samples = list(wa.get("deleted_samples") or [])[:8] or [
        s.get("title") for s in (deleted.get("samples") or []) if "whatsapp" in str(s.get("file_path") or "").lower()
    ][:8]
    return {
        "count": count,
        "samples": samples,
        "description": (
            "Deleted WhatsApp messages / chat data with deletion dates in brackets when known."
        ),
    }


def _collect_deleted_social(db, job_id: str) -> dict[str, Any]:
    from app.services.deleted_evidence import count_deleted_job_artifacts

    info = count_deleted_job_artifacts(db, job_id)
    samples = [
        s.get("title") or s.get("file_path")
        for s in (info.get("samples") or [])
        if s.get("recovery_state") == "social_deleted"
        or any(
            m in str(s.get("file_path") or "").lower()
            for m in ("whatsapp", "telegram", "signal", "instagram", "facebook", "messenger")
        )
    ][:10]
    return {
        "count": int(info.get("deleted_social") or 0),
        "samples": samples,
        "description": (
            "Deleted social networking evidence (WhatsApp, Telegram, Signal, Instagram, Facebook, etc.)."
        ),
    }


def _collect_browser_history(db, job_id: str) -> dict[str, Any]:
    count = _count_path(
        db,
        job_id,
        [
            "%/History",
            "%places.sqlite",
            "%/Web Data",
            "%History.db",
        ],
    )
    # Prefer encyclopedia browser IDs when classified
    row = fetchone(
        db,
        """SELECT count(*) c FROM job_artifacts WHERE job_id=:j
           AND encyclopedia_artifact_id ~ '^(BRW-)'""",
        {"j": job_id},
    )
    enc = int(row["c"]) if row else 0
    url_n = 0
    url_samples: list[str] = []
    try:
        from app.services.browser_url_inventory import collect_job_browser_url_records

        records = collect_job_browser_url_records(db, job_id)
        records = [r for r in records if str(r.get("record_origin") or "browser_history") == "browser_history"]
        url_n = len(records)
        seen: list[str] = []
        for rec in records:
            src = str(rec.get("source") or "")
            if src and src not in seen:
                seen.append(src)
            if len(seen) >= 8:
                break
        url_samples = seen
    except Exception:
        pass
    total = max(count, enc, url_n)
    samples = fetchall(
        db,
        """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
             encyclopedia_artifact_id ~ '^(BRW-)'
             OR file_path ILIKE '%/History' OR file_path ILIKE '%places.sqlite'
             OR file_path ILIKE '%History.db'
           ) ORDER BY size_bytes DESC NULLS LAST LIMIT 8""",
        {"j": job_id},
    )
    sample_paths = url_samples or [r["file_path"] for r in samples]
    return {
        "count": total,
        "samples": sample_paths,
        "description": (
            "Visited URLs from browser history (Chrome/Edge/Firefox/Safari), "
            "with content type and visit counts when recovered."
        ),
    }


def _collect_web_related_files(db, job_id: str) -> dict[str, Any]:
    """Axiom report 'Web Related Files' — browser history, cookies, downloads, web data."""
    from app.services.axiom_section_queries import WEB_RELATED_WHERE

    row = fetchone(
        db,
        f"SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND ({WEB_RELATED_WHERE})",
        {"j": job_id},
    )
    samples = fetchall(
        db,
        f"""SELECT file_path FROM job_artifacts WHERE job_id=:j AND ({WEB_RELATED_WHERE})
            ORDER BY size_bytes DESC NULLS LAST LIMIT 8""",
        {"j": job_id},
    )
    return {
        "count": int(row["c"]) if row else 0,
        "samples": [r["file_path"] for r in samples],
        "description": (
            "Browser history, cookies, downloads, and other web usage artifacts "
            "examined during forensic review."
        ),
    }


def _collect_logfile_analysis(db, job_id: str) -> dict[str, Any]:
    """Axiom report 'Logfile Analysis' — system/activity logs (not generic *log* paths)."""
    from app.services.axiom_aligned_counts import count_logfile_analysis_occurrences

    count = count_logfile_analysis_occurrences(db, job_id)
    samples = fetchall(
        db,
        """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
             lower(coalesce(extension,'')) IN ('.log','.evtx','.etl')
             OR file_path ILIKE '%/Logs/%'
             OR file_path ILIKE '%winevt/Logs/%'
           )
           ORDER BY size_bytes DESC NULLS LAST LIMIT 8""",
        {"j": job_id},
    )
    return {
        "count": count,
        "samples": [r["file_path"] for r in samples],
        "description": (
            "System logs showing user activity, shutdowns, errors, and access patterns."
        ),
    }


def _iter_jump_records(db, job_id: str):
    """Yield (file_path, record) for jump-list parse results."""
    import json as _json

    rows = fetchall(
        db,
        """SELECT ja.file_path, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:j AND (
             ja.file_path ILIKE '%.automaticdestinations-ms'
             OR ja.file_path ILIKE '%.customdestinations-ms'
             OR apr.normalized::text ILIKE '%jump_list%'
           )""",
        {"j": job_id},
    )
    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = _json.loads(norm)
            except Exception:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if isinstance(rec, dict):
                yield row.get("file_path"), rec


def _collect_jump_lists(db, job_id: str) -> dict[str, Any]:
    """Axiom report 'Jump List' — DestList entries (Automatic Destinations)."""
    from app.services.artifact_live_counts import count_jump_list_destinations

    info = count_jump_list_destinations(db, job_id)
    entry_total = int(info.get("count") or 0)
    samples: list[str] = []
    if entry_total <= 0:
        row = fetchone(
            db,
            """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND (
                 file_path ILIKE '%.automaticdestinations-ms'
                 OR encyclopedia_artifact_id = 'WFS-SHL-0002'
               )""",
            {"j": job_id},
        )
        entry_total = int(row["c"] or 0)
        rows = fetchall(
            db,
            """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
                 file_path ILIKE '%.automaticdestinations-ms'
               ) ORDER BY size_bytes DESC NULLS LAST LIMIT 8""",
            {"j": job_id},
        )
        samples = [r["file_path"] for r in rows]

    return {
        "count": entry_total,
        "samples": samples[:8],
        "description": (
            "Recently accessed files or programs used by the user via Start Menu or taskbar."
        ),
    }


def _collect_lnk(db, job_id: str) -> dict[str, Any]:
    """Axiom report 'LNK Files' — filesystem shortcuts + LNKs embedded in Jump Lists."""
    from app.services.artifact_live_counts import count_jump_list_destinations

    row = fetchone(
        db,
        """SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND (
             lower(coalesce(extension,''))='.lnk'
             OR file_path ILIKE '%.lnk'
             OR encyclopedia_artifact_id = 'WFS-SHL-0001'
           )""",
        {"j": job_id},
    )
    fs_count = int(row["c"]) if row else 0

    embedded = 0
    for _path, rec in _iter_jump_records(db, job_id):
        if rec.get("record_type") == "jump_list_file":
            if (rec.get("jump_list_kind") or "").lower() != "custom":
                embedded += int(rec.get("embedded_lnk_count") or 0)

    if embedded <= 0:
        info = count_jump_list_destinations(db, job_id)
        embedded = int(info.get("embedded_lnk") or 0)

    # Standalone .lnk files overlap jump-list embedded structures; take the larger
    # recovered total (AXIOM-style) rather than summing both.
    count = max(fs_count, embedded) if embedded > 0 else fs_count

    return {
        "count": count,
        "samples": _sample_ext(db, job_id, [".lnk"]),
        "description": (
            "Shortcut files referencing deleted or moved data, used to trace historical access."
        ),
        "filesystem_lnk": fs_count,
        "embedded_in_jumplists": embedded,
    }


def _collect_prefetch(db, job_id: str) -> dict[str, Any]:
    return {
        "count": _count_ext(db, job_id, [".pf"]),
        "samples": _sample_ext(db, job_id, [".pf"]),
        "description": "Windows Prefetch (.pf) program execution evidence.",
    }


def _collect_event_logs(db, job_id: str) -> dict[str, Any]:
    count = _count_ext(db, job_id, [".evtx"])
    samples = fetchall(
        db,
        """SELECT file_path FROM job_artifacts WHERE job_id=:j
           AND lower(coalesce(extension,''))='.evtx'
           ORDER BY size_bytes DESC NULLS LAST LIMIT 8""",
        {"j": job_id},
    )
    return {
        "count": count,
        "samples": [r["file_path"] for r in samples],
        "description": "Windows Event Log (.evtx) channels.",
    }


_AUDIO_EXTS = [
    ".mp3", ".wav", ".wma", ".m4a", ".aac", ".flac", ".ogg", ".oga",
    ".mid", ".midi", ".aiff", ".aif", ".opus", ".amr", ".ra", ".ram",
]
_PICTURE_EXTS = [
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".heic", ".heif", ".ico", ".jfif", ".raw", ".cr2", ".nef", ".dng",
    ".svg", ".emf", ".wmf", ".exif", ".jpe",
]
_VIDEO_EXTS = [
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg",
    ".m4v", ".3gp", ".webm", ".ts", ".mts", ".vob", ".asf",
]
_PHOTOSHOP_EXTS = [".psd", ".psb", ".pdd"]


def _collect_media_audio(db, job_id: str) -> dict[str, Any]:
    from app.services.media_inventory import media_counts_for_answer

    try:
        inv = media_counts_for_answer(db, job_id)
        count = int(inv.get("audio") or 0)
        samples = (inv.get("samples") or {}).get("audio") or []
    except Exception as exc:
        log.warning("media inventory audio failed, falling back to extracted files: %s", exc)
        count = _count_ext(db, job_id, list(_AUDIO_EXTS))
        samples = _sample_ext(db, job_id, list(_AUDIO_EXTS))
    if not samples:
        samples = _sample_ext(db, job_id, list(_AUDIO_EXTS))
    return {
        "count": count,
        "samples": samples,
        "description": (
            "Sound or voice recordings possibly related to user activity or media consumption."
        ),
        "extensions": list(_AUDIO_EXTS),
    }


def _collect_media_picture(db, job_id: str) -> dict[str, Any]:
    from app.services.media_inventory import media_counts_for_answer

    try:
        inv = media_counts_for_answer(db, job_id)
        count = int(inv.get("picture") or 0)
        samples = (inv.get("samples") or {}).get("picture") or []
    except Exception as exc:
        log.warning("media inventory picture failed, falling back to extracted files: %s", exc)
        count = _count_ext(db, job_id, list(_PICTURE_EXTS))
        samples = _sample_ext(db, job_id, list(_PICTURE_EXTS))
    if not samples:
        samples = _sample_ext(db, job_id, list(_PICTURE_EXTS))
    return {
        "count": count,
        "samples": samples,
        "description": "Includes personal photos, screenshots, and internet images.",
        "extensions": list(_PICTURE_EXTS),
    }


def _collect_media_video(db, job_id: str) -> dict[str, Any]:
    from app.services.media_inventory import media_counts_for_answer

    try:
        inv = media_counts_for_answer(db, job_id)
        count = int(inv.get("video") or 0)
        samples = (inv.get("samples") or {}).get("video") or []
    except Exception as exc:
        log.warning("media inventory video failed, falling back to extracted files: %s", exc)
        count = _count_ext(db, job_id, list(_VIDEO_EXTS))
        samples = _sample_ext(db, job_id, list(_VIDEO_EXTS))
    if not samples:
        samples = _sample_ext(db, job_id, list(_VIDEO_EXTS))
    return {
        "count": count,
        "samples": samples,
        "description": (
            "Saved or downloaded videos that may show usage, recordings, or visual evidence."
        ),
        "extensions": list(_VIDEO_EXTS),
    }


def _collect_media_photoshop(db, job_id: str) -> dict[str, Any]:
    from app.services.media_inventory import media_counts_for_answer

    try:
        inv = media_counts_for_answer(db, job_id)
        count = int(inv.get("photoshop") or 0)
        samples = (inv.get("samples") or {}).get("photoshop") or []
    except Exception as exc:
        log.warning("media inventory photoshop failed, falling back: %s", exc)
        count = _count_ext(db, job_id, list(_PHOTOSHOP_EXTS))
        samples = _sample_ext(db, job_id, list(_PHOTOSHOP_EXTS))
    if not samples:
        samples = _sample_ext(db, job_id, list(_PHOTOSHOP_EXTS)) or [
            r["file_path"]
            for r in fetchall(
                db,
                """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
                     lower(coalesce(extension,'')) IN ('.psd','.psb','.pdd')
                     OR file_path ILIKE '%.psd'
                   ) ORDER BY size_bytes DESC NULLS LAST LIMIT 8""",
                {"j": job_id},
            )
        ]
    return {
        "count": count,
        "samples": samples,
        "description": (
            "Edited or created images using Adobe Photoshop, useful for visual forensic analysis."
        ),
        "extensions": list(_PHOTOSHOP_EXTS),
    }


# Axiom-style section catalog (matches examiner report layout) + encyclopedia coverage.
SECTION_CATALOG: list[dict[str, Any]] = [
    {
        "key": "connected_devices",
        "title": "Connected Devices",
        "sort_order": 1,
        "items": [
            {"key": "usb_devices", "title": "USB Devices", "collector": _collect_usb_devices},
            {"key": "phone_devices", "title": "Your Phone Device", "collector": _collect_phone_devices},
            {"key": "rdp", "title": "Remote Desktop Protocol (RDP)", "collector": _collect_rdp},
        ],
    },
    {
        "key": "application_usages",
        "title": "Application Usages",
        "sort_order": 2,
        "items": [
            {"key": "feature_usage", "title": "Feature Usage", "collector": _collect_feature_usage},
            {
                "key": "ms_programs",
                "title": "Installed Microsoft Programs",
                "collector": _collect_ms_programs,
            },
            {
                "key": "non_ms_programs",
                "title": "Installed Programs (Non-Microsoft)",
                "collector": _collect_non_ms_programs,
            },
            {
                "key": "windows_defender",
                "title": "Windows Defender Logs",
                "collector": _collect_defender,
            },
        ],
    },
    {
        "key": "operating_system",
        "title": "Operating System",
        "sort_order": 3,
        "items": [
            {
                "key": "logfile_analysis",
                "title": "Logfile Analysis",
                "collector": _collect_logfile_analysis,
            },
            {
                "key": "jump_list",
                "title": "Jump List",
                "collector": _collect_jump_lists,
            },
            {
                "key": "lnk_files",
                "title": "LNK Files",
                "collector": _collect_lnk,
            },
        ],
    },
    {
        "key": "communication",
        "title": "Communication",
        "sort_order": 4,
        "items": [
            {"key": "web_chat_urls", "title": "Web Chat URLs", "collector": _collect_web_chat},
            {"key": "social_media_urls", "title": "Social Media URLs", "collector": _collect_social},
            {
                "key": "malware_phishing_urls",
                "title": "Malware/Phishing URLs",
                "collector": _collect_malware_urls,
            },
            {"key": "pornography_urls", "title": "Pornography URLs", "collector": _collect_pornography_urls},
            {"key": "dating_site_urls", "title": "Dating Site URLs", "collector": _collect_dating_urls},
            {"key": "email_artifacts", "title": "Email (PST/OST/EML)", "collector": _collect_email},
            {"key": "whatsapp", "title": "WhatsApp", "collector": _collect_whatsapp},
            {
                "key": "deleted_files",
                "title": "Deleted Files (All Types)",
                "collector": _collect_deleted_files,
            },
            {
                "key": "deleted_whatsapp",
                "title": "Deleted WhatsApp Data",
                "collector": _collect_deleted_whatsapp,
            },
            {
                "key": "deleted_social",
                "title": "Deleted Social Networking Data",
                "collector": _collect_deleted_social,
            },
        ],
    },
    {
        "key": "documents",
        "title": "Documents",
        "sort_order": 5,
        "items": [
            {
                "key": "csv_documents",
                "title": "CSV Documents",
                "collector": _doc_collector(
                    [".csv"], "Raw data or logs stored in comma-separated format."
                ),
            },
            {
                "key": "powerpoint_documents",
                "title": "Microsoft PowerPoint Documents",
                "collector": _doc_collector(
                    [".ppt", ".pptx"],
                    "Presentation files used for discussions, lectures, or visual reporting.",
                ),
            },
            {
                "key": "excel_documents",
                "title": "Microsoft Excel Documents",
                "collector": _doc_collector(
                    [".xls", ".xlsx"],
                    "Spreadsheets used for calculations, lists, logs, and financial data.",
                ),
            },
            {
                "key": "pdf_documents",
                "title": "PDF Documents",
                "collector": _doc_collector(
                    [".pdf"], "Fixed-layout documents like contracts, bills, and receipts."
                ),
            },
            {
                "key": "rtf_documents",
                "title": "RTF Documents",
                "collector": _doc_collector(
                    [".rtf"], "Rich Text Format files with styled text, common for documentation."
                ),
            },
            {
                "key": "text_documents",
                "title": "Text Documents",
                "collector": _doc_collector(
                    [".txt", ".log"], "Plain text files, often used for scripts, logs, or notes."
                ),
            },
            {
                "key": "word_documents",
                "title": "Microsoft Word Documents",
                "collector": _doc_collector(
                    [".doc", ".docx"],
                    "Word-processed documents such as reports, letters, and internal communication.",
                ),
            },
        ],
    },
    {
        "key": "email_calendar",
        "title": "Email & Calendar",
        "sort_order": 6,
        "items": [
            {"key": key, "title": title, "collector": _make_email_collector(title)}
            for key, title in _EMAIL_CALENDAR_ITEMS
        ],
    },
    {
        "key": "encryption_credentials",
        "title": "Encryption & Credentials",
        "sort_order": 7,
        "items": [
            {"key": key, "title": title, "collector": _make_encryption_collector(title)}
            for key, title in _ENCRYPTION_ITEMS
        ],
    },
    {
        "key": "media",
        "title": "Media",
        "sort_order": 8,
        "items": [
            {"key": "audio", "title": "Audio", "collector": _collect_media_audio},
            {"key": "picture", "title": "Picture", "collector": _collect_media_picture},
            {"key": "video", "title": "Video", "collector": _collect_media_video},
            {
                "key": "photoshop_files",
                "title": "Photoshop Files",
                "collector": _collect_media_photoshop,
            },
        ],
    },
    {
        "key": "web_related",
        "title": "Web Related",
        "sort_order": 9,
        "items": [
            {
                "key": "web_related_files",
                "title": "Web Related Files",
                "collector": _collect_web_related_files,
            },
        ],
    },
    {
        "key": "browser_internet",
        "title": "Browser & Internet",
        "sort_order": 10,
        "items": [
            {
                "key": "browser_history",
                "title": "Browser History / Web Data",
                "collector": _collect_browser_history,
            },
        ],
    },
    {
        "key": "execution_evidence",
        "title": "Execution Evidence",
        "sort_order": 11,
        "items": [
            {"key": "prefetch", "title": "Prefetch", "collector": _collect_prefetch},
            {"key": "lnk_shortcuts", "title": "LNK Shortcuts", "collector": _collect_lnk},
            {"key": "event_logs", "title": "Windows Event Logs", "collector": _collect_event_logs},
        ],
    },
]


def _run_section_item_collectors(db, job_id: str, section_key: str) -> dict[str, int]:
    """Run collectors for one SECTION_CATALOG block; return normalized title → count."""
    section = next((s for s in SECTION_CATALOG if s.get("key") == section_key), None)
    if not section:
        return {}
    out: dict[str, int] = {}
    for item in section.get("items") or []:
        title = item.get("title") or ""
        norm = re.sub(r"\s+", " ", title.strip().lower())
        try:
            with db.begin_nested():
                data = item["collector"](db, job_id) or {}
            out[norm] = int(data.get("count") or 0)
        except Exception as exc:
            log.warning("Section collector %s failed: %s", item.get("key"), exc)
            out[norm] = 0
    return out


def collect_email_calendar_title_counts(db, job_id: str) -> dict[str, int]:
    from app.services.email_inventory import compute_report_email_counts

    return compute_report_email_counts(db, job_id)


def collect_encryption_credentials_title_counts(db, job_id: str, *, scan_encrypted: bool = False) -> dict[str, int]:
    from app.services.encryption_inventory import compute_report_encryption_counts

    return compute_report_encryption_counts(db, job_id, scan_encrypted=scan_encrypted)


def collect_media_title_counts(db, job_id: str) -> dict[str, int]:
    """Media counts — prefer cached full-disk inventory; SQL fallback avoids slow re-scan."""
    try:
        from app.services.media_inventory import _load_disk_source

        ds = _load_disk_source(db, job_id)
        inv = ds.get("media_disk_inventory")
        if isinstance(inv, dict) and int(inv.get("enumerated_files") or 0) > 0:
            picture = int(inv.get("picture_with_thumbcache") or 0)
            if picture <= 0:
                picture = int(inv.get("picture") or 0) + int(inv.get("thumbcache_entries") or 0)
            return {
                "audio": int(inv.get("audio") or 0),
                "picture": picture,
                "video": int(inv.get("video") or 0),
                "photoshop files": int(inv.get("photoshop") or 0),
            }
    except Exception as exc:
        log.debug("media cache read failed: %s", exc)

    return {
        "audio": _count_ext(db, job_id, list(_AUDIO_EXTS)),
        "picture": _count_ext(db, job_id, list(_PICTURE_EXTS)),
        "video": _count_ext(db, job_id, list(_VIDEO_EXTS)),
        "photoshop files": _count_ext(db, job_id, list(_PHOTOSHOP_EXTS)),
    }


def collect_operating_system_title_counts(db, job_id: str) -> dict[str, int]:
    return _run_section_item_collectors(db, job_id, "operating_system")


def collect_web_related_title_counts(db, job_id: str) -> dict[str, int]:
    return _run_section_item_collectors(db, job_id, "web_related")


def collect_document_title_counts(db, job_id: str) -> dict[str, int]:
    return _run_section_item_collectors(db, job_id, "documents")


def collect_application_usage_title_counts(db, job_id: str) -> dict[str, int]:
    """Fast path: Application Usages collectors used by the report template."""
    section = next((s for s in SECTION_CATALOG if s.get("key") == "application_usages"), None)
    if not section:
        return {}
    out: dict[str, int] = {}
    for item in section.get("items") or []:
        title = item.get("title") or ""
        norm = re.sub(r"\s+", " ", title.strip().lower())
        try:
            with db.begin_nested():
                data = item["collector"](db, job_id) or {}
            out[norm] = int(data.get("count") or 0)
        except Exception as exc:
            log.warning("Application usage collector %s failed: %s", item.get("key"), exc)
            out[norm] = 0
    return out


def collect_communication_url_title_counts(db, job_id: str) -> dict[str, int]:
    """Fast path: Communication URL aggregates used in section B of the report."""
    section = next((s for s in SECTION_CATALOG if s.get("key") == "communication"), None)
    if not section:
        return {}
    url_keys = frozenset({"web_chat_urls", "social_media_urls", "malware_phishing_urls"})
    out: dict[str, int] = {}
    for item in section.get("items") or []:
        if item.get("key") not in url_keys:
            continue
        title = item.get("title") or ""
        norm = re.sub(r"\s+", " ", title.strip().lower())
        try:
            with db.begin_nested():
                data = item["collector"](db, job_id) or {}
            out[norm] = int(data.get("count") or 0)
        except Exception as exc:
            log.warning("Communication URL collector %s failed: %s", item.get("key"), exc)
            out[norm] = 0
    return out


def collect_connected_device_title_counts(db, job_id: str) -> dict[str, int]:
    """Fast path: run only Connected Devices collectors (USB, Phone, RDP)."""
    section = next((s for s in SECTION_CATALOG if s.get("key") == "connected_devices"), None)
    if not section:
        return {}
    out: dict[str, int] = {}
    for item in section.get("items") or []:
        title = item.get("title") or ""
        norm = re.sub(r"\s+", " ", title.strip().lower())
        try:
            with db.begin_nested():
                data = item["collector"](db, job_id) or {}
            out[norm] = int(data.get("count") or 0)
        except Exception as exc:
            log.warning("Connected device collector %s failed: %s", item.get("key"), exc)
            out[norm] = 0
    return out


def build_job_artifact_sections(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    email_counts: dict[str, int] | None = None,
    encryption_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Compute live Axiom-style section inventory for a job."""
    from app.db.session import apply_firm_search_path

    apply_firm_search_path(db, schema_name)
    from app.services.email_inventory import clear_email_count_cache, compute_all_email_counts
    from app.services.encryption_inventory import clear_encryption_count_cache, compute_all_encryption_counts

    clear_email_count_cache(job_id)
    if email_counts is None:
        email_counts = compute_all_email_counts(db, job_id)
    if encryption_counts is None:
        clear_encryption_count_cache(job_id)
        encryption_counts = compute_all_encryption_counts(db, job_id)

    sections_out: list[dict[str, Any]] = []
    grand_total = 0
    for sec in SECTION_CATALOG:
        items_out: list[dict[str, Any]] = []
        sec_total = 0
        for item in sec["items"]:
            data: dict[str, Any]
            if sec.get("key") == "email_calendar":
                title = item.get("title") or ""
                norm = re.sub(r"\s+", " ", title.strip().lower())
                count = int(email_counts.get(norm, 0))
                data = {
                    "count": count,
                    "samples": [],
                    "description": f"Email & Calendar — {title}.",
                }
            elif sec.get("key") == "encryption_credentials":
                title = item.get("title") or ""
                norm = re.sub(r"\s+", " ", title.strip().lower())
                count = int(encryption_counts.get(norm, 0))
                data = {
                    "count": count,
                    "samples": [],
                    "description": f"Encryption & Credentials — {title}.",
                }
            else:
                # Savepoint so one collector failure cannot abort the whole transaction
                # (Postgres InFailedSqlTransaction → every later count becomes 0).
                try:
                    with db.begin_nested():
                        data = item["collector"](db, job_id) or {}
                except Exception as exc:
                    log.warning("Section collector %s failed: %s", item["key"], exc)
                    # begin_nested already rolled back the savepoint; keep outer txn alive.
                    apply_firm_search_path(db, schema_name)
                    data = {"count": 0, "samples": [], "description": "", "error": str(exc)}
            count = int(data.get("count") or 0)
            sec_total += count
            items_out.append({
                "key": item["key"],
                "title": item["title"],
                "count": count,
                "description": data.get("description") or "",
                "samples": data.get("samples") or [],
                "usage_events": data.get("usage_events"),
                "extensions": data.get("extensions"),
                "extra": {k: v for k, v in data.items() if k not in {
                    "count", "samples", "description", "usage_events", "extensions"
                }},
            })
        grand_total += sec_total
        sections_out.append({
            "key": sec["key"],
            "title": sec["title"],
            "sort_order": sec["sort_order"],
            "count": sec_total,
            "items": items_out,
        })

    # Encyclopedia category rollup — covers all classified artifacts beyond fixed Axiom cards
    try:
        from app.services.forensic_inventory import collect_encyclopedia_category_rollup

        with db.begin_nested():
            enc_items = collect_encyclopedia_category_rollup(db, job_id)
        enc_total = sum(int(i.get("count") or 0) for i in enc_items)
        sections_out.append({
            "key": "encyclopedia_categories",
            "title": "Encyclopedia Categories",
            "sort_order": 99,
            "count": enc_total,
            "items": [
                {
                    "key": i["key"],
                    "title": i["title"],
                    "count": int(i.get("count") or 0),
                    "description": i.get("description") or "",
                    "samples": i.get("samples") or [],
                    "usage_events": None,
                    "extensions": None,
                    "extra": {},
                }
                for i in enc_items
            ],
        })
        grand_total += enc_total
    except Exception as exc:
        log.warning("Encyclopedia rollup failed: %s", exc)
        apply_firm_search_path(db, schema_name)

    return {
        "job_id": job_id,
        "total_items": grand_total,
        "sections": sections_out,
    }


def is_section_summary_query(query: str) -> bool:
    """True when the question asks for Axiom-style section inventory (skip slow vector embed)."""
    q = (query or "").lower()
    if not q.strip():
        return False
    if re.search(
        r"\b(data\s+leakage|artifact\s+sections?|axiom\s+summary|artifact\s+catalog|"
        r"b\.\s*artifacts|list\s+all\s+artifact|all\s+artifact\s+sections?)\b",
        q,
        re.I,
    ):
        return True
    named = sum(
        1
        for pat in (
            r"\bconnected\s+devices\b",
            r"\bcommunication\b",
            r"\bdocuments\b",
            r"\bmedia\b",
            r"\bbrowser\b",
            r"\bapplication\s+usages?\b",
            r"\boperating\s+system\b",
            r"\bexecution\s+evidence\b",
        )
        if re.search(pat, q, re.I)
    )
    return named >= 2


def format_sections_markdown(inventory: dict[str, Any]) -> str:
    lines = ["# B. ARTIFACTS", ""]
    lines.append(
        "For Connected Devices, **Devices used (connect/usage events)** is the primary "
        "activity metric; unique device inventory is secondary."
    )
    lines.append("")
    for i, sec in enumerate(inventory.get("sections") or [], start=1):
        lines.append(f"## {i}. {sec.get('title')}")
        lines.append("")
        for j, item in enumerate(sec.get("items") or [], start=1):
            lines.append(f"{j}. **{item.get('title')}**")
            usage = item.get("usage_events")
            if usage is not None:
                lines.append(f"   - Devices used (connect/usage events): {int(usage):,}")
                lines.append(f"   - Unique devices/items: {int(item.get('count') or 0):,}")
            else:
                lines.append(f"   - Count: {int(item.get('count') or 0):,}")
            if item.get("description"):
                lines.append(f"   - Description: {item['description']}")
            samples = item.get("samples") or []
            if samples:
                lines.append("   - Examples:")
                for s in samples[:5]:
                    lines.append(f"     - `{s}`")
            lines.append("")
    return "\n".join(lines).strip()


def format_sections_table(
    inventory: dict[str, Any],
    *,
    matches: list[dict[str, Any]] | None = None,
) -> str:
    """Markdown table for section/item counts (data leakage / examiner reports)."""
    sections = inventory.get("sections") or []
    if matches:
        keys = {(m.get("section") or {}).get("key") for m in matches if m.get("section")}
        sections = [s for s in sections if s.get("key") in keys]

    lines = [
        "## Artifact summary (table)",
        "",
        "| Section | Artifact type | Count | Usage/connect events | Description |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for sec in sections:
        if sec.get("key") == "encyclopedia_categories":
            continue
        for item in sec.get("items") or []:
            usage = item.get("usage_events")
            usage_s = f"{int(usage):,}" if usage is not None else "—"
            count_s = f"{int(item.get('count') or 0):,}"
            desc = (item.get("description") or "").replace("|", "/").replace("\n", " ")[:140]
            lines.append(
                f"| {sec.get('title') or ''} | {item.get('title') or ''} | {count_s} | "
                f"{usage_s} | {desc} |"
            )
    lines.append("")
    lines.append(
        "**Note:** Usage/connect events count how many times a device class was used or connected "
        "(same device may appear multiple times). **Count** is unique items/devices/files found."
    )
    return "\n".join(lines)


def ensure_section_rag_chunks(db, job_id: str, inventory: dict[str, Any] | None = None) -> int:
    """Write/refresh synthetic RAG chunks so hybrid retrieval + Ollama see section facts."""
    inv = inventory or build_job_artifact_sections(db, job_id)
    written = 0
    # Full catalog chunk
    full_path = "__forensic__/artifact_sections"
    full_text = format_sections_markdown(inv)
    meta = json.dumps({"kind": "artifact_sections", "inventory": inv}, default=str)
    existing = fetchone(
        db,
        "SELECT id FROM rag_chunks WHERE job_id=:j AND file_path=:p LIMIT 1",
        {"j": job_id, "p": full_path},
    )
    if existing:
        execute(
            db,
            "UPDATE rag_chunks SET content=:c, metadata=CAST(:m AS jsonb) WHERE id=:id",
            {"c": full_text[:12000], "m": meta, "id": existing["id"]},
        )
    else:
        execute(
            db,
            """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
               artifact_id, chunk_type, metadata)
               VALUES (:j, :p, 0, :c, NULL, NULL, 'AXM-SEC-0000', 'evidence', CAST(:m AS jsonb))""",
            {"j": job_id, "p": full_path, "c": full_text[:12000], "m": meta},
        )
    written += 1

    for sec in inv.get("sections") or []:
        sec_key = sec.get("key")
        path = f"__forensic__/sections/{sec_key}"
        lines = [
            f"Artifact section: {sec.get('title')}",
            f"Total count across sub-artifacts: {int(sec.get('count') or 0)}",
            "",
        ]
        for item in sec.get("items") or []:
            usage = item.get("usage_events")
            if usage is not None:
                lines.append(
                    f"- {item.get('title')}: devices_used(connect_events)={int(usage)}, "
                    f"unique_devices={int(item.get('count') or 0)}"
                )
            else:
                lines.append(f"- {item.get('title')}: count={int(item.get('count') or 0)}")
            if item.get("description"):
                lines.append(f"  Description: {item['description']}")
            for s in (item.get("samples") or [])[:5]:
                lines.append(f"  Example: {s}")
        content = "\n".join(lines)
        smeta = json.dumps({"kind": "artifact_section", "section": sec}, default=str)
        row = fetchone(
            db,
            "SELECT id FROM rag_chunks WHERE job_id=:j AND file_path=:p LIMIT 1",
            {"j": job_id, "p": path},
        )
        if row:
            execute(
                db,
                "UPDATE rag_chunks SET content=:c, metadata=CAST(:m AS jsonb) WHERE id=:id",
                {"c": content[:8000], "m": smeta, "id": row["id"]},
            )
        else:
            execute(
                db,
                """INSERT INTO rag_chunks (job_id, file_path, chunk_index, content, embedding, embedding_v2,
                   artifact_id, chunk_type, metadata)
                   VALUES (:j, :p, 0, :c, NULL, NULL, :aid, 'evidence', CAST(:m AS jsonb))""",
                {
                    "j": job_id,
                    "p": path,
                    "c": content[:8000],
                    "aid": f"AXM-SEC-{sec_key}",
                    "m": smeta,
                },
            )
        written += 1
    return written


def match_section_query(query: str, inventory: dict[str, Any]) -> dict[str, Any] | None:
    """Match a natural-language question to the best section or sub-artifact."""
    matches = match_all_section_queries(query, inventory)
    return matches[0] if matches else None


def match_all_section_queries(query: str, inventory: dict[str, Any]) -> list[dict[str, Any]]:
    """Return all sections/items the question names (supports multi-section asks)."""
    q = (query or "").lower()
    if not q.strip():
        return []

    section_hits: list[tuple[int, dict[str, Any]]] = []
    item_hits: list[tuple[int, dict[str, Any]]] = []

    for sec in inventory.get("sections") or []:
        sec_title = (sec.get("title") or "").lower()
        sec_key = (sec.get("key") or "").lower()
        sec_score = 0
        # Prefer whole-phrase / word-boundary matches (esp. short titles like "Media").
        if sec_title and re.search(rf"\b{re.escape(sec_title)}\b", q):
            sec_score = 6 if sec_key == "media" and "social media" not in q else 5
        elif sec_key.replace("_", " ") and re.search(
            rf"\b{re.escape(sec_key.replace('_', ' '))}\b", q
        ):
            sec_score = 4
        # "artifacts for Media" / "Media artifacts" boost
        if sec_score and re.search(r"\bartifacts?\b", q):
            sec_score += 2
        if sec_score >= 3:
            section_hits.append((sec_score, {"level": "section", "section": sec, "item": None}))

        for item in sec.get("items") or []:
            title = (item.get("title") or "").lower()
            key = (item.get("key") or "").lower()
            score = 0
            for token in re.findall(r"[a-z0-9]{3,}", title):
                if token in {"and", "the", "for", "with", "from", "your", "non"}:
                    continue
                if token in q:
                    score += 2
            if key.replace("_", " ") in q or key.replace("_", "") in q.replace(" ", ""):
                score += 3
            aliases = {
                "usb_devices": [r"\busb\b", r"flash\s+drive", r"pen\s+drive", r"removable"],
                "phone_devices": [r"\bphones?\b", r"mobile", r"android", r"iphone", r"portable\s+device", r"your\s+phone"],
                "rdp": [r"\brdp\b", r"remote\s+desktop"],
                "web_chat_urls": [r"web\s+chat", r"whatsapp\s+web", r"chat\s+url"],
                "social_media_urls": [r"social\s+media", r"facebook", r"instagram", r"linkedin", r"twitter"],
                "malware_phishing_urls": [r"malware", r"phishing"],
                "email_artifacts": [r"\bemails?\b", r"\bpst\b", r"\bost\b", r"outlook"],
                "whatsapp": [r"whatsapp"],
                "browser_history": [r"browser\s+history", r"web\s+history", r"chrome\s+history", r"edge\s+history"],
                "prefetch": [r"\bprefetch\b"],
                "lnk_shortcuts": [r"\blnk\b", r"shortcuts?"],
                "event_logs": [r"event\s+logs?", r"\bevtx\b"],
                "logfile_analysis": [r"logfile", r"log\s*file\s+analysis", r"system\s+logs?"],
                "jump_list": [r"jump\s*lists?"],
                "lnk_files": [r"\blnk\s+files?\b", r"shortcut\s+files?"],
                "audio": [r"\baudio\b", r"\bmp3\b", r"sound\s+recordings?"],
                "picture": [r"\bpictures?\b", r"\bphotos?\b", r"\bimages?\b"],
                "video": [r"\bvideos?\b", r"\bmovies?\b"],
                "photoshop_files": [r"photoshop", r"\bpsd\b"],
                "csv_documents": [r"\bcsv\b"],
                "pdf_documents": [r"\bpdfs?\b"],
                "excel_documents": [r"\bexcel\b", r"\bxlsx?\b", r"spreadsheet"],
                "word_documents": [r"\bword\b", r"\bdocx?\b"],
                "powerpoint_documents": [r"powerpoint", r"\bpptx?\b"],
                "rtf_documents": [r"\brtf\b"],
                "text_documents": [r"text\s+(files?|documents?)", r"\btxt\b"],
                "ms_programs": [r"microsoft\s+programs?", r"installed\s+microsoft"],
                "non_ms_programs": [r"non[- ]microsoft", r"third[- ]party\s+programs?"],
                "windows_defender": [r"defender", r"antivirus"],
                "feature_usage": [r"feature\s+usage", r"prefetch"],
            }
            for pat in aliases.get(key, []):
                if re.search(pat, q, re.I):
                    score += 4
            if score >= 3:
                item_hits.append((score, {"level": "item", "section": sec, "item": item}))

    # Prefer every named parent section when the ask spans multiple sections.
    if len(section_hits) >= 2:
        section_hits.sort(key=lambda x: (-x[0], (x[1].get("section") or {}).get("sort_order", 99)))
        return [m for _, m in section_hits]

    if section_hits:
        # One named section — return that section (not a single child item).
        section_hits.sort(key=lambda x: -x[0])
        return [section_hits[0][1]]

    if not item_hits:
        return []
    item_hits.sort(key=lambda x: -x[0])
    # Multiple distinct items named (e.g. USB and PDF) → return all above threshold.
    if len(item_hits) >= 2:
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for score, m in item_hits:
            key = (m.get("item") or {}).get("key") or id(m)
            if key in seen:
                continue
            seen.add(str(key))
            out.append(m)
        return out
    return [item_hits[0][1]]


def detect_usage_focus(query: str) -> bool:
    """True when the question wants connect/usage events, not unique device inventory."""
    q = query or ""
    return bool(
        re.search(
            r"\b("
            r"how\s+many\s+times|times?\s+(used|connected|plugged)|"
            r"devices?\s+used|used\s+count|usage\s+count|usage/?connect|"
            r"connect(ion)?\s+events?|plugged\s+in|"
            r"(used|connected|plugged)\b.*\b(how\s+many|count)|"
            r"\busages?\b"
            r")\b",
            q,
            re.I,
        )
    )


def format_section_answer(match: dict[str, Any], *, usage_focus: bool = False) -> str:
    return format_multi_section_answer([match], usage_focus=usage_focus)


def format_multi_section_answer(
    matches: list[dict[str, Any]],
    *,
    usage_focus: bool = False,
    report_style: bool = False,
) -> str:
    """Human-readable answer for one or more Axiom section/item matches."""
    if not matches:
        return "No matching artifact sections were found for this question."

    blocks: list[str] = []
    multi = len(matches) > 1 and not report_style
    if multi:
        blocks.append("# Requested artifact sections")
        blocks.append("")
        blocks.append(
            f"This question names **{len(matches)}** artifact areas. "
            "Details for each are below."
        )
        blocks.append("")

    for idx, match in enumerate(matches, start=1):
        sec = match.get("section") or {}
        item = match.get("item")
        if match.get("level") == "section" or not item:
            # Report-style block for every Axiom section (Media, OS, Documents, …)
            if report_style or sec.get("key") in {
                "operating_system",
                "media",
                "documents",
                "connected_devices",
                "application_usages",
                "communication",
                "browser_internet",
                "execution_evidence",
            }:
                lines = [
                    f"**{sec.get('title') or 'Section'} artifacts**",
                    "",
                ]
                for i, it in enumerate(sec.get("items") or [], start=1):
                    lines.append(f"{i}. **{it.get('title')}**")
                    usage = it.get("usage_events")
                    if usage is not None and usage_focus:
                        lines.append(
                            f"   - **Devices used (connect/usage events):** {int(usage):,}"
                        )
                        lines.append(
                            f"   - **Unique devices/items:** {int(it.get('count') or 0):,}"
                        )
                    else:
                        lines.append(f"   - **Count:** {int(it.get('count') or 0):,}")
                        if usage is not None:
                            lines.append(
                                f"   - **Devices used (connect/usage events):** {int(usage):,}"
                            )
                    if it.get("description"):
                        lines.append(f"   - **Description:** {it['description']}")
                    samples = it.get("samples") or []
                    if samples:
                        lines.append("   - Examples:")
                        for s in samples[:5]:
                            lines.append(f"     - `{s}`")
                    lines.append("")
                blocks.append("\n".join(lines).rstrip())
                continue

            header = f"## {idx}. {sec.get('title')}" if multi else f"**{sec.get('title')}** — artifact section summary"
            lines = [header, ""]
            if usage_focus and (sec.get("key") == "connected_devices" or any(
                it.get("usage_events") is not None for it in (sec.get("items") or [])
            )):
                lines.append(
                    "Primary metric below is **devices used (connect/usage events)**. "
                    "Unique device inventory is listed second."
                )
                lines.append("")
            else:
                lines.append(f"Total catalog items in this section: **{int(sec.get('count') or 0):,}**")
                lines.append("")
            for i, it in enumerate(sec.get("items") or [], start=1):
                lines.extend(_format_item_lines(it, i, usage_focus=usage_focus, indent=""))
            blocks.append("\n".join(lines).rstrip())
            continue

        title = item.get("title")
        header = (
            f"## {idx}. {title} (section: {sec.get('title')})"
            if multi
            else f"**{title}** (section: {sec.get('title')})"
        )
        lines = [header, ""]
        lines.extend(_format_item_lines(item, None, usage_focus=usage_focus, indent=""))
        blocks.append("\n".join(lines).rstrip())

    return "\n\n".join(blocks).strip()


def _format_item_lines(
    item: dict[str, Any],
    index: int | None,
    *,
    usage_focus: bool,
    indent: str = "",
) -> list[str]:
    title = item.get("title") or "Item"
    unique = int(item.get("count") or 0)
    usage = item.get("usage_events")
    prefix = f"{index}. " if index is not None else ""
    lines: list[str] = []

    if usage is not None and usage_focus:
        lines.append(f"{indent}{prefix}**{title}**")
        lines.append(f"{indent}- **Devices used (connect/usage events):** **{int(usage):,}**")
        lines.append(f"{indent}- Unique devices/items registered: {unique:,}")
    elif usage is not None:
        lines.append(f"{indent}{prefix}**{title}**")
        lines.append(f"{indent}- Unique devices/items: **{unique:,}**")
        lines.append(f"{indent}- **Devices used (connect/usage events):** **{int(usage):,}**")
    else:
        lines.append(f"{indent}{prefix}**{title}** — Count: **{unique:,}**")

    if item.get("description"):
        lines.append(f"{indent}  {item['description']}")
    samples = item.get("samples") or []
    if samples:
        lines.append(f"{indent}  Examples:")
        for s in samples[:8]:
            lines.append(f"{indent}  - `{s}`")
    return lines

