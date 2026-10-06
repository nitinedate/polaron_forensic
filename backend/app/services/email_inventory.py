"""Email & Calendar artifact counts — AXIOM-style report and catalog mapping."""

from __future__ import annotations

import json
import re
from typing import Any

from app.db.sql_helpers import fetchall, fetchone

# Paths that are installers / OS bundles, not user mail evidence.
_SYSTEM_MAIL_EXCLUDE = """
  AND file_path NOT ILIKE '%Program Files%'
  AND file_path NOT ILIKE '%Program Files (x86)%'
  AND file_path NOT ILIKE '%WindowsApps%'
  AND file_path NOT ILIKE '%/Office/root/%'
  AND file_path NOT ILIKE '%MSOCache%'
  AND file_path NOT ILIKE '%.exe'
  AND file_path NOT ILIKE '%.dll'
  AND file_path NOT ILIKE '%.msi'
  AND file_path NOT ILIKE '%.bmp'
  AND file_path NOT ILIKE '%.png'
  AND file_path NOT ILIKE '%.gif'
  AND file_path NOT ILIKE '%.xml'
"""

_JOB_WEBMAIL_CACHE: dict[str, dict[str, int]] = {}


def _webmail_cache_for(job_id: str, override: dict[str, int] | None = None) -> dict[str, int]:
    if override is not None:
        return override
    return _JOB_WEBMAIL_CACHE.setdefault(job_id, {})


def clear_email_count_cache(job_id: str | None = None) -> None:
    if job_id:
        _JOB_WEBMAIL_CACHE.pop(job_id, None)
    else:
        _JOB_WEBMAIL_CACHE.clear()
    from app.services.email_mime_inventory import clear_email_mime_scan_cache

    clear_email_mime_scan_cache(job_id)


_WEBMAIL_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "gmail webmail": [re.compile(r"mail\.google\.com|gmail\.com", re.I)],
    "gmail fragments": [re.compile(r"mail\.google\.com|gmail\.com|google\.com/mail", re.I)],
    "offline gmail": [re.compile(r"mail\.google\.com|gmail\.com|google\.com/mail", re.I)],
    "hotmail webmail": [re.compile(r"hotmail\.com|outlook\.live\.com|live\.com/mail|login\.live\.com", re.I)],
    "gmx webmail": [re.compile(r"gmx\.(com|net)|navigator\.gmx", re.I)],
    "yahoo! webmail": [re.compile(r"mail\.yahoo\.(com|co\.)|yahoo\.com/mail", re.I)],
    "hushmail fragments": [re.compile(r"hushmail\.com", re.I)],
    "hushmail inbox": [re.compile(r"hushmail\.com", re.I)],
    "mail.ru": [re.compile(r"mail\.ru|e\.mail\.ru", re.I)],
    "outlook web app email inbox": [re.compile(r"outlook\.office\.com|outlook\.live\.com|office365\.com", re.I)],
    "outlook web app email fragments": [re.compile(r"outlook\.office\.com|outlook\.live\.com", re.I)],
    "outlook webmail inbox": [re.compile(r"outlook\.office\.com|outlook\.live\.com|outlook\.com/mail", re.I)],
    "outlook webmail fragments": [re.compile(r"outlook\.office\.com|outlook\.live\.com", re.I)],
    "outlook webmail inbox fragments": [re.compile(r"outlook\.office\.com|outlook\.live\.com", re.I)],
    "mailinator inbox access": [re.compile(r"mailinator\.com", re.I)],
    "mailinator snippets": [re.compile(r"mailinator\.com", re.I)],
}


def _count_sql(db, job_id: str, where: str) -> int:
    row = fetchone(
        db,
        f"SELECT count(*) c FROM job_artifacts WHERE job_id=:j AND ({where}){_SYSTEM_MAIL_EXCLUDE}",
        {"j": job_id},
    )
    return int(row["c"]) if row else 0


def _sample_sql(db, job_id: str, where: str, *, limit: int = 8) -> list[str]:
    rows = fetchall(
        db,
        f"""SELECT file_path FROM job_artifacts WHERE job_id=:j AND ({where})
            {_SYSTEM_MAIL_EXCLUDE}
            ORDER BY size_bytes DESC NULLS LAST LIMIT :lim""",
        {"j": job_id, "lim": limit},
    )
    return [r["file_path"] for r in rows]


def _iter_parsed_records(db, job_id: str, *, pattern: str, limit: int = 500):
    rows = fetchall(
        db,
        """SELECT ja.file_path, apr.normalized
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           WHERE ja.job_id=:j AND apr.normalized::text ILIKE :pat
           LIMIT :lim""",
        {"j": job_id, "pat": pattern, "lim": limit},
    )
    for row in rows:
        norm = row.get("normalized")
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                continue
        if not isinstance(norm, list):
            continue
        for rec in norm:
            if isinstance(rec, dict):
                yield row.get("file_path"), rec


def _count_parsed_records(db, job_id: str, *, record_type: str) -> int:
    """Sum parsed record counts for a record_type across all parse results (no row cap)."""
    row = fetchone(
        db,
        """SELECT coalesce(sum(
               CASE
                 WHEN elem->>'record_type' = :rt THEN
                   coalesce(
                     nullif(elem->>'count', '')::bigint,
                     nullif(elem->>'message_count', '')::bigint,
                     1
                   )
                 ELSE 0
               END
           ), 0) AS c
           FROM job_artifacts ja
           JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
           LEFT JOIN LATERAL jsonb_array_elements(
             CASE WHEN jsonb_typeof(apr.normalized) = 'array' THEN apr.normalized ELSE '[]'::jsonb END
           ) AS elem ON TRUE
           WHERE ja.job_id = :j""",
        {"j": job_id, "rt": record_type},
    )
    return int(row["c"]) if row else 0


def count_eml_files(db, job_id: str) -> dict[str, Any]:
    """EML(X) Files — count exactly what the examiner can open in evidence browse.

    MIME reconciliation runs first so extensionless RFC822 messages are promoted
    into the same metadata-backed predicate used by the browse API.  Carved EML
    rows are added only when they are independently listable and are not duplicates
    of an allocated EML source.
    """
    from app.services.axiom_section_queries import EMLX_FILE_WHERE
    from app.services.email_mime_inventory import scan_job_email_mime_inventory

    scan = scan_job_email_mime_inventory(db, job_id)
    # IMPORTANT: query after scan, because the scan can promote byte-validated
    # extensionless messages to message/rfc822 metadata.
    filtered_count = _count_sql(db, job_id, EMLX_FILE_WHERE)
    carved_eml = 0
    try:
        from app.services.signature_carve_inventory import list_carve_evidence

        carved_eml = int(
            list_carve_evidence(
                db, job_id, axiom_name="EML(X) Files", page=1, page_size=1
            ).get("total")
            or 0
        )
    except Exception:
        carved_eml = 0
    count = filtered_count + carved_eml
    return {
        "count": count,
        "samples": _sample_sql(db, job_id, EMLX_FILE_WHERE),
        "filtered_files": filtered_count,
        "mime_validated_messages": int(scan.get("message_occurrences") or 0),
        "extensionless_messages": int(scan.get("extensionless_messages") or 0),
        "eml_emlx_scanned": int(scan.get("eml_emlx_files_scanned") or 0),
        "mime_rows_promoted": int(scan.get("mime_rows_promoted") or 0),
        "parse_failures": int(scan.get("parse_failures") or 0),
        "carved_eml": carved_eml,
        "count_domain": "browseable_eml_occurrences",
    }


def email_attachment_browse_where_sql() -> str:
    """Path filter for attachment browse — match attach markers, not catalog title tokens."""
    from app.services.axiom_section_queries import EMAIL_ATTACHMENT_WHERE
    from app.services.handbook_query_sql import sql_ilike_contains

    return f"""
    (
      ({EMAIL_ATTACHMENT_WHERE.strip()})
      OR (
        file_path ILIKE '%attach%'
        OR {sql_ilike_contains(':2,S')}
        OR {sql_ilike_contains(':2,PS')}
      )
    )
    AND file_path NOT ILIKE '%.pst'
    AND file_path NOT ILIKE '%.ost'
    AND file_path NOT ILIKE '%WebKit%'
    AND file_path NOT ILIKE '%ResourceLoadStatistics%'
    AND file_path NOT ILIKE '%WebsiteData%'
    AND lower(file_name) NOT IN (
      'observations.db', 'pcm.db', 'tips-store.db', 'enhancedsecuritysites.db'
    )
    AND lower(file_name) NOT LIKE '%.js'
    AND lower(coalesce(extension,'')) NOT IN ('.db', '.sqlite', '.sqlite3', 'db', 'sqlite', 'sqlite3')
    """


def email_attachment_files_where(*, base_params: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
    """SQL filter for indexed email attachment files (browse + export)."""
    params = dict(base_params or {})
    suffix = f" AND ({email_attachment_browse_where_sql().strip()}){_SYSTEM_MAIL_EXCLUDE}"
    return suffix, params


def _count_email_calendar_attachment_paths(db, job_id: str) -> int:
    """Attachment-like files under email/calendar client trees (Email and Calendar category scope)."""
    where = """
    (
      file_path ILIKE '%/Microsoft/Outlook/%'
      OR file_path ILIKE '%/Olk/%'
      OR file_path ILIKE '%Thunderbird%'
      OR file_path ILIKE '%/Windows Mail/%'
      OR file_path ILIKE '%windowscommunicationsapps%'
    )
    AND (
      file_path ILIKE '%/Attachments/%'
      OR file_path ILIKE '%/Attachment/%'
      OR file_path ILIKE '%Content.Outlook%'
      OR file_path ILIKE '%attach%'
    )
    AND file_path NOT ILIKE '%.pst'
    AND file_path NOT ILIKE '%.ost'
    AND file_path NOT ILIKE '%.db'
    AND file_path NOT ILIKE '%.sqlite'
    AND size_bytes > 64
    """
    return _count_sql(db, job_id, where)


def count_email_attachments(db, job_id: str) -> dict[str, Any]:
    """Count attachment occurrences that have browseable evidence rows.

    PST/OST attachment estimates are diagnostic only until the mailbox has been
    materialized to actual message/part evidence; estimates must never inflate the
    UI category beyond what an examiner can open.
    """
    from app.services.email_mime_inventory import scan_job_email_mime_inventory

    browse_where = email_attachment_browse_where_sql()
    folder_count = _count_sql(db, job_id, browse_where)
    calendar_paths = _count_email_calendar_attachment_paths(db, job_id)
    scan = scan_job_email_mime_inventory(db, job_id)
    mime_attachments = int(scan.get("attachment_occurrences") or 0)
    parsed = _count_parsed_records(db, job_id, record_type="email_attachment")
    if parsed <= 0:
        parsed = _count_parsed_records(db, job_id, record_type="attachment")

    path_occurrences = max(folder_count, calendar_paths)
    indexed_files = folder_count
    pst_attach = 0
    carved_attach = 0
    try:
        from app.services.pst_mailbox_inventory import scan_job_pst_mailboxes

        pst_attach = int(scan_job_pst_mailboxes(db, job_id).get("attachment_estimate") or 0)
    except Exception:
        pst_attach = 0
    try:
        from app.services.signature_carve_inventory import list_carve_evidence

        carved_attach = int(
            list_carve_evidence(
                db, job_id, axiom_name="Email Attachments", page=1, page_size=1
            ).get("total")
            or 0
        )
    except Exception:
        carved_attach = 0

    # MIME parts are exposed as virtual evidence rows by artifact_evidence_browse.
    # Parsed records are a cross-check, not an extra additive domain.
    count = path_occurrences + mime_attachments + carved_attach
    return {
        "count": count,
        "samples": _sample_sql(db, job_id, browse_where),
        "folder_files": folder_count,
        "indexed_files": indexed_files,
        "calendar_attachment_paths": calendar_paths,
        "mime_attachment_occurrences": mime_attachments,
        "unmaterialized_pst_attachment_estimate": pst_attach,
        "pst_attachment_estimate": pst_attach,
        "carved_attachments": carved_attach,
        "path_occurrences": path_occurrences,
        "parsed_attachments": parsed,
        "parse_failures": int(scan.get("parse_failures") or 0),
        "count_domain": "browseable_attachment_occurrences",
    }


def count_windows_mail(db, job_id: str) -> dict[str, Any]:
    """AXIOM Windows Mail — message records, not store-container file counts.

    Magnet reports 0 when the Windows Mail / HxStore corpus has no recoverable
    messages. Counting every file under windowscommunicationsapps inflated totals
    into the tens of thousands on large jobs.
    """
    from app.services.axiom_section_queries import WINDOWS_MAIL_WHERE

    store_files = _count_sql(db, job_id, WINDOWS_MAIL_WHERE)
    parsed = _count_parsed_records(db, job_id, record_type="windows_mail_message")
    if parsed <= 0:
        parsed = _count_parsed_records(db, job_id, record_type="windows_mail")
    # Message-level only. Store containers alone are not AXIOM "Windows Mail" hits.
    if parsed > 0 and (store_files <= 0 or parsed <= max(store_files * 50, 500)):
        count = parsed
    else:
        count = 0
    return {
        "count": count,
        "samples": _sample_sql(db, job_id, WINDOWS_MAIL_WHERE),
        "store_files": store_files,
        "parsed_messages": parsed,
    }


def count_outlook_emails(db, job_id: str) -> dict[str, Any]:
    """AXIOM Outlook Emails — .msg + PST/OST expanded messages (not every Outlook path)."""
    from app.services.axiom_section_queries import OUTLOOK_EMAIL_WHERE, OUTLOOK_MSG_WHERE
    from app.services.pst_mailbox_inventory import scan_job_pst_mailboxes

    msg_count = _count_sql(db, job_id, OUTLOOK_MSG_WHERE)
    mailbox_files = _count_sql(
        db,
        job_id,
        """
        lower(coalesce(extension,'')) IN ('.pst', '.ost')
        OR file_path ILIKE '%.pst'
        OR file_path ILIKE '%.ost'
        """,
    )
    # Do NOT reuse generic email_message parse counts (shared with EML) — that inflated Outlook.
    parsed_outlook = _count_parsed_records(db, job_id, record_type="outlook_message")

    # New Outlook (Olk) mail items only — exclude caches/DBs/attachments.
    olk_mail = _count_sql(
        db,
        job_id,
        """
        file_path ILIKE '%/Olk/%'
        AND (
          file_path ILIKE '%/Mail/%'
          OR file_path ILIKE '%/message/%'
          OR file_path ILIKE '%.eml'
          OR file_path ILIKE '%.msg'
        )
        AND file_path NOT ILIKE '%Attachment%'
        AND file_path NOT ILIKE '%.db'
        AND file_path NOT ILIKE '%.sqlite'
        AND size_bytes > 512
        """,
    )

    pst = scan_job_pst_mailboxes(db, job_id)
    pst_messages = int(pst.get("message_count") or 0)

    carved_mail = 0
    try:
        from app.services.signature_carve_inventory import carved_axiom_count

        carved_mail = carved_axiom_count(db, job_id, "outlook emails")
    except Exception:
        carved_mail = 0

    count = max(msg_count, parsed_outlook, olk_mail, pst_messages, carved_mail)
    if count == 0 and mailbox_files > 0:
        # PST/OST present but messages not expanded — report containers only (not path sprawl).
        count = mailbox_files
    return {
        "count": count,
        "samples": _sample_sql(db, job_id, OUTLOOK_EMAIL_WHERE),
        "mailbox_files": mailbox_files,
        "msg_files": msg_count,
        "olk_mail_files": olk_mail,
        "parsed_outlook_messages": parsed_outlook,
        "pst_messages": pst_messages,
        "pst_attachment_estimate": int(pst.get("attachment_estimate") or 0),
        "carved_mail": carved_mail,
    }


def count_outlook_items(db, job_id: str, *, kind: str) -> dict[str, Any]:
    """Outlook Tasks / Contacts / Appointments — parsed item records only.

    Path ILIKE '%task%' / '%contact%' previously matched unrelated AppData trees and
    produced hundreds of false positives when AXIOM reported 0.
    """
    type_map = {
        "tasks": ("outlook_task",),
        "contacts": ("outlook_contact",),
        "appointments": ("outlook_appointment",),
        "calendar": ("calendar_event", "outlook_appointment"),
    }
    record_types = type_map.get(kind, (f"outlook_{kind}",))
    parsed = 0
    for rt in record_types:
        parsed += _count_parsed_records(db, job_id, record_type=rt)

    # .ics only for calendar/appointments — and only under Outlook/calendar trees.
    file_count = 0
    if kind in {"calendar", "appointments"}:
        file_count = _count_sql(
            db,
            job_id,
            """
            (lower(coalesce(extension,''))='.ics' OR file_path ILIKE '%.ics')
            AND (
              file_path ILIKE '%Outlook%'
              OR file_path ILIKE '%/Calendar/%'
              OR file_path ILIKE '%/Olk/%'
            )
            """,
        )
    count = parsed if parsed > 0 else file_count
    return {"count": count, "samples": [], "parsed_items": parsed, "ics_files": file_count}


def count_mbox_emails(db, job_id: str) -> dict[str, Any]:
    from app.services.handbook_query_sql import MBOX_EMAIL_WHERE

    count = _count_sql(db, job_id, MBOX_EMAIL_WHERE)
    return {"count": count, "samples": _sample_sql(db, job_id, MBOX_EMAIL_WHERE)}


def _ensure_webmail_cache(db, job_id: str, cache: dict[str, int]) -> None:
    """Fill all webmail pattern counts in one browser-history scan (avoids N× SQLite reads)."""
    if cache.get("__webmail_multi_done__"):
        return
    from app.services.artifact_live_counts import count_browser_url_hits_multi

    groups = {key: pats for key, pats in _WEBMAIL_PATTERNS.items() if pats}
    totals = count_browser_url_hits_multi(db, job_id, groups, count_visits=True)
    if not any(int(v or 0) > 0 for v in totals.values()):
        totals = count_browser_url_hits_multi(db, job_id, groups, count_visits=False)
    for key, value in totals.items():
        cache[key] = int(value or 0)
    cache["__webmail_multi_done__"] = 1


def count_webmail(db, job_id: str, *, catalog_key: str, _cache: dict[str, int] | None = None) -> dict[str, Any]:
    cache = _cache if _cache is not None else _webmail_cache_for(job_id)
    pats = _WEBMAIL_PATTERNS.get(catalog_key.lower(), [])
    if not pats:
        return {"count": 0, "samples": []}
    cache_key = catalog_key.lower()
    if cache_key not in cache:
        _ensure_webmail_cache(db, job_id, cache)
    return {"count": int(cache.get(cache_key) or 0), "samples": [], "files_scanned": 0}


def compute_report_email_counts(db, job_id: str) -> dict[str, int]:
    """Fast Email & Calendar counts for report section B (no browser webmail scan)."""
    titles = [
        "Email Attachments",
        "EML(X) Files",
        "Windows Mail",
        "Outlook Emails",
        "Outlook Tasks",
        "Outlook Contacts",
        "Outlook Appointments",
    ]
    out: dict[str, int] = {}
    for title in titles:
        data = collect_email_artifact(db, job_id, title, _webmail_cache={})
        key = re.sub(r"\s+", " ", title.strip().lower())
        out[key] = int(data.get("count") or 0)
    return out


def compute_all_email_counts(db, job_id: str, *, platform: str | None = None) -> dict[str, int]:
    """Compute counts for all email catalog titles on this platform."""
    from sqlalchemy import text

    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    platform = platform or resolve_job_axiom_platform(db, job_id)
    out = compute_report_email_counts(db, job_id)

    rows = db.execute(
        text(
            """SELECT artifact_name FROM public.axiom_artifacts
               WHERE platform = :platform
                 AND (lower(category) LIKE '%email%' OR lower(category) LIKE '%calendar%')"""
        ),
        {"platform": platform},
    ).scalars().all()

    file_titles = [
        "Calendar Events (ICS)",
        "MBOX Emails",
        "Outlook 11 Emails",
        "Outlook 11 Contacts",
        "Outlook 11 Calendar",
        "Outlook 11 To Do",
        "Outlook 11 Notes",
        "Outlook Journals",
        "Outlook Notes",
    ]
    titles = list(dict.fromkeys([*(rows or []), *file_titles]))
    for title in titles:
        data = collect_email_artifact(db, job_id, str(title), _webmail_cache={})
        norm = re.sub(r"\s+", " ", str(title).strip().lower())
        out[norm] = int(data.get("count") or 0)

    from app.services.artifact_live_counts import count_browser_url_hits_multi

    webmail_totals = count_browser_url_hits_multi(db, job_id, _WEBMAIL_PATTERNS, count_visits=True)
    if sum(webmail_totals.values()) <= 0:
        webmail_totals = count_browser_url_hits_multi(db, job_id, _WEBMAIL_PATTERNS, count_visits=False)
    for catalog_key, count in webmail_totals.items():
        out[catalog_key] = int(count or 0)

    # Aliases that share counts with primary collectors / webmail keys.
    _EMAIL_COUNT_ALIASES = {
        "outlook web app email fragments": "outlook web app email inbox",
        "outlook webmail fragments": "outlook webmail inbox",
        "outlook webmail inbox fragments": "outlook webmail inbox",
        "mail.ru chat parsed": "mail.ru",
        "mail.ru contacts": "mail.ru",
        "mail.ru groups": "mail.ru",
    }
    for alias, source in _EMAIL_COUNT_ALIASES.items():
        out[alias] = out.get(source, 0)

    return out


# Report + catalog titles → collector key
EMAIL_COLLECTORS: dict[str, str] = {
    "email attachments": "attachments",
    "eml(x) files": "eml",
    "eml files": "eml",
    "windows mail": "windows_mail",
    "outlook emails": "outlook_emails",
    "outlook tasks": "outlook_tasks",
    "outlook contacts": "outlook_contacts",
    "outlook appointments": "outlook_appointments",
    "calendar events (ics)": "calendar",
    "mbox emails": "mbox",
    "outlook 11 emails": "outlook_emails",
    "outlook 11 contacts": "outlook_contacts",
    "outlook 11 calendar": "outlook_appointments",
    "outlook 11 to do": "outlook_tasks",
    "outlook 11 notes": "outlook_tasks",
    "outlook journals": "outlook_tasks",
    "outlook notes": "outlook_tasks",
}


def collect_email_artifact(
    db,
    job_id: str,
    title: str,
    *,
    _webmail_cache: dict[str, int] | None = None,
) -> dict[str, Any]:
    key = re.sub(r"\s+", " ", (title or "").strip().lower())
    collector = EMAIL_COLLECTORS.get(key)
    if collector is None:
        for label, coll in EMAIL_COLLECTORS.items():
            if label in key or key in label:
                collector = coll
                break
    if collector == "attachments":
        return count_email_attachments(db, job_id)
    if collector == "eml":
        return count_eml_files(db, job_id)
    if collector == "windows_mail":
        return count_windows_mail(db, job_id)
    if collector == "outlook_emails":
        return count_outlook_emails(db, job_id)
    if collector == "outlook_tasks":
        return count_outlook_items(db, job_id, kind="tasks")
    if collector == "outlook_contacts":
        return count_outlook_items(db, job_id, kind="contacts")
    if collector == "outlook_appointments":
        return count_outlook_items(db, job_id, kind="appointments")
    if collector == "calendar":
        return count_outlook_items(db, job_id, kind="calendar")
    if collector == "mbox":
        return count_mbox_emails(db, job_id)
    if key in _WEBMAIL_PATTERNS:
        cache = _webmail_cache_for(job_id, _webmail_cache)
        return count_webmail(db, job_id, catalog_key=key, _cache=cache)
    if key.startswith("mail.ru"):
        cache = _webmail_cache_for(job_id, _webmail_cache)
        return count_webmail(db, job_id, catalog_key="mail.ru", _cache=cache)
    return {"count": 0, "samples": []}


def build_email_section_items(db, job_id: str) -> list[dict[str, Any]]:
    """Build Email & Calendar section items for report-style inventory."""
    titles = [
        "Email Attachments",
        "EML(X) Files",
        "Windows Mail",
        "Outlook Emails",
        "Outlook Tasks",
        "Outlook Contacts",
        "Outlook Appointments",
        "Calendar Events (ICS)",
        "MBOX Emails",
        "Gmail Webmail",
        "Gmail Fragments",
        "Hotmail Webmail",
        "GMX Webmail",
        "Yahoo! Webmail",
        "Outlook Web App Email Inbox",
        "Outlook Webmail Inbox",
    ]
    items: list[dict[str, Any]] = []
    for title in titles:
        data = collect_email_artifact(db, job_id, title)
        items.append({
            "key": re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_"),
            "title": title,
            "count": int(data.get("count") or 0),
            "samples": data.get("samples") or [],
            "description": f"Email & Calendar — {title}",
        })
    return items
