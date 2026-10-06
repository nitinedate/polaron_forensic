"""Resolve catalog artifact / section filters to job_artifacts SQL (browse + export)."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone
from app.services.catalog_categories import canonical_category


def list_where_for_email_attachments(*, job_id: str) -> tuple[str, dict[str, Any]]:
    from app.services.email_inventory import email_attachment_files_where

    return email_attachment_files_where(base_params={"jid": job_id})


def list_where_for_artifact_name(
    db: Session,
    job_id: str,
    *,
    artifact_name: str,
    category: str | None,
    platform: str,
) -> tuple[str, dict[str, Any]]:
    """Build a WHERE suffix (AND …) plus params for one catalog artifact."""
    from app.services.catalog_aligned_counts import _norm_axiom_name, document_extensions_for
    from app.services.axiom_section_queries import (
        EMLX_FILE_WHERE,
        JUMP_LIST_WHERE,
        LNK_FILE_WHERE,
        LOGFILE_ANALYSIS_WHERE,
        OUTLOOK_EMAIL_WHERE,
        WEB_RELATED_WHERE,
        WINDOWS_MAIL_WHERE,
    )
    from app.services.email_inventory import EMAIL_COLLECTORS, email_attachment_files_where

    name = _norm_axiom_name(artifact_name)
    cat = canonical_category(category)
    params: dict[str, Any] = {"jid": job_id}

    # Mobile path families (WhatsApp / SMS / SIM / apps / LinkedIn / …).
    mobile_filters: dict[str, tuple[str, ...]] = {
        "whatsapp messages": ("%whatsapp%", "%msgstore%", "%chatstorage%"),
        "whatsapp calls": ("%whatsapp%call%", "%wacall%"),
        "whatsapp": ("%whatsapp%",),
        "sms messages": ("%mmssms.db%", "%/sms.db%", "%telephony%"),
        "android sms": ("%mmssms.db%", "%sms%"),
        "sms/mms": ("%mmssms.db%", "%sms%"),
        "call logs": ("%calllog%", "%call_history%", "%callhistory%"),
        "android call logs": ("%calllog%", "%calls.db%"),
        "ios call logs": ("%callhistory%", "%call_history%"),
        "telegram": ("%telegram%", "%org.telegram%"),
        "signal": ("%signal%", "%securesms%"),
        "instagram": ("%instagram%",),
        "facebook messenger": ("%facebook%", "%messenger%"),
        "facebook": ("%facebook%",),
        "linkedin": ("%linkedin%",),
        "android device information": ("%build.prop%", "%device_info.json%", "%acquisition_manifest.json%"),
        "ios device information": ("%info.plist%", "%device_info.json%"),
        "installed applications": ("%packages.xml%", "%.apk%", "%/data/app/%"),
        "accounts": ("%accounts.db%", "%accounts.xml%"),
        "sim card": ("%iccid%", "%imsi%", "%siminfo%", "%telephony%"),
        "sim card iccid": ("%iccid%",),
        "sim card imsi": ("%imsi%",),
    }
    for key, patterns in mobile_filters.items():
        if name == key or (key in name and "url" not in name):
            clauses = " OR ".join(f"file_path ILIKE :mp{i} OR file_name ILIKE :mp{i}" for i in range(len(patterns)))
            for i, pat in enumerate(patterns):
                params[f"mp{i}"] = pat
            return f" AND ({clauses})", params

    if name in {"email attachments", "email attachment"}:
        return email_attachment_files_where(base_params={"jid": job_id})

    if name in {"eml(x) files", "eml files"}:
        # Self-heal historical jobs before applying the list predicate.  The MIME
        # scan promotes byte-validated extensionless messages into message/rfc822
        # metadata, so a stored non-zero catalog count cannot open to an empty pane.
        try:
            from app.services.email_mime_inventory import scan_job_email_mime_inventory

            scan_job_email_mime_inventory(db, job_id)
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        return f" AND ({EMLX_FILE_WHERE.strip()})", params

    if name == "windows mail":
        return f" AND ({WINDOWS_MAIL_WHERE.strip()})", params

    if name in {"outlook emails", "outlook 11 emails"}:
        return f" AND ({OUTLOOK_EMAIL_WHERE.strip()})", params

    if name == "outlook tasks" or name == "outlook 11 to do":
        return " AND (file_path ILIKE '%task%' OR file_path ILIKE '%.task%')", params

    if name in {"outlook contacts", "outlook 11 contacts"}:
        return " AND (file_path ILIKE '%contact%' OR file_path ILIKE '%.vcf%')", params

    if name in {"outlook appointments", "outlook 11 calendar", "calendar events (ics)"}:
        return (
            " AND (lower(coalesce(extension,''))='.ics' OR file_path ILIKE '%.ics' OR file_path ILIKE '%appointment%' OR file_path ILIKE '%calendar%')",
            params,
        )

    if name == "mbox emails":
        from app.services.handbook_query_sql import MBOX_EMAIL_WHERE

        return f" AND ({MBOX_EMAIL_WHERE.strip()})", params

    if name == "usb devices":
        return (
            " AND (file_path ILIKE '%/SYSTEM' OR lower(file_name)='system' "
            "OR file_path ILIKE '%setupapi.dev%')",
            params,
        )
    if name in {"your phone device", "your phone devices", "your phone contacts"}:
        return (
            " AND (file_path ILIKE '%CrossDevice%' OR file_path ILIKE '%YourPhone%' "
            "OR file_path ILIKE '%WPDBUSENUM%' OR file_path ILIKE '%setupapi.dev%')",
            params,
        )
    if name in {"remote desktop protocol", "remote desktop protocol (rdp)"}:
        return (
            " AND (lower(file_name)='ntuser.dat' OR file_path ILIKE '%/NTUSER.DAT')",
            params,
        )

    if name in {"jump list", "jump lists"}:
        return f" AND ({JUMP_LIST_WHERE.strip()})", params

    if name == "lnk files":
        return f" AND ({LNK_FILE_WHERE.strip()})", params

    if name in {"logfile analysis", "$logfile analysis"}:
        return f" AND ({LOGFILE_ANALYSIS_WHERE.strip()})", params

    if name == "web related files":
        return f" AND ({WEB_RELATED_WHERE.strip()})", params

    doc_exts = document_extensions_for(name)
    if doc_exts or cat == "documents":
        if doc_exts:
            ext_clauses = " OR ".join(
                f"lower(coalesce(extension,''))=:ext{i} OR file_path ILIKE :pat{i}"
                for i in range(len(doc_exts))
            )
            for i, ext in enumerate(doc_exts):
                params[f"ext{i}"] = ext if ext.startswith(".") else f".{ext}"
                params[f"pat{i}"] = f"%{ext if ext.startswith('.') else '.' + ext}"
            return f" AND ({ext_clauses})", params

    if name in {"picture", "pictures"}:
        from app.services.handbook_query_sql import sql_media_where

        return f" AND ({sql_media_where('picture')})", params
    if name == "audio":
        from app.services.handbook_query_sql import sql_media_where

        return f" AND ({sql_media_where('audio')})", params
    if name in {"video", "videos"}:
        from app.services.handbook_query_sql import sql_media_where

        return f" AND ({sql_media_where('video')})", params
    if name == "photoshop files":
        from app.services.handbook_query_sql import sql_media_where

        return f" AND ({sql_media_where('photoshop')})", params

    collector = EMAIL_COLLECTORS.get(name)
    if collector == "attachments":
        return email_attachment_files_where(base_params={"jid": job_id})
    if collector and name not in EMAIL_COLLECTORS:
        pass

    # Email/calendar artifacts without explicit list SQL — path keyword fallback (never match catalog title).
    if "email" in cat.lower() or "calendar" in cat.lower():
        if "attach" in name:
            return " AND (file_path ILIKE '%attach%' OR file_path ILIKE '%Content.Outlook%')", params
        tokens = [t for t in re.split(r"[^a-z0-9]+", name) if len(t) > 3 and t not in {"email", "calendar"}][:4]
        if tokens:
            clauses = " OR ".join(f"file_path ILIKE :p{i}" for i in range(len(tokens)))
            for i, tok in enumerate(tokens):
                params[f"p{i}"] = f"%{tok}%"
            return f" AND ({clauses})", params

    # Handbook-aligned fallback: extensions, extensionless mail, special basenames, path markers.
    from app.services.handbook_query_sql import sql_handbook_evidence_fallback

    hb = sql_handbook_evidence_fallback(name, category=cat or "")
    if hb and hb != "FALSE":
        return f" AND ({hb})", params

    # Last resort: encyclopedia label match or artifact-name token in path (never match literal artifact title).
    row = fetchone(
        db,
        "SELECT artifact_name, category FROM public.axiom_artifacts WHERE platform=:p AND artifact_name=:n LIMIT 1",
        {"p": platform, "n": artifact_name},
    )
    if row:
        tokens = [t for t in re.split(r"[^a-z0-9]+", _norm_axiom_name(row["artifact_name"])) if len(t) > 3][:3]
        if tokens:
            clauses = " OR ".join(f"file_path ILIKE :fp{i} OR file_name ILIKE :fp{i}" for i in range(len(tokens)))
            for i, tok in enumerate(tokens):
                params[f"fp{i}"] = f"%{tok}%"
            return f" AND ({clauses})", params

    return "", params


def list_where_for_catalog_key(
    db: Session,
    job_id: str,
    catalog_key: str,
    *,
    platform: str | None = None,
) -> tuple[str, dict[str, Any]]:
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    platform = platform or resolve_job_axiom_platform(db, job_id)
    ax = fetchone(
        db,
        "SELECT artifact_name, category FROM public.axiom_artifacts WHERE artifact_id=:k",
        {"k": catalog_key},
    )
    if not ax:
        return "", {"jid": job_id}
    suffix, params = list_where_for_artifact_name(
        db,
        job_id,
        artifact_name=ax["artifact_name"] or "",
        category=ax.get("category"),
        platform=platform,
    )
    params["jid"] = job_id
    return suffix, params


def list_where_for_catalog_section(
    db: Session,
    job_id: str,
    catalog_section: str,
    *,
    platform: str | None = None,
) -> tuple[str, dict[str, Any]]:
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    platform = platform or resolve_job_axiom_platform(db, job_id)
    section_title = canonical_category(catalog_section)
    rows = fetchall(
        db,
        """SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts
           WHERE platform=:platform""",
        {"platform": platform},
    )
    matched = [r for r in rows if canonical_category(r.get("category")) == section_title]
    if not matched:
        return "", {"jid": job_id}

    or_parts: list[str] = []
    params: dict[str, Any] = {"jid": job_id}
    for idx, row in enumerate(matched):
        suffix, part_params = list_where_for_artifact_name(
            db,
            job_id,
            artifact_name=row.get("artifact_name") or "",
            category=row.get("category"),
            platform=platform,
        )
        inner = suffix.replace(" AND ", "", 1).strip() if suffix.startswith(" AND ") else suffix.strip()
        if not inner:
            continue
        renamed: dict[str, Any] = {}
        for key, val in part_params.items():
            if key == "jid":
                continue
            new_key = f"{key}_{idx}"
            renamed[new_key] = val
            inner = inner.replace(f":{key}", f":{new_key}")
        or_parts.append(f"({inner})")
        params.update(renamed)

    if not or_parts:
        return "", params
    return f" AND ({' OR '.join(or_parts)})", params
