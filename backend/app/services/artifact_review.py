"""Examiner review signals for extracted evidence.

These are deterministic triage signals, not findings of guilt/malware.  The UI
must label them as review flags so the examiner keeps final judgement.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone
from app.services.artifact_file_forensics import classify_file_row
from app.services.artifact_preview import _load_artifact_row

_DANGEROUS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi", ".dll", ".com"}
_SHORTCUT = {".lnk", ".automaticdestinations-ms", ".customdestinations-ms"}
_MAIL = {".eml", ".emlx", ".msg", ".pst", ".ost", ".mbox"}
_LOGS = {".log", ".evtx", ".evt", ".etl"}
_LOLBINS = re.compile(r"\b(powershell|pwsh|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)\b", re.I)
_SUSPICIOUS_TEXT = re.compile(
    r"\b(encodedcommand|-enc\b|downloadstring|invoke-webrequest|invoke-expression|frombase64string|credential|password|seed phrase|wallet|gift card|wire transfer|one[- ]time password|otp)\b",
    re.I,
)
_URL_SIGNAL = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)|https?://[^\s/]*xn--", re.I)
_SOCIAL = re.compile(r"(?:whatsapp|telegram|signal|facebook|instagram|linkedin|discord|tiktok|twitter|x\.com)", re.I)
_MEDIA_REVIEW_TEXT = re.compile(
    r"\b(firearm|gun|weapon|knife|blood|violence|narcotic|drug package|credential|password|seed phrase|wallet|qr code|screen capture|document scan)\b",
    re.I,
)


def _ext(row: dict[str, Any]) -> str:
    ext = str(row.get("extension") or "").lower().strip()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    if not ext:
        ext = PurePosixPath(str(row.get("file_name") or row.get("file_path") or "")).suffix.lower()
    return ext


def review_row(row: dict[str, Any], *, content_text: str = "") -> dict[str, Any]:
    classified = classify_file_row({
        **row,
        "source_path": row.get("source_path") or row.get("file_path"),
        "title": row.get("title") or row.get("file_name"),
    })
    meta = classified.get("metadata") if isinstance(classified.get("metadata"), dict) else {}
    ext = _ext(row)
    path = str(row.get("source_path") or row.get("file_path") or "")
    name = str(row.get("file_name") or row.get("title") or "")
    text = "\n".join(
        str(value or "")
        for value in (
            path,
            name,
            meta.get("original_name"),
            meta.get("target_path"),
            meta.get("command_line"),
            meta.get("url"),
            meta.get("subject"),
            meta.get("sender"),
            meta.get("body"),
            content_text[:80_000],
        )
    )
    signals: list[dict[str, str]] = []

    def add(code: str, label: str, severity: str, detail: str) -> None:
        if not any(s["code"] == code for s in signals):
            signals.append({"code": code, "label": label, "severity": severity, "detail": detail})

    if ext in _DANGEROUS:
        add("active_content", "Executable / active-content file", "high", f"{ext or 'active content'} warrants examiner review.")
    if bool(meta.get("extension_mismatch")):
        add("extension_mismatch", "Extension mismatch", "high", "File signature and displayed extension differ.")
    if bool(meta.get("double_extension")):
        add("double_extension", "Double extension", "high", "Filename uses a double extension often used to disguise content.")
    if ext in _SHORTCUT or "jumplist" in path.lower():
        add("shortcut_execution", "Shortcut / Jump List execution evidence", "medium", "Review target path and command-line context.")
    if ext in _MAIL and any(token in text.lower() for token in ("attachment", "http://", "https://")):
        add("email_content", "Email with link/attachment context", "medium", "Review sender, recipients, links and attachments.")
    if _LOLBINS.search(text):
        add("command_execution", "Command/interpreter activity", "high", "Evidence references a command interpreter or LOLBin.")
    if _SUSPICIOUS_TEXT.search(text):
        add("content_keyword", "Sensitive / suspicious-content signal", "medium", "Recovered text contains a term requiring examiner review.")
    if _URL_SIGNAL.search(text):
        add("url_anomaly", "Unusual URL form", "medium", "URL uses an IP literal or internationalized/punycode hostname.")
    if _SOCIAL.search(text):
        add("social_web", "Social / messaging web activity", "info", "Social or messaging-service evidence is present.")
    media_kind = str(
        meta.get("file_kind")
        or meta.get("detected_kind")
        or ((meta.get("file_forensics") or {}).get("kind") if isinstance(meta.get("file_forensics"), dict) else "")
        or ""
    ).lower()
    if media_kind in {"image", "video", "audio"} and content_text and _MEDIA_REVIEW_TEXT.search(content_text):
        add(
            "media_content_review",
            "Media content requiring examiner review",
            "medium",
            "OCR, derived image description, or recovered media text contains a review-sensitive concept; inspect the original media before drawing conclusions.",
        )
    if ext in _LOGS and (_LOLBINS.search(text) or _SUSPICIOUS_TEXT.search(text)):
        add("log_signal", "Log activity requiring review", "high", "Recovered log content contains command or sensitive activity signals.")
    if bool(meta.get("is_deleted")) or bool(meta.get("deleted_at")):
        add("deleted_recovered", "Deleted / recovered evidence", "low", "Evidence was deleted or recovered from deleted storage structures.")
    if bool(meta.get("is_modified")):
        add("modified", "Modified / renamed evidence", "low", "Metadata indicates modification, rename, or recovered filesystem state.")

    media_observation = meta.get("media_review") or {}
    if media_observation.get("flagged"):
        add("suspicious_activity_media", "Suspicious Activity — image/video observation", "medium", str(media_observation.get("description") or "Source-linked media observation requires examiner review"))

    order = {"high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
    severity = max((s["severity"] for s in signals), key=lambda s: order.get(s, 0), default="none")
    return {
        "flagged": bool(signals),
        "severity": severity,
        "signal_count": len(signals),
        "signals": signals,
        "disclaimer": "Automated examiner-review signals are triage aids, not conclusions about intent or maliciousness.",
    }


def artifact_review(db: Session, job_id: str, artifact_id: str) -> dict[str, Any]:
    row = _load_artifact_row(db, job_id, artifact_id)
    if not row:
        raise LookupError("Artifact not found")
    text_parts: list[str] = []
    try:
        parsed = fetchall(
            db,
            """SELECT normalized::text AS text FROM artifact_parse_results
               WHERE job_artifact_id=:aid ORDER BY created_at DESC LIMIT 4""",
            {"aid": artifact_id},
        )
        text_parts.extend(str(r.get("text") or "") for r in parsed)
        ocr = fetchall(
            db,
            """SELECT ocr_text AS text FROM ocr_results
               WHERE job_artifact_id=:aid ORDER BY page_index LIMIT 20""",
            {"aid": artifact_id},
        )
        text_parts.extend(str(r.get("text") or "") for r in ocr)
        image = fetchone(
            db,
            """SELECT ocr_text, ai_description FROM rag_image_assets
               WHERE job_artifact_id=:aid ORDER BY updated_at DESC LIMIT 1""",
            {"aid": artifact_id},
        )
        if image:
            text_parts.extend([str(image.get("ocr_text") or ""), str(image.get("ai_description") or "")])
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    result = review_row(dict(row), content_text="\n".join(text_parts))
    result.update({"artifact_id": artifact_id, "job_id": job_id})
    return result


def job_review_summary(db: Session, job_id: str, *, limit: int = 120) -> dict[str, Any]:
    # Do not pull an entire multi-million-row case into Python merely to build
    # a dashboard badge.  This predicate is intentionally broad: it finds the
    # file/metadata classes that can be classified without parsing/OCR text.
    # Deep content review remains an on-demand operation for the selected
    # artifact via ``artifact_review``.
    candidate_predicate = """
        (
          lower(CASE
            WHEN coalesce(extension, '') = '' THEN ''
            WHEN left(extension, 1) = '.' THEN extension
            ELSE '.' || extension
          END) IN (
            '.exe','.scr','.bat','.cmd','.ps1','.vbs','.js','.hta','.msi','.dll','.com',
            '.lnk','.automaticdestinations-ms','.customdestinations-ms',
            '.eml','.emlx','.msg','.pst','.ost','.mbox',
            '.log','.evtx','.evt','.etl'
          )
          OR lower(coalesce(file_path, '')) LIKE '%jumplist%'
          OR lower(coalesce(file_path, '')) LIKE '%whatsapp%'
          OR lower(coalesce(file_path, '')) LIKE '%telegram%'
          OR lower(coalesce(file_path, '')) LIKE '%signal%'
          OR lower(coalesce(file_path, '')) LIKE '%facebook%'
          OR lower(coalesce(file_path, '')) LIKE '%instagram%'
          OR lower(coalesce(file_path, '')) LIKE '%discord%'
          OR lower(coalesce(file_path, '')) LIKE '%tiktok%'
          OR lower(coalesce(file_name, '')) ~ '\\.[a-z0-9]{1,8}\\.(exe|scr|bat|cmd|ps1|vbs|js|hta|msi|com)$'
          OR coalesce(metadata::text, '') ILIKE '%"is_deleted": true%'
          OR coalesce(metadata::text, '') ILIKE '%"extension_mismatch": true%'
          OR coalesce(metadata::text, '') ILIKE '%"double_extension": true%'
          OR metadata->>'suspicious_activity'='true'
          OR coalesce(metadata::text, '') ILIKE '%"is_modified": true%'
          OR coalesce(metadata::text, '') ~* '(powershell|pwsh|cmd\\.exe|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)'
        )
    """
    total_row = fetchone(
        db,
        "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid",
        {"jid": job_id},
    ) or {}
    scan_cap = max(200, min(5000, max(1, int(limit)) * 20))
    rows = fetchall(
        db,
        f"""SELECT id, job_id, file_path, file_name, extension, size_bytes, metadata
             FROM job_artifacts
            WHERE job_id=:jid AND {candidate_predicate}
            ORDER BY created_at DESC
            LIMIT :scan_cap""",
        {"jid": job_id, "scan_cap": scan_cap + 1},
    )
    candidate_limited = len(rows) > scan_cap
    if candidate_limited:
        rows = rows[:scan_cap]
    buckets = {"high": 0, "medium": 0, "low": 0, "info": 0}
    flagged: list[dict[str, Any]] = []
    for row in rows:
        review = review_row(row)
        if not review["flagged"]:
            continue
        sev = str(review["severity"])
        buckets[sev] = buckets.get(sev, 0) + 1
        if len(flagged) < max(1, min(int(limit), 500)):
            flagged.append({
                "artifact_id": str(row.get("id")),
                "file_name": row.get("file_name"),
                "source_path": row.get("file_path"),
                "size_bytes": row.get("size_bytes"),
                "severity": sev,
                "signals": review["signals"],
            })
    return {
        "job_id": job_id,
        "total_artifacts": int(total_row.get("c") or 0),
        "flagged_total": sum(buckets.values()),
        "candidate_total": None,
        "scanned_candidates": len(rows),
        "by_severity": buckets,
        "items": flagged,
        "limited": candidate_limited or sum(buckets.values()) > len(flagged),
        "disclaimer": (
            "Review flags identify evidence for examiner attention; they are not automatic findings of wrongdoing or malware. "
            "Dashboard screening is metadata/file-type based; OCR and parsed-content review is performed when evidence is opened."
        ),
    }
