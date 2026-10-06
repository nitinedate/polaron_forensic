"""Ingest Aetheris report template artifacts/objectives from sample PDF extracts into DB."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

REPORT_ARTIFACTS: list[dict[str, str]] = [
    # Connected Devices
    {"category": "Connected Devices", "name": "USB Devices", "description": "External storage devices like pen drives or hard drives used to move or copy data."},
    {"category": "Connected Devices", "name": "Your Phone Device", "description": "Mobile devices connected using Microsoft Your Phone feature."},
    {"category": "Connected Devices", "name": "Remote Desktop Protocol (RDP)", "description": "Allows remote access/control of the desktop."},
    # Application Usage
    {"category": "Application Usage", "name": "Feature Usage", "description": "Records of system feature usage like accessibility tools, file explorer, or system settings."},
    {"category": "Application Usage", "name": "Installed Microsoft Programs", "description": "Microsoft applications such as Word, Excel, Outlook installed on the system."},
    {"category": "Application Usage", "name": "Installed Programs (Non-Microsoft)", "description": "User-installed software, including browsers, communication tools, or utilities."},
    {"category": "Application Usage", "name": "Windows Defender Logs", "description": "Logs from Windows Defender antivirus software."},
    # Communication
    {"category": "Communication", "name": "Web Chat URLs", "description": "Links to web-based chat platforms indicating chat usage."},
    {"category": "Communication", "name": "Social Media URLs", "description": "URLs linking to social media platforms."},
    {"category": "Communication", "name": "Malware/Phishing URLs", "description": "Links designed to steal information or install harmful software."},
    {"category": "Communication", "name": "Pornography URLs", "description": "Visited browser-history URLs classified as adult/pornography sites."},
    {"category": "Communication", "name": "Dating Site URLs", "description": "Visited browser-history URLs classified as online dating platforms."},
    # Documents
    {"category": "Documents", "name": "CSV Documents", "description": "Raw data or logs stored in comma-separated format."},
    {"category": "Documents", "name": "Microsoft PowerPoint Documents", "description": "Presentation files used for discussions or visual reporting."},
    {"category": "Documents", "name": "Microsoft Excel Documents", "description": "Spreadsheets used for calculations, lists, logs, and financial data."},
    {"category": "Documents", "name": "PDF Documents", "description": "Fixed-layout documents like contracts, bills, and receipts."},
    {"category": "Documents", "name": "RTF Documents", "description": "Rich Text Format files with styled text."},
    {"category": "Documents", "name": "Text Documents", "description": "Plain text files, often used for scripts, logs, or notes."},
    {"category": "Documents", "name": "Microsoft Word Documents", "description": "Word-processed documents such as reports and letters."},
    # Email & Calendar
    {"category": "Email & Calendar", "name": "Email Attachments", "description": "Email attachments detected in local email clients."},
    {"category": "Email & Calendar", "name": "EML(X) Files", "description": "Archived or exported emails preserving headers and metadata."},
    {"category": "Email & Calendar", "name": "Windows Mail", "description": "Emails and related information saved by the Windows Mail app."},
    {"category": "Email & Calendar", "name": "Outlook Emails", "description": "Emails found from Microsoft Outlook client."},
    {"category": "Email & Calendar", "name": "Outlook Tasks", "description": "Tasks created in Microsoft Outlook."},
    {"category": "Email & Calendar", "name": "Outlook Contacts", "description": "Saved contact details in Outlook."},
    {"category": "Email & Calendar", "name": "Outlook Appointments", "description": "Calendar events saved in Outlook."},
    # Encryption & Credentials
    {"category": "Encryption & Credentials", "name": "Encrypted Files", "description": "Files encrypted, potentially indicating attempts to protect or hide content."},
    {"category": "Encryption & Credentials", "name": "Windows Stored Credentials", "description": "Passwords and authentication data saved by Windows."},
    # Media
    {"category": "Media", "name": "Audio", "description": "Sound or voice recordings possibly related to user activity."},
    {"category": "Media", "name": "Picture", "description": "Personal photos, screenshots, and internet images."},
    {"category": "Media", "name": "Video", "description": "Saved or downloaded videos."},
    {"category": "Media", "name": "Photoshop Files", "description": "Edited or created images using Adobe Photoshop."},
    # Operating System
    {"category": "Operating System", "name": "Logfile Analysis", "description": "System logs showing user activity, shutdowns, errors, and access patterns."},
    {"category": "Operating System", "name": "Jump List", "description": "Recently accessed files or programs via Start Menu or taskbar."},
    {"category": "Operating System", "name": "LNK Files", "description": "Shortcut files referencing deleted or moved data."},
    # Web Related
    {"category": "Web Related", "name": "Web Related Files", "description": "Browser history, cookies, cache, downloads, and other web usage artifacts."},
]


# Stable IDs for report-section B artifacts (must match 06_report_template_artifacts.sql where set).
_REPORT_ARTIFACT_IDS: dict[tuple[str, str], str] = {
    ("Connected Devices", "Your Phone Device"): "RPT-ART-001",
    ("Connected Devices", "Remote Desktop Protocol (RDP)"): "RPT-ART-002",
    ("Application Usage", "Installed Programs (Non-Microsoft)"): "RPT-ART-003",
    ("Communication", "Web Chat URLs"): "RPT-ART-004",
    ("Communication", "Social Media URLs"): "RPT-ART-005",
    ("Communication", "Malware/Phishing URLs"): "RPT-ART-013",
    ("Communication", "Pornography URLs"): "RPT-ART-018",
    ("Communication", "Dating Site URLs"): "RPT-ART-019",
    ("Email & Calendar", "Email Attachments"): "RPT-ART-006",
    ("Email & Calendar", "EML(X) Files"): "RPT-ART-014",
    ("Email & Calendar", "Outlook Emails"): "RPT-ART-015",
    ("Encryption & Credentials", "Encrypted Files"): "RPT-ART-016",
    ("Media", "Audio"): "RPT-ART-017",
    ("Media", "Picture"): "RPT-ART-007",
    ("Media", "Video"): "RPT-ART-008",
    ("Media", "Photoshop Files"): "RPT-ART-009",
    ("Operating System", "Logfile Analysis"): "RPT-ART-010",
    ("Operating System", "Jump List"): "RPT-ART-011",
    ("Web Related", "Web Related Files"): "RPT-ART-012",
}

_REPORT_CRITICAL_ARTIFACTS: frozenset[tuple[str, str]] = frozenset({
    ("Communication", "Web Chat URLs"),
    ("Communication", "Social Media URLs"),
    ("Communication", "Malware/Phishing URLs"),
})

_REPORT_SORT_ORDER: dict[tuple[str, str], int] = {
    ("Communication", "Web Chat URLs"): 1,
    ("Communication", "Social Media URLs"): 2,
    ("Communication", "Malware/Phishing URLs"): 3,
    ("Communication", "Pornography URLs"): 4,
    ("Communication", "Dating Site URLs"): 5,
}


def ensure_report_template_artifacts(db: Session, *, platform: str = "Windows") -> None:
    """Idempotently insert report-template catalog rows (section B) missing from axiom_artifacts."""
    missing = False
    for art in REPORT_ARTIFACTS:
        if not _find_artifact_id(db, platform, art["name"], art.get("category")):
            missing = True
            break
    if not missing:
        return
    sync_report_catalog_to_db(db, platform=platform)


def _obj(title: str) -> dict[str, str]:
    from app.services.axiom_forensic_kb import controlled_objective_text
    from app.services.report_objective_procedures import procedure_for_title

    return {
        "title": title,
        "statement": controlled_objective_text(title),
        "procedure": procedure_for_title(title),
        "domain": "Aetheris Report Template",
    }


# Intake display order is product UI metadata. The forensic Objective and Procedure
# text for every title is generated from ``aetheris_axiom_kb_starter`` above.
DISK_REPORT_OBJECTIVE_TITLES: list[str] = [
    "User Accounts & Login Activity",
    "File Access and Handling",
    "USB and External Device Usage",
    "Network Connections",
    "Installed Applications & Tools",
    "Registry Analysis",
    "Scheduled Tasks & Startup Items",
    "Antivirus & Patch Status",
    "Event Logs & Timeline Reconstruction",
    "Email Artifacts (Local Clients)",
    "Clipboard & Print Activity",
    "Virtual Machines or Sandbox Use",
    "Chat / Communication Apps",
    "Hidden Partitions / Alternate Data Streams (ADS)",
    "Anti-Forensic Tools or Cleanup Attempts",
    "Data Sync Clients",
    "Shadow Copies & Backup Artifacts",
    "Detection of Torrent Activity",
    "Malware, Phishing and Pornography URLs",
    "Access to Cloud Storage Services",
    "Connection of External Hard Disks",
    "Use of WhatsApp Web and Download of RRP Files",
    "Deleted Files Found in Recycle Bin",
    "Presence of Encrypted Files",
    "Email Accounts Used on the Laptop",
    "Storage of Email Login Details in Notepad",
    "Storage of RRP-Related Documents on Personal Laptop",
]

REPORT_OBJECTIVES: list[dict[str, str]] = [_obj(title) for title in DISK_REPORT_OBJECTIVE_TITLES]


# Append mobile forensic objectives (titles used by mobile_forensic report type).
from app.services.mobile_report_catalog import MOBILE_FORENSIC_OBJECTIVE_TITLES  # noqa: E402

for _mobile_title in MOBILE_FORENSIC_OBJECTIVE_TITLES:
    REPORT_OBJECTIVES.append(_obj(_mobile_title))


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _artifact_prompt(platform: str, category: str, name: str, description: str) -> str:
    return (
        f"For the {platform} forensic report artifact \"{name}\" ({category}): "
        f"report the total count recovered on this evidence, a concise explanation of what was found, "
        f"and the forensic significance. {description}"
    ).strip()


def _objective_prompt(obj: dict[str, str], proc: dict[str, str]) -> str:
    return (
        f"Objective — {obj['title']}: {obj.get('statement') or ''} "
        f"Procedure: {proc.get('detailed_procedure') or ''} "
        f"Report observed facts, counts, corroboration, and limitations grounded in indexed evidence."
    ).strip()


def _procedure_prompt(proc: dict[str, str], obj: dict[str, str]) -> str:
    return (
        f"Procedure {proc['procedure_id']} — {proc.get('title') or ''}: "
        f"{proc.get('detailed_procedure') or ''} "
        f"Expected observations for objective: {obj.get('title') or ''}."
    ).strip()


def _norm_name(s: str) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip().lower())
    s = s.replace("(non-microsoft)", "non-microsoft").replace("(rdp)", "rdp")
    s = re.sub(r"[()]", "", s)
    return s


_CATALOG_NAME_ALIASES: dict[str, str] = {
    "installed programs (non-microsoft)": "installed programs",
    "installed programs non-microsoft": "installed programs",
}


def _find_artifact_id(db: Session, platform: str, name: str, category: str | None = None) -> str | None:
    rows = db.execute(
        text(
            """SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts
               WHERE platform = :platform"""
        ),
        {"platform": platform},
    ).mappings().all()
    target = _norm_name(name)
    alias_target = _CATALOG_NAME_ALIASES.get(target)
    for r in rows:
        norm = _norm_name(r["artifact_name"])
        name_match = norm == target or (alias_target and norm == alias_target)
        if not name_match:
            continue
        if category and (r.get("category") or "").lower() != category.lower():
            continue
        return r["artifact_id"]
    return None


def cleanup_duplicate_report_artifacts(db: Session, *, platform: str = "Windows") -> int:
    """Remove RPT-* rows that duplicate an existing AXIOM artifact name."""
    rows = db.execute(
        text(
            """SELECT artifact_id, artifact_name FROM public.axiom_artifacts
               WHERE platform = :platform AND artifact_id LIKE 'RPT-%'"""
        ),
        {"platform": platform},
    ).mappings().all()
    all_names = db.execute(
        text(
            """SELECT artifact_id, artifact_name FROM public.axiom_artifacts
               WHERE platform = :platform AND artifact_id NOT LIKE 'RPT-%'"""
        ),
        {"platform": platform},
    ).mappings().all()
    canon = {_norm_name(r["artifact_name"]): r["artifact_id"] for r in all_names}
    removed = 0
    for row in rows:
        if _norm_name(row["artifact_name"]) in canon:
            db.execute(
                text("DELETE FROM public.axiom_artifacts WHERE artifact_id = :aid"),
                {"aid": row["artifact_id"]},
            )
            removed += 1
    if removed:
        db.flush()
    return removed


def sync_report_catalog_to_db(db: Session, *, platform: str = "Windows") -> dict[str, Any]:
    """Add report-template artifacts/objectives missing from axiom tables."""
    added_artifacts = 0
    skipped_artifacts = 0
    added_objectives = 0
    added_procedures = 0

    max_sort = db.execute(
        text("SELECT coalesce(max(sort_order), 0) m FROM public.axiom_artifacts WHERE platform = :p"),
        {"p": platform},
    ).mappings().first()
    sort_order = int(max_sort["m"]) if max_sort else 0

    for art in REPORT_ARTIFACTS:
        existing = _find_artifact_id(db, platform, art["name"], art.get("category"))
        if existing:
            skipped_artifacts += 1
            continue
        sort_order += 1
        key = (art["category"], art["name"])
        aid = _REPORT_ARTIFACT_IDS.get(key) or f"RPT-{uuid.uuid4().hex[:8].upper()}"
        prompt = _artifact_prompt(platform, art["category"], art["name"], art["description"])
        critical = key in _REPORT_CRITICAL_ARTIFACTS
        row_sort = _REPORT_SORT_ORDER.get(key, sort_order)
        db.execute(
            text(
                """INSERT INTO public.axiom_artifacts
                   (artifact_id, platform, category, artifact_name, recovery_method,
                    prompt_question, critical, sort_order, observation_focus, metadata, updated_at)
                   VALUES (:aid, :platform, :category, :name, 'Parsing', :prompt, :critical, :sort,
                           :obs, CAST(:meta AS jsonb), NOW())
                   ON CONFLICT (artifact_id) DO UPDATE SET
                     platform = EXCLUDED.platform,
                     category = EXCLUDED.category,
                     artifact_name = EXCLUDED.artifact_name,
                     prompt_question = EXCLUDED.prompt_question,
                     critical = EXCLUDED.critical,
                     observation_focus = EXCLUDED.observation_focus,
                     metadata = EXCLUDED.metadata,
                     updated_at = NOW()"""
            ),
            {
                "aid": aid,
                "platform": platform,
                "category": art["category"],
                "name": art["name"],
                "prompt": prompt,
                "critical": critical,
                "sort": row_sort,
                "obs": art["description"],
                "meta": json.dumps({"source": "aetheris_report_template", "report_section": "B. ARTIFACTS"}),
            },
        )
        added_artifacts += 1

    existing_titles = {
        _norm(r["title"])
        for r in db.execute(text("SELECT title FROM public.axiom_objectives")).mappings().all()
    }

    obj_seq = db.execute(text("SELECT count(*) c FROM public.axiom_objectives")).mappings().first()
    proc_seq = db.execute(text("SELECT count(*) c FROM public.axiom_procedures")).mappings().first()
    obj_n = int(obj_seq["c"]) if obj_seq else 100
    proc_n = int(proc_seq["c"]) if proc_seq else 100

    for item in REPORT_OBJECTIVES:
        if _norm(item["title"]) in existing_titles:
            continue
        obj_n += 1
        proc_n += 1
        oid = f"RPT-O{obj_n:03d}"
        pid = f"RPT-P{proc_n:03d}"
        obj_row = {
            "objective_id": oid,
            "procedure_id": pid,
            "domain": item["domain"],
            "title": item["title"],
            "statement": item["statement"],
            "required_observation_fields": "Observed facts; counts; timestamps; source paths; corroboration; limitations",
            "minimum_corroboration": "Independent artifact or log entry where available",
            "limitations": "Absence of evidence is not proof of absence.",
            "priority": "Report",
        }
        proc_row = {
            "procedure_id": pid,
            "objective_id": oid,
            "domain": item["domain"],
            "title": f"Procedure for {item['title']}",
            "detailed_procedure": item["procedure"],
            "mandatory_corroboration": "Cross-check with at least one independent artifact where available.",
            "expected_output_fields": "Observed facts; counts; timestamps; users; source paths",
            "limitations": item.get("limitations") or "Interpretation separate from observed facts.",
        }
        obj_prompt = _objective_prompt(obj_row, proc_row)
        proc_prompt = _procedure_prompt(proc_row, obj_row)
        db.execute(
            text(
                """INSERT INTO public.axiom_objectives
                   (objective_id, procedure_id, domain, title, statement,
                    required_observation_fields, minimum_corroboration, limitations, priority, prompt_question)
                   VALUES (:objective_id, :procedure_id, :domain, :title, :statement,
                           :required_observation_fields, :minimum_corroboration, :limitations, :priority, :prompt)
                   ON CONFLICT (objective_id) DO NOTHING"""
            ),
            {**obj_row, "prompt": obj_prompt},
        )
        db.execute(
            text(
                """INSERT INTO public.axiom_procedures
                   (procedure_id, objective_id, domain, title, detailed_procedure,
                    mandatory_corroboration, expected_output_fields, limitations, prompt_question)
                   VALUES (:procedure_id, :objective_id, :domain, :title, :detailed_procedure,
                           :mandatory_corroboration, :expected_output_fields, :limitations, :prompt)
                   ON CONFLICT (procedure_id) DO NOTHING"""
            ),
            {**proc_row, "prompt": proc_prompt},
        )
        existing_titles.add(_norm(item["title"]))
        added_objectives += 1
        added_procedures += 1

    db.flush()
    removed_dupes = cleanup_duplicate_report_artifacts(db, platform=platform)
    return {
        "added_artifacts": added_artifacts,
        "skipped_artifacts_existing": skipped_artifacts,
        "removed_duplicate_report_artifacts": removed_dupes,
        "added_objectives": added_objectives,
        "added_procedures": added_procedures,
        "report_artifact_templates": len(REPORT_ARTIFACTS),
        "report_objective_templates": len(REPORT_OBJECTIVES),
    }


def parse_pdf_extract_path(data_dir: Path | None = None) -> list[Path]:
    data_dir = data_dir or Path(__file__).resolve().parents[2] / "data" / "axiom"
    return list(data_dir.glob("*_extract.txt"))
