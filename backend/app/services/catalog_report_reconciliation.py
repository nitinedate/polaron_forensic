"""Compare application counts to AXIOM PDF report section B reference targets."""

from __future__ import annotations

import re
from typing import Any

from app.services.report_catalog_sync import REPORT_ARTIFACTS

# Reference counts from Ex-5 Histotechlab1 AXIOM report (section B).
PDF_REFERENCE_COUNTS: dict[str, int] = {
    "USB Devices": 39,
    "Your Phone Device": 2,
    "Remote Desktop Protocol (RDP)": 6,
    "Feature Usage": 42,
    "Installed Microsoft Programs": 31,
    "Installed Programs (Non-Microsoft)": 167,
    "Windows Defender Logs": 3,
    "Web Chat URLs": 10,
    "Social Media URLs": 50,
    "Malware/Phishing URLs": 0,
    "CSV Documents": 5,
    "Microsoft PowerPoint Documents": 21,
    "Microsoft Excel Documents": 150,
    "PDF Documents": 400,
    "RTF Documents": 5847,
    "Text Documents": 2473,
    "Microsoft Word Documents": 305,
    "Email Attachments": 312,
    "EML(X) Files": 18,
    "Windows Mail": 0,
    "Outlook Emails": 216,
    "Outlook Tasks": 0,
    "Outlook Contacts": 0,
    "Outlook Appointments": 0,
    "Encrypted Files": 56,
    "Windows Stored Credentials": 0,
    "Audio": 594,
    "Picture": 70580,
    "Video": 330,
    "Photoshop Files": 50,
    "Logfile Analysis": 12463,
    "Jump List": 721,
    "LNK Files": 1443,
}

# Why a gap may remain after collector fixes (for operator guidance).
GAP_REASONS: dict[str, str] = {
    "Picture": (
        "AXIOM = allocated FS + thumbcache/CMMM + full parse/carve of unalloc+pagefile. "
        "App: full-disk extensions + CMMM + sampled pagefile windows + ~2.5–4 GiB largest-unalloc carve. "
        "Residual gap is AXIOM’s deeper photorec-style unalloc recovery on this 512GB image."
    ),
    "PDF Documents": (
        "Allocated census + carved %PDF- from pagefile/unalloc/mail. "
        "AXIOM also recovers fragmented PDFs beyond the sampled unalloc budget."
    ),
    "Video": (
        "Allocated containers (all paths except .ts false positives) + carved BMFF/AVI/MKV from pagefile/unalloc. "
        "AXIOM recovers more fragmented streams from full unalloc."
    ),
    "Photoshop Files": (
        "No allocated .psd on this volume — AXIOM count is 8BPS carve-only. "
        "App samples pagefile/unalloc for 8BPS (hiberfil is often Xpress-compressed and yields little)."
    ),
    "Outlook Emails": (
        "PST/OST on this image are empty shells (~271KB, IPM.Note=0). "
        "AXIOM 216 comes from carved MSG/EML + Search/mail stores; app uses pagefile EML/IPM markers + MSG carve."
    ),
    "Email Attachments": "Path/MIME/PST estimates + mail-adjacent carved docs/PDF/MSG.",
    "EML(X) Files": "Allocated .eml/.emlx + carved MIME/From signatures (incl. pagefile).",
    "Encrypted Files": "Header scan is bounded; AXIOM runs deeper content analysis.",
    "Social Media URLs": (
        "Edge History DBs are tiny (~256KB); AXIOM also carves URLs from pagefile/unalloc. "
        "App merges History + carved pagefile/unalloc URL strings into the social-domain classifier."
    ),
    "Web Chat URLs": "Same URL pipeline with web-chat domain classifier (Skype/Teams/WhatsApp Web/…).",
    "Logfile Analysis": "AXIOM counts log events/lines; estimate uses size heuristic when logs are unparsed.",
    "RTF Documents": (
        "Allocated .rtf census (~3777) + carved {\\rtf. AXIOM’s extra ~2k are almost entirely carved from unalloc."
    ),
}


def norm_name(value: str | None) -> str:
    text = re.sub(r"\s+", " ", (value or "").strip().lower())
    text = text.replace("&", "and").replace("—", "-").replace("–", "-")
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


XLSX_ALIASES: dict[str, list[str]] = {
    "jump list": ["jump lists", "jump list"],
    "picture": ["pictures", "picture"],
    "video": ["videos", "video"],
    "remote desktop protocol (rdp)": ["remote desktop protocol", "remote desktop protocol (rdp)"],
    "your phone device": ["your phone device", "your phone devices"],
    "logfile analysis": ["logfile analysis", "$logfile analysis"],
    "email attachments": ["email attachments"],
    "eml(x) files": ["eml(x) files"],
    "outlook emails": ["outlook emails"],
}


def app_count_for_report_artifact(app_rows: dict[str, dict], artifact_name: str) -> int | None:
    """Resolve app/xlsx count for a PDF report artifact name."""
    key = norm_name(artifact_name)
    if key in app_rows:
        return int(app_rows[key].get("count") or 0)
    for alias in XLSX_ALIASES.get(key, [key]):
        n = norm_name(alias)
        if n in app_rows:
            return int(app_rows[n].get("count") or 0)
    for row_key, row in app_rows.items():
        if key == row_key or key in row_key or row_key in key:
            return int(row.get("count") or 0)
    return None


def build_report_reconciliation(app_rows: dict[str, dict]) -> list[dict[str, Any]]:
    """Return row-wise PDF vs app comparison for section B artifacts."""
    out: list[dict[str, Any]] = []
    for art in REPORT_ARTIFACTS:
        name = art["name"]
        if name not in PDF_REFERENCE_COUNTS:
            continue
        pdf = int(PDF_REFERENCE_COUNTS.get(name, 0))
        app = app_count_for_report_artifact(app_rows, name)
        delta = None if app is None else int(app) - pdf
        status = "missing_in_app"
        if app is None:
            pass
        elif delta == 0:
            status = "match"
        elif abs(delta or 0) <= max(3, int(pdf * 0.05)) if pdf else abs(delta or 0) <= 3:
            status = "near_match"
        else:
            status = "gap"
        out.append({
            "category": art["category"],
            "artifact": name,
            "pdf_count": pdf,
            "app_count": app,
            "delta": delta,
            "status": status,
            "reason": GAP_REASONS.get(name, ""),
        })
    return out
