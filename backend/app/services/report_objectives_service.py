"""Report types and examination objectives — intake catalog with report-type recommendations."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.services.axiom_catalog_ingest import get_axiom_objectives_catalog
from app.services.report_catalog_sync import REPORT_OBJECTIVES

REPORT_TYPES: list[dict[str, Any]] = [
    {
        "id": "general_computer_forensic",
        "label": "General Computer Forensic Report",
        "domain": "forensic",
        "default_os": ["windows"],
        "description": "Standard Windows workstation examination (Aetheris template).",
    },
    {
        "id": "general",
        "label": "General Forensic Examination",
        "domain": "general",
        "default_os": [],
        "description": "Alias for general computer forensic report.",
    },
    {
        "id": "incident_response",
        "label": "Incident Response Report",
        "domain": "cyber",
        "default_os": ["windows"],
        "description": "Security incident and compromise assessment.",
    },
    {
        "id": "insider_threat",
        "label": "Insider Threat Report",
        "domain": "hr",
        "default_os": ["windows"],
        "description": "Internal misuse, data theft, and policy violations.",
    },
    {
        "id": "malware",
        "label": "Malware / Incident Response Report",
        "domain": "malware",
        "default_os": ["windows", "linux"],
        "description": "Malware presence, persistence, and IOC analysis.",
    },
    {
        "id": "data_exfiltration",
        "label": "Data Exfiltration Report",
        "domain": "dlp",
        "default_os": ["windows"],
        "description": "Unauthorized data staging, copy, upload, or email exfiltration.",
    },
    {
        "id": "data_leakage",
        "label": "Data Leakage Report",
        "domain": "dlp",
        "default_os": ["windows"],
        "description": "Alias for data exfiltration / leakage investigations.",
    },
    {
        "id": "email_investigation",
        "label": "Email Investigation Report",
        "domain": "communication",
        "default_os": ["windows"],
        "description": "Local and webmail email artifact examination.",
    },
    {
        "id": "mobile_forensic",
        "label": "Mobile Device Forensic Report",
        "domain": "mobile",
        "default_os": ["android", "ios"],
        "description": "Mobile messaging, location, and app artifacts.",
    },
    {
        "id": "policy_violation",
        "label": "Policy Violation Report",
        "domain": "hr",
        "default_os": ["windows"],
        "description": "Workplace policy violations and unauthorized activity (RRP / Seger template).",
    },
]

# Keyword hints used to mark objectives as recommended per report type.
_REPORT_TYPE_KEYWORDS: dict[str, list[str]] = {
    "general_computer_forensic": [
        "user", "login", "account", "file access", "usb", "external", "timeline", "event log",
        "registry", "installed", "application", "jump list", "lnk", "browser", "email account",
    ],
    "general": [
        "user", "login", "account", "file access", "usb", "external", "timeline", "event log",
        "registry", "installed", "application",
    ],
    "incident_response": [
        "malware", "persistence", "event log", "antivirus", "phishing", "network", "anti-forensic",
        "logon", "security",
    ],
    "insider_threat": [
        "user", "file access", "email", "usb", "cloud", "copy", "delete", "print", "clipboard",
        "rrp", "storage", "exfil",
    ],
    "malware": [
        "malware", "persistence", "anti-forensic", "event log", "antivirus", "phishing",
        "scheduled", "startup", "registry",
    ],
    "data_exfiltration": [
        "exfil", "cloud", "email", "usb", "network", "sync", "copy", "upload", "torrent",
        "rrp", "storage", "whatsapp",
    ],
    "data_leakage": [
        "exfil", "cloud", "email", "usb", "network", "sync", "copy", "upload", "rrp", "storage",
    ],
    "email_investigation": [
        "email", "outlook", "eml", "webmail", "attachment", "account",
    ],
    "mobile_forensic": [
        "mobile", "message", "chat", "whatsapp", "signal", "location", "android", "ios",
    ],
    "policy_violation": [
        "user", "login", "malware", "phishing", "pornography", "installed", "usb", "chat",
        "network", "registry", "event log", "email", "policy",
    ],
}

_ALIASES = {
    "general": "general_computer_forensic",
    "data_leakage": "data_exfiltration",
    "malware_incident": "malware",
}


def _norm_report_type(report_type: str | None) -> str:
    rt = (report_type or "general_computer_forensic").strip().lower()
    return _ALIASES.get(rt, rt)


def _norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _load_all_objectives(db: Session) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()

    try:
        catalog = get_axiom_objectives_catalog(db)
        for section in catalog.get("sections") or []:
            for row in section.get("items") or []:
                oid = str(row.get("key") or "")
                if not oid or oid in seen:
                    continue
                seen.add(oid)
                items.append({
                    "id": oid,
                    "title": row.get("label") or oid,
                    "objective": row.get("statement") or "",
                    "procedure": row.get("procedure_title") or "",
                    "procedure_text": row.get("detailed_procedure") or row.get("procedure_prompt") or "",
                    "domain": row.get("domain") or section.get("title") or "",
                    "priority": row.get("priority"),
                    "critical": bool(row.get("critical")),
                    "prompt_question": row.get("prompt_question"),
                    "source": "axiom",
                })
    except Exception:
        pass

    for idx, obj in enumerate(REPORT_OBJECTIVES):
        title = obj.get("title") or ""
        from app.services.report_template_service import _REPORT_TITLE_AXIOM_OBJECTIVE_ID

        if title.strip() in _REPORT_TITLE_AXIOM_OBJECTIVE_ID:
            continue
        if _norm_text(title) in {_norm_text(i["title"]) for i in items}:
            continue
        oid = f"RPT-O{idx + 1:03d}"
        if oid in seen:
            continue
        seen.add(oid)
        items.append({
            "id": oid,
            "title": title,
            "objective": obj.get("statement") or "",
            "procedure": obj.get("procedure") or "",
            "procedure_text": obj.get("procedure") or "",
            "domain": obj.get("domain") or "Aetheris Report Template",
            "priority": "core",
            "critical": True,
            "prompt_question": None,
            "source": "report_template",
        })

    return items


def _score_objective(obj: dict[str, Any], keywords: list[str]) -> int:
    blob = _norm_text(f"{obj.get('title')} {obj.get('objective')} {obj.get('domain')}")
    score = 0
    for kw in keywords:
        if kw in blob:
            score += 2
    if obj.get("critical"):
        score += 1
    return score


def list_report_types(db: Session | None = None) -> list[dict[str, Any]]:
    if db is not None:
        try:
            from app.services.case_type_catalog_service import load_report_type_templates

            items = load_report_type_templates(db)
            if items:
                return items
        except Exception:
            pass
    return list(REPORT_TYPES)


def list_objectives_for_report_type(db: Session, report_type: str | None) -> dict[str, Any]:
    from app.services.report_template_service import (
        list_all_catalog_objectives,
        list_template_objectives,
        normalize_report_type_id,
        purge_duplicate_report_objectives,
        _norm_title,
    )

    rt = normalize_report_type_id(report_type)
    purge_duplicate_report_objectives(db, rt)
    template_rows = list_template_objectives(db, rt)
    template_titles = {_norm_title(r["title"]) for r in template_rows}

    all_catalog = list_all_catalog_objectives(db)
    catalog_by_title = {_norm_title(r["title"]): r for r in all_catalog}

    recommended_ids: list[str] = []
    seen_rec: set[str] = set()
    for row in template_rows:
        title_key = _norm_title(row["title"])
        catalog_row = catalog_by_title.get(title_key) or row
        oid = str(catalog_row.get("id") or catalog_row.get("objective_id"))
        if oid in seen_rec:
            continue
        seen_rec.add(oid)
        recommended_ids.append(oid)

    recommended_set = set(recommended_ids)
    template_order = {_norm_title(r["title"]): idx for idx, r in enumerate(template_rows)}

    api_items: list[dict[str, Any]] = []
    for r in all_catalog:
        oid = str(r.get("id") or r.get("objective_id"))
        title_key = _norm_title(r["title"])
        in_template = title_key in template_titles
        api_items.append({
            "id": oid,
            "title": r["title"],
            "objective": r.get("objective") or r.get("statement") or "",
            "recommended": oid in recommended_set or in_template,
            "in_template": in_template,
            "report_type": rt,
            "procedure": r.get("procedure_text") or r.get("procedure") or "",
            "procedure_text": r.get("procedure_text") or r.get("procedure") or "",
            "evidence_prompt": r.get("evidence_prompt") or "",
            "axiom_objective_id": r.get("axiom_objective_id") or "",
            "domain": "Report Template" if in_template else "Catalog",
            "evidence_questions": [],
        })

    api_items.sort(
        key=lambda x: (
            0 if x["in_template"] else 1,
            template_order.get(_norm_title(x["title"]), 9999),
            _norm_title(x["title"]),
        )
    )
    return {"items": api_items, "report_type": rt, "recommended_ids": recommended_ids}


def resolve_intake_objectives(db: Session, intake: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve selected intake objective IDs + custom objectives to full records."""
    import json

    ids = intake.get("objective_ids") or []
    if isinstance(ids, str):
        ids = json.loads(ids)
    custom = intake.get("custom_objectives") or []
    if isinstance(custom, str):
        custom = json.loads(custom)

    from app.services.report_template_service import (
        list_all_catalog_objectives,
        normalize_report_type_id,
        resolve_catalog_objective_id,
        _norm_title,
    )

    report_type = normalize_report_type_id(intake.get("report_type"))
    ids = [resolve_catalog_objective_id(db, str(x), report_type) for x in ids]
    catalog_rows = list_all_catalog_objectives(db)
    by_id = {
        str(r.get("objective_id") or r.get("id")): {
            "id": str(r.get("objective_id") or r.get("id")),
            "title": r.get("title") or "",
            "objective": r.get("objective") or r.get("statement") or "",
            "procedure_text": r.get("procedure_text") or r.get("procedure") or "",
            "procedure": r.get("procedure_text") or r.get("procedure") or "",
            "evidence_prompt": r.get("evidence_prompt") or "",
            "axiom_objective_id": r.get("axiom_objective_id") or "",
            "source": "reports_objective",
        }
        for r in catalog_rows
    }
    by_title = {_norm_title(str(r.get("title") or "")): by_id[str(r.get("objective_id") or r.get("id"))] for r in catalog_rows if r.get("title")}
    by_axiom: dict[str, dict[str, Any]] = {}
    for r in catalog_rows:
        axiom_id = str(r.get("axiom_objective_id") or "").strip()
        if axiom_id and axiom_id not in by_axiom:
            by_axiom[axiom_id] = by_id[str(r.get("objective_id") or r.get("id"))]

    out: list[dict[str, Any]] = []
    for raw_id in ids:
        oid = str(raw_id)
        base = by_id.get(oid)
        if not base:
            base = by_axiom.get(oid)
        if not base:
            title = None
            from app.services.report_template_service import _axiom_id_to_report_title

            mapped_title = _axiom_id_to_report_title(oid, report_type)
            if mapped_title:
                base = by_title.get(_norm_title(mapped_title))
        if base:
            out.append(dict(base))
        else:
            out.append({"id": oid, "title": oid, "objective": "", "procedure_text": ""})

    for idx, row in enumerate(custom):
        if not isinstance(row, dict):
            continue
        title = (row.get("title") or "").strip()
        if not title:
            continue
        proc = row.get("procedure")
        if isinstance(proc, list):
            proc_text = "\n".join(str(p) for p in proc if p)
        else:
            proc_text = str(row.get("procedure") or row.get("objective") or "")
        out.append({
            "id": f"custom-{idx + 1}",
            "title": title,
            "objective": row.get("objective") or "",
            "procedure_text": proc_text,
            "source": "custom",
        })

    return out
