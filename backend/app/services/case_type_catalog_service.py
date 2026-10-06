"""Case type and report-type template catalog — DB-backed with Python fallback."""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone
from app.services.report_objectives_service import REPORT_TYPES

_ALIASES = {
    "general": "general_computer_forensic",
    "data_leakage": "data_exfiltration",
    "malware_incident": "malware",
}


def _norm_id(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (value or "").strip().lower()).strip("_")


def _table_exists(db: Session, table: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 FROM information_schema.tables
           WHERE table_schema = 'public' AND table_name = :t LIMIT 1""",
        {"t": table},
    )
    return bool(row)


def load_report_type_templates(db: Session) -> list[dict[str, Any]]:
    if not _table_exists(db, "report_type_templates"):
        return []
    rows = fetchall(
        db,
        """SELECT report_type_id, label, domain, description, default_os, sort_order
           FROM public.report_type_templates
           ORDER BY sort_order, label""",
    )
    if not rows:
        return []
    return [
        {
            "id": r["report_type_id"],
            "label": r["label"],
            "domain": r.get("domain"),
            "default_os": list(r.get("default_os") or []),
            "description": r.get("description"),
        }
        for r in rows
    ]


def load_case_types(db: Session) -> list[dict[str, Any]]:
    if not _table_exists(db, "case_types"):
        return _fallback_case_types()
    rows = fetchall(
        db,
        """SELECT ct.case_type_id, ct.label, ct.description, ct.platforms, ct.sort_order,
                  ct.default_report_type_id,
                  rt.label AS default_report_type_label
           FROM public.case_types ct
           LEFT JOIN public.report_type_templates rt
             ON rt.report_type_id = ct.default_report_type_id
           ORDER BY ct.sort_order, ct.label""",
    )
    if not rows:
        return _fallback_case_types()
    return [
        {
            "id": r["case_type_id"],
            "label": r["label"],
            "description": r.get("description"),
            "platforms": list(r.get("platforms") or []),
            "default_report_type_id": r.get("default_report_type_id"),
            "default_report_type_label": r.get("default_report_type_label"),
        }
        for r in rows
    ]


def _fallback_case_types() -> list[dict[str, Any]]:
    mapping = [
        ("general_computer_forensic", "General Computer Forensic", "general_computer_forensic"),
        ("data_leakage", "Data Leakage / Exfiltration", "data_exfiltration"),
        ("insider_threat", "Insider Threat", "insider_threat"),
        ("malware_incident", "Malware / Security Incident", "malware"),
        ("email_investigation", "Email Investigation", "email_investigation"),
        ("mobile_device", "Mobile Device Examination", "mobile_forensic"),
    ]
    labels = {t["id"]: t["label"] for t in REPORT_TYPES}
    return [
        {
            "id": cid,
            "label": label,
            "description": None,
            "platforms": [],
            "default_report_type_id": rt,
            "default_report_type_label": labels.get(rt),
        }
        for cid, label, rt in mapping
    ]


def resolve_case_type(db: Session, case_type: str | None) -> dict[str, Any] | None:
    raw = (case_type or "").strip()
    if not raw:
        return None
    norm = _norm_id(raw)
    if _table_exists(db, "case_types"):
        row = fetchone(
            db,
            """SELECT case_type_id, label, default_report_type_id
               FROM public.case_types
               WHERE case_type_id = :id OR lower(label) = lower(:label)
               LIMIT 1""",
            {"id": norm, "label": raw},
        )
        if row:
            return dict(row)
    for item in _fallback_case_types():
        if item["id"] == norm or item["label"].lower() == raw.lower():
            return {
                "case_type_id": item["id"],
                "label": item["label"],
                "default_report_type_id": item["default_report_type_id"],
            }
    return {"case_type_id": norm, "label": raw, "default_report_type_id": None}


def validate_case_type(db: Session, case_type: str | None) -> dict[str, Any] | None:
    return resolve_case_type(db, case_type)


def default_report_type_for_case(db: Session, case_type: str | None) -> str | None:
    resolved = resolve_case_type(db, case_type)
    if not resolved:
        return None
    rt = resolved.get("default_report_type_id")
    if rt:
        return _ALIASES.get(str(rt), str(rt))
    return None


def mandatory_area_codes(db: Session, report_type_id: str) -> list[str]:
    rt = _ALIASES.get(report_type_id, report_type_id)
    if not _table_exists(db, "report_type_mandatory_areas"):
        return []
    rows = fetchall(
        db,
        """SELECT area_code FROM public.report_type_mandatory_areas
           WHERE report_type_id = :rt ORDER BY sort_order""",
        {"rt": rt},
    )
    return [str(r["area_code"]) for r in rows if r.get("area_code")]
