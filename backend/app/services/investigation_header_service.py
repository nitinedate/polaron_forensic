"""Investigation-area mapping and scope suggestions (PDF §4–5)."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone
from app.services.case_type_catalog_service import mandatory_area_codes, resolve_case_type


def _table_exists(db: Session, table: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 FROM information_schema.tables
           WHERE table_schema = 'public' AND table_name = :t LIMIT 1""",
        {"t": table},
    )
    return bool(row)


def load_investigation_areas(db: Session) -> list[dict[str, Any]]:
    if not _table_exists(db, "investigation_area_templates"):
        return _fallback_areas()
    rows = fetchall(
        db,
        """SELECT area_code, header_title, description, default_objective_id, sort_order
           FROM public.investigation_area_templates
           ORDER BY sort_order, header_title""",
    )
    if not rows:
        return _fallback_areas()
    return [dict(r) for r in rows]


def _fallback_areas() -> list[dict[str, Any]]:
    return [
        {"area_code": "USB_EXTERNAL_DEVICES", "header_title": "USB and External Device Usage"},
        {"area_code": "FILE_ACCESS_HANDLING", "header_title": "File Access and Handling"},
        {"area_code": "EMAIL_ACTIVITY", "header_title": "Email Activity"},
        {"area_code": "COMMUNICATION_MESSAGING", "header_title": "Communication and Messaging"},
    ]


def artifact_ids_for_areas(db: Session, area_codes: set[str]) -> list[str]:
    if not area_codes or not _table_exists(db, "artifact_investigation_area_map"):
        return []
    rows = fetchall(
        db,
        """SELECT artifact_id FROM public.artifact_investigation_area_map
           WHERE area_code = ANY(:codes)""",
        {"codes": list(area_codes)},
    )
    return [str(r["artifact_id"]) for r in rows if r.get("artifact_id")]


def areas_for_artifact_ids(db: Session, artifact_ids: set[str]) -> dict[str, list[str]]:
    if not artifact_ids or not _table_exists(db, "artifact_investigation_area_map"):
        return {}
    rows = fetchall(
        db,
        """SELECT m.artifact_id, m.area_code, t.header_title
           FROM public.artifact_investigation_area_map m
           JOIN public.investigation_area_templates t ON t.area_code = m.area_code
           WHERE m.artifact_id = ANY(:ids)""",
        {"ids": list(artifact_ids)},
    )
    out: dict[str, list[str]] = {}
    for row in rows:
        aid = str(row["artifact_id"])
        out.setdefault(aid, []).append(str(row["area_code"]))
    return out


def _inventory_nonzero(db: Session, job_id: str) -> dict[str, int]:
    rows = fetchall(
        db,
        """SELECT artifact_id, COALESCE(occurrence_count, artifact_count, 0) AS cnt
           FROM job_axiom_artifact_results
           WHERE job_id = :jid AND status = 'done'""",
        {"jid": job_id},
    )
    return {str(r["artifact_id"]): int(r["cnt"] or 0) for r in rows if int(r["cnt"] or 0) > 0}


def suggest_investigation_scope(
    db: Session,
    job_id: str,
    *,
    case_type: str | None = None,
    report_type: str | None = None,
    intake_allegations: str | None = None,
) -> dict[str, Any]:
    """Recommend investigation headers, artifact keys, and objective IDs from catalog mapping."""
    nonzero = _inventory_nonzero(db, job_id)
    present_ids = set(nonzero.keys())

    area_codes: set[str] = set()
    if report_type:
        area_codes.update(mandatory_area_codes(db, report_type))

    mapped = areas_for_artifact_ids(db, present_ids)
    for codes in mapped.values():
        area_codes.update(codes)

    blob = (intake_allegations or "").lower()
    if "usb" in blob or "external" in blob:
        area_codes.add("USB_EXTERNAL_DEVICES")
    if "email" in blob or "outlook" in blob:
        area_codes.add("EMAIL_ACTIVITY")
    if "exfil" in blob or "leak" in blob or "upload" in blob:
        area_codes.add("DATA_EXFILTRATION")
    if "malware" in blob or "ransom" in blob:
        area_codes.add("MALWARE_SECURITY")

    areas = load_investigation_areas(db)
    area_by_code = {a["area_code"]: a for a in areas}
    recommended_headers = [
        {
            "area_code": code,
            "header_title": area_by_code.get(code, {}).get("header_title") or code.replace("_", " ").title(),
            "mandatory": code in set(mandatory_area_codes(db, report_type or "")),
        }
        for code in sorted(area_codes)
        if code in area_by_code or code
    ]

    artifact_keys = artifact_ids_for_areas(db, area_codes)
    if not artifact_keys:
        artifact_keys = list(present_ids)

    enabled_artifact_keys = [aid for aid in artifact_keys if aid in present_ids or aid in artifact_keys]

    objective_ids: list[str] = []
    for header in recommended_headers:
        obj_id = area_by_code.get(header["area_code"], {}).get("default_objective_id")
        if obj_id:
            objective_ids.append(str(obj_id))

    case = resolve_case_type(db, case_type)
    return {
        "case_type": case,
        "report_type": report_type,
        "recommended_headers": recommended_headers,
        "recommended_artifact_ids": sorted(set(enabled_artifact_keys)),
        "recommended_objective_ids": sorted(set(objective_ids)),
        "nonzero_artifact_count": len(nonzero),
    }


def persist_scope_suggestion(db: Session, job_id: str, suggestion: dict[str, Any]) -> None:
    """Store latest suggestion on artifact_scope for analyst review."""
    from app.db.sql_helpers import execute

    payload = json.dumps({
        "investigation_scope_suggestion": {
            "headers": suggestion.get("recommended_headers"),
            "artifact_ids": suggestion.get("recommended_artifact_ids"),
            "objective_ids": suggestion.get("recommended_objective_ids"),
        }
    })
    row = fetchone(db, "SELECT sections FROM artifact_scope WHERE job_id=:jid", {"jid": job_id})
    if row:
        execute(
            db,
            """UPDATE artifact_scope SET sections = sections, updated_at = NOW()
               WHERE job_id = :jid""",
            {"jid": job_id},
        )
    _ = payload  # reserved for future artifact_scope metadata column
