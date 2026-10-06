"""Report-type template catalog (reports_artifacts / reports_objective) and per-job selections."""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.report_objectives_service import _norm_report_type

# Histotechlab / Ex-5 — data leakage report (Section C, 19 objectives)
_HISTOTECHLAB_OBJECTIVE_TITLES: list[str] = [
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
]

# Seger RRP / Mr. Seger — policy violation report (Section C, 8 objectives)
_SEGER_POLICY_OBJECTIVE_TITLES: list[str] = [
    "Access to Cloud Storage Services",
    "Connection of External Hard Disks",
    "Use of WhatsApp Web and Download of RRP Files",
    "Deleted Files Found in Recycle Bin",
    "Presence of Encrypted Files",
    "Email Accounts Used on the Laptop",
    "Storage of Email Login Details in Notepad",
    "Storage of RRP-Related Documents on Personal Laptop",
]

# Both reference PDFs use the full Aetheris Section B artifact catalog (9 groups).
_EMAIL_ARTIFACT_NAMES: list[tuple[str, str]] = [
    ("Email & Calendar", "Email Attachments"),
    ("Email & Calendar", "EML(X) Files"),
    ("Email & Calendar", "Windows Mail"),
    ("Email & Calendar", "Outlook Emails"),
    ("Email & Calendar", "Outlook Tasks"),
    ("Email & Calendar", "Outlook Contacts"),
    ("Email & Calendar", "Outlook Appointments"),
    ("Communication", "Web Chat URLs"),
    ("Documents", "Microsoft Word Documents"),
    ("Documents", "PDF Documents"),
    ("Operating System", "LNK Files"),
    ("Operating System", "Jump List"),
    ("Operating System", "Logfile Analysis"),
]

_INCIDENT_OBJECTIVE_TITLES: list[str] = [
    "User Accounts & Login Activity",
    "File Access and Handling",
    "Network Connections",
    "Registry Analysis",
    "Scheduled Tasks & Startup Items",
    "Antivirus & Patch Status",
    "Event Logs & Timeline Reconstruction",
    "Anti-Forensic Tools or Cleanup Attempts",
    "Malware, Phishing and Pornography URLs",
]

_INSIDER_OBJECTIVE_TITLES: list[str] = [
    "User Accounts & Login Activity",
    "File Access and Handling",
    "USB and External Device Usage",
    "Network Connections",
    "Email Artifacts (Local Clients)",
    "Chat / Communication Apps",
    "Data Sync Clients",
    "Access to Cloud Storage Services",
    "Deleted Files Found in Recycle Bin",
    "Presence of Encrypted Files",
]

_MALWARE_OBJECTIVE_TITLES: list[str] = [
    "Malware, Phishing and Pornography URLs",
    "Antivirus & Patch Status",
    "Registry Analysis",
    "Scheduled Tasks & Startup Items",
    "Event Logs & Timeline Reconstruction",
    "Anti-Forensic Tools or Cleanup Attempts",
    "Installed Applications & Tools",
    "Network Connections",
]

_EMAIL_OBJECTIVE_TITLES: list[str] = [
    "Email Artifacts (Local Clients)",
    "Email Accounts Used on the Laptop",
    "File Access and Handling",
    "Chat / Communication Apps",
]

_CLOUD_OBJECTIVE_TITLES: list[str] = [
    "Access to Cloud Storage Services",
    "Data Sync Clients",
    "Network Connections",
    "USB and External Device Usage",
    "File Access and Handling",
    "Email Artifacts (Local Clients)",
]

_REPORT_TYPE_ALIASES: dict[str, str] = {
    "data_leakage": "data_exfiltration",
    "general": "general_computer_forensic",
}


def _full_template_artifact_names() -> list[tuple[str, str]]:
    from app.services.report_catalog_sync import REPORT_ARTIFACTS

    return [(a["category"], a["name"]) for a in REPORT_ARTIFACTS]


def _report_template_specs() -> dict[str, dict[str, Any]]:
    from app.services.mobile_report_catalog import (
        MOBILE_FORENSIC_ARTIFACTS,
        MOBILE_FORENSIC_ARTIFACTS_IOS,
        MOBILE_FORENSIC_OBJECTIVE_TITLES,
    )

    full_arts = _full_template_artifact_names()
    histo_objs = _HISTOTECHLAB_OBJECTIVE_TITLES
    return {
        # PDF: Ex-5 Histotechlab1 — data leakage
        "data_exfiltration": {"artifacts": full_arts, "objectives": histo_objs},
        "data_leakage": {"artifacts": full_arts, "objectives": histo_objs},
        # PDF: RRP Mr. Seger — policy violation (workplace misconduct)
        "policy_violation": {
            "artifacts": full_arts,
            "objectives": _SEGER_POLICY_OBJECTIVE_TITLES,
        },
        "general_computer_forensic": {"artifacts": full_arts, "objectives": histo_objs},
        "general": {"artifacts": full_arts, "objectives": histo_objs},
        "incident_response": {"artifacts": full_arts, "objectives": _INCIDENT_OBJECTIVE_TITLES},
        "insider_threat": {"artifacts": full_arts, "objectives": _INSIDER_OBJECTIVE_TITLES},
        "malware": {"artifacts": full_arts, "objectives": _MALWARE_OBJECTIVE_TITLES},
        "email_investigation": {"artifacts": _EMAIL_ARTIFACT_NAMES, "objectives": _EMAIL_OBJECTIVE_TITLES},
        "cloud_forensic": {"artifacts": full_arts, "objectives": _CLOUD_OBJECTIVE_TITLES},
        "mobile_forensic": {
            "artifacts": list(MOBILE_FORENSIC_ARTIFACTS),
            "artifacts_by_platform": {
                "Android": list(MOBILE_FORENSIC_ARTIFACTS),
                "iOS": list(MOBILE_FORENSIC_ARTIFACTS_IOS),
            },
            "objectives": list(MOBILE_FORENSIC_OBJECTIVE_TITLES),
            "platform": "Android",
        },
    }


def normalize_report_type_id(report_type: str | None) -> str:
    rt = _norm_report_type(report_type)
    return _REPORT_TYPE_ALIASES.get(rt, rt)


def _norm_title(s: str) -> str:
    t = re.sub(r"\s+", " ", (s or "").strip().lower())
    t = t.replace("&", " and ")
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _objective_dedupe_key(row: dict[str, Any]) -> str:
    """Stable dedupe key — one row per report section title."""
    norm = _norm_title(str(row.get("title") or ""))
    if norm:
        return f"title:{norm}"
    oid = str(row.get("objective_id") or row.get("id") or "").strip().upper()
    if oid:
        return f"id:{oid}"
    return "title:"


def _is_detailed_procedure_text(procedure_text: str | None) -> bool:
    text = str(procedure_text or "").strip()
    if len(text) < 180:
        return False
    return (
        text.startswith("1")
        or text.startswith("Examination approach")
        or "AXIOM examination procedure" in text
        or "How to check / find evidence" in text
    )


def _objective_row_score(r: dict[str, Any]) -> tuple[int, int, int, int]:
    oid = str(r.get("objective_id") or r.get("id") or "")
    proc = str(r.get("procedure_text") or r.get("procedure") or "")
    obj_len = len(str(r.get("objective") or r.get("statement") or ""))
    rpt = 0 if _is_report_template_objective_id(oid) else 1
    # Prefer substantial narrative+AXIOM procedures over one-liner stubs.
    stub = 0 if _is_detailed_procedure_text(proc) else 1
    return (rpt, stub, -len(proc), -obj_len)


_REPORT_TEMPLATE_OBJECTIVE_ID_BASE = 901


def _is_legacy_objective_id(objective_id: str | None) -> bool:
    oid = str(objective_id or "").strip().upper()
    return oid.startswith("RPT-")


def _is_report_template_objective_id(objective_id: str | None) -> bool:
    oid = str(objective_id or "").strip().upper()
    if not oid.startswith("RPT-O"):
        return False
    match = re.fullmatch(r"RPT-O(\d+)", oid)
    if not match:
        return False
    num = int(match.group(1))
    return num >= _REPORT_TEMPLATE_OBJECTIVE_ID_BASE


def _report_objective_catalog_entry(
    title: str,
    db: Session | None = None,
) -> dict[str, Any] | None:
    """Title-specific objective statement; procedure prefers AXIOM detailed_procedure when db given."""
    from app.services.report_catalog_sync import REPORT_OBJECTIVES
    from app.services.report_objective_procedures import procedure_for_title

    norm = _norm_title(title)
    for idx, item in enumerate(REPORT_OBJECTIVES):
        if _norm_title(item.get("title") or "") != norm:
            continue
        display_title = (item.get("title") or "").strip()
        axiom_id = _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get(display_title)
        fallback = procedure_for_title(display_title, fallback=str(item.get("procedure") or ""))
        if db is not None:
            procedure = resolve_axiom_procedure_for_title(
                db,
                display_title,
                axiom_objective_id=axiom_id,
                fallback=fallback,
            )
        else:
            # Offline/unit path: keep synthetic fallback until seed with DB.
            from app.services.report_objective_procedures import enrich_axiom_procedure_for_title

            procedure = enrich_axiom_procedure_for_title(display_title, fallback)
        return {
            "objective_id": f"RPT-O{_REPORT_TEMPLATE_OBJECTIVE_ID_BASE + idx:03d}",
            "title": display_title,
            "statement": (item.get("statement") or "").strip(),
            "procedure_text": procedure.strip(),
            "axiom_objective_id": axiom_id,
        }
    return None


def artifact_lookup_objective_id(
    objective: dict[str, Any],
    db: Session | None = None,
) -> str:
    """AXIOM workbook id used to link artifacts — may differ from per-title report objective id."""
    axiom_id = str(objective.get("axiom_objective_id") or "").strip()
    if axiom_id:
        return axiom_id
    title = str(objective.get("title") or "").strip()
    mapped = _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get(title)
    if mapped:
        return mapped
    oid = str(objective.get("id") or objective.get("objective_id") or "").strip()
    if oid and not _is_legacy_objective_id(oid):
        return oid
    if db is not None and _is_legacy_objective_id(oid):
        resolved = canonical_objective_id(db, oid)
        if resolved and not _is_legacy_objective_id(resolved):
            return resolved
    return oid


def purge_legacy_report_objectives(db: Session) -> int:
    """Remove shared AXIOM O-* rows superseded by per-title RPT-O9xx template objectives."""
    row = fetchone(
        db,
        """SELECT count(*) AS c FROM public.reports_objective ro
           WHERE ro.objective_id NOT LIKE 'RPT-%'
             AND EXISTS (
               SELECT 1 FROM public.reports_objective keeper
               WHERE keeper.report_type_id = ro.report_type_id
                 AND lower(trim(keeper.title)) = lower(trim(ro.title))
                 AND keeper.objective_id LIKE 'RPT-O%'
             )""",
        {},
    )
    execute(
        db,
        """DELETE FROM public.reports_objective ro
           WHERE ro.objective_id NOT LIKE 'RPT-%'
             AND EXISTS (
               SELECT 1 FROM public.reports_objective keeper
               WHERE keeper.report_type_id = ro.report_type_id
                 AND lower(trim(keeper.title)) = lower(trim(ro.title))
                 AND keeper.objective_id LIKE 'RPT-O%'
             )""",
        {},
    )
    db.flush()
    return int((row or {}).get("c") or 0)


def dedupe_objective_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one row per report section title — prefer per-title RPT template rows."""
    by_key: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for row in rows:
        key = _objective_dedupe_key(row)
        if not key or key == "title:":
            continue
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = row
            order.append(key)
            continue
        if _objective_row_score(row) < _objective_row_score(existing):
            by_key[key] = row

    return [by_key[k] for k in order]


def _procedure_starts_with_one(procedure_text: str | None) -> bool:
    return str(procedure_text or "").lstrip().startswith("1")


def _pick_report_objective_keeper(group: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer per-title RPT template row, then longest title-specific procedure."""
    rpt_rows = [
        r for r in group
        if _is_report_template_objective_id(str(r.get("objective_id") or ""))
    ]
    if rpt_rows:
        return min(rpt_rows, key=_objective_row_score)
    return min(group, key=_objective_row_score)


def purge_duplicate_report_objectives(db: Session, report_type_id: str | None = None) -> dict[str, Any]:
    """Keep one objective per (report_type, title): numbered procedure (1.) wins over legacy short rows."""
    sql = """SELECT report_type_id, objective_id, title, objective, procedure_text
             FROM public.reports_objective"""
    params: dict[str, Any] = {}
    if report_type_id:
        sql += " WHERE report_type_id = :rt"
        params["rt"] = normalize_report_type_id(report_type_id)
    rows = fetchall(db, sql, params)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        rt = str(row["report_type_id"])
        title_key = _norm_title(str(row.get("title") or ""))
        if not title_key:
            continue
        grouped.setdefault((rt, title_key), []).append(dict(row))

    removed_rows: list[dict[str, Any]] = []
    for (_rt, _title), group in grouped.items():
        if len(group) <= 1:
            continue
        keeper = _pick_report_objective_keeper(group)
        keeper_id = str(keeper["objective_id"])
        rt = str(keeper["report_type_id"])
        for row in group:
            oid = str(row["objective_id"])
            if oid == keeper_id:
                continue
            execute(
                db,
                """DELETE FROM public.reports_objective
                   WHERE report_type_id = :rt AND objective_id = :oid""",
                {"rt": rt, "oid": oid},
            )
            removed_rows.append(row)

    legacy_removed = fetchone(
        db,
        """WITH doomed AS (
               SELECT ro.report_type_id, ro.objective_id
               FROM public.reports_objective ro
               WHERE ro.objective_id NOT LIKE 'RPT-%'
                 AND EXISTS (
                   SELECT 1 FROM public.reports_objective keeper
                   WHERE keeper.report_type_id = ro.report_type_id
                     AND lower(trim(keeper.title)) = lower(trim(ro.title))
                     AND keeper.objective_id LIKE 'RPT-O%'
                 )
           )
           SELECT count(*) AS c FROM doomed""",
        {},
    ) or {}
    execute(
        db,
        """DELETE FROM public.reports_objective ro
           WHERE ro.objective_id NOT LIKE 'RPT-%'
             AND EXISTS (
               SELECT 1 FROM public.reports_objective keeper
               WHERE keeper.report_type_id = ro.report_type_id
                 AND lower(trim(keeper.title)) = lower(trim(ro.title))
                 AND keeper.objective_id LIKE 'RPT-O%'
             )""",
        {},
    )

    if removed_rows:
        db.flush()
    legacy_count = int(legacy_removed.get("c") or 0)
    if legacy_count:
        db.flush()
    return {
        "deleted": len(removed_rows) + int(legacy_removed.get("c") or 0),
        "duplicate_title_rows": len(removed_rows),
        "legacy_rpt_rows": int(legacy_removed.get("c") or 0),
        "rows": [
            {
                "report_type_id": str(r["report_type_id"]),
                "objective_id": str(r["objective_id"]),
                "title": str(r.get("title") or ""),
                "procedure_preview": str(r.get("procedure_text") or "")[:80],
            }
            for r in removed_rows
        ],
    }


def dedupe_objectives_for_display(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One tile per title — prefer per-title RPT template row over shared AXIOM workbook text."""
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def score(it: dict[str, Any]) -> tuple[int, int, int]:
        proc = str(it.get("procedure_text") or it.get("procedure") or "")
        oid = str(it.get("id") or it.get("objective_id") or "")
        rpt = 0 if _is_report_template_objective_id(oid) else 1
        generic_axiom = 1 if _procedure_starts_with_one(proc) else 0
        return (rpt, generic_axiom, -len(proc))

    for item in items:
        key = _norm_title(str(item.get("title") or ""))
        if not key:
            continue
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = item
            order.append(key)
            continue
        if score(item) < score(existing):
            grouped[key] = item
    return [grouped[k] for k in order]


def purge_all_job_objective_storage(db: Session) -> dict[str, Any]:
    """Clear per-job objective/procedure/observation selections across all firm schemas."""
    totals = {
        "firm_schemas": 0,
        "observations_deleted": 0,
        "selections_deleted": 0,
        "scope_deleted": 0,
        "intake_rows_cleared": 0,
    }
    firm_rows = fetchall(
        db,
        "SELECT schema_name FROM public.firms WHERE status = 'active' AND schema_name IS NOT NULL",
        {},
    )
    for firm in firm_rows:
        schema = str(firm["schema_name"])
        try:
            obs = fetchone(
                db,
                f'SELECT count(*) AS c FROM "{schema}".job_objective_observations',
                {},
            ) or {}
            execute(db, f'DELETE FROM "{schema}".job_objective_observations')
            sel = fetchone(
                db,
                f'SELECT count(*) AS c FROM "{schema}".selected_job_objectives_procedure',
                {},
            ) or {}
            execute(db, f'DELETE FROM "{schema}".selected_job_objectives_procedure')
            scope = fetchone(
                db,
                f'SELECT count(*) AS c FROM "{schema}".objective_procedure_scope',
                {},
            ) or {}
            execute(db, f'DELETE FROM "{schema}".objective_procedure_scope')
            intake = fetchone(
                db,
                f'SELECT count(*) AS c FROM "{schema}".case_intake',
                {},
            ) or {}
            execute(
                db,
                f"""UPDATE "{schema}".case_intake
                    SET objective_ids='[]'::jsonb,
                        custom_objectives='[]'::jsonb,
                        updated_at=NOW()""",
            )
            totals["firm_schemas"] += 1
            totals["observations_deleted"] += int(obs.get("c") or 0)
            totals["selections_deleted"] += int(sel.get("c") or 0)
            totals["scope_deleted"] += int(scope.get("c") or 0)
            totals["intake_rows_cleared"] += int(intake.get("c") or 0)
        except Exception:
            continue
    db.flush()
    return totals


def reset_objectives_catalog_and_jobs(db: Session) -> dict[str, Any]:
    """Reseed reports_objective from AXIOM, purge duplicate titles, clear all job storage."""
    catalog = reseed_reports_objective_axiom_only(db)
    purged = purge_duplicate_report_objectives(db)
    jobs = purge_all_job_objective_storage(db)
    db.flush()
    return {"catalog": catalog, "purged": purged, "jobs": jobs}


def purge_duplicate_objectives_without_numbered_procedure(db: Session) -> dict[str, Any]:
    """Delete duplicate-title rows whose procedure_text does not start with '1'."""
    return purge_duplicate_report_objectives(db)


def list_all_catalog_objectives(db: Session) -> list[dict[str, Any]]:
    """All unique report objectives (one row per title, prefer per-title RPT template)."""
    rows = fetchall(
        db,
        """SELECT DISTINCT ON (lower(trim(title)))
                  objective_id, title, objective, procedure_text, evidence_prompt,
                  required_observation_fields, expected_output_fields, axiom_objective_id,
                  sort_order
           FROM public.reports_objective
           ORDER BY lower(trim(title)),
                    CASE WHEN objective_id LIKE 'RPT-O%' THEN 0 ELSE 1 END,
                    CASE WHEN trim(coalesce(procedure_text, '')) ~ '^1' THEN 1 ELSE 0 END,
                    length(coalesce(procedure_text, '')) DESC,
                    sort_order,
                    objective_id""",
        {},
    )
    return dedupe_objectives_for_display([
        {
            **dict(r),
            "id": str(r.get("objective_id")),
            "statement": r.get("objective") or "",
            "procedure": r.get("procedure_text") or "",
            "axiom_objective_id": r.get("axiom_objective_id"),
            "source": "reports_objective",
        }
        for r in dedupe_objective_rows([dict(r) for r in rows])
    ])


def _reports_objective_list_sql(*, report_type_id: str) -> tuple[str, dict[str, Any]]:
    """One row per title — prefer per-title RPT template objective."""
    sql = """SELECT DISTINCT ON (lower(trim(ro.title)))
                    ro.objective_id, ro.title, ro.objective, ro.procedure_text, ro.evidence_prompt,
                    ro.required_observation_fields, ro.expected_output_fields, ro.axiom_objective_id,
                    ro.sort_order, ro.default_enabled
             FROM public.reports_objective ro
             WHERE ro.report_type_id = :rt
             ORDER BY lower(trim(ro.title)),
                      CASE WHEN ro.objective_id LIKE 'RPT-O%' THEN 0 ELSE 1 END,
                      CASE WHEN trim(coalesce(ro.procedure_text, '')) ~ '^1' THEN 1 ELSE 0 END,
                      length(coalesce(ro.procedure_text, '')) DESC,
                      ro.sort_order,
                      ro.objective_id"""
    return sql, {"rt": report_type_id}


def canonical_objective_id(db: Session, objective_id: str) -> str:
    """Map legacy intake ids to AXIOM workbook ids for artifact linking."""
    oid = str(objective_id or "").strip()
    if not _is_legacy_objective_id(oid):
        return oid

    title: str | None = None
    match = re.fullmatch(r"RPT-O(\d+)", oid.upper())
    if match:
        from app.services.report_catalog_sync import REPORT_OBJECTIVES

        num = int(match.group(1))
        if num >= _REPORT_TEMPLATE_OBJECTIVE_ID_BASE:
            idx = num - _REPORT_TEMPLATE_OBJECTIVE_ID_BASE
        else:
            idx = num - 1
        if 0 <= idx < len(REPORT_OBJECTIVES):
            title = (REPORT_OBJECTIVES[idx].get("title") or "").strip() or None

    if not title and db is not None:
        row = fetchone(
            db,
            "SELECT title FROM public.reports_objective WHERE objective_id = :oid LIMIT 1",
            {"oid": oid},
        )
        if row:
            title = (row.get("title") or "").strip() or None
    if not title and db is not None:
        row = fetchone(
            db,
            "SELECT title FROM public.axiom_objectives WHERE objective_id = :oid",
            {"oid": oid},
        )
        if row:
            title = (row.get("title") or "").strip() or None

    if title:
        mapped = _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get(title)
        if mapped:
            return mapped
    return oid


def _axiom_id_to_report_title(axiom_id: str, report_type: str | None = None) -> str | None:
    """Map an AXIOM workbook objective id to a report section title."""
    aid = str(axiom_id or "").strip()
    if not aid:
        return None
    candidates = [title for title, mapped in _REPORT_TITLE_AXIOM_OBJECTIVE_ID.items() if mapped == aid]
    if not candidates:
        return None
    if report_type:
        rt = normalize_report_type_id(report_type)
        template_titles = set(_report_template_specs().get(rt, {}).get("objectives") or [])
        for title in candidates:
            if title in template_titles:
                return title
    return candidates[0]


def resolve_catalog_objective_id(
    db: Session,
    objective_id: str,
    report_type: str | None = None,
) -> str:
    """Resolve any legacy id to the per-title reports_objective row id (RPT-O9xx)."""
    oid = str(objective_id or "").strip()
    if not oid:
        return oid
    rt = normalize_report_type_id(report_type) if report_type else None

    row = fetchone(
        db,
        "SELECT objective_id FROM public.reports_objective WHERE objective_id = :oid LIMIT 1",
        {"oid": oid},
    )
    if row:
        return str(row["objective_id"])

    if rt:
        row = fetchone(
            db,
            """SELECT objective_id FROM public.reports_objective
               WHERE report_type_id = :rt AND axiom_objective_id = :axiom
               ORDER BY CASE WHEN objective_id LIKE 'RPT-O%' THEN 0 ELSE 1 END
               LIMIT 1""",
            {"rt": rt, "axiom": oid},
        )
        if row:
            return str(row["objective_id"])

    title: str | None = None
    match = re.fullmatch(r"RPT-O(\d+)", oid.upper())
    if match:
        from app.services.report_catalog_sync import REPORT_OBJECTIVES

        num = int(match.group(1))
        if num >= _REPORT_TEMPLATE_OBJECTIVE_ID_BASE:
            idx = num - _REPORT_TEMPLATE_OBJECTIVE_ID_BASE
        else:
            idx = num - 1
        if 0 <= idx < len(REPORT_OBJECTIVES):
            title = (REPORT_OBJECTIVES[idx].get("title") or "").strip() or None

    if not title:
        axiom_id = canonical_objective_id(db, oid)
        title = _axiom_id_to_report_title(axiom_id or oid, report_type)

    if title:
        if rt:
            row = fetchone(
                db,
                """SELECT objective_id FROM public.reports_objective
                   WHERE report_type_id = :rt AND lower(trim(title)) = lower(trim(:title))
                   ORDER BY CASE WHEN objective_id LIKE 'RPT-O%' THEN 0 ELSE 1 END
                   LIMIT 1""",
                {"rt": rt, "title": title},
            )
            if row:
                return str(row["objective_id"])
        entry = _report_objective_catalog_entry(title)
        if entry:
            return entry["objective_id"]
        row = fetchone(
            db,
            """SELECT objective_id FROM public.reports_objective
               WHERE lower(trim(title)) = lower(trim(:title))
               ORDER BY CASE WHEN objective_id LIKE 'RPT-O%' THEN 0 ELSE 1 END
               LIMIT 1""",
            {"title": title},
        )
        if row:
            return str(row["objective_id"])
    return oid


def canonical_objective_ids(db: Session, objective_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in objective_ids or []:
        cid = canonical_objective_id(db, str(raw))
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


# Report Section C titles → Magnet AXIOM workbook objective IDs (detailed statement + procedure).
# Prefer unique AXIOM IDs per title so procedure_text differs; shared IDs still get a title-scope step.
_REPORT_TITLE_AXIOM_OBJECTIVE_ID: dict[str, str] = {
    "User Accounts & Login Activity": "O016",
    "File Access and Handling": "O022",
    "USB and External Device Usage": "O065",
    "Network Connections": "O072",
    "Installed Applications & Tools": "O011",
    "Registry Analysis": "O018",
    "Scheduled Tasks & Startup Items": "O018",
    "Antivirus & Patch Status": "O079",
    "Event Logs & Timeline Reconstruction": "O007",
    "Email Artifacts (Local Clients)": "O045",
    "Clipboard & Print Activity": "O019",
    "Virtual Machines or Sandbox Use": "O020",
    "Chat / Communication Apps": "O043",
    "Hidden Partitions / Alternate Data Streams (ADS)": "O030",
    "Anti-Forensic Tools or Cleanup Attempts": "O076",
    "Data Sync Clients": "O067",
    "Shadow Copies & Backup Artifacts": "O020",
    "Detection of Torrent Activity": "O087",
    "Malware, Phishing and Pornography URLs": "O077",
    "Access to Cloud Storage Services": "O059",
    "Connection of External Hard Disks": "O089",
    "Use of WhatsApp Web and Download of RRP Files": "O048",
    "Deleted Files Found in Recycle Bin": "O024",
    "Presence of Encrypted Files": "O075",
    "Email Accounts Used on the Laptop": "O074",
    "Storage of Email Login Details in Notepad": "O056",
    "Storage of RRP-Related Documents on Personal Laptop": "O028",
}

# Merge mobile title → AXIOM objective map.
from app.services.mobile_report_catalog import MOBILE_TITLE_AXIOM_OBJECTIVE_ID  # noqa: E402

_REPORT_TITLE_AXIOM_OBJECTIVE_ID.update(MOBILE_TITLE_AXIOM_OBJECTIVE_ID)


def _fetch_axiom_objective_detail(db: Session, objective_id: str) -> dict[str, Any] | None:
    if not objective_id or str(objective_id).startswith("RPT-"):
        return None
    row = fetchone(
        db,
        """SELECT o.objective_id, o.title, o.statement, o.required_observation_fields,
                  o.minimum_corroboration, o.limitations, o.priority,
                  p.detailed_procedure, p.expected_output_fields, p.title AS procedure_title
           FROM public.axiom_objectives o
           LEFT JOIN public.axiom_procedures p ON p.procedure_id = o.procedure_id
           WHERE o.objective_id = :oid
             AND o.objective_id NOT LIKE 'RPT-%'""",
        {"oid": objective_id},
    )
    if not row:
        return None
    proc = (row.get("detailed_procedure") or "").strip()
    if not proc:
        proc = (row.get("statement") or "").strip()
    return {
        "objective_id": str(row["objective_id"]),
        "title": row.get("title") or "",
        "statement": (row.get("statement") or "").strip(),
        "procedure_text": proc,
        "required_observation_fields": row.get("required_observation_fields"),
        "minimum_corroboration": row.get("minimum_corroboration"),
        "limitations": row.get("limitations"),
        "priority": row.get("priority"),
        "expected_output_fields": row.get("expected_output_fields"),
        "source": "axiom",
    }


def resolve_axiom_procedure_for_title(
    db: Session | None,
    title: str,
    *,
    axiom_objective_id: str | None = None,
    fallback: str = "",
) -> str:
    """Load AXIOM detailed_procedure for the title's mapped objective, then title-scope + OCR enrich."""
    from app.services.report_objective_procedures import enrich_axiom_procedure_for_title, procedure_for_title

    display = (title or "").strip()
    axiom_id = (axiom_objective_id or _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get(display) or "").strip()
    axiom_proc = ""
    if db is not None and axiom_id:
        detail = _fetch_axiom_objective_detail(db, axiom_id)
        axiom_proc = str((detail or {}).get("procedure_text") or "").strip()
    if not axiom_proc and db is not None and display:
        # Fallback: best AXIOM title match when mapping missing.
        row = fetchone(
            db,
            """SELECT p.detailed_procedure
               FROM public.axiom_objectives o
               LEFT JOIN public.axiom_procedures p ON p.procedure_id = o.procedure_id
               WHERE o.objective_id NOT LIKE 'RPT-%'
                 AND lower(trim(o.title)) = lower(trim(:title))
               ORDER BY length(coalesce(p.detailed_procedure, '')) DESC
               LIMIT 1""",
            {"title": display},
        )
        axiom_proc = str((row or {}).get("detailed_procedure") or "").strip()
    if not axiom_proc:
        axiom_proc = (fallback or procedure_for_title(display)).strip()
    if not axiom_proc:
        return ""
    return enrich_axiom_procedure_for_title(display, axiom_proc)


def _build_evidence_prompt_for_header(
    header_title: str,
    detail: dict[str, Any],
    *,
    report_type: str | None = None,
    db: Session | None = None,
) -> str:
    from app.services.report_objective_evidence import (
        build_objective_evidence_prompt,
        list_catalog_artifacts_for_objective,
    )

    axiom_id = detail.get("axiom_objective_id") or detail.get("objective_id")
    linked_artifacts: list[dict[str, str]] = []
    platform = "Android" if str(report_type or "").startswith("mobile") else "Windows"
    if db is not None and axiom_id:
        linked_artifacts = list_catalog_artifacts_for_objective(
            db,
            axiom_objective_id=str(axiom_id),
            header_title=header_title,
            platform=platform,
        )

    return build_objective_evidence_prompt(
        header_title=header_title,
        objective_statement=detail.get("statement") or detail.get("objective") or "",
        procedure_text=detail.get("procedure_text") or "",
        report_type=report_type,
        axiom_objective_id=str(axiom_id) if axiom_id else None,
        required_observation_fields=detail.get("required_observation_fields"),
        expected_output_fields=detail.get("expected_output_fields"),
        minimum_corroboration=detail.get("minimum_corroboration"),
        limitations=detail.get("limitations"),
        linked_artifacts=linked_artifacts,
    )


def _report_display_title(report_title: str, axiom_detail: dict[str, Any] | None) -> str:
    """Keep the report template section title; AXIOM title is often more technical."""
    return (report_title or "").strip() or (axiom_detail or {}).get("title") or ""


def enrich_objective_record(
    db: Session,
    record: dict[str, Any],
    *,
    report_title: str | None = None,
) -> dict[str, Any]:
    """Keep client-facing template prose, while syncing internal evidence requirements from AXIOM."""
    title = (report_title or record.get("title") or "").strip()
    stored_proc = (record.get("procedure_text") or record.get("procedure") or "").strip()
    stored_obj = (record.get("objective") or record.get("statement") or "").strip()
    stored_prompt = (record.get("evidence_prompt") or "").strip()
    oid = str(record.get("objective_id") or record.get("id") or "").strip()
    axiom_id = str(record.get("axiom_objective_id") or "").strip()
    if not axiom_id and title:
        axiom_id = _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get(title) or ""
    if not axiom_id and oid and not _is_legacy_objective_id(oid):
        axiom_id = oid

    # Always refresh the internal observation requirements from the live AXIOM catalog.
    # The report may keep a short client-facing Objective/Procedure, but the evidence
    # planner must use AXIOM's detailed procedure, required fields, expected outputs,
    # corroboration and limitations for every linked report objective.
    axiom_detail = _fetch_axiom_objective_detail(db, axiom_id) if axiom_id else None

    if stored_proc and stored_obj:
        evidence_prompt = stored_prompt
        if not evidence_prompt:
            evidence_prompt = _build_evidence_prompt_for_header(
                title,
                {
                    "statement": (axiom_detail or {}).get("statement") or stored_obj,
                    "procedure_text": (axiom_detail or {}).get("procedure_text") or stored_proc,
                    "axiom_objective_id": axiom_id,
                    "required_observation_fields": (axiom_detail or {}).get("required_observation_fields") or record.get("required_observation_fields"),
                    "expected_output_fields": (axiom_detail or {}).get("expected_output_fields") or record.get("expected_output_fields"),
                    "minimum_corroboration": (axiom_detail or {}).get("minimum_corroboration") or record.get("minimum_corroboration"),
                    "limitations": (axiom_detail or {}).get("limitations") or record.get("limitations"),
                },
                db=db,
            )
        from app.services.evidence_contract import (
            baseline_disk_evidence_contract,
            contract_to_evidence_prompt_section,
        )

        contract = record.get("evidence_contract")
        if not isinstance(contract, dict):
            contract = baseline_disk_evidence_contract(title)
        block = contract_to_evidence_prompt_section(contract)
        if evidence_prompt and "EVIDENCE CONTRACT" not in evidence_prompt:
            evidence_prompt = (evidence_prompt + "\n\n" + block).strip()
        elif not evidence_prompt:
            evidence_prompt = block
        return {
            **record,
            "id": oid or record.get("id"),
            "objective_id": oid or record.get("objective_id"),
            "axiom_objective_id": axiom_id or None,
            "title": title or record.get("title"),
            "objective": stored_obj,
            "statement": stored_obj,
            "procedure_text": stored_proc,
            "procedure": stored_proc,
            "evidence_prompt": evidence_prompt,
            "evidence_contract": contract,
            "required_observation_fields": (axiom_detail or {}).get("required_observation_fields") or record.get("required_observation_fields"),
            "expected_output_fields": (axiom_detail or {}).get("expected_output_fields") or record.get("expected_output_fields"),
            "minimum_corroboration": (axiom_detail or {}).get("minimum_corroboration") or record.get("minimum_corroboration"),
            "limitations": (axiom_detail or {}).get("limitations") or record.get("limitations"),
            "axiom_statement": (axiom_detail or {}).get("statement") or "",
            "axiom_procedure_text": (axiom_detail or {}).get("procedure_text") or "",
            "source": record.get("source") or "reports_objective",
        }

    entry = _report_objective_catalog_entry(title) if title else None
    if entry:
        entry_axiom_id = str(entry.get("axiom_objective_id") or axiom_id or "").strip()
        entry_axiom = axiom_detail
        if not entry_axiom and entry_axiom_id:
            entry_axiom = _fetch_axiom_objective_detail(db, entry_axiom_id)
        entry_axiom = entry_axiom or {}
        detail = {
            **entry,
            "required_observation_fields": entry_axiom.get("required_observation_fields") or record.get("required_observation_fields"),
            "expected_output_fields": entry_axiom.get("expected_output_fields") or record.get("expected_output_fields"),
            "minimum_corroboration": entry_axiom.get("minimum_corroboration") or record.get("minimum_corroboration"),
            "limitations": entry_axiom.get("limitations") or record.get("limitations"),
        }
        evidence_prompt = stored_prompt or _build_evidence_prompt_for_header(title, detail, db=db)
        return {
            **record,
            "id": entry["objective_id"],
            "objective_id": entry["objective_id"],
            "axiom_objective_id": entry_axiom_id or None,
            "title": entry["title"],
            "objective": entry["statement"],
            "statement": entry["statement"],
            "procedure_text": entry["procedure_text"],
            "procedure": entry["procedure_text"],
            "evidence_prompt": evidence_prompt,
            "required_observation_fields": detail.get("required_observation_fields"),
            "expected_output_fields": detail.get("expected_output_fields"),
            "minimum_corroboration": detail.get("minimum_corroboration"),
            "limitations": detail.get("limitations"),
            "axiom_statement": entry_axiom.get("statement") or "",
            "axiom_procedure_text": entry_axiom.get("procedure_text") or "",
            "source": "report_template",
        }

    if axiom_id:
        detail = axiom_detail or _fetch_axiom_objective_detail(db, axiom_id)
        if detail:
            display_title = _report_display_title(title, detail)
            evidence_prompt = stored_prompt or _build_evidence_prompt_for_header(
                display_title,
                {**detail, "axiom_objective_id": axiom_id},
                db=db,
            )
            return {
                **record,
                "id": oid or detail["objective_id"],
                "objective_id": oid or detail["objective_id"],
                "axiom_objective_id": axiom_id,
                "title": display_title,
                "objective": detail["statement"],
                "statement": detail["statement"],
                "procedure_text": detail["procedure_text"],
                "procedure": detail["procedure_text"],
                "evidence_prompt": evidence_prompt,
                "required_observation_fields": detail.get("required_observation_fields"),
                "expected_output_fields": detail.get("expected_output_fields"),
                "minimum_corroboration": detail.get("minimum_corroboration"),
                "limitations": detail.get("limitations"),
                "axiom_statement": detail.get("statement") or "",
                "axiom_procedure_text": detail.get("procedure_text") or "",
                "source": "axiom",
            }

    return {
        **record,
        "id": oid or record.get("id"),
        "objective_id": oid or record.get("objective_id"),
        "title": title or record.get("title"),
        "objective": stored_obj,
        "statement": stored_obj,
        "procedure_text": stored_proc,
        "procedure": stored_proc,
    }


def _lookup_artifact(db: Session, *, category: str, name: str, platform: str = "Windows") -> dict[str, Any] | None:
    row = fetchone(
        db,
        """SELECT artifact_id, category, artifact_name, observation_focus
           FROM public.axiom_artifacts
           WHERE platform = :platform AND artifact_name = :name
             AND (category = :category OR :category = '' OR category IS NULL)
           ORDER BY CASE WHEN category = :category THEN 0 ELSE 1 END
           LIMIT 1""",
        {"platform": platform, "name": name, "category": category},
    )
    if row:
        return dict(row)
    row = fetchone(
        db,
        """SELECT artifact_id, category, artifact_name, observation_focus
           FROM public.axiom_artifacts
           WHERE platform = :platform AND lower(trim(artifact_name)) = lower(trim(:name))
           ORDER BY sort_order
           LIMIT 1""",
        {"platform": platform, "name": name},
    )
    return dict(row) if row else None


def _ios_name_for_android_artifact(name: str) -> str:
    from app.services.mobile_report_catalog import ANDROID_TO_IOS_ARTIFACT_NAME

    name = (name or "").strip()
    if name in ANDROID_TO_IOS_ARTIFACT_NAME:
        return ANDROID_TO_IOS_ARTIFACT_NAME[name]
    if " - Android" in name:
        return name.replace(" - Android", " - iOS")
    if name.startswith("Android "):
        return "iOS " + name[len("Android ") :]
    return name


def remap_artifact_ids_to_platform(
    db: Session,
    artifact_ids: list[str],
    *,
    target_platform: str,
) -> list[str]:
    """Map selected AX-* ids onto the job platform (fixes Android defaults on iOS jobs)."""
    target = (target_platform or "").strip() or "Windows"
    out: list[str] = []
    seen: set[str] = set()
    for aid in artifact_ids:
        aid = str(aid or "").strip()
        if not aid:
            continue
        row = fetchone(
            db,
            """SELECT artifact_id, category, artifact_name, platform
               FROM public.axiom_artifacts WHERE artifact_id = :aid
               ORDER BY CASE WHEN platform = :p THEN 0 ELSE 1 END
               LIMIT 1""",
            {"aid": aid, "p": target},
        )
        if not row:
            continue
        src_platform = str(row.get("platform") or "")
        if src_platform == target:
            if aid not in seen:
                seen.add(aid)
                out.append(aid)
            continue
        name = str(row.get("artifact_name") or "")
        category = str(row.get("category") or "")
        candidates = [name]
        if src_platform.lower() == "android" and target.lower() == "ios":
            candidates = [_ios_name_for_android_artifact(name), name]
        elif src_platform.lower() == "ios" and target.lower() == "android":
            candidates = [
                name.replace(" - iOS", " - Android").replace("iOS ", "Android "),
                name,
            ]
        matched = None
        for cand in candidates:
            matched = _lookup_artifact(db, category=category, name=cand, platform=target)
            if matched:
                break
        if not matched:
            continue
        mid = str(matched["artifact_id"])
        if mid not in seen:
            seen.add(mid)
            out.append(mid)
    return out


def _lookup_objective_by_title(db: Session, title: str) -> dict[str, Any] | None:
    mapped_id = _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get((title or "").strip())
    if mapped_id:
        detail = _fetch_axiom_objective_detail(db, mapped_id)
        if detail:
            return detail

    row = fetchone(
        db,
        """SELECT o.objective_id, o.title, o.statement,
                  coalesce(nullif(btrim(p.detailed_procedure), ''), o.statement) AS procedure_text
           FROM public.axiom_objectives o
           LEFT JOIN public.axiom_procedures p ON p.procedure_id = o.procedure_id
           WHERE lower(trim(o.title)) = lower(trim(:title))
             AND o.objective_id NOT LIKE 'RPT-%'
           ORDER BY length(coalesce(p.detailed_procedure, '')) DESC
           LIMIT 1""",
        {"title": title},
    )
    if row:
        return dict(row)
    return None


def _insert_report_objective_row(
    db: Session,
    *,
    report_type_id: str,
    title: str,
    sort_order: int,
    default_enabled: bool = True,
) -> bool:
    """Insert one reports_objective row with AXIOM detailed procedure for this title."""
    entry = _report_objective_catalog_entry(title, db=db)
    if not entry:
        return False

    oid = entry["objective_id"]
    axiom_id = entry.get("axiom_objective_id")
    statement = entry["statement"]
    # Always resolve from AXIOM at seed time so DB does not keep synthetic stubs.
    procedure = resolve_axiom_procedure_for_title(
        db,
        title,
        axiom_objective_id=str(axiom_id) if axiom_id else None,
        fallback=str(entry.get("procedure_text") or ""),
    )

    axiom_detail = _fetch_axiom_objective_detail(db, axiom_id) if axiom_id else None
    evidence_prompt = _build_evidence_prompt_for_header(
        title,
        {
            "statement": statement,
            "procedure_text": procedure,
            "axiom_objective_id": axiom_id,
            "required_observation_fields": (axiom_detail or {}).get("required_observation_fields"),
            "expected_output_fields": (axiom_detail or {}).get("expected_output_fields"),
            "minimum_corroboration": (axiom_detail or {}).get("minimum_corroboration"),
            "limitations": (axiom_detail or {}).get("limitations"),
        },
        report_type=report_type_id,
        db=db,
    )

    execute(
        db,
        """DELETE FROM public.reports_objective
           WHERE report_type_id = :rt
             AND lower(trim(title)) = lower(trim(:title))
             AND objective_id <> :oid""",
        {"rt": report_type_id, "title": title, "oid": oid},
    )
    execute(
        db,
        """INSERT INTO public.reports_objective
           (report_type_id, objective_id, axiom_objective_id, title, objective, procedure_text,
            evidence_prompt, required_observation_fields, expected_output_fields,
            sort_order, default_enabled)
           VALUES (:rt, :oid, :axiom, :title, :obj, :proc, :ep, :rof, :eof, :sort, :enabled)
           ON CONFLICT (report_type_id, objective_id) DO UPDATE SET
             axiom_objective_id = EXCLUDED.axiom_objective_id,
             title = EXCLUDED.title,
             objective = EXCLUDED.objective,
             procedure_text = EXCLUDED.procedure_text,
             evidence_prompt = EXCLUDED.evidence_prompt,
             required_observation_fields = EXCLUDED.required_observation_fields,
             expected_output_fields = EXCLUDED.expected_output_fields,
             sort_order = EXCLUDED.sort_order,
             default_enabled = EXCLUDED.default_enabled,
             updated_at = NOW()""",
        {
            "rt": report_type_id,
            "oid": oid,
            "axiom": axiom_id,
            "title": title,
            "obj": statement,
            "proc": procedure,
            "ep": evidence_prompt[:12000],
            "rof": (axiom_detail or {}).get("required_observation_fields"),
            "eof": (axiom_detail or {}).get("expected_output_fields"),
            "sort": sort_order,
            "enabled": default_enabled,
        },
    )
    return True


def reseed_reports_objective_axiom_only(db: Session) -> dict[str, Any]:
    """Delete all reports_objective rows and re-insert from AXIOM for existing titles only."""
    from app.services.report_objective_evidence import ensure_reports_objective_evidence_columns

    ensure_reports_objective_evidence_columns(db)
    existing = fetchall(
        db,
        """SELECT report_type_id, title,
                  MIN(sort_order) AS sort_order,
                  BOOL_OR(default_enabled) AS default_enabled
           FROM public.reports_objective
           GROUP BY report_type_id, lower(trim(title)), title
           ORDER BY report_type_id, MIN(sort_order), title""",
        {},
    )
    if not existing:
        template_specs = _report_template_specs()
        for report_type_id, spec in template_specs.items():
            for sort, title in enumerate(spec.get("objectives") or [], 1):
                existing.append({
                    "report_type_id": report_type_id,
                    "title": title,
                    "sort_order": sort,
                    "default_enabled": True,
                })

    deleted = fetchone(db, "SELECT count(*) AS c FROM public.reports_objective", {}) or {}
    execute(db, "DELETE FROM public.reports_objective", {})
    db.flush()

    inserted = 0
    skipped: list[str] = []
    for row in existing:
        rt = str(row["report_type_id"])
        title = str(row["title"])
        sort_order = int(row.get("sort_order") or 0)
        default_enabled = bool(row.get("default_enabled", True))
        if _insert_report_objective_row(
            db,
            report_type_id=rt,
            title=title,
            sort_order=sort_order,
            default_enabled=default_enabled,
        ):
            inserted += 1
        else:
            skipped.append(f"{rt}:{title}")

    db.flush()
    purge_duplicate_report_objectives(db)
    return {
        "deleted": int(deleted.get("c") or 0),
        "inserted": inserted,
        "skipped": skipped,
    }


def seed_report_template_catalog(db: Session, *, platform: str = "Windows") -> dict[str, int]:
    from app.db.sql_helpers import rollback_aborted_transaction
    from app.services.report_catalog_sync import REPORT_ARTIFACTS, ensure_report_template_artifacts
    from app.services.report_objective_evidence import ensure_reports_objective_evidence_columns, sync_axiom_objective_prompt_questions

    ensure_reports_objective_evidence_columns(db)
    purge_legacy_report_objectives(db)
    try:
        with db.begin_nested():
            ensure_report_template_artifacts(db, platform=platform)
    except Exception:
        rollback_aborted_transaction(db)
        raise

    added_artifacts = 0
    added_objectives = 0
    skipped_artifacts: list[str] = []
    desc_by_name = {(a["category"], a["name"]): a.get("description") or "" for a in REPORT_ARTIFACTS}

    template_specs = _report_template_specs()
    for report_type_id, spec in template_specs.items():
        artifact_names: list[tuple[str, str]] = spec.get("artifacts") or []
        by_platform: dict[str, list[tuple[str, str]]] = spec.get("artifacts_by_platform") or {}
        objective_titles: list[str] = spec.get("objectives") or []
        type_platform = str(spec.get("platform") or platform or "Windows")
        seed_platforms: list[tuple[str, list[tuple[str, str]]]] = []
        if by_platform:
            for plat, names in by_platform.items():
                seed_platforms.append((str(plat), list(names or [])))
        else:
            seed_platforms.append((type_platform, list(artifact_names)))

        sort = 0
        for seed_platform, names in seed_platforms:
            for category, name in names:
                art = _lookup_artifact(db, category=category, name=name, platform=seed_platform)
                if not art and seed_platform != platform:
                    art = _lookup_artifact(db, category=category, name=name, platform=platform)
                if not art and seed_platform == "Android":
                    # Fall back to iOS twin name when Android row missing.
                    ios_name = _ios_name_for_android_artifact(name)
                    art = _lookup_artifact(db, category=category, name=ios_name, platform="iOS")
                if not art:
                    skipped_artifacts.append(f"{report_type_id}:{seed_platform}:{category}/{name}")
                    continue
                sort += 1
                execute(
                    db,
                    """INSERT INTO public.reports_artifacts
                       (report_type_id, artifact_id, category, artifact_name, description, sort_order, default_enabled)
                       VALUES (:rt, :aid, :cat, :name, :desc, :sort, TRUE)
                       ON CONFLICT (report_type_id, artifact_id) DO UPDATE SET
                         category = EXCLUDED.category,
                         artifact_name = EXCLUDED.artifact_name,
                         description = EXCLUDED.description,
                         sort_order = EXCLUDED.sort_order,
                         updated_at = NOW()""",
                    {
                        "rt": report_type_id,
                        "aid": art["artifact_id"],
                        "cat": art.get("category") or category,
                        "name": art.get("artifact_name") or name,
                        "desc": art.get("observation_focus") or desc_by_name.get((category, name), ""),
                        "sort": sort,
                    },
                )
                added_artifacts += 1

        sort = 0
        execute(
            db,
            "DELETE FROM public.reports_objective WHERE report_type_id = :rt",
            {"rt": report_type_id},
        )
        for title in objective_titles:
            sort += 1
            if not _insert_report_objective_row(
                db,
                report_type_id=report_type_id,
                title=title,
                sort_order=sort,
                default_enabled=True,
            ):
                continue
            added_objectives += 1

    sync_axiom_objective_prompt_questions(db)
    purge_duplicate_report_objectives(db)
    db.flush()
    return {
        "artifacts": added_artifacts,
        "objectives": added_objectives,
        "skipped_artifacts": skipped_artifacts,
    }


def reset_report_template_catalog(
    db: Session,
    *,
    platform: str = "Windows",
    clear_job_selections: bool = True,
) -> dict[str, Any]:
    """Delete all report template rows and per-job frozen selections, then re-seed from AXIOM."""
    deleted_artifacts = fetchone(
        db, "SELECT count(*) AS c FROM public.reports_artifacts", {},
    )
    deleted_objectives = fetchone(
        db, "SELECT count(*) AS c FROM public.reports_objective", {},
    )
    execute(db, "DELETE FROM public.reports_artifacts")
    execute(db, "DELETE FROM public.reports_objective")
    purge_legacy_report_objectives(db)

    cleared_jobs = 0
    if clear_job_selections:
        firm_rows = fetchall(
            db,
            "SELECT schema_name FROM public.firms WHERE status = 'active' AND schema_name IS NOT NULL",
            {},
        )
        for firm in firm_rows:
            schema = firm["schema_name"]
            try:
                execute(db, f'DELETE FROM "{schema}".selected_job_artifacts')
                execute(db, f'DELETE FROM "{schema}".selected_job_objectives_procedure')
                cleared_jobs += 1
            except Exception:
                continue

    seed_result = seed_report_template_catalog(db, platform=platform)
    db.flush()
    return {
        "deleted_artifacts": int((deleted_artifacts or {}).get("c") or 0),
        "deleted_objectives": int((deleted_objectives or {}).get("c") or 0),
        "cleared_firm_schemas": cleared_jobs,
        "seed": seed_result,
    }


def list_template_artifacts(db: Session, report_type: str | None, *, platform: str = "Windows") -> list[dict[str, Any]]:
    rt = normalize_report_type_id(report_type)
    seed_report_template_catalog(db, platform=platform)
    rows = fetchall(
        db,
        """SELECT ra.artifact_id, ra.category, ra.artifact_name, ra.description, ra.sort_order,
                  ra.default_enabled, aa.platform, aa.recovery_method, aa.critical,
                  aa.primary_objective_id, aa.mapping_note
           FROM public.reports_artifacts ra
           LEFT JOIN public.axiom_artifacts aa
             ON aa.artifact_id = ra.artifact_id AND aa.platform = :platform
           WHERE ra.report_type_id = :rt
           ORDER BY ra.sort_order, ra.artifact_name""",
        {"rt": rt, "platform": platform},
    )
    return [dict(r) for r in rows]


def get_report_artifact_mapping(
    db: Session,
    *,
    report_type: str | None = None,
    platform: str = "Windows",
) -> dict[str, Any]:
    """Report type → AXIOM group (category) → artifact name, joined to axiom_artifacts."""
    seed_report_template_catalog(db, platform=platform)
    rt_filter = normalize_report_type_id(report_type) if report_type else None

    params: dict[str, Any] = {"platform": platform}
    type_clause = ""
    if rt_filter:
        type_clause = "AND ra.report_type_id = :rt"
        params["rt"] = rt_filter

    rows = fetchall(
        db,
        f"""SELECT rt.report_type_id, rt.label AS report_name, rt.domain AS report_domain,
                   ra.category AS group_name, ra.artifact_name, ra.artifact_id,
                   ra.description AS report_description, ra.sort_order, ra.default_enabled,
                   aa.platform AS axiom_platform, aa.category AS axiom_category,
                   aa.artifact_name AS axiom_artifact_name, aa.recovery_method,
                   aa.critical AS axiom_critical, aa.primary_objective_id,
                   aa.mapping_note, aa.prompt_question AS axiom_prompt_question
            FROM public.reports_artifacts ra
            JOIN public.report_type_templates rt ON rt.report_type_id = ra.report_type_id
            LEFT JOIN public.axiom_artifacts aa
              ON aa.artifact_id = ra.artifact_id AND aa.platform = :platform
            WHERE 1=1 {type_clause}
            ORDER BY rt.sort_order, ra.category, ra.sort_order, ra.artifact_name""",
        params,
    )

    by_report: dict[str, dict[str, Any]] = {}
    unmapped_axiom: list[dict[str, Any]] = []
    for row in rows:
        rt_id = str(row["report_type_id"])
        if rt_id not in by_report:
            by_report[rt_id] = {
                "report_type_id": rt_id,
                "report_name": row.get("report_name"),
                "report_domain": row.get("report_domain"),
                "groups": {},
            }
        group = str(row.get("group_name") or row.get("axiom_category") or "Other")
        groups = by_report[rt_id]["groups"]
        if group not in groups:
            groups[group] = {"category": group, "artifacts": []}
        axiom_id = row.get("artifact_id")
        axiom_joined = bool(row.get("axiom_platform"))
        if axiom_id and not axiom_joined:
            unmapped_axiom.append({
                "report_type_id": rt_id,
                "artifact_id": axiom_id,
                "artifact_name": row.get("artifact_name"),
                "group_name": group,
            })
        groups[group]["artifacts"].append({
            "artifact_id": axiom_id,
            "artifact_name": row.get("artifact_name") or row.get("axiom_artifact_name"),
            "axiom_category": row.get("axiom_category") or group,
            "report_description": row.get("report_description"),
            "recovery_method": row.get("recovery_method"),
            "critical": bool(row.get("axiom_critical")),
            "primary_objective_id": row.get("primary_objective_id"),
            "mapping_note": row.get("mapping_note"),
            "default_enabled": bool(row.get("default_enabled")),
            "sort_order": int(row.get("sort_order") or 0),
            "axiom_matched": axiom_joined,
            "prompt_question": row.get("axiom_prompt_question"),
        })

    report_types = []
    for rt_id in sorted(by_report.keys(), key=lambda x: (by_report[x].get("report_name") or x)):
        entry = by_report[rt_id]
        groups_list = []
        for cat in sorted(entry["groups"].keys()):
            g = entry["groups"][cat]
            g["artifacts"].sort(key=lambda a: (a.get("sort_order") or 0, a.get("artifact_name") or ""))
            groups_list.append(g)
        report_types.append({
            "report_type_id": entry["report_type_id"],
            "report_name": entry["report_name"],
            "report_domain": entry["report_domain"],
            "groups": groups_list,
            "artifact_count": sum(len(g["artifacts"]) for g in groups_list),
        })

    return {
        "platform": platform,
        "report_type_filter": rt_filter,
        "report_types": report_types,
        "unmapped_template_artifact_ids": unmapped_axiom,
    }


def list_axiom_artifacts_by_group(
    db: Session,
    *,
    platform: str = "Windows",
    category: str | None = None,
) -> list[dict[str, Any]]:
    """Full AXIOM catalog grouped by category — for building report template mappings."""
    sql = """SELECT artifact_id, category, artifact_name, recovery_method, critical,
                    primary_objective_id, observation_focus, mapping_note
             FROM public.axiom_artifacts
             WHERE platform = :platform"""
    params: dict[str, Any] = {"platform": platform}
    if category:
        sql += " AND category = :cat"
        params["cat"] = category
    sql += " ORDER BY category, sort_order, artifact_name"
    return [dict(r) for r in fetchall(db, sql, params)]


def list_template_objectives(db: Session, report_type: str | None) -> list[dict[str, Any]]:
    rt = normalize_report_type_id(report_type)
    seed_report_template_catalog(db)
    purge_duplicate_report_objectives(db, rt)
    sql, params = _reports_objective_list_sql(report_type_id=rt)
    rows = fetchall(db, sql, params)
    deduped = dedupe_objective_rows([dict(r) for r in rows])
    return dedupe_objectives_for_display([
        {
            **dict(r),
            "id": str(r.get("objective_id")),
            "statement": r.get("objective") or "",
            "procedure": r.get("procedure_text") or "",
            "axiom_objective_id": r.get("axiom_objective_id"),
            "source": "reports_objective",
        }
        for r in deduped
    ])


def template_artifact_id_set(
    db: Session,
    report_type: str | None,
    *,
    platform: str = "Windows",
) -> set[str]:
    return {
        str(r["artifact_id"])
        for r in list_template_artifacts(db, report_type, platform=platform)
    }


def template_default_objective_ids(db: Session, report_type: str | None) -> list[str]:
    return [
        str(r["objective_id"])
        for r in list_template_objectives(db, report_type)
        if r.get("default_enabled")
    ]


def _intake_report_type(db: Session, job_id: str) -> str | None:
    row = fetchone(db, "SELECT report_type FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    return (row or {}).get("report_type")


def get_selected_job_artifacts(db: Session, job_id: str) -> dict[str, Any] | None:
    row = fetchone(
        db,
        """SELECT job_id, report_type_id, artifact_ids, artifacts_json, saved_at, updated_at
           FROM selected_job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    return dict(row) if row else None


def get_selected_job_objectives(db: Session, job_id: str) -> dict[str, Any] | None:
    row = fetchone(
        db,
        """SELECT job_id, report_type_id, objective_ids, custom_objectives, objectives_json,
                  saved_at, updated_at
           FROM selected_job_objectives_procedure WHERE job_id=:jid""",
        {"jid": job_id},
    )
    return dict(row) if row else None


def _artifact_snapshot(db: Session, artifact_ids: list[str], report_type: str | None) -> list[dict[str, Any]]:
    ids = [str(aid) for aid in artifact_ids if str(aid).strip()]
    if not ids:
        return []
    rows = fetchall(
        db,
        """SELECT ra.artifact_id, ra.category, ra.artifact_name, ra.description, ra.sort_order
           FROM public.reports_artifacts ra
           WHERE ra.report_type_id = :rt AND ra.artifact_id = ANY(:ids)
           ORDER BY ra.sort_order""",
        {"rt": normalize_report_type_id(report_type), "ids": ids},
    )
    out = [dict(r) for r in rows]
    if len(out) >= len(ids):
        return out
    found = {str(r["artifact_id"]) for r in out}
    missing = [aid for aid in ids if aid not in found]
    if missing:
        catalog = fetchall(
            db,
            """SELECT artifact_id, category, artifact_name, observation_focus AS description
               FROM public.axiom_artifacts WHERE artifact_id = ANY(:ids)""",
            {"ids": missing},
        )
        out.extend(dict(r) for r in catalog)
    return out


def purge_deselected_artifact_results(db: Session, job_id: str, keep_artifact_ids: list[str]) -> None:
    """Remove inventory rows for artifacts no longer selected for this job.

    Never wipe the full inventory when ``keep`` is empty — that erased AXIOM counts
    before mobile report generation and left Objectives with zero evidence.
    """
    keep = [str(a) for a in keep_artifact_ids if str(a).strip()]
    if not keep:
        return
    execute(
        db,
        """DELETE FROM job_axiom_artifact_results
           WHERE job_id=:jid AND NOT (artifact_id = ANY(:ids))""",
        {"jid": job_id, "ids": keep},
    )
    db.flush()


def purge_stale_job_observations(db: Session, job_id: str, keep_objective_ids: list[str]) -> None:
    """Remove generated observations for objectives no longer on the job."""
    keep = [str(o) for o in keep_objective_ids if str(o).strip()]
    if keep:
        execute(
            db,
            """DELETE FROM job_objective_observations
               WHERE job_id=:jid AND NOT (objective_id = ANY(:ids))""",
            {"jid": job_id, "ids": keep},
        )
    else:
        execute(db, "DELETE FROM job_objective_observations WHERE job_id=:jid", {"jid": job_id})
    db.flush()


def objective_ids_from_snapshot(snapshot: list[dict[str, Any]]) -> list[str]:
    return [
        str(obj.get("id") or obj.get("objective_id") or "")
        for obj in snapshot
        if str(obj.get("id") or obj.get("objective_id") or "").strip()
    ]


def save_selected_job_artifacts(
    db: Session,
    job_id: str,
    artifact_ids: list[str],
    *,
    report_type: str | None = None,
    sync_scope: bool = True,
) -> dict[str, Any]:
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    report_type = normalize_report_type_id(report_type or _intake_report_type(db, job_id))
    platform = resolve_job_axiom_platform(db, job_id) or "Windows"
    clean_ids = remap_artifact_ids_to_platform(
        db,
        [str(a) for a in artifact_ids if str(a).strip()],
        target_platform=platform,
    )
    if not clean_ids:
        # Fall back to raw ids only when remapping found nothing (non-mobile / unknown).
        clean_ids = [str(a) for a in artifact_ids if str(a).strip()]
    snapshot = _artifact_snapshot(db, clean_ids, report_type)
    execute(db, "DELETE FROM selected_job_artifacts WHERE job_id=:jid", {"jid": job_id})
    execute(
        db,
        """INSERT INTO selected_job_artifacts
           (job_id, report_type_id, artifact_ids, artifacts_json, saved_at, updated_at)
           VALUES (:jid, :rt, CAST(:ids AS jsonb), CAST(:snap AS jsonb), NOW(), NOW())""",
        {
            "jid": job_id,
            "rt": report_type,
            "ids": json.dumps(clean_ids),
            "snap": json.dumps(snapshot),
        },
    )
    purge_deselected_artifact_results(db, job_id, clean_ids)
    if sync_scope:
        _sync_artifact_scope_keys(db, job_id, clean_ids)
    db.flush()
    return get_selected_job_artifacts(db, job_id) or {}


def _sync_artifact_scope_keys(db: Session, job_id: str, keys: list[str]) -> None:
    """Keep artifact_scope + job groups aligned with report artifact selection."""
    import json

    from app.services.artifact_group_service import resolve_artifact_scope
    from app.services.artifact_selection_catalog import get_selection_artifact_catalog, resolve_job_axiom_platform

    execute(
        db,
        """INSERT INTO artifact_scope (job_id, sections) VALUES (:jid, CAST(:s AS jsonb))
           ON CONFLICT (job_id) DO UPDATE SET sections=EXCLUDED.sections, updated_at=NOW()""",
        {"jid": job_id, "s": json.dumps(keys)},
    )
    platform = resolve_job_axiom_platform(db, job_id)
    catalog = get_selection_artifact_catalog(db, platform=platform, job_id=job_id)
    resolve_artifact_scope(
        db,
        job_id,
        catalog,
        stored_enabled=keys,
        persist=True,
        allow_zero_count=True,
    )


def _objective_records_for_ids(
    db: Session,
    report_type: str | None,
    objective_ids: list[str],
    custom_objectives: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rt = normalize_report_type_id(report_type)
    _, by_id, by_title, by_axiom = _template_objective_indexes(db, rt)
    out: list[dict[str, Any]] = []
    for oid in objective_ids:
        row = resolve_objective_to_template_row(db, str(oid), rt, by_id=by_id, by_title=by_title, by_axiom=by_axiom)
        if row:
            out.append(row)
        else:
            from app.services.report_generator_agent import hydrate_section_c_objective

            out.append(
                hydrate_section_c_objective(
                    {
                        "id": str(oid),
                        "objective_id": str(oid),
                        "title": str(oid),
                        "objective": "",
                        "procedure_text": "",
                        "source": "unknown",
                    },
                    db,
                )
            )
    for idx, row in enumerate(custom_objectives or []):
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
            "procedure": proc_text,
            "source": "custom",
        })
    return out


def _template_objective_indexes(
    db: Session,
    report_type: str | None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    rows = list_template_objectives(db, report_type)
    by_id = {str(r["objective_id"]): r for r in rows}
    by_title = {_norm_title(str(r.get("title") or "")): r for r in rows if r.get("title")}
    by_axiom: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        axiom_id = str(row.get("axiom_objective_id") or "").strip()
        if axiom_id:
            by_axiom.setdefault(axiom_id, []).append(row)
    return rows, by_id, by_title, by_axiom


def _objective_payload_from_template_row(
    row: dict[str, Any],
    overlay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "id": str(row.get("objective_id") or row.get("id") or ""),
        "objective_id": str(row.get("objective_id") or row.get("id") or ""),
        "title": row.get("title") or "",
        "objective": row.get("objective") or row.get("statement") or "",
        "procedure_text": row.get("procedure_text") or row.get("procedure") or "",
        "procedure": row.get("procedure_text") or row.get("procedure") or "",
        "evidence_prompt": row.get("evidence_prompt") or "",
        "axiom_objective_id": row.get("axiom_objective_id") or "",
        # Keep AXIOM observation/output requirements attached to the resolved
        # report objective. Dropping these fields caused the Observation agent to
        # fall back to broad artifact totals instead of answering the exact question.
        "required_observation_fields": row.get("required_observation_fields"),
        "expected_output_fields": row.get("expected_output_fields"),
        "minimum_corroboration": row.get("minimum_corroboration"),
        "limitations": row.get("limitations"),
        "axiom_statement": row.get("axiom_statement") or "",
        "axiom_procedure_text": row.get("axiom_procedure_text") or "",
        "source": row.get("source") or "report_template",
    }
    if overlay:
        template_proc = str(payload.get("procedure_text") or "")
        for key, value in overlay.items():
            if value is None or value == "":
                continue
            if key in {"id", "objective_id"}:
                continue
            # Intake snapshots often store the catalog key (RPT-O920) as title.
            # Never let that replace the printed question name.
            if key == "title" and re.fullmatch(r"RPT-O\d+", str(value).strip(), re.I):
                continue
            # Keep catalog detailed procedures; do not let stale snapshots overwrite them.
            if key in {"procedure", "procedure_text", "evidence_prompt", "objective", "statement"}:
                overlay_proc = str(value)
                if key in {"procedure", "procedure_text"}:
                    if _is_detailed_procedure_text(template_proc) and len(template_proc) >= len(overlay_proc):
                        continue
                elif key in {"evidence_prompt", "objective", "statement"} and payload.get(key):
                    continue
            payload[key] = value
        # Keep procedure aliases aligned after merge.
        proc = str(payload.get("procedure_text") or payload.get("procedure") or "")
        payload["procedure_text"] = proc
        payload["procedure"] = proc
    return payload


def resolve_objective_to_template_row(
    db: Session,
    objective_ref: str | dict[str, Any],
    report_type: str | None,
    *,
    by_id: dict[str, dict[str, Any]] | None = None,
    by_title: dict[str, dict[str, Any]] | None = None,
    by_axiom: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any] | None:
    """Map intake/snapshot objective refs (O*, RPT-O*, title) to a report-type template row."""
    if by_id is None or by_title is None or by_axiom is None:
        _, by_id, by_title, by_axiom = _template_objective_indexes(db, report_type)

    overlay: dict[str, Any] = {}
    if isinstance(objective_ref, dict):
        overlay = dict(objective_ref)
        oid = str(
            objective_ref.get("objective_id")
            or objective_ref.get("id")
            or objective_ref.get("axiom_objective_id")
            or ""
        ).strip()
        title_key = _norm_title(str(objective_ref.get("title") or ""))
    else:
        oid = str(objective_ref or "").strip()
        title_key = ""

    if oid and oid in by_id:
        return _objective_payload_from_template_row(by_id[oid], overlay)

    if title_key and title_key in by_title:
        return _objective_payload_from_template_row(by_title[title_key], overlay)

    if oid:
        axiom_id = canonical_objective_id(db, oid) if db is not None else oid
        for candidate in by_axiom.get(axiom_id, []) + by_axiom.get(oid, []):
            return _objective_payload_from_template_row(candidate, overlay)

        resolved = resolve_catalog_objective_id(db, oid, report_type) if db is not None else oid
        if resolved in by_id:
            return _objective_payload_from_template_row(by_id[resolved], overlay)

        title = _axiom_id_to_report_title(axiom_id or oid, report_type)
        if title:
            title_key = _norm_title(title)
            if title_key in by_title:
                return _objective_payload_from_template_row(by_title[title_key], overlay)

    if title_key and title_key in by_title:
        return _objective_payload_from_template_row(by_title[title_key], overlay)

    return None


def _resolve_objective_ids_for_template(
    db: Session,
    report_type: str | None,
    objective_ids: list[str],
) -> list[str]:
    _, by_id, by_title, by_axiom = _template_objective_indexes(db, report_type)
    clean: list[str] = []
    seen: set[str] = set()
    for raw in objective_ids or []:
        row = resolve_objective_to_template_row(db, str(raw), report_type, by_id=by_id, by_title=by_title, by_axiom=by_axiom)
        if not row:
            oid = str(raw).strip()
            if oid and oid not in seen:
                seen.add(oid)
                clean.append(oid)
            continue
        oid = str(row.get("objective_id") or row.get("id") or "")
        if oid and oid not in seen:
            seen.add(oid)
            clean.append(oid)
    return clean


def save_selected_job_objectives(
    db: Session,
    job_id: str,
    *,
    report_type: str | None = None,
    objective_ids: list[str] | None = None,
    custom_objectives: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    intake = fetchone(
        db,
        "SELECT report_type, objective_ids, custom_objectives FROM case_intake WHERE job_id=:jid",
        {"jid": job_id},
    ) or {}
    report_type = normalize_report_type_id(report_type or intake.get("report_type"))
    oids = objective_ids
    if oids is None:
        raw = intake.get("objective_ids") or []
        if isinstance(raw, str):
            raw = json.loads(raw)
        oids = [str(x) for x in raw]
    custom = custom_objectives
    if custom is None:
        raw = intake.get("custom_objectives") or []
        if isinstance(raw, str):
            raw = json.loads(raw)
        custom = raw if isinstance(raw, list) else []

    template_ids = {str(r["objective_id"]) for r in list_template_objectives(db, report_type)}
    clean_ids = _resolve_objective_ids_for_template(db, report_type, oids or [])
    if not clean_ids and template_ids and oids:
        clean_ids = [oid for oid in (oids or []) if oid in template_ids]
    snapshot = _objective_records_for_ids(db, report_type, clean_ids, custom)

    execute(db, "DELETE FROM selected_job_objectives_procedure WHERE job_id=:jid", {"jid": job_id})
    execute(
        db,
        """INSERT INTO selected_job_objectives_procedure
           (job_id, report_type_id, objective_ids, custom_objectives, objectives_json, saved_at, updated_at)
           VALUES (:jid, :rt, CAST(:oids AS jsonb), CAST(:custom AS jsonb), CAST(:snap AS jsonb), NOW(), NOW())""",
        {
            "jid": job_id,
            "rt": report_type,
            "oids": json.dumps(clean_ids),
            "custom": json.dumps(custom or []),
            "snap": json.dumps(snapshot),
        },
    )
    purge_stale_job_observations(db, job_id, objective_ids_from_snapshot(snapshot))
    db.flush()
    return get_selected_job_objectives(db, job_id) or {}


def resolve_report_artifact_keys(db: Session, job_id: str) -> set[str]:
    """Artifact keys for report generation — saved selection, then artifact_scope, then defaults."""
    from app.services.artifact_selection_catalog import resolve_job_axiom_platform

    report_type = normalize_report_type_id(_intake_report_type(db, job_id))
    platform = resolve_job_axiom_platform(db, job_id) or "Windows"
    template_ids = template_artifact_id_set(db, report_type, platform=platform)

    selected = get_selected_job_artifacts(db, job_id)
    if selected:
        raw = selected.get("artifact_ids") or []
        if isinstance(raw, str):
            raw = json.loads(raw)
        keys = {str(x) for x in raw if str(x).strip()}
        if keys:
            remapped = remap_artifact_ids_to_platform(db, sorted(keys), target_platform=platform)
            return set(remapped) if remapped else keys

    row = fetchone(db, "SELECT sections FROM artifact_scope WHERE job_id=:jid", {"jid": job_id})
    if row is not None:
        stored = row["sections"] if row else []
        if isinstance(stored, str):
            stored = json.loads(stored)
        if isinstance(stored, list) and (not stored or isinstance(stored[0], str)):
            scope_keys = {str(x) for x in stored if str(x).strip()}
            if scope_keys:
                remapped = remap_artifact_ids_to_platform(
                    db, sorted(scope_keys), target_platform=platform
                )
                return set(remapped) if remapped else scope_keys

    from app.services.artifact_export import artifact_scope_payload

    scope = artifact_scope_payload(db, job_id, read_only=True)
    scope_keys = {str(k) for k in (scope.get("enabled_keys") or []) if str(k).strip()}
    if scope_keys:
        remapped = remap_artifact_ids_to_platform(db, sorted(scope_keys), target_platform=platform)
        return set(remapped) if remapped else scope_keys
    if template_ids:
        return set(template_default_artifact_ids(db, report_type, platform=platform))
    return set()


def resolve_report_objectives(db: Session, job_id: str, intake: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if intake is None:
        intake = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id}) or {}
    report_type = normalize_report_type_id(intake.get("report_type"))
    _, by_id, by_title, by_axiom = _template_objective_indexes(db, report_type)

    def _is_custom(obj: dict[str, Any]) -> bool:
        src = str(obj.get("source") or "").lower()
        oid = str(obj.get("id") or obj.get("objective_id") or "")
        return src == "custom" or oid.startswith("custom-")

    def _custom_payload(obj: dict[str, Any]) -> dict[str, Any]:
        oid = str(obj.get("id") or obj.get("objective_id") or obj.get("title") or "custom")
        proc = obj.get("procedure_text") or obj.get("procedure") or ""
        if isinstance(proc, list):
            proc = "\n".join(str(p) for p in proc if p)
        return {
            "id": oid,
            "objective_id": oid,
            "title": obj.get("title") or oid,
            "objective": obj.get("objective") or obj.get("statement") or "",
            "procedure_text": str(proc),
            "procedure": str(proc),
            "source": "custom",
        }

    def _coerce_many(objectives: list[dict[str, Any]]) -> list[dict[str, Any]]:
        coerced: list[dict[str, Any]] = []
        seen: set[str] = set()
        for obj in objectives:
            if _is_custom(obj):
                row = _custom_payload(obj)
            else:
                row = resolve_objective_to_template_row(
                    db, obj, report_type, by_id=by_id, by_title=by_title, by_axiom=by_axiom
                )
                if not row:
                    from app.services.report_generator_agent import hydrate_section_c_objective

                    row = hydrate_section_c_objective(
                        {
                            "id": str(obj.get("id") or obj.get("objective_id") or ""),
                            "objective_id": str(obj.get("id") or obj.get("objective_id") or ""),
                            "title": str(obj.get("title") or obj.get("id") or ""),
                            "objective": obj.get("objective") or obj.get("statement") or "",
                            "procedure_text": obj.get("procedure_text") or obj.get("procedure") or "",
                            "axiom_objective_id": obj.get("axiom_objective_id") or "",
                            "source": obj.get("source") or "intake",
                        },
                        db,
                    )
            oid = str(row.get("objective_id") or row.get("id") or "")
            if not oid or oid in seen:
                continue
            seen.add(oid)
            coerced.append(row)
        return coerced

    selected = get_selected_job_objectives(db, job_id)
    snapshot_rows: list[dict[str, Any]] = []
    if selected and selected.get("objectives_json"):
        raw = selected["objectives_json"]
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, list) and raw:
            snapshot_rows = _coerce_many([dict(obj) for obj in raw if isinstance(obj, dict)])

    if not snapshot_rows and selected:
        raw_ids = selected.get("objective_ids") or []
        if isinstance(raw_ids, str):
            raw_ids = json.loads(raw_ids)
        custom = selected.get("custom_objectives") or []
        if isinstance(custom, str):
            custom = json.loads(custom)
        if raw_ids or custom:
            snapshot_rows = _coerce_many(
                _objective_records_for_ids(
                    db,
                    report_type,
                    [str(x) for x in (raw_ids or [])],
                    custom if isinstance(custom, list) else None,
                )
            )

    from app.services.report_objectives_service import resolve_intake_objectives
    from app.services.report_generator_agent import repair_section_c_objectives, sort_objectives_in_catalog_order

    intake_rows = _coerce_many(resolve_intake_objectives(db, intake))
    # Latest Case-intake selection wins: add, replace, and delete.
    chosen = intake_rows or snapshot_rows
    catalog = list_template_objectives(db, report_type)
    return repair_section_c_objectives(sort_objectives_in_catalog_order(chosen, catalog), db)


def template_default_artifact_ids(
    db: Session,
    report_type: str | None,
    *,
    platform: str = "Windows",
) -> list[str]:
    """Artifact ids marked default for this report type template (filtered by platform)."""
    return [
        str(r["artifact_id"])
        for r in list_template_artifacts(db, report_type, platform=platform)
        if r.get("default_enabled")
    ]


def apply_report_template_artifact_defaults(
    scope: dict[str, Any],
    template_artifact_ids: set[str],
) -> dict[str, Any]:
    """Mark template artifacts on the full catalog; do not hide non-template items."""
    if not template_artifact_ids:
        return scope

    def _sort_subs(subs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            subs,
            key=lambda s: (
                0 if s.get("key") in template_artifact_ids else 1,
                (s.get("label") or s.get("key") or "").lower(),
            ),
        )

    sections = []
    for section in scope.get("sections") or []:
        subs = [
            {**sub, "in_template": sub.get("key") in template_artifact_ids}
            for sub in section.get("subcategories") or []
        ]
        if not subs:
            continue
        subs = _sort_subs(subs)
        sections.append({
            **section,
            "subcategories": subs,
            "count": sum(int(s.get("count") or 0) for s in subs),
        })

    groups = []
    for group in scope.get("groups") or []:
        arts = [
            {
                **art,
                "in_template": (art.get("key") or art.get("artifact_id")) in template_artifact_ids,
            }
            for art in group.get("artifacts") or []
        ]
        groups.append({**group, "artifacts": arts})

    recommended = sorted(template_artifact_ids)
    return {
        **scope,
        "sections": sections,
        "groups": groups,
        "recommended_artifact_ids": recommended,
        "report_template_artifact_count": len(template_artifact_ids),
        "report_template_filtered": False,
    }


def filter_scope_to_report_template(
    scope: dict[str, Any],
    template_artifact_ids: set[str],
) -> dict[str, Any]:
    """Legacy alias — full catalog with template defaults marked."""
    return apply_report_template_artifact_defaults(scope, template_artifact_ids)
