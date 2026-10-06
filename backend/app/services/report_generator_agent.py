"""Report Evidence & Content Agent.

This agent owns forensic content only: artifact selection, evidence classification,
Objective / Procedure / Observation, Annexure traceability and Analysis Summary.
Document formation (A4 packing, continuation pages, PDF/DOCX parity) is owned by
``report_formation_agent``.  Content rules still forbid legacy device-only banners such as
``Laptop [1]`` and raw XML/JSON/binary payloads. Every accepted observation keeps the plain-language
``This means ...`` explanation rule. Compatibility aliases remain here for older callers.
"""

from __future__ import annotations

import re
from typing import Any

from app.services.report_formation_agent import (
    A4_WIDTH_MM,
    A4_HEIGHT_MM,
    HEADER_MM as LETTERHEAD_HEADER_MM,
    FOOTER_MM as LETTERHEAD_FOOTER_MM,
    TABLE_PAGE_UNITS,
    TABLE_CHARS_PER_LINE,
    chunk_table_rows,
    table_row_units,
    wrap_table_cell,
)

_OPO_HEADING_RE = re.compile(
    r"(?m)^###\s+\d+\.\s+(?!Objective\b)(?!Procedure\b)(?!Observations?\b).+"
)
_RPT_ID_RE = re.compile(r"^RPT-[O0](\d+)$", re.I)
_BLANK_RE = re.compile(r"^[\s—\-–_]*$")


def _is_blank(value: Any) -> bool:
    text = str(value or "").strip()
    return not text or bool(_BLANK_RE.fullmatch(text))


def _is_catalog_id_title(value: Any) -> bool:
    return bool(_RPT_ID_RE.fullmatch(str(value or "").strip()))


def display_objective_title(obj_or_title: Any, db: Any = None) -> str:
    """Progress/print heading: never show a catalog key (for example RPT-O920).

    Prefer the title already carried by the objective, then the database catalog, then
    the static report catalog.  The database lookup is important for firms that have
    catalog rows added/reordered after deployment.
    """
    if isinstance(obj_or_title, dict):
        title = str(obj_or_title.get("title") or "").strip()
        oid = str(obj_or_title.get("id") or obj_or_title.get("objective_id") or "").strip()
    else:
        title = str(obj_or_title or "").strip()
        oid = title if _is_catalog_id_title(title) else ""
    if title and not _is_catalog_id_title(title) and not _is_blank(title):
        return title

    lookup_id = title or oid
    if db is not None and lookup_id:
        try:
            from app.db.sql_helpers import fetchone

            candidates = [lookup_id]
            match = _RPT_ID_RE.fullmatch(lookup_id)
            if match:
                canonical = f"RPT-O{int(match.group(1))}"
                if canonical not in candidates:
                    candidates.append(canonical)
            found = fetchone(
                db,
                "SELECT title FROM public.reports_objective WHERE objective_id = ANY(:oids) "
                "AND NULLIF(trim(title), '') IS NOT NULL LIMIT 1",
                {"oids": candidates},
            )
            db_title = str((found or {}).get("title") or "").strip()
            if db_title and not _is_catalog_id_title(db_title):
                return db_title
        except Exception:
            pass

    return catalog_title_for_rpt_id(lookup_id) or catalog_title_for_rpt_id(oid) or title or oid or "Examination question"


def catalog_title_for_rpt_id(objective_id: str) -> str:
    """RPT-O920 → Access to Cloud Storage Services (catalog index, not a printed heading)."""
    match = _RPT_ID_RE.fullmatch(str(objective_id or "").strip())
    if not match:
        return ""
    from app.services.report_catalog_sync import REPORT_OBJECTIVES
    from app.services.report_template_service import _REPORT_TEMPLATE_OBJECTIVE_ID_BASE

    num = int(match.group(1))
    idx = num - _REPORT_TEMPLATE_OBJECTIVE_ID_BASE if num >= _REPORT_TEMPLATE_OBJECTIVE_ID_BASE else num - 1
    if 0 <= idx < len(REPORT_OBJECTIVES):
        return str(REPORT_OBJECTIVES[idx].get("title") or "").strip()
    return ""


def hydrate_section_c_objective(obj: dict[str, Any], db: Any = None) -> dict[str, Any]:
    """Report agent repair: never print catalog IDs or blank Objective/Procedure."""
    from app.services.report_examination_narratives import format_client_objective, format_client_procedure
    from app.services.report_objective_evidence import format_procedure_for_report
    from app.services.report_template_service import (
        _REPORT_TITLE_AXIOM_OBJECTIVE_ID,
        _report_objective_catalog_entry,
        canonical_objective_id,
    )

    row = dict(obj or {})
    oid = str(row.get("id") or row.get("objective_id") or "").strip()
    title = str(row.get("title") or "").strip()
    # A saved intake snapshot can contain only the RPT catalog key as its title.
    # Resolve that key from the live report-objective catalog first so firm-specific
    # titles remain authoritative; use the static catalog only as a fallback.
    if _is_catalog_id_title(title) or _is_blank(title):
        title = display_objective_title({"title": title, "id": oid}, db)
    if _is_blank(title) and oid:
        title = display_objective_title({"id": oid}, db)
    if _is_blank(title) and db is not None and oid:
        try:
            mapped = canonical_objective_id(db, oid)
            from app.services.report_template_service import _axiom_id_to_report_title

            title = str(_axiom_id_to_report_title(mapped, None) or title).strip()
        except Exception:
            pass
    if _is_blank(title) and db is not None and oid:
        try:
            from app.db.sql_helpers import fetchone

            found = fetchone(
                db,
                "SELECT title, objective, procedure_text, axiom_objective_id FROM public.reports_objective "
                "WHERE objective_id=:oid LIMIT 1",
                {"oid": oid},
            )
            if found:
                title = str(found.get("title") or title).strip()
                if _is_blank(row.get("objective")):
                    row["objective"] = found.get("objective") or ""
                if _is_blank(row.get("axiom_objective_id")):
                    row["axiom_objective_id"] = found.get("axiom_objective_id") or ""
        except Exception:
            pass

    if _is_catalog_id_title(title):
        title = catalog_title_for_rpt_id(title) or title

    entry = _report_objective_catalog_entry(title, db=db) if title and not _is_catalog_id_title(title) else None
    if entry:
        title = str(entry.get("title") or title).strip()
        if _is_blank(row.get("axiom_objective_id")):
            row["axiom_objective_id"] = entry.get("axiom_objective_id") or ""
        if _is_blank(row.get("id")) and entry.get("objective_id"):
            row["id"] = entry["objective_id"]
            row["objective_id"] = entry["objective_id"]

    if _is_blank(row.get("axiom_objective_id")) and title:
        row["axiom_objective_id"] = _REPORT_TITLE_AXIOM_OBJECTIVE_ID.get(title) or ""

    # The legacy AXIOM objective id is retained only as a catalog/reference key.
    # V8 no longer hydrates procedure/evidence rules from the old axiom_objectives
    # table. The user-supplied AXIOM KB is the single runtime source of report rules.
    try:
        from app.services.axiom_forensic_kb import objective_knowledge_plan

        kb_plan = objective_knowledge_plan(title, str(row.get("objective") or row.get("statement") or ""))
        row["kb_report_ids"] = list(kb_plan.get("report_ids") or [])
        row["kb_direct_report_ids"] = list(kb_plan.get("direct_report_ids") or [])
        row["kb_procedure_ids"] = list(kb_plan.get("procedure_ids") or [])
        row["kb_limitations"] = list(kb_plan.get("limitations") or [])
    except Exception:
        row["kb_report_ids"] = []
        row["kb_direct_report_ids"] = []
        row["kb_procedure_ids"] = []
        row["kb_limitations"] = []

    objective_text = str(row.get("objective") or row.get("statement") or "").strip()
    if _is_blank(objective_text) or _is_catalog_id_title(objective_text):
        objective_text = format_client_objective(title)
    elif title:
        # Prefer the client sentence even when catalog stored examiner wording.
        client_obj = format_client_objective(title)
        if client_obj:
            objective_text = client_obj

    procedure_text = format_procedure_for_report(
        str(row.get("procedure_text") or row.get("procedure") or ""),
        title=title,
    )
    if _is_blank(procedure_text):
        procedure_text = format_client_procedure(title)

    row["title"] = title or oid or "Examination question"
    row["objective"] = objective_text or format_client_objective(row["title"]) or "To examine this area of the computer."
    row["statement"] = row["objective"]
    row["procedure_text"] = procedure_text or "The related records on the computer were examined."
    row["procedure"] = row["procedure_text"]
    if oid and not row.get("id"):
        row["id"] = oid
        row["objective_id"] = oid
    return row


def section_c_issues(obj: dict[str, Any]) -> list[str]:
    """Issues the Report Generator Agent must repair before printing Section C."""
    issues: list[str] = []
    title = str(obj.get("title") or "").strip()
    if _is_blank(title) or _is_catalog_id_title(title):
        issues.append("heading_is_catalog_id")
    if _is_blank(obj.get("objective") or obj.get("statement")):
        issues.append("empty_objective")
    if _is_blank(obj.get("procedure_text") or obj.get("procedure")):
        issues.append("empty_procedure")
    return issues


def repair_section_c_objectives(objectives: list[dict[str, Any]], db: Any = None) -> list[dict[str, Any]]:
    """Hydrate every selected objective so Section C is never ID + dashes."""
    return [hydrate_section_c_objective(obj, db) for obj in (objectives or [])]


_SECTION_C_DEVICE_BANNER_RE = re.compile(
    r"(?mi)^\s*(?:#{1,6}\s*)?[-•]?\s*(?:\*\*|__)?"
    r"(?:Laptop|Desktop|Computer|Device)(?:\s*\[\d+\])?"
    r"(?:\*\*|__)?\s*$\n?"
)


def sanitize_section_c_markdown(markdown: str | None) -> str:
    """Remove legacy device-only banners from Section C before preview/PDF/DOCX."""
    return _SECTION_C_DEVICE_BANNER_RE.sub("", str(markdown or ""))


def count_disk_opo_blocks(markdown: str | None) -> int:
    """Count catalog objective cards (not the mobile 1/2/3 sub-headings)."""
    return len(_OPO_HEADING_RE.findall(markdown or ""))


def sort_objectives_in_catalog_order(
    rows: list[dict[str, Any]],
    catalog: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Keep selected objectives in Case-intake / catalog order, not hash order."""
    rank: dict[str, int] = {}
    for i, row in enumerate(catalog or []):
        oid = str(row.get("objective_id") or row.get("id") or "")
        if oid:
            rank[oid] = i
        axiom = str(row.get("axiom_objective_id") or "").strip()
        if axiom:
            rank.setdefault(axiom, i)
        title = str(row.get("title") or "").strip().lower()
        if title:
            rank.setdefault(f"title:{title}", i)

    def _key(row: dict[str, Any]) -> tuple[int, int, str]:
        oid = str(row.get("objective_id") or row.get("id") or "")
        title = str(row.get("title") or "").strip().lower()
        if oid in rank:
            return (0, rank[oid], title)
        title_key = f"title:{title}"
        if title_key in rank:
            return (0, rank[title_key], title)
        return (1, 10_000, title or oid)

    return sorted(list(rows or []), key=_key)


def ensure_all_objectives_in_report(markdown: str, objectives: list[dict[str, Any]]) -> str:
    """If generation dropped catalog cards, append the missing titles from intake."""
    expected = repair_section_c_objectives(objectives)
    expected = [o for o in expected if str(o.get("title") or "").strip() and not _is_catalog_id_title(o.get("title"))]
    if not expected:
        return markdown
    present = count_disk_opo_blocks(markdown)
    if present >= len(expected):
        return markdown
    parts = [markdown.rstrip(), ""]
    start = present + 1
    for idx, obj in enumerate(expected[present:], start):
        title = str(obj.get("title") or f"Objective {idx}")
        obj_text = str(obj.get("objective") or obj.get("statement") or "").strip()
        proc = str(obj.get("procedure_text") or obj.get("procedure") or "").strip()
        parts.extend(
            [
                f"### {idx}. {title}",
                "",
                "**Objective**",
                "",
                obj_text or "To examine this area of the computer.",
                "",
                "**Procedure**",
                "",
                proc or "The related records on the computer were examined.",
                "",
                "**Observation**",
                "",
                "The objective-specific evidence result was not available for this report card. Examiner review is required before a finding is stated. This means no negative or positive conclusion was invented for the missing card.",
                "",
            ]
        )
    return "\n".join(parts)
