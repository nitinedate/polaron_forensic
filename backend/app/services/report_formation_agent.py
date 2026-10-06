"""Report Formation Agent.

This agent is deliberately separate from forensic evidence reasoning.

Responsibilities
----------------
* Consume the approved/saved report sections produced by the Report Generator Agent.
* NEVER rewrite, summarize, paraphrase, add, delete, or reorder report content.
* Pack that exact content onto A4 pages while using available remaining page space.
* Keep rows/panels together when they fit; split only when the physical page requires it.
* Drive PDF and DOCX from the same canonical section snapshot used by the UI.
* Record a content fingerprint so exports can be proven to contain the same report text.

The reference reports teach layout/pagination behaviour only; their case values are never
copied into another case.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

FORMATION_AGENT_VERSION = "report-formation-v2.5"
_FORMATION_TRAINING_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "report_reference_corpus" / "report_formation_training_v2.json"
A4_WIDTH_MM = 210
A4_HEIGHT_MM = 297
HEADER_MM = 44
FOOTER_MM = 26
BODY_HEIGHT_MM = A4_HEIGHT_MM - HEADER_MM - FOOTER_MM
# Physical-height budget for annexure / structured tables — lockstep with
# frontend reportPagination.ts / annexure_table_training v2.2.  Not a row cap.
TABLE_PAGE_UNITS = 26
TABLE_PACK_SLACK_UNITS = 2
TABLE_TOTAL_CHARS_PER_LINE = 88
TABLE_URL_CHARS_PER_LINE = 18
TABLE_CHARS_PER_LINE = TABLE_URL_CHARS_PER_LINE
TABLE_HEADER_UNITS = 2
TABLE_TITLE_UNITS = 2
TABLE_NOTE_BASE_UNITS = 1
TABLE_NOTE_CHARS_PER_LINE = 78
TABLE_GAP_UNITS = 2
TABLE_MIN_SPLIT_ROOM_UNITS = 8
TABLE_MAX_URL_ROWS_FIRST = 5
TABLE_MAX_URL_ROWS_CONTINUED = 6
TABLE_MAX_PROSE_ROWS = 2
TABLE_PROSE_CELL_CHARS = 120
TABLE_MAX_ROW_UNITS = 16
_URL_WRAP_RE = re.compile(r"([/?&=._-])")
_DATEISH_CELL_RE = re.compile(
    r"^\s*\d{1,4}[/-]\d{1,2}[/-]\d{1,4}(?:\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)?\s*$",
    re.IGNORECASE,
)
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")

FORMATION_RULES: tuple[str, ...] = (
    "The saved UI report content is immutable input. Formation never rewrites forensic text.",
    "Use one 210x297 mm A4 sheet with header/footer inside that sheet.",
    "Before starting a continuation page, test whether the next complete block fits in remaining space.",
    "Pull content upward when it fits; do not leave avoidable half-empty pages.",
    "Never split a table row. Repeat the table header on a true continuation page.",
    "Keep a heading with at least the first body line. Avoid orphan Objective/Procedure/Observation labels.",
    "Keep a complete O/P/O card together when it fits; split only an oversized card or when meaningful space remains.",
    "Section C occupies leftover A4 body: pull the next complete card or a useful prefix before opening a continuation.",
    "Never drop Objective, Procedure or Observation text. Every source line must appear on some page.",
    "PDF and DOCX must use the same canonical section snapshot and section order as the UI.",
    "PDF/DOCX may change presentation mechanics only (page breaks, native table cells, headers/footers), never text.",
    "Introduction is a formal reference-style letter page: one normal line below the header, centered uppercase underlined title, date right, compact recipient block, centered subject and right-aligned sign-off.",
    "The report watermark is very faint (approximately 6-8% effective opacity) and never competes with report text.",
    "Do not use a fixed 12-row page ceiling; actual wrapped row height and remaining A4 space decide continuation.",
    "Annexure tables occupy leftover A4 body only when the next rows still fit above the footer.",
    "After every table page pack, verify every source row appears in order. Missing serials (7 then 9) are a formation failure.",
    "Place only the rows that fit on the current A4 body. A wrapping 5-column URL table holds at most 5 data rows with its title/note, or 6 on a continuation. A 4-column Objective/Procedure/Observation table holds at most 2 tall rows. Leftover white space is required if another row would enter the footer.",
)


@lru_cache(maxsize=1)
def load_formation_training() -> dict[str, Any]:
    return json.loads(_FORMATION_TRAINING_PATH.read_text(encoding="utf-8"))


def formation_training_fingerprint() -> str:
    return hashlib.sha256(_FORMATION_TRAINING_PATH.read_bytes()).hexdigest()


def introduction_layout_profile() -> dict[str, Any]:
    """Return the trained formal-letter profile used by UI/PDF/DOCX formation.

    Keeping this profile in the formation corpus makes the layout behaviour explicit
    and testable without letting case-specific exemplar values leak into a report.
    """
    training = load_formation_training()
    return dict(training.get("introduction_page_training") or {})


def annexure_table_training() -> dict[str, Any]:
    """Return the trained annexure table packing profile used by UI/PDF/DOCX."""
    training = load_formation_training()
    return dict(training.get("annexure_table_training") or {})



@dataclass(frozen=True)
class FormationSnapshot:
    section_order: tuple[str, ...]
    sections: tuple[dict[str, Any], ...]
    sha256: str


def _normalize_newlines(value: Any) -> str:
    # Newline normalization is representational, not a content rewrite.  Do not trim
    # prose or collapse whitespace because export parity is based on the saved UI text.
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n")


def canonical_sections(
    sections: Iterable[dict[str, Any]],
    *,
    order: Iterable[str],
) -> list[dict[str, Any]]:
    """Return the canonical UI/export snapshot without changing report prose."""
    by_key = {str(s.get("section_key") or ""): dict(s) for s in sections}
    result: list[dict[str, Any]] = []
    for key in order:
        sec = by_key.get(str(key))
        if not sec:
            continue
        result.append(
            {
                "section_key": str(key),
                "title": str(sec.get("title") or ""),
                "content_md": _normalize_newlines(sec.get("content_md")),
                "confidence_grade": sec.get("confidence_grade"),
            }
        )
    return result


def snapshot_report(
    sections: Iterable[dict[str, Any]],
    *,
    order: Iterable[str],
) -> FormationSnapshot:
    canonical = canonical_sections(sections, order=order)
    payload = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return FormationSnapshot(
        section_order=tuple(str(x) for x in order),
        sections=tuple(canonical),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def assert_export_content_parity(
    source_sections: Iterable[dict[str, Any]],
    export_sections: Iterable[dict[str, Any]],
    *,
    order: Iterable[str],
) -> str:
    """Fail closed if an export path mutated the saved UI report content."""
    source = snapshot_report(source_sections, order=order)
    exported = snapshot_report(export_sections, order=order)
    if source.sha256 != exported.sha256:
        raise RuntimeError(
            "Report Formation Agent blocked export because PDF/DOCX content no longer "
            "matches the saved UI report content"
        )
    return source.sha256



def _should_soft_wrap_table_cell(text: Any) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return False
    if _DATEISH_CELL_RE.match(raw):
        return False
    if "://" in raw or raw.lower().startswith("www."):
        return True
    if _DRIVE_PATH_RE.match(raw) or "\\" in raw:
        return True
    return raw.count("/") >= 3 and bool(re.search(r"[A-Za-z]", raw))


def wrap_table_cell(text: Any) -> str:
    """Presentation-only soft wrapping for long URLs/paths; visible characters are unchanged."""
    raw = str(text or "")
    if _should_soft_wrap_table_cell(raw):
        return _URL_WRAP_RE.sub(lambda m: m.group(1) + "\u200b", raw)
    return raw


def _is_url_like_cell(value: str) -> bool:
    text = str(value or "").strip().lower()
    return text.startswith(("http://", "https://", "www.", "blob:"))


def max_manageable_table_rows(
    columns: list[Any] | None = None,
    row_sample: list[list[Any]] | None = None,
    *,
    continued: bool = False,
) -> int:
    """Hard cap: only place rows that stay above the letterhead footer."""
    sample = row_sample or []
    width = max(len(columns or []), len(sample[0]) if sample else 0)
    wrapping_urls = width >= 4 and any(_is_url_like_cell(str(cell or "")) for row in sample for cell in (row or []))
    if wrapping_urls:
        return TABLE_MAX_URL_ROWS_CONTINUED if continued else TABLE_MAX_URL_ROWS_FIRST
    tall_prose = width >= 3 and any(
        len(" ".join(str(cell or "").split()).strip()) >= TABLE_PROSE_CELL_CHARS
        for row in sample
        for cell in (row or [])
    )
    if tall_prose:
        return TABLE_MAX_PROSE_ROWS
    return 14


def table_row_units(
    row: list[Any] | None,
    *,
    columns: list[Any] | None = None,
    chars_per_line: int | None = None,
) -> int:
    """Estimate physical row height for A4 packing without inspecting forensic meaning."""
    cells = [str(c or "") for c in (row or [])]
    if not cells:
        return 1
    column_count = max(1, len(columns or []) or len(cells))
    default_width = max(14, TABLE_TOTAL_CHARS_PER_LINE // column_count)
    wrapped = 1
    for raw in cells:
        text = " ".join(str(raw or "").split()).strip() or " "
        if _is_url_like_cell(text):
            width = min(TABLE_URL_CHARS_PER_LINE, default_width)
        else:
            width = chars_per_line if chars_per_line else default_width
        wrapped = max(wrapped, max(1, (len(text) + width - 1) // width))
    padding = 1 if wrapped >= 2 else 0
    return max(1, min(TABLE_MAX_ROW_UNITS, wrapped + padding))


def table_chunk_chrome_units(title: str | None, note: str | None, continued: bool) -> int:
    units = TABLE_HEADER_UNITS
    if str(title or "").strip():
        units += TABLE_TITLE_UNITS
    if not continued and str(note or "").strip():
        units += TABLE_NOTE_BASE_UNITS + max(1, (len(str(note)) + TABLE_NOTE_CHARS_PER_LINE - 1) // TABLE_NOTE_CHARS_PER_LINE)
    return units


def table_chunk_units(chunk: dict[str, Any]) -> int:
    columns = list(chunk.get("columns") or [])
    chrome = table_chunk_chrome_units(chunk.get("title"), chunk.get("note"), bool(chunk.get("continued")))
    rows = chunk.get("rows") or []
    return chrome + sum(table_row_units(row, columns=columns) for row in rows)


def chunk_table_rows(
    rows: list[list[Any]],
    *,
    page_units: int = TABLE_PAGE_UNITS,
    columns: list[Any] | None = None,
) -> list[list[list[Any]]]:
    """Pack whole table rows into A4 chunks; never split one row across pages."""
    body = rows or []
    if not body:
        return [[]]
    chunks: list[list[list[Any]]] = []
    current: list[list[Any]] = []
    used = 0
    for row in body:
        cost = table_row_units(row, columns=columns)
        if current and used + cost > page_units:
            chunks.append(current)
            current = []
            used = 0
        current.append(row)
        used += cost
    if current:
        chunks.append(current)
    return chunks


def _page_table_units(chunks: list[dict[str, Any]]) -> int:
    return sum((TABLE_GAP_UNITS if idx else 0) + table_chunk_units(chunk) for idx, chunk in enumerate(chunks))


def annexure_pages_cover_source(tables: list[dict[str, Any]], pages: list[list[dict[str, Any]]]) -> bool:
    source = [
        (str(table.get("title") or ""), [str(c or "") for c in (row or [])])
        for table in tables or []
        for row in table.get("rows") or []
    ]
    packed = [
        (str(chunk.get("title") or ""), [str(c or "") for c in (row or [])])
        for page in pages or []
        for chunk in page
        for row in chunk.get("rows") or []
    ]
    return source == packed


def missing_annexure_rows(tables: list[dict[str, Any]], pages: list[list[dict[str, Any]]]) -> list[str]:
    """Return human-readable gaps after a pack. Empty means every row is present in order."""
    if annexure_pages_cover_source(tables, pages):
        return []
    missing: list[str] = []
    for table in tables or []:
        title = str(table.get("title") or "table")
        source = list(table.get("rows") or [])
        packed = [
            list(row or [])
            for page in pages or []
            for chunk in page
            if str(chunk.get("title") or "") == title
            for row in chunk.get("rows") or []
        ]
        packed_keys = {tuple(str(c or "") for c in row) for row in packed}
        for idx, row in enumerate(source):
            key = tuple(str(c or "") for c in (row or []))
            if key not in packed_keys:
                serial = (row or [idx + 1])[0] if row else idx + 1
                missing.append(f"{title} row {serial}")
    return missing


def pack_annexure_tables(
    tables: list[dict[str, Any]],
    *,
    capacity: int = TABLE_PAGE_UNITS,
) -> list[list[dict[str, Any]]]:
    """Fill each A4 table page, then continue. Never drop a source row."""
    budget = max(8, capacity - TABLE_PACK_SLACK_UNITS)
    pages: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    used = 0

    def flush() -> None:
        nonlocal current, used
        if current:
            pages.append(current)
        current = []
        used = 0

    for table in tables or []:
        rows = list(table.get("rows") or [])
        columns = list(table.get("columns") or [])
        title = table.get("title")
        note = table.get("note")
        offset = 0
        continued = False
        if not rows:
            chrome = table_chunk_chrome_units(title, note, continued)
            gap = TABLE_GAP_UNITS if current else 0
            if current and used + gap + chrome > budget:
                flush()
                gap = 0
            current.append({"title": title, "columns": columns, "rows": [], "continued": continued, "note": note})
            used += gap + chrome
            continue
        while offset < len(rows):
            remaining_rows = rows[offset:]
            chrome = table_chunk_chrome_units(title, None if continued else note, continued)
            gap = TABLE_GAP_UNITS if current else 0
            first_cost = table_row_units(remaining_rows[0], columns=columns)
            if current and gap + chrome + first_cost > budget - used:
                flush()
                continue
            start_chrome = chrome + (TABLE_GAP_UNITS if current else 0)
            cap = max_manageable_table_rows(columns, remaining_rows, continued=continued)
            take = 0
            row_cost = 0
            while take < len(remaining_rows) and take < cap:
                cost = table_row_units(remaining_rows[take], columns=columns)
                if start_chrome + row_cost + cost > budget - used:
                    break
                row_cost += cost
                take += 1
            if take <= 0:
                if current:
                    flush()
                    continue
                take = 1
                row_cost = table_row_units(remaining_rows[0], columns=columns)
            current.append(
                {
                    "title": title,
                    "columns": columns,
                    "rows": remaining_rows[:take],
                    "continued": continued,
                    "note": None if continued else note,
                }
            )
            used += start_chrome + row_cost
            offset += take
            continued = True
            if offset < len(rows):
                flush()
    if current:
        pages.append(current)

    packed = [[dict(chunk, rows=list(chunk.get("rows") or [])) for chunk in page] for page in pages if page]
    i = 0
    while i < len(packed) - 1:
        if not packed[i + 1]:
            packed.pop(i + 1)
            continue
        dest = packed[i]
        room = budget - _page_table_units(dest)
        nxt = packed[i + 1][0]
        dest_last = dest[-1] if dest else None
        same_table = bool(
            dest_last
            and nxt
            and str(dest_last.get("title") or "") == str(nxt.get("title") or "")
            and nxt.get("continued")
        )
        if same_table and (nxt.get("rows") or []):
            pulled = 0
            nxt_rows = list(nxt.get("rows") or [])
            cap = max_manageable_table_rows(
                dest_last.get("columns") or [],
                dest_last.get("rows") or [],
                continued=bool(dest_last.get("continued")),
            )
            while pulled < len(nxt_rows) and len(dest_last.get("rows") or []) + pulled < cap:
                cost = table_row_units(nxt_rows[pulled], columns=nxt.get("columns") or [])
                if cost > room:
                    break
                dest_last["rows"].append(nxt_rows[pulled])
                room -= cost
                pulled += 1
            if pulled:
                nxt["rows"] = nxt_rows[pulled:]
                if not nxt["rows"]:
                    packed[i + 1].pop(0)
                    continue
            i += 1
            continue
        next_cost = (TABLE_GAP_UNITS if dest else 0) + table_chunk_units(nxt)
        if next_cost > 0 and next_cost <= room:
            dest.append(packed[i + 1].pop(0))
            continue
        nxt_rows = list(nxt.get("rows") or [])
        if room >= TABLE_MIN_SPLIT_ROOM_UNITS and nxt_rows:
            chrome = table_chunk_chrome_units(nxt.get("title"), nxt.get("note"), bool(nxt.get("continued")))
            gap = TABLE_GAP_UNITS if dest else 0
            first = table_row_units(nxt_rows[0], columns=nxt.get("columns") or [])
            if gap + chrome + first <= room:
                take = 0
                row_cost = 0
                cap = max_manageable_table_rows(
                    nxt.get("columns") or [],
                    nxt_rows,
                    continued=bool(nxt.get("continued")),
                )
                while take < len(nxt_rows) and take < cap:
                    cost = table_row_units(nxt_rows[take], columns=nxt.get("columns") or [])
                    if gap + chrome + row_cost + cost > room:
                        break
                    row_cost += cost
                    take += 1
                if take >= 1:
                    dest.append({**nxt, "rows": nxt_rows[:take]})
                    nxt["rows"] = nxt_rows[take:]
                    nxt["continued"] = True
                    nxt["note"] = None
                    if not nxt["rows"]:
                        packed[i + 1].pop(0)
                    continue
        i += 1
    packed = [page for page in packed if page]
    if annexure_pages_cover_source(tables or [], packed) and not missing_annexure_rows(tables or [], packed):
        return packed
    fallback = [page for page in pages if page]
    if not annexure_pages_cover_source(tables or [], fallback):
        raise RuntimeError("Report Formation Agent refused a pack that would drop annexure rows")
    return fallback


# Trained Section C page budget — keep in lockstep with frontend reportPagination.ts.
OPO_CHARS_PER_LINE = 78
OPO_PAGE_UNITS = 34
OPO_CARD_OVERHEAD_UNITS = 3
OPO_MIN_SPLIT_ROOM_UNITS = 6
_OPO_LABEL_RE = re.compile(r"^(?:\*\*)?(Objective|Procedure|Observation|Status)(?:\*\*)?:?$", re.I)
_OPO_CONTINUED_RE = re.compile(r"\s*\(continued\)\s*$", re.I)


def opo_line_units(line: str) -> int:
    text = str(line or "").strip()
    if not text:
        return 0
    return max(1, (len(text) + OPO_CHARS_PER_LINE - 1) // OPO_CHARS_PER_LINE)


def opo_card_units(card: list[str]) -> int:
    total = sum(opo_line_units(line) for line in card or [])
    return max(1, total + OPO_CARD_OVERHEAD_UNITS)


def _is_opo_label(line: str) -> bool:
    return bool(_OPO_LABEL_RE.match(str(line or "").strip()))


def take_opo_card_prefix(card: list[str], max_units: int) -> tuple[list[str], list[str]]:
    """Take as many lines as fit. Never orphan a section label."""
    if not card:
        return [], []
    if opo_card_units(card) <= max_units:
        return list(card), []
    title = card[0] if card else ""
    fit: list[str] = []
    used = OPO_CARD_OVERHEAD_UNITS
    for i, line in enumerate(card):
        cost = opo_line_units(line)
        if fit and used + cost > max_units:
            # A single oversized line must still advance. Keep it on this page
            # rather than rebuilding the same title/label/line continuation forever.
            if used + cost > max_units and cost >= max_units - OPO_CARD_OVERHEAD_UNITS - 2:
                fit.append(line)
                rest = list(card[i + 1 :])
                return fit, ([title, *rest] if rest else [])
            rest = list(card[i:])
            if len(fit) > 1 and _is_opo_label(fit[-1]) and rest:
                rest.insert(0, fit.pop())
            return fit, ([title, *rest] if rest else [])
        fit.append(line)
        used += cost
    return fit, []


def _opo_prefix_is_useful(fit: list[str]) -> bool:
    if len(fit) < 3:
        return False
    return any(str(line).strip() and not _is_opo_label(line) for line in fit[1:])


def pack_opo_cards(cards: list[list[str]], *, capacity: int = OPO_PAGE_UNITS) -> list[list[list[str]]]:
    """Fill each A4 Section C page, then continue. Never drop a source line."""
    pages: list[list[list[str]]] = []
    current: list[list[str]] = []
    used = 0

    def flush() -> None:
        nonlocal current, used
        if current:
            pages.append(current)
        current = []
        used = 0

    for card in cards or []:
        cost = opo_card_units(card)
        if cost <= 0:
            continue
        room = capacity - used
        if cost <= room:
            current.append(list(card))
            used += cost
            continue

        remaining = list(card)
        if current and room >= OPO_MIN_SPLIT_ROOM_UNITS:
            fit, rest = take_opo_card_prefix(remaining, room)
            if _opo_prefix_is_useful(fit) and rest:
                current.append(fit)
                remaining = rest
                flush()
            else:
                flush()
        elif current:
            flush()

        if remaining and opo_card_units(remaining) <= capacity:
            current.append(remaining)
            used = opo_card_units(remaining)
            continue

        while remaining:
            prev_len = len(remaining)
            fit, rest = take_opo_card_prefix(remaining, capacity)
            if rest and len(rest) >= prev_len and fit == remaining[: len(fit)]:
                current.append(remaining)
                remaining = []
                flush()
                break
            if not fit:
                current.append(remaining)
                remaining = []
                flush()
                break
            current.append(fit)
            used = opo_card_units(fit)
            remaining = rest
            if remaining:
                flush()

    if current:
        pages.append(current)

    packed = [page[:] for page in pages if page]
    i = 0
    while i < len(packed) - 1:
        if not packed[i + 1]:
            packed.pop(i + 1)
            continue
        dest_used = sum(opo_card_units(card) for card in packed[i])
        nxt = packed[i + 1][0]
        nxt_cost = opo_card_units(nxt)
        if nxt_cost > 0 and dest_used + nxt_cost <= capacity:
            packed[i].append(packed[i + 1].pop(0))
            continue
        i += 1
    packed = [page for page in packed if page]
    if not opo_pages_cover_source(cards or [], packed):
        raise RuntimeError("Report Formation Agent refused a Section C pack that would drop Objective/Procedure/Observation text")
    return packed


def opo_pages_cover_source(cards: list[list[str]], pages: list[list[list[str]]]) -> bool:
    seen = {
        _OPO_CONTINUED_RE.sub("", str(line or "")).strip()
        for page in pages
        for card in page
        for line in card
        if str(line or "").strip()
    }
    return all(
        (not str(line or "").strip()) or str(line).strip() in seen
        for card in cards or []
        for line in card
    )


def formation_agent_health(snap: dict[str, Any] | None = None) -> dict[str, Any]:

    snap = snap or {}
    status = str(snap.get("status") or "")
    active = status in {"report_forming", "report_exporting"}
    return {
        "complete": not active,
        "forming": active,
        "should_run": False,
        "should_stand_down": not active,
        "version": FORMATION_AGENT_VERSION,
        "duty": (
            "Report Formation Agent owns pagination and PDF/DOCX formation only. It receives the exact saved UI "
            "sections from Report Generator Agent, applies the formal reference-trained Introduction layout, fills "
            "remaining A4 space (including annexure URL-table leftover) before starting a continuation, keeps "
            "rows/panels intact when they fit, applies a very light watermark, and is forbidden to rewrite report "
            "content. PDF and DOCX use the same canonical section snapshot and carry its SHA-256 fingerprint."
        ),
    }
