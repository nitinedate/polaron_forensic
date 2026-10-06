"""Native text PDF export that matches the editable DOCX / on-screen A4 report.

The PDF is built with ReportLab flowables (paragraphs and tables), not page
screenshots.  Letterhead chrome is stamped afterwards by apply_forensic_letterhead.
"""

from __future__ import annotations

import html
import io
import re
from pathlib import Path
from typing import Any

from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.services.report_docx_export import (
    _clean_export_text,
    _display_artifact_group_title,
    _intro_marker,
    _intro_plain,
    _opo_cards_from_markdown,
    _tables_from_section,
)
from app.services.report_renderer import section_title, strip_redundant_section_heading

_NAVY = HexColor("#082C5C")
_GOLD = HexColor("#FFC000")
_ROW_A = HexColor("#D9E2F3")
_INK = HexColor("#111111")
_BLUE = HexColor("#2F6FB2")
_USABLE_WIDTH = 178 * mm
_HIDDEN = frozenset({"limitations", "evidence_details"})
_TOC_ROWS: tuple[tuple[str, str], ...] = (
    ("introduction", "INTRODUCTION"),
    ("scope_of_work", "SCOPE OF WORK"),
    ("tools_used", "TOOLS USED"),
    ("forensic_imaging", "FORENSIC IMAGING"),
    ("os_information", "A. OPERATING SYSTEM"),
    ("user_profile_information", "A. OPERATING SYSTEM — User Profile"),
    ("artifact_summary", "B. ARTIFACTS"),
    ("objectives_procedure_observation", "C. OBJECTIVE, PROCEDURE & OBSERVATION"),
    ("annexure", "D. ANNEXURE"),
    ("final_analysis_summary", "E. ANALYSIS SUMMARY"),
    ("appendix", "F. APPENDIX"),
)
_MOBILE_TOC_ROWS: tuple[tuple[str, str], ...] = (
    ("introduction", "INTRODUCTION"),
    ("tools_used", "TOOLS USED FOR ACQUISITION AND ANALYSIS"),
    ("device_information", "DEVICE INFORMATION"),
    ("extraction_summary", "EXTRACTION SUMMARY"),
    ("objectives_procedure_observation", "OBJECTIVE, OBSERVATION with FINDINGS"),
)
_FONT_REGULAR = "ReportSerif"
_FONT_BOLD = "ReportSerif-Bold"
_FONT_ITALIC = "ReportSerif-Italic"
_FONTS_READY = False


def _first_existing(*paths: Path) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None


def _register_embedded_fonts() -> tuple[str, str, str]:
    """Embed a real serif TTF so viewers cannot collapse Type1 space widths."""
    global _FONTS_READY
    if _FONTS_READY:
        return _FONT_REGULAR, _FONT_BOLD, _FONT_ITALIC
    regular = _first_existing(
        Path("/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf"),
        Path("C:/Windows/Fonts/times.ttf"),
        Path("C:/Windows/Fonts/timesnr.ttf"),
    )
    bold = _first_existing(
        Path("/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf"),
        Path("C:/Windows/Fonts/timesbd.ttf"),
    )
    italic = _first_existing(
        Path("/usr/share/fonts/truetype/liberation/LiberationSerif-Italic.ttf"),
        Path("C:/Windows/Fonts/timesi.ttf"),
    )
    if regular and bold:
        pdfmetrics.registerFont(TTFont(_FONT_REGULAR, str(regular)))
        pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(bold)))
        if italic:
            pdfmetrics.registerFont(TTFont(_FONT_ITALIC, str(italic)))
        else:
            pdfmetrics.registerFont(TTFont(_FONT_ITALIC, str(regular)))
        pdfmetrics.registerFontFamily(
            _FONT_REGULAR, normal=_FONT_REGULAR, bold=_FONT_BOLD, italic=_FONT_ITALIC
        )
        _FONTS_READY = True
        return _FONT_REGULAR, _FONT_BOLD, _FONT_ITALIC
    return "Times-Roman", "Times-Bold", "Times-Italic"


def _styles() -> dict[str, ParagraphStyle]:
    regular, bold, italic = _register_embedded_fonts()
    return {
        "body": ParagraphStyle(
            "ReportBody",
            fontName=regular,
            fontSize=11,
            leading=16,
            textColor=_INK,
            alignment=TA_LEFT,
            spaceAfter=6,
        ),
        "justify": ParagraphStyle(
            "ReportJustify",
            fontName=regular,
            fontSize=10.5,
            leading=15,
            textColor=_INK,
            alignment=TA_LEFT,
            spaceAfter=5,
        ),
        "left": ParagraphStyle(
            "ReportLeft",
            fontName=regular,
            fontSize=10.5,
            leading=14,
            textColor=_INK,
            alignment=TA_LEFT,
            spaceAfter=3,
        ),
        "right": ParagraphStyle(
            "ReportRight",
            fontName=regular,
            fontSize=10.5,
            leading=14,
            textColor=_INK,
            alignment=TA_RIGHT,
            spaceAfter=3,
        ),
        "center": ParagraphStyle(
            "ReportCenter",
            fontName=regular,
            fontSize=10.5,
            leading=14,
            textColor=_INK,
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "h1": ParagraphStyle(
            "ReportH1",
            fontName=bold,
            fontSize=16,
            leading=20,
            textColor=_NAVY,
            alignment=TA_LEFT,
            spaceBefore=4,
            spaceAfter=10,
        ),
        "intro_title": ParagraphStyle(
            "ReportIntroTitle",
            fontName=bold,
            fontSize=16,
            leading=20,
            textColor=_NAVY,
            alignment=TA_CENTER,
            spaceBefore=12,
            spaceAfter=18,
        ),
        "h3": ParagraphStyle(
            "ReportH3",
            fontName=bold,
            fontSize=12,
            leading=16,
            textColor=HexColor("#103B63"),
            spaceBefore=6,
            spaceAfter=6,
        ),
        "cover_title": ParagraphStyle(
            "ReportCoverTitle",
            fontName=bold,
            fontSize=18,
            leading=24,
            textColor=_NAVY,
            alignment=TA_CENTER,
            spaceAfter=16,
        ),
        "cover_sub": ParagraphStyle(
            "ReportCoverSub",
            fontName=bold,
            fontSize=14,
            leading=20,
            textColor=_INK,
            alignment=TA_CENTER,
            spaceAfter=16,
        ),
        "artifact_group": ParagraphStyle(
            "ReportArtifactGroup",
            fontName=bold,
            fontSize=13,
            leading=17,
            textColor=_BLUE,
            spaceBefore=6,
            spaceAfter=6,
        ),
        "artifact_item": ParagraphStyle(
            "ReportArtifactItem",
            fontName=regular,
            fontSize=11.5,
            leading=15,
            textColor=_INK,
            leftIndent=18,
            spaceAfter=1,
        ),
        "th": ParagraphStyle(
            "ReportTh",
            fontName=bold,
            fontSize=10,
            leading=13,
            textColor=black,
            alignment=TA_CENTER,
        ),
        "td": ParagraphStyle(
            "ReportTd",
            fontName=regular,
            fontSize=10,
            leading=13,
            textColor=_INK,
            alignment=TA_LEFT,
        ),
        "td_center": ParagraphStyle(
            "ReportTdCenter",
            fontName=regular,
            fontSize=10,
            leading=13,
            textColor=_INK,
            alignment=TA_CENTER,
        ),
        "opo_title": ParagraphStyle(
            "ReportOpoTitle",
            fontName=bold,
            fontSize=13,
            leading=17,
            textColor=_NAVY,
            spaceAfter=4,
        ),
        "opo_label": ParagraphStyle(
            "ReportOpoLabel",
            fontName=bold,
            fontSize=11,
            leading=15,
            textColor=_NAVY,
            spaceBefore=3,
            spaceAfter=2,
        ),
        "opo_body": ParagraphStyle(
            "ReportOpoBody",
            fontName=regular,
            fontSize=11,
            leading=15,
            textColor=_INK,
            alignment=TA_LEFT,
            spaceAfter=3,
        ),
        "note": ParagraphStyle(
            "ReportNote",
            fontName=italic,
            fontSize=9,
            leading=12,
            textColor=HexColor("#64748B"),
            spaceBefore=10,
        ),
    }


def _rich(text: object) -> str:
    """Escape text and keep the tiny Markdown subset as ReportLab inline markup."""
    raw = _clean_export_text(text)
    escaped = html.escape(raw)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"(?<!\*)\*(.+?)\*(?!\*)", r"<i>\1</i>", escaped)
    escaped = re.sub(r"`([^`]+)`", r"<font face='Courier'>\1</font>", escaped)
    return escaped.replace("\n", "<br/>")


def _markup(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text or "&nbsp;", style)


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return _markup(_rich(text), style)


def _heading(text: object, style: ParagraphStyle):
    """Section title plus a rule — avoids <u> character-by-character drawing."""
    label = _clean_export_text(text)
    para = _p(label, style)
    width = min(
        _USABLE_WIDTH,
        pdfmetrics.stringWidth(label, style.fontName, style.fontSize) + 4,
    )
    rule = HRFlowable(
        width=width,
        thickness=1.1,
        color=style.textColor or _NAVY,
        spaceBefore=1,
        spaceAfter=10,
    )
    rule.hAlign = "CENTER" if style.alignment == TA_CENTER else "LEFT"
    return KeepTogether([para, rule])


def _column_widths(header: list[str], rows: list[list[str]]) -> list[float]:
    if not header:
        return [_USABLE_WIDTH]
    weights: list[float] = []
    for idx, cell in enumerate(header):
        h = str(cell or "").strip().lower()
        sample = [str(row[idx]) if idx < len(row) else "" for row in rows[:30]]
        max_len = max([len(h)] + [len(v) for v in sample], default=4)
        if h in {"sr no", "sr. no", "sr.no", "sr. no.", "no", "count", "visits", "page"}:
            weight = 0.65
        elif "url" in h or "description" in h or "observation" in h or "procedure" in h:
            weight = 3.2
        elif "device id" in h or "path" in h or "source" in h:
            weight = 2.5
        elif "date" in h or "time" in h:
            weight = 1.6
        else:
            weight = min(2.2, max(0.9, max_len / 18.0))
        weights.append(weight)
    total = sum(weights) or 1.0
    return [_USABLE_WIDTH * w / total for w in weights]


def _make_table(header: list[str], rows: list[list[str]], styles: dict[str, ParagraphStyle]) -> Table:
    cols = max(len(header), 1)
    widths = _column_widths(header, rows)
    data: list[list[Any]] = [[_p(header[ci] if ci < len(header) else "", styles["th"]) for ci in range(cols)]]
    for row in rows:
        cells = []
        for ci in range(cols):
            style = styles["td_center"] if widths[ci] < 25 * mm else styles["td"]
            cells.append(_p(row[ci] if ci < len(row) else "", style))
        data.append(cells)
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="CENTER")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), _GOLD),
        ("TEXTCOLOR", (0, 0), (-1, 0), black),
        ("FONTNAME", (0, 0), (-1, 0), _FONT_BOLD if _FONTS_READY else "Times-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.6, black),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for ri in range(1, len(data)):
        commands.append(("BACKGROUND", (0, ri), (-1, ri), _ROW_A if ri % 2 else white))
    table.setStyle(TableStyle(commands))
    table.splitByRow = 1
    return table


def _add_packed_tables(story: list, tables: list[dict[str, Any]], *, title: str, styles: dict[str, ParagraphStyle]) -> None:
    from app.services.report_formation_agent import pack_annexure_tables

    pages = pack_annexure_tables(tables)
    for pi, page in enumerate(pages):
        if pi:
            story.append(PageBreak())
            story.append(_heading(f"{title} (continued)", styles["h1"]))
        for chunk in page:
            label = str(chunk.get("title") or "").strip()
            if label:
                heading = f"{label} (continued)" if chunk.get("continued") else label
                story.append(_p(heading.upper(), styles["h3"]))
            note = chunk.get("note")
            if note and not chunk.get("continued"):
                story.append(_p(note, styles["note"]))
            story.append(
                _make_table(
                    [str(c) for c in (chunk.get("columns") or [])],
                    [[str(c) for c in (row or [])] for row in (chunk.get("rows") or [])],
                    styles,
                )
            )
            story.append(Spacer(1, 6))


def _add_opo(story: list, content: str, *, title: str, styles: dict[str, ParagraphStyle]) -> bool:
    from app.services.report_formation_agent import pack_opo_cards

    cards = _opo_cards_from_markdown(content)
    if not cards:
        return False
    pages = pack_opo_cards(cards)
    for pi, page in enumerate(pages):
        if pi:
            story.append(PageBreak())
            story.append(_heading(f"{title} (continued)", styles["h1"]))
        for card in page:
            inner: list = []
            for idx, line in enumerate(card):
                label = bool(re.match(r"^(Objective|Procedure|Observation|Status):?$", line, re.I))
                style = styles["opo_title"] if idx == 0 else styles["opo_label"] if label else styles["opo_body"]
                inner.append(_p(line, style))
            box = Table([[inner]], colWidths=[_USABLE_WIDTH])
            box.setStyle(
                TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 1.25, _NAVY),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ]
                )
            )
            story.append(KeepTogether([box, Spacer(1, 10)]))
    return True


def _add_markdown(story: list, content: str, styles: dict[str, ParagraphStyle]) -> None:
    from app.services.report_docx_export import _is_table_sep, _parse_table_row

    lines = (content or "").replace("\r\n", "\n").split("\n")
    i = 0
    para_buf: list[str] = []

    def flush() -> None:
        text = " ".join(para_buf).strip()
        para_buf.clear()
        if text:
            story.append(_p(text, styles["body"]))

    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped:
            flush()
            i += 1
            continue
        if stripped.startswith("|") and i + 1 < len(lines) and _is_table_sep(lines[i + 1]):
            flush()
            header = _parse_table_row(stripped)
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|") and not _is_table_sep(lines[i]):
                rows.append(_parse_table_row(lines[i]))
                i += 1
            story.append(_make_table(header, rows, styles))
            story.append(Spacer(1, 6))
            continue
        if stripped.startswith("### "):
            flush()
            story.append(_p(stripped[4:].strip(), styles["h3"]))
            i += 1
            continue
        if stripped.startswith("## "):
            flush()
            story.append(_p(stripped[3:].strip(), styles["h1"]))
            i += 1
            continue
        if stripped.startswith("# "):
            flush()
            story.append(_p(stripped[2:].strip(), styles["h1"]))
            i += 1
            continue
        if stripped.startswith("**") and stripped.endswith("**") and stripped.count("**") == 2:
            flush()
            story.append(_markup(f"<b>{html.escape(stripped[2:-2].strip())}</b>", styles["left"]))
            i += 1
            continue
        if "•" in stripped and not stripped.startswith("|"):
            pieces = [piece.strip() for piece in stripped.split("•") if piece.strip()]
            if len(pieces) > 1:
                flush()
                story.append(
                    ListFlowable(
                        [ListItem(_p(piece, styles["body"]), leftIndent=12) for piece in pieces],
                        bulletType="bullet",
                        start="•",
                    )
                )
                i += 1
                continue
        if stripped.startswith("- ") or stripped.startswith("• "):
            flush()
            items: list[str] = []
            while i < len(lines):
                item = lines[i].strip()
                if not (item.startswith("- ") or item.startswith("• ")):
                    break
                items.append(item[2:].strip())
                i += 1
            story.append(
                ListFlowable(
                    [ListItem(_p(item, styles["body"]), leftIndent=12) for item in items],
                    bulletType="bullet",
                    start="•",
                )
            )
            continue
        para_buf.append(stripped)
        i += 1
    flush()


def _add_cover(story: list, content: str, *, mobile: bool, styles: dict[str, ParagraphStyle]) -> None:
    title = "MOBILE FORENSIC ANALYSIS REPORT" if mobile else "CYBER FORENSIC ANALYSIS REPORT"
    subject = ""
    company = "POLARON TECHNOLOGIES PVT. LTD."
    for line in (content or "").splitlines():
        s = line.strip().replace("**", "").strip()
        if not s or s.startswith("#"):
            continue
        if "TECHNOLOGIES" in s.upper():
            company = s
        elif not subject:
            subject = s.strip('"')
    story.append(Spacer(1, 55 * mm))
    story.append(_p(title, styles["cover_title"]))
    if subject:
        story.append(_p(f'"{subject}"', styles["cover_sub"]))
    story.append(_p(company, styles["cover_sub"]))


def _add_introduction(story: list, content: str, styles: dict[str, ParagraphStyle]) -> None:
    lines = [_intro_plain(line) for line in (content or "").replace("\r\n", "\n").split("\n")]
    lines = [line for line in lines if line and not line.startswith("##")]
    date_line = next((line for line in lines if line.lower().startswith("date:")), "")
    subject_line = next((line for line in lines if line.lower().startswith("subject:")), "")
    to_idx = next((i for i, line in enumerate(lines) if _intro_marker(line, "to") or _intro_marker(line, "to,")), -1)
    subject_idx = next((i for i, line in enumerate(lines) if line.lower().startswith("subject:")), -1)
    dear_idx = next((i for i, line in enumerate(lines) if line.lower().startswith("dear sir")), -1)
    scope_idx = next((i for i, line in enumerate(lines) if _intro_marker(line, "scope of work")), -1)
    terms_idx = next(
        (
            i
            for i, line in enumerate(lines)
            if _intro_marker(line, "terms and condition") or _intro_marker(line, "terms and conditions")
        ),
        -1,
    )
    address_end = subject_idx if subject_idx >= 0 else dear_idx if dear_idx >= 0 else len(lines)
    address_start = to_idx + 1 if to_idx >= 0 else 0
    narrative_re = re.compile(
        r"\b(forensic|examination|requested|device identified|evidence ex-|transferred outside|"
        r"submitted forensic|conduct cyber forensic)\b",
        re.I,
    )
    address = [
        line
        for line in lines[address_start:address_end]
        if line != date_line and len(line) <= 120 and not narrative_re.search(line)
    ]
    salutation_end = scope_idx if scope_idx >= 0 else terms_idx if terms_idx >= 0 else len(lines)
    salutation_start = dear_idx if dear_idx >= 0 else subject_idx + 1 if subject_idx >= 0 else 0
    salutation = lines[salutation_start:salutation_end]
    scope = lines[scope_idx:terms_idx] if scope_idx >= 0 and terms_idx >= 0 else lines[scope_idx:] if scope_idx >= 0 else []
    terms = lines[terms_idx:] if terms_idx >= 0 else []
    signoff: list[str] = []
    if terms_idx >= 0:
        after_terms = [line for line in lines[terms_idx + 1 :] if not re.match(r"^\d+\.\s", line)]
        signoff = after_terms[-2:] if len(after_terms) >= 2 else after_terms
        if signoff:
            terms = [line for line in terms if line not in signoff]

    if date_line:
        story.append(_markup(f"<b>{html.escape(date_line)}</b>", styles["right"]))
        story.append(Spacer(1, 8 * mm))
    story.append(_p("To,", styles["left"]))
    for idx, line in enumerate(address):
        story.append(_markup(f"<b>{html.escape(line)}</b>", styles["left"]) if idx == 0 else _p(line, styles["left"]))
    if address:
        story.append(Spacer(1, 4 * mm))
    if subject_line:
        match = re.match(r"^(Subject:)\s*(.*)$", subject_line, re.I)
        if match:
            story.append(
                _markup(
                    f"<b>{html.escape(match.group(1))}</b> {html.escape(match.group(2))}",
                    styles["center"],
                )
            )
        else:
            story.append(_p(subject_line, styles["center"]))
    for idx, line in enumerate(salutation):
        style = styles["left"] if idx == 0 and line.lower().startswith("dear") else styles["justify"]
        story.append(_p(line, style))
    for block in (scope, terms):
        for line in block:
            is_label = (
                _intro_marker(line, "scope of work")
                or _intro_marker(line, "terms and condition")
                or _intro_marker(line, "terms and conditions")
            )
            is_numbered = bool(re.match(r"^\d+\.\s", line))
            if is_label:
                story.append(_markup(f"<b>{html.escape(line)}</b>", styles["left"]))
            elif is_numbered:
                story.append(_p(line, styles["left"]))
            else:
                story.append(_p(line, styles["justify"]))
        if block:
            story.append(Spacer(1, 4 * mm))
    if signoff:
        story.append(Spacer(1, 8 * mm))
        for line in signoff:
            story.append(_markup(f"<b>{html.escape(line)}</b>", styles["right"]))


def _add_artifacts(story: list, section: dict, styles: dict[str, ParagraphStyle]) -> bool:
    structured = section.get("structured_json") if isinstance(section.get("structured_json"), dict) else {}
    catalog = (structured or {}).get("catalog") if isinstance(structured, dict) else {}
    groups = (catalog or {}).get("sections") if isinstance(catalog, dict) else []
    if not groups:
        categories = ((structured or {}).get("categories") if isinstance(structured, dict) else None) or []
        groups = [
            {
                "title": category.get("title"),
                "subcategories": [
                    {
                        "name": item.get("label") or item.get("key") or "Artifact",
                        "usage_count": item.get("count"),
                        "description": item.get("description"),
                    }
                    for item in (category.get("items") or [])
                    if isinstance(item, dict)
                ],
            }
            for category in categories
            if isinstance(category, dict)
        ]
    if not groups:
        return False
    for gi, group in enumerate(groups, 1):
        story.append(_p(f"{gi}. {_display_artifact_group_title(group.get('title') or 'Artifacts')}:", styles["artifact_group"]))
        for si, sub in enumerate(group.get("subcategories") or [], 1):
            name = _clean_export_text(sub.get("name") or "Artifact")
            count = sub.get("usage_count") if sub.get("usage_count") is not None else sub.get("count")
            count_text = "Reviewed" if isinstance(count, (int, float)) and count < 0 else _clean_export_text(count if count is not None else 0)
            desc = _clean_export_text(sub.get("description") or "Artifacts examined during forensic review.")
            story.append(_markup(f"<b>{si}. {html.escape(name)}</b>", styles["artifact_item"]))
            story.append(_markup(f"<b>Count:</b> {html.escape(str(count_text))}", styles["artifact_item"]))
            story.append(_markup(f"<b>Description:</b> {html.escape(desc)}", styles["artifact_item"]))
            story.append(Spacer(1, 4))
    return True


def _add_toc(story: list, sections: list[dict], *, order: list[str], mobile: bool, styles: dict[str, ParagraphStyle]) -> None:
    from app.services.report_export import _estimate_section_pages

    by_key = {str(s.get("section_key") or ""): s for s in sections}
    visible = [key for key in order if key in by_key and key not in _HIDDEN]
    page = 1
    starts: dict[str, int] = {}
    for key in visible:
        starts[key] = page
        page += _estimate_section_pages(by_key[key], key)
    rows = [(key,section_title(key,mobile=mobile)) for key in order if key not in {'cover_page','table_of_contents'}]
    data = [[_p("Sr No", styles["th"]), _p("Description", styles["th"]), _p("Page", styles["th"])]]
    idx = 0
    for key, label in rows:
        if key not in starts:
            continue
        idx += 1
        data.append(
            [
                _p(str(idx), styles["td_center"]),
                _p(label, styles["td"]),
                _p(str(starts[key]), styles["td_center"]),
            ]
        )
    table = Table(data, colWidths=[22 * mm, 128 * mm, 28 * mm], repeatRows=1, hAlign="CENTER")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), white),
        ("TEXTCOLOR", (0, 0), (-1, 0), _NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for ri in range(1, len(data)):
        commands.append(("BACKGROUND", (0, ri), (-1, ri), HexColor("#F3F4F6") if ri % 2 else white))
    table.setStyle(TableStyle(commands))
    story.append(table)
    story.append(_p("Page numbers follow the live report preview layout.", styles["note"]))


def build_report_pdf(
    sections: list[dict],
    *,
    intake: dict | None = None,
    job_id: str = "",
    order: list[str] | None = None,
    mobile: bool = False,
) -> bytes:
    """Build a selectable, editable-text A4 PDF from the same saved sections as DOCX."""
    del intake, job_id
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=44 * mm,
        bottomMargin=36 * mm,
        title="Mobile Forensic Analysis Report" if mobile else "Cyber Forensic Analysis Report",
        author="POLARON TECHNOLOGIES PVT. LTD.",
        subject="Digital forensic examination report",
    )
    story: list = []
    section_map = {str(s.get("section_key")): s for s in sections}
    keys = list(order or section_map.keys())
    first = True

    for key in keys:
        sec = section_map.get(key)
        if not sec:
            continue
        title = section_title(key, mobile=mobile)
        content = strip_redundant_section_heading(sec.get("content_md") or "", title)

        if key in _HIDDEN:
            continue

        if key == "cover_page":
            _add_cover(story, content, mobile=mobile, styles=styles)
            first = False
            continue

        # UI / TOC contract: every listed description starts on a fresh A4 page.
        if not first:
            story.append(PageBreak())
        first = False

        if key == "table_of_contents":
            story.append(_heading(title, styles["h1"]))
            _add_toc(story, sections, order=keys, mobile=mobile, styles=styles)
            continue
        if key == "introduction":
            story.append(_heading(title, styles["intro_title"]))
            _add_introduction(story, content, styles)
            continue

        story.append(_heading(title, styles["h1"]))
        if key == 'suspicious_activity':
            from app.services.suspicious_activity import REVIEW_NOTE, card_lines, evidence_image_bytes
            cards=(sec.get('structured_json') or {}).get('suspicious_activity') or []
            for index,card in enumerate(cards):
                if index:
                    story.extend([PageBreak(),_heading(title,styles['h1'])])
                detail_style=ParagraphStyle('EvidenceCaption',parent=styles['left'],fontSize=8.5,leading=11,spaceAfter=3,wordWrap='CJK')
                story.append(_p(REVIEW_NOTE,detail_style))
                blob=evidence_image_bytes(card)
                if blob:
                    from PIL import Image as PILImage
                    with PILImage.open(io.BytesIO(blob)) as picture:
                        width,height=picture.size
                    scale=min(160*mm/width,55*mm/height)
                    story.append(Image(io.BytesIO(blob),width=width*scale,height=height*scale))
                for line in card_lines(card):
                    story.append(_p(line,detail_style))
            if cards:
                from app.services.suspicious_activity import examiner_observations
                story.extend([PageBreak(),_heading(title,styles['h1'])])
                _add_markdown(story,examiner_observations(sec),styles)
                continue
        if key == "artifact_summary" and _add_artifacts(story, sec, styles):
            continue
        if key == "objectives_procedure_observation" and _add_opo(story, content, title=title, styles=styles):
            continue
        if key in {"annexure", "final_analysis_summary", "os_information", "user_profile_information", "forensic_imaging"}:
            packed = _tables_from_section(sec)
            if packed:
                _add_packed_tables(story, packed, title=title, styles=styles)
                continue
        _add_markdown(story, content, styles)

    if not story:
        story.append(_p("Forensic Examination Report", styles["h1"]))
    doc.build(story)
    data = buf.getvalue()
    if not data.startswith(b"%PDF"):
        raise RuntimeError("PDF renderer did not produce a valid PDF file")
    return data
