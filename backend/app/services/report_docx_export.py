"""Professional DOCX export for forensic reports.

The DOCX export uses the same saved report sections as the PDF export, but renders
those sections as native Word paragraphs/tables instead of embedding HTML.  It is
intended to remain editable while preserving the A4 Polaron report chrome.
"""

from __future__ import annotations

import io
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Mm, Pt, RGBColor

from app.services.report_renderer import section_title, strip_redundant_section_heading

_STATIC = Path(__file__).resolve().parents[1] / "static" / "report"
_NAVY = "082C5C"
_GOLD = "FFC000"
_ROW_A = "D9E2F3"
_ROW_B = "FFFFFF"
_LIGHT_BORDER = "B7C9DA"
_USABLE_WIDTH_MM = 178  # A4 210mm minus 16mm left/right margins.


DEFAULT_FONT_SIZE = 11.5
_DISPLAY_CONTROL_RE = re.compile(r"[​‌‍‎‏‪-‮⁠﻿]")


def _clean_export_text(value: object) -> str:
    return _DISPLAY_CONTROL_RE.sub("", str(value or ""))


def _display_artifact_group_title(title: str) -> str:
    clean = _clean_export_text(title).strip()
    if clean == "Application Usage":
        return "Application Usages"
    return clean


def _json_field(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return default
    return value


def _asset(name: str) -> bytes:
    path = _STATIC / name
    return path.read_bytes() if path.is_file() else b""


def _combined_header_png() -> bytes:
    """Return header artwork with the confidential seal already positioned."""
    from PIL import Image

    header_raw = _asset("letterhead-header.png")
    if not header_raw:
        return b""
    header = Image.open(io.BytesIO(header_raw)).convert("RGBA")
    seal_raw = _asset("confidential-stamp.png")
    if seal_raw:
        seal = Image.open(io.BytesIO(seal_raw)).convert("RGBA")
        target_w = max(80, int(header.width * 0.145))
        target_h = max(60, int(target_w * seal.height / max(seal.width, 1)))
        seal = seal.resize((target_w, target_h), Image.Resampling.LANCZOS)
        inset_x = max(24, int(header.width * 0.035))
        inset_y = max(10, int(header.height * 0.08))
        header.alpha_composite(seal, (header.width - target_w - inset_x, inset_y))
    white = Image.new("RGBA", header.size, (255, 255, 255, 255))
    out = Image.alpha_composite(white, header).convert("RGB")
    buf = io.BytesIO()
    out.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _set_page_number(paragraph) -> None:
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(0)
    paragraph.paragraph_format.space_after = Pt(0)
    run = paragraph.add_run("Page ")
    run.font.name = "Times New Roman"
    run.font.size = Pt(8)
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = " PAGE "
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instr)
    run._r.append(end)


def _float_picture_behind_text(inline) -> None:
    """Convert a python-docx inline picture to a centered page anchor behind text."""
    parent = inline.getparent()
    anchor = OxmlElement("wp:anchor")
    for name, value in (
        ("distT", "0"),
        ("distB", "0"),
        ("distL", "0"),
        ("distR", "0"),
        ("simplePos", "0"),
        ("relativeHeight", "0"),
        ("behindDoc", "1"),
        ("locked", "0"),
        ("layoutInCell", "1"),
        ("allowOverlap", "1"),
    ):
        anchor.set(name, value)

    simple_pos = OxmlElement("wp:simplePos")
    simple_pos.set("x", "0")
    simple_pos.set("y", "0")
    anchor.append(simple_pos)

    pos_h = OxmlElement("wp:positionH")
    pos_h.set("relativeFrom", "page")
    align_h = OxmlElement("wp:align")
    align_h.text = "center"
    pos_h.append(align_h)
    anchor.append(pos_h)

    pos_v = OxmlElement("wp:positionV")
    pos_v.set("relativeFrom", "page")
    align_v = OxmlElement("wp:align")
    align_v.text = "center"
    pos_v.append(align_v)
    anchor.append(pos_v)

    for tag in ("wp:extent", "wp:effectExtent"):
        node = inline.find(qn(tag))
        if node is not None:
            anchor.append(deepcopy(node))

    anchor.append(OxmlElement("wp:wrapNone"))
    for tag in ("wp:docPr", "wp:cNvGraphicFramePr", "a:graphic"):
        node = inline.find(qn(tag))
        if node is not None:
            anchor.append(deepcopy(node))
    parent.replace(inline, anchor)


def _add_header_watermark(header) -> None:
    """Repeat the same faint centered watermark used by UI/PDF on every Word page."""
    raw = _asset("watermark.png")
    if not raw:
        return
    p = header.add_paragraph()
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run()
    shape = run.add_picture(io.BytesIO(raw), width=Mm(125))
    _float_picture_behind_text(shape._inline)


def _configure_a4_section(section) -> None:
    section.page_width = Mm(210)
    section.page_height = Mm(297)
    section.top_margin = Mm(44)
    section.bottom_margin = Mm(26)
    section.left_margin = Mm(16)
    section.right_margin = Mm(16)
    section.header_distance = Mm(0)
    section.footer_distance = Mm(0)

    # Header artwork spans the full paper width, outside the text margins.
    header = section.header
    header.is_linked_to_previous = True
    hp = header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.LEFT
    hp.paragraph_format.left_indent = -Mm(16)
    hp.paragraph_format.right_indent = -Mm(16)
    hp.paragraph_format.space_before = Pt(0)
    hp.paragraph_format.space_after = Pt(0)
    combined = _combined_header_png()
    if combined:
        hp.add_run().add_picture(io.BytesIO(combined), width=Mm(210), height=Mm(44))
    _add_header_watermark(header)

    footer = section.footer
    footer.is_linked_to_previous = True
    fp_num = footer.paragraphs[0]
    _set_page_number(fp_num)
    fp_img = footer.add_paragraph()
    fp_img.alignment = WD_ALIGN_PARAGRAPH.LEFT
    fp_img.paragraph_format.left_indent = -Mm(16)
    fp_img.paragraph_format.right_indent = -Mm(16)
    fp_img.paragraph_format.space_before = Pt(0)
    fp_img.paragraph_format.space_after = Pt(0)
    footer_raw = _asset("letterhead-footer.png")
    if footer_raw:
        fp_img.add_run().add_picture(io.BytesIO(footer_raw), width=Mm(210), height=Mm(26))


def _configure_styles(doc: Document) -> None:
    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal.font.size = Pt(10.5)
    normal.paragraph_format.space_after = Pt(4)
    normal.paragraph_format.line_spacing = 1.08

    for style_name, size in (("Title", 18), ("Heading 1", 18), ("Heading 2", 14), ("Heading 3", 11.5)):
        style = doc.styles[style_name]
        style.font.name = "Times New Roman"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor.from_string(_NAVY)
        style.font.bold = True


def _set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def _set_cell_margins(cell, *, top=70, start=90, bottom=70, end=90) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for m, v in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{m}"))
        if node is None:
            node = OxmlElement(f"w:{m}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(v))
        node.set(qn("w:type"), "dxa")


def _repeat_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def _keep_row_together(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def _set_keep_with_next(paragraph, value: bool = True) -> None:
    paragraph.paragraph_format.keep_with_next = value


def _clean_inline(text: str) -> str:
    return _clean_export_text(text).replace("`", "")


def _add_inline_runs(paragraph, text: str) -> None:
    """Render the tiny Markdown subset used by report sections."""
    text = _clean_inline(text)
    pattern = re.compile(r"(\*\*.+?\*\*|(?<!\*)\*[^*]+?\*(?!\*))")
    pos = 0
    for match in pattern.finditer(text):
        if match.start() > pos:
            run = paragraph.add_run(text[pos : match.start()])
            run.font.name = "Times New Roman"
        token = match.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            run.bold = True
        else:
            run = paragraph.add_run(token[1:-1])
            run.italic = True
        run.font.name = "Times New Roman"
        pos = match.end()
    if pos < len(text):
        run = paragraph.add_run(text[pos:])
        run.font.name = "Times New Roman"


def _column_weights(header: list[str], rows: list[list[str]]) -> list[float]:
    if not header:
        return [1.0]
    values_by_col: list[list[str]] = [[] for _ in header]
    for idx, cell in enumerate(header):
        values_by_col[idx].append(cell)
    for row in rows[:40]:
        for idx in range(len(header)):
            values_by_col[idx].append(row[idx] if idx < len(row) else "")
    weights: list[float] = []
    for idx, values in enumerate(values_by_col):
        h = header[idx].strip().lower()
        max_len = max((len(v or "") for v in values), default=4)
        if h in {"sr no", "sr. no", "sr.no", "no", "count", "visits", "page"}:
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
    return weights


def _add_table(doc: Document, header: list[str], rows: list[list[str]]) -> None:
    cols = max(len(header), 1)
    table = doc.add_table(rows=1, cols=cols)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    weights = _column_weights(header, rows)
    total = sum(weights) or 1.0
    widths = [Mm(_USABLE_WIDTH_MM * w / total) for w in weights]

    hdr = table.rows[0]
    _repeat_header(hdr)
    _keep_row_together(hdr)
    for ci in range(cols):
        cell = hdr.cells[ci]
        cell.width = widths[ci]
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        _set_cell_shading(cell, _GOLD)
        _set_cell_margins(cell)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(header[ci] if ci < len(header) else "")
        run.bold = True
        run.font.name = "Times New Roman"
        run.font.size = Pt(11)

    wide = cols >= 5
    for ri, row_values in enumerate(rows):
        row = table.add_row()
        _keep_row_together(row)
        fill = _ROW_A if ri % 2 == 0 else _ROW_B
        for ci in range(cols):
            cell = row.cells[ci]
            cell.width = widths[ci]
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
            _set_cell_shading(cell, fill)
            _set_cell_margins(cell)
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if widths[ci].mm < 25 else WD_ALIGN_PARAGRAPH.LEFT
            _add_inline_runs(p, row_values[ci] if ci < len(row_values) else "")
            for run in p.runs:
                run.font.size = Pt(10 if wide else 11)

    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _set_table_borders(table, color: str = _NAVY, sz: str = "12") -> None:
    tbl = table._tbl
    tbl_pr = tbl.tblPr if tbl.tblPr is not None else OxmlElement("w:tblPr")
    borders = tbl_pr.find(qn("w:tblBorders"))
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        node = borders.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            borders.append(node)
        node.set(qn("w:val"), "single")
        node.set(qn("w:sz"), sz)
        node.set(qn("w:space"), "0")
        node.set(qn("w:color"), color)


def _tables_from_section(section: dict) -> list[dict[str, Any]]:
    structured = section.get("structured_json") if isinstance(section.get("structured_json"), dict) else {}
    existing = list((structured or {}).get("tables") or [])
    parsed: list[dict[str, Any]] = []
    content = str(section.get("content_md") or "")
    lines = content.replace("\r\n", "\n").split("\n")
    i = 0
    pending_title = ""
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("### "):
            pending_title = stripped[4:].strip()
            i += 1
            continue
        if stripped.startswith("|") and i + 1 < len(lines) and _is_table_sep(lines[i + 1]):
            header = _parse_table_row(stripped)
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|") and not _is_table_sep(lines[i]):
                rows.append(_parse_table_row(lines[i]))
                i += 1
            parsed.append({"title": pending_title, "columns": header, "rows": rows})
            pending_title = ""
            continue
        i += 1
    if parsed and (not existing or sum(len(t.get("rows") or []) for t in parsed) >= sum(len(t.get("rows") or []) for t in existing)):
        return parsed
    return [
        {
            "title": table.get("title"),
            "columns": list(table.get("columns") or []),
            "rows": [list(row or []) for row in (table.get("rows") or [])],
            "note": table.get("note"),
        }
        for table in existing
        if table.get("columns")
    ]


def _add_packed_tables(doc: Document, tables: list[dict[str, Any]], *, section_title_text: str) -> None:
    from app.services.report_formation_agent import pack_annexure_tables

    pages = pack_annexure_tables(tables)
    for pi, page in enumerate(pages):
        if pi:
            doc.add_page_break()
            _add_section_heading(doc, f"{section_title_text} (continued)")
        for chunk in page:
            title = str(chunk.get("title") or "").strip()
            if title:
                p = doc.add_paragraph(style="Heading 3")
                _set_keep_with_next(p)
                label = f"{title} (continued)" if chunk.get("continued") else title
                run = p.add_run(label.upper())
                run.font.name = "Times New Roman"
                run.font.size = Pt(14)
                run.bold = True
                run.font.color.rgb = RGBColor.from_string("103B63")
            note = chunk.get("note")
            if note and not chunk.get("continued"):
                np = doc.add_paragraph()
                nr = np.add_run(str(note))
                nr.italic = True
                nr.font.name = "Times New Roman"
                nr.font.size = Pt(11)
            _add_table(doc, list(chunk.get("columns") or []), [list(row or []) for row in (chunk.get("rows") or [])])


def _opo_cards_from_markdown(content: str) -> list[list[str]]:
    raw = (content or "").replace("\r\n", "\n")
    if not re.search(r"^###\s+\d+\.", raw, re.M):
        return []
    cards: list[list[str]] = []
    for part in re.split(r"\n(?=###\s+\d+\.\s)", raw):
        lines: list[str] = []
        for line in part.splitlines():
            text = re.sub(r"^#{1,6}\s*", "", line).strip()
            text = text.replace("**", "").strip()
            if text and not text.startswith("|") and not re.match(r"^C\.\s+OBJECTIVE", text, re.I):
                lines.append(text)
        if lines:
            cards.append(lines)
    return cards


def _add_opo_card(doc: Document, lines: list[str]) -> None:
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    _set_table_borders(table, _NAVY, "16")
    cell = table.cell(0, 0)
    cell.width = Mm(_USABLE_WIDTH_MM)
    _set_cell_margins(cell, top=140, start=160, bottom=140, end=160)
    first = True
    for idx, line in enumerate(lines):
        p = cell.paragraphs[0] if first else cell.add_paragraph()
        first = False
        p.paragraph_format.space_before = Pt(2 if idx else 0)
        p.paragraph_format.space_after = Pt(2)
        label = bool(re.match(r"^(Objective|Procedure|Observation|Status):?$", line, re.I))
        run = p.add_run(line)
        run.font.name = "Times New Roman"
        run.bold = bool(label or idx == 0)
        run.font.size = Pt(13 if idx == 0 else 11)
        run.font.color.rgb = RGBColor.from_string(_NAVY if label or idx == 0 else "111111")
    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(10)


def _add_packed_opo(doc: Document, content: str, *, section_title_text: str) -> bool:
    from app.services.report_formation_agent import pack_opo_cards

    cards = _opo_cards_from_markdown(content)
    if not cards:
        return False
    pages = pack_opo_cards(cards)
    for pi, page in enumerate(pages):
        if pi:
            doc.add_page_break()
            _add_section_heading(doc, f"{section_title_text} (continued)")
        for card in page:
            _add_opo_card(doc, card)
    return True


def _is_table_sep(line: str) -> bool:
    s = line.strip()
    return bool(s.startswith("|") and re.match(r"^\|[\s\-:|]+\|\s*$", s))


def _parse_table_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _add_markdown(doc: Document, content: str) -> None:
    lines = (content or "").replace("\r\n", "\n").split("\n")
    i = 0
    para_buf: list[str] = []

    def flush_para() -> None:
        text = " ".join(para_buf).strip()
        para_buf.clear()
        if not text:
            return
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_after = Pt(4)
        _add_inline_runs(p, text)

    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped:
            flush_para()
            i += 1
            continue

        if stripped.startswith("|") and i + 1 < len(lines) and _is_table_sep(lines[i + 1]):
            flush_para()
            header = _parse_table_row(stripped)
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|") and not _is_table_sep(lines[i]):
                rows.append(_parse_table_row(lines[i]))
                i += 1
            _add_table(doc, header, rows)
            continue

        if stripped.startswith("### "):
            flush_para()
            p = doc.add_paragraph(style="Heading 3")
            _set_keep_with_next(p)
            _add_inline_runs(p, stripped[4:].strip())
            i += 1
            continue
        if stripped.startswith("## "):
            flush_para()
            p = doc.add_paragraph(style="Heading 2")
            _set_keep_with_next(p)
            _add_inline_runs(p, stripped[3:].strip())
            i += 1
            continue
        if stripped.startswith("# "):
            flush_para()
            p = doc.add_paragraph(style="Heading 1")
            _set_keep_with_next(p)
            _add_inline_runs(p, stripped[2:].strip())
            i += 1
            continue

        # Whole-line forensic labels: Objective / Procedure / Observation / Status.
        if stripped.startswith("**") and stripped.endswith("**") and stripped.count("**") == 2:
            flush_para()
            p = doc.add_paragraph()
            _set_keep_with_next(p)
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(1)
            run = p.add_run(stripped[2:-2].strip())
            run.bold = True
            run.font.name = "Times New Roman"
            run.font.size = Pt(10.5)
            run.font.color.rgb = RGBColor.from_string(_NAVY)
            i += 1
            continue

        # Several generated procedures contain multiple bullet glyphs on one line.
        # Split those first; otherwise a line beginning with "• " would become one
        # list item containing the second bullet as literal text.
        if "•" in stripped and not stripped.startswith("|"):
            pieces = [piece.strip() for piece in stripped.split("•") if piece.strip()]
            if len(pieces) > 1:
                flush_para()
                for piece in pieces:
                    p = doc.add_paragraph(style="List Bullet")
                    p.paragraph_format.space_after = Pt(1)
                    _add_inline_runs(p, piece)
                i += 1
                continue

        if stripped.startswith("- ") or stripped.startswith("• "):
            flush_para()
            while i < len(lines):
                item = lines[i].strip()
                if not (item.startswith("- ") or item.startswith("• ")):
                    break
                p = doc.add_paragraph(style="List Bullet")
                p.paragraph_format.space_after = Pt(1)
                _add_inline_runs(p, item[2:].strip())
                i += 1
            continue

        para_buf.append(stripped)
        i += 1

    flush_para()


def _add_section_heading(doc: Document, title: str, *, major: bool = True) -> None:
    p = doc.add_paragraph(style="Heading 1" if major else "Heading 2")
    _set_keep_with_next(p)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(8)
    run = p.add_run(title.upper() if major else title)
    run.font.name = "Times New Roman"
    run.font.size = Pt(18 if major else 14)
    run.font.color.rgb = RGBColor.from_string(_NAVY)
    run.bold = True
    run.underline = True


def _add_introduction_heading(doc: Document, title: str) -> None:
    """Reference-report Introduction title: one normal line below header, centered/underlined."""
    p = doc.add_paragraph()
    _set_keep_with_next(p)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Mm(4.5)
    p.paragraph_format.space_after = Mm(7)
    run = p.add_run((title or "INTRODUCTION").upper())
    run.font.name = "Times New Roman"
    run.font.size = Pt(16)
    run.font.color.rgb = RGBColor.from_string(_NAVY)
    run.bold = True
    run.underline = True


def _intro_plain(line: str) -> str:
    return (line or "").replace("**", "").strip()


def _intro_marker(line: str, marker: str) -> bool:
    return _intro_plain(line).rstrip(":").lower() == marker.lower()


def _intro_paragraph(
    doc: Document,
    text: str,
    *,
    alignment=WD_ALIGN_PARAGRAPH.LEFT,
    bold: bool = False,
    space_after_mm: float = 1.5,
    left_indent_mm: float = 0,
):
    p = doc.add_paragraph()
    p.alignment = alignment
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Mm(space_after_mm)
    if left_indent_mm:
        p.paragraph_format.left_indent = Mm(left_indent_mm)
    r = p.add_run(text)
    r.font.name = "Times New Roman"
    r.font.size = Pt(10.5)
    r.bold = bold
    return p


def _add_introduction(doc: Document, content: str) -> None:
    """Render introduction as a compact formal forensic letter without changing its text."""
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
        after_terms = [line for line in lines[terms_idx + 1:] if not re.match(r"^\d+\.\s", line)]
        signoff = after_terms[-2:] if len(after_terms) >= 2 else after_terms
        if signoff:
            terms = [line for line in terms if line not in signoff]

    if date_line:
        _intro_paragraph(doc, date_line, alignment=WD_ALIGN_PARAGRAPH.RIGHT, bold=True, space_after_mm=7)
    _intro_paragraph(doc, "To,", space_after_mm=0.6)
    for idx, line in enumerate(address):
        _intro_paragraph(doc, line, bold=idx == 0, space_after_mm=0.6)
    if address:
        doc.paragraphs[-1].paragraph_format.space_after = Mm(6)

    if subject_line:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Mm(7)
        match = re.match(r"^(Subject:)\s*(.*)$", subject_line, re.I)
        if match:
            r = p.add_run(match.group(1))
            r.bold = True
            r.font.name = "Times New Roman"
            r.font.size = Pt(10.5)
            r = p.add_run(" " + match.group(2))
        else:
            r = p.add_run(subject_line)
        r.font.name = "Times New Roman"
        r.font.size = Pt(10.5)

    for idx, line in enumerate(salutation):
        _intro_paragraph(
            doc,
            line,
            alignment=WD_ALIGN_PARAGRAPH.LEFT if idx == 0 and line.lower().startswith("dear") else WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_after_mm=2 if idx < len(salutation) - 1 else 5,
        )

    for block in (scope, terms):
        for idx, line in enumerate(block):
            is_label = (
                _intro_marker(line, "scope of work")
                or _intro_marker(line, "terms and condition")
                or _intro_marker(line, "terms and conditions")
            )
            is_numbered = bool(re.match(r"^\d+\.\s", line))
            _intro_paragraph(
                doc,
                line,
                alignment=WD_ALIGN_PARAGRAPH.LEFT if is_label or is_numbered else WD_ALIGN_PARAGRAPH.JUSTIFY,
                bold=is_label,
                space_after_mm=2 if is_label else 1.5,
                left_indent_mm=4 if is_numbered else 0,
            )
        if block and doc.paragraphs:
            doc.paragraphs[-1].paragraph_format.space_after = Mm(5)

    if signoff:
        spacer = doc.add_paragraph()
        spacer.paragraph_format.space_before = Mm(3)
        spacer.paragraph_format.space_after = Pt(0)
        for line in signoff:
            _intro_paragraph(doc, line, alignment=WD_ALIGN_PARAGRAPH.RIGHT, bold=True, space_after_mm=0.6)


def _add_cover(doc: Document, content: str, *, mobile: bool) -> None:
    # Keep the cover clean and centered while using the same letterhead chrome.
    title = "MOBILE FORENSIC ANALYSIS REPORT" if mobile else "CYBER FORENSIC ANALYSIS REPORT"
    subject = ""
    company = "POLARON TECHNOLOGIES PVT. LTD."
    for line in (content or "").splitlines():
        s = line.strip().replace("**", "").strip()
        if s.startswith("#"):
            continue
        if not s:
            continue
        if "TECHNOLOGIES" in s.upper():
            company = s
        elif not subject:
            subject = s.strip('"')
    for _ in range(4):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(12)
    run = p.add_run(title)
    run.bold = True
    run.font.name = "Times New Roman"
    run.font.size = Pt(22)
    run.font.color.rgb = RGBColor.from_string(_NAVY)
    if subject:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(f'"{subject}"')
        r.bold = True
        r.font.name = "Times New Roman"
        r.font.size = Pt(14)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(company)
    r.bold = True
    r.font.name = "Times New Roman"
    r.font.size = Pt(13)


def _add_artifact_summary_section(doc: Document, section: dict) -> bool:
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
                ],
            }
            for category in categories
        ]
    if not groups:
        return False
    for gi, group in enumerate(groups, 1):
        gp = doc.add_paragraph()
        gp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        gp.paragraph_format.space_before = Pt(4)
        gp.paragraph_format.space_after = Pt(6)
        gr = gp.add_run(f"{gi}. {_display_artifact_group_title(group.get('title') or 'Artifacts')}:")
        gr.bold = True
        gr.font.size = Pt(14)
        gr.font.name = "Times New Roman"
        try:
            gr.font.color.rgb = RGBColor(47, 111, 178)
        except Exception:
            pass
        for si, sub in enumerate(group.get("subcategories") or [], 1):
            name = _clean_export_text(sub.get("name") or "Artifact")
            count = sub.get("usage_count") if sub.get("usage_count") is not None else sub.get("count")
            count_text = "Reviewed" if isinstance(count, (int, float)) and count < 0 else _clean_export_text(count if count is not None else 0)
            desc = _clean_export_text(sub.get("description") or "Artifacts examined during forensic review.")

            p1 = doc.add_paragraph()
            p1.paragraph_format.left_indent = Inches(0.35)
            p1.paragraph_format.space_before = Pt(0)
            p1.paragraph_format.space_after = Pt(0)
            r1 = p1.add_run(f"{si}. {name}")
            r1.bold = True
            r1.font.name = "Times New Roman"
            r1.font.size = Pt(DEFAULT_FONT_SIZE)

            p2 = doc.add_paragraph()
            p2.paragraph_format.left_indent = Inches(0.35)
            p2.paragraph_format.space_before = Pt(0)
            p2.paragraph_format.space_after = Pt(0)
            r2a = p2.add_run("Count: ")
            r2a.bold = True
            r2a.font.name = "Times New Roman"
            r2a.font.size = Pt(DEFAULT_FONT_SIZE)
            r2b = p2.add_run(count_text)
            r2b.font.name = "Times New Roman"
            r2b.font.size = Pt(DEFAULT_FONT_SIZE)

            p3 = doc.add_paragraph()
            p3.paragraph_format.left_indent = Inches(0.35)
            p3.paragraph_format.space_before = Pt(0)
            p3.paragraph_format.space_after = Pt(8)
            r3a = p3.add_run("Description: ")
            r3a.bold = True
            r3a.font.name = "Times New Roman"
            r3a.font.size = Pt(DEFAULT_FONT_SIZE)
            r3b = p3.add_run(desc)
            r3b.font.name = "Times New Roman"
            r3b.font.size = Pt(DEFAULT_FONT_SIZE)
    return True


def build_report_docx(
    sections: list[dict],
    *,
    intake: dict | None = None,
    job_id: str = "",
    order: list[str] | None = None,
    mobile: bool = False,
) -> bytes:
    """Build an editable A4 DOCX with the same saved report content as the PDF."""
    doc = Document()
    _configure_styles(doc)
    for section in doc.sections:
        _configure_a4_section(section)

    section_map = {str(s.get("section_key")): s for s in sections}
    keys = list(order or section_map.keys())
    first_content = True
    hidden = {"limitations", "evidence_details"}

    for key in keys:
        if key in hidden:
            continue
        sec = section_map.get(key)
        if not sec:
            continue
        title = section_title(key, mobile=mobile)
        content = sec.get("content_md") or ""
        content = strip_redundant_section_heading(content, title)

        if key == "cover_page":
            _add_cover(doc, content, mobile=mobile)
            first_content = False
            continue

        # UI / TOC contract: every listed description starts on a fresh A4 page.
        if not first_content:
            doc.add_page_break()
        first_content = False

        # Use the report's formal section labels, not internal key names.  Introduction
        # is a reference-trained formal letter, not a generic markdown section.
        if key == "introduction":
            _add_introduction_heading(doc, title)
            _add_introduction(doc, content)
        else:
            _add_section_heading(doc, title, major=True)
            if key == 'table_of_contents':
                from app.services.report_export import _estimate_section_pages
                page=1
                rows=[]
                for other_key in keys:
                    if other_key in hidden or other_key not in section_map:
                        continue
                    if other_key not in {'cover_page','table_of_contents'}:
                        rows.append([str(len(rows)+1),section_title(other_key,mobile=mobile),str(page)])
                    page+=_estimate_section_pages(section_map[other_key],other_key)
                _add_table(doc,['Sr No','Description','Page'],rows)
                continue
            if key == 'suspicious_activity':
                from app.services.suspicious_activity import REVIEW_NOTE, card_lines, evidence_image_bytes
                cards=(sec.get('structured_json') or {}).get('suspicious_activity') or []
                for index,card in enumerate(cards):
                    if index:
                        doc.add_page_break()
                        _add_section_heading(doc,title,major=True)
                    for line in [REVIEW_NOTE]:
                        paragraph=doc.add_paragraph(line)
                        paragraph.paragraph_format.space_after=Pt(3)
                        for run in paragraph.runs:
                            run.font.size=Pt(8.5)
                    blob=evidence_image_bytes(card)
                    if blob:
                        from PIL import Image as PILImage
                        with PILImage.open(io.BytesIO(blob)) as image:
                            width,height=image.size
                        ratio=min(160/width,55/height)
                        doc.add_picture(io.BytesIO(blob),width=Mm(width*ratio),height=Mm(height*ratio))
                    for line in card_lines(card):
                        paragraph=doc.add_paragraph(line)
                        paragraph.paragraph_format.space_after=Pt(3)
                        paragraph.paragraph_format.line_spacing=1
                        for run in paragraph.runs:
                            run.font.size=Pt(8.5)
                if cards:
                    from app.services.suspicious_activity import examiner_observations
                    doc.add_page_break()
                    _add_section_heading(doc,title,major=True)
                    _add_markdown(doc,examiner_observations(sec))
                    continue
            if key == "artifact_summary" and _add_artifact_summary_section(doc, sec):
                continue
            if key == "objectives_procedure_observation" and _add_packed_opo(doc, content, section_title_text=title):
                continue
            if key in {"annexure", "final_analysis_summary", "os_information", "user_profile_information", "forensic_imaging"}:
                packed = _tables_from_section(sec)
                if packed:
                    _add_packed_tables(doc, packed, section_title_text=title)
                    continue
            _add_markdown(doc, content)

    # Remove the empty starter paragraph if it remains before a cover/title.
    if doc.paragraphs and not doc.paragraphs[0].text and len(doc.paragraphs) > 1:
        p = doc.paragraphs[0]._element
        p.getparent().remove(p)

    # Core properties are useful but do not expose internal HTML implementation.
    doc.core_properties.title = "Mobile Forensic Analysis Report" if mobile else "Cyber Forensic Analysis Report"
    doc.core_properties.subject = "Digital forensic examination report"
    doc.core_properties.author = "POLARON TECHNOLOGIES PVT. LTD."
    doc.core_properties.keywords = "forensic, digital evidence, report"

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
