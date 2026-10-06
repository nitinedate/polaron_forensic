"""Markdown → HTML for A4 forensic report export (tables, headings, paragraphs)."""

from __future__ import annotations

import html
import re


def _is_table_sep(line: str) -> bool:
    s = line.strip()
    if not s.startswith("|"):
        return False
    return bool(re.match(r"^\|[\s\-:|]+\|\s*$", s))


def _parse_table_row(line: str) -> list[str]:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    return cells


def _inline_html(text: str) -> str:
    """Render the small inline-markdown subset emitted by report collectors."""
    escaped = html.escape(text or "")
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+?)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"<em>\1</em>", escaped)
    return escaped


from app.services.report_formation_agent import TABLE_PAGE_UNITS, chunk_table_rows, wrap_table_cell

TABLE_ROWS_PER_PAGE = TABLE_PAGE_UNITS


def _table_html(header: list[str], rows: list[list[str]]) -> str:
    parts = ["<table><thead><tr>"]
    for cell in header:
        parts.append(f"<th>{_inline_html(cell)}</th>")
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>")
        for cell in row:
            parts.append(f"<td>{_inline_html(wrap_table_cell(cell))}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def _render_table(header: list[str], rows: list[list[str]], *, title: str | None = None) -> str:
    body = rows or []
    chunks = chunk_table_rows(body)
    parts: list[str] = []
    for idx, chunk in enumerate(chunks):
        cls = "table-block" if idx == 0 else "table-block table-continued"
        parts.append(f"<div class='{cls}'>")
        if title:
            label = f"{title} (continued)" if idx else title
            parts.append(f"<h3>{html.escape(label)}</h3>")
        elif idx:
            parts.append("<h3>(continued)</h3>")
        parts.append(_table_html(header, chunk))
        parts.append("</div>")
    return "".join(parts)


def markdown_to_html(content: str) -> str:
    """Convert a subset of markdown used in forensic reports to print-friendly HTML."""
    if not content:
        return ""

    lines = content.replace("\r\n", "\n").split("\n")
    out: list[str] = []
    i = 0
    para_buf: list[str] = []
    opo_open = False
    in_observation = False
    last_opo_title = ""

    def flush_para() -> None:
        if not para_buf:
            return
        text = " ".join(para_buf).strip()
        if text:
            if in_observation:
                from app.services.report_observation_style import client_safe_observation

                text = client_safe_observation(text, title=last_opo_title)
            out.append(f"<p>{_inline_html(text)}</p>")
        para_buf.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            flush_para()
            i += 1
            continue

        if stripped.startswith("|") and i + 1 < len(lines) and _is_table_sep(lines[i + 1]):
            flush_para()
            header = _parse_table_row(stripped)
            i += 2
            body_rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|") and not _is_table_sep(lines[i]):
                body_rows.append(_parse_table_row(lines[i]))
                i += 1
            title = None
            if out and out[-1].startswith("<h3>"):
                title = html.unescape(re.sub(r"</?h3>", "", out[-1])).strip()
                out.pop()
            out.append(_render_table(header, body_rows, title=title or None))
            continue

        if stripped.startswith("### "):
            flush_para()
            heading = stripped[4:].strip()
            in_observation = False
            numbered = re.match(r"^\d+\.\s+(.+)", heading)
            if numbered:
                last_opo_title = numbered.group(1).strip()
            if opo_open:
                out.append("</div>")
                opo_open = False
            if numbered:
                out.append("<div class='opo-card'>")
                opo_open = True
            out.append(f"<h3>{html.escape(heading)}</h3>")
            i += 1
            continue

        if stripped.startswith("## "):
            flush_para()
            in_observation = False
            if opo_open:
                out.append("</div>")
                opo_open = False
            out.append(f"<h2>{html.escape(stripped[3:].strip())}</h2>")
            i += 1
            continue

        if stripped.startswith("# "):
            flush_para()
            in_observation = False
            if opo_open:
                out.append("</div>")
                opo_open = False
            out.append(f"<h1>{html.escape(stripped[2:].strip())}</h1>")
            i += 1
            continue

        if stripped.startswith("**") and stripped.endswith("**") and stripped.count("**") == 2:
            flush_para()
            label = stripped[2:-2].strip().rstrip(":").lower()
            if label.startswith("observation"):
                in_observation = True
            elif label.startswith("objective") or label.startswith("procedure") or label.startswith("status"):
                in_observation = False
            out.append(f"<p><strong>{html.escape(stripped[2:-2].strip())}</strong></p>")
            i += 1
            continue

        if stripped.startswith("- ") or stripped.startswith("• "):
            flush_para()
            items: list[str] = []
            while i < len(lines):
                item_line = lines[i].strip()
                if not (item_line.startswith("- ") or item_line.startswith("• ")):
                    break
                items.append(_inline_html(item_line[2:].strip()))
                i += 1
            out.append("<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>")
            continue

        if stripped.startswith(">"):
            flush_para()
            quote_lines: list[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote_lines.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append(f"<blockquote>{html.escape(' '.join(quote_lines))}</blockquote>")
            continue

        para_buf.append(stripped)
        i += 1

    flush_para()
    if opo_open:
        out.append("</div>")
    return "\n".join(out)


A4_PRINT_CSS = """
@page { size: A4 portrait; margin: 44mm 16mm 36mm 16mm; }
* { box-sizing: border-box; }
html, body {
  /* @page margins match the UI sheet: 44mm letterhead, 16mm sides,
     26mm footer + 10mm "Page N" band. */
  width: 100%;
  max-width: 100%;
  margin: 0;
  padding: 0;
}
body {
  font-family: 'Times New Roman', Times, Georgia, serif;
  font-size: 11pt;
  line-height: 1.5;
  color: #111;
}
.report-a4-sheet {
  width: 100%;
  /* Printable body is 297 - 44 - 36 = 217mm, same as the UI A4 content box. */
  min-height: 217mm;
  max-width: 100%;
  page-break-after: always;
  break-after: page;
  /* Allow long Objective/Procedure/Findings to flow; clipping hid observations. */
  overflow: visible;
}
.report-a4-sheet:last-child {
  page-break-after: auto;
  break-after: auto;
}
h1 { font-size: 18pt; color: #062d61; font-weight: bold; text-transform: uppercase; border: 0; padding: 0; page-break-after: avoid; }
h2 {
  font-size: 13.5pt;
  color: #082c5c;
  margin: 2mm 0 4mm;
  font-weight: bold;
  text-transform: uppercase;
  text-decoration: underline;
  text-underline-offset: 3px;
  page-break-after: avoid;
}
h1.no-break { page-break-after: avoid; }
h2.no-break { page-break-before: auto; }
h3 { font-size: 11.5pt; margin-top: 0.8em; page-break-after: avoid; }
.opo-card {
  /* Long O/P/O panels may use the remaining printable body before continuing.
     Keeping every card unbreakable caused large blank areas and extra pages. */
  page-break-inside: auto;
  break-inside: auto;
}
.opo-card > h3 { page-break-after: avoid; break-after: avoid; }
.opo-card > p > strong { page-break-after: avoid; break-after: avoid; }
.opo-card + .opo-card { margin-top: 0.8em; }
p { margin: 0.45em 0; text-align: left; line-height: 1.55; word-spacing: 0.12em; }
.observation p, h3 + p { line-height: 1.6; }
ul { margin: 0.4em 0 0.6em 1.2em; }
blockquote { margin: 0.6em 0; padding-left: 1em; border-left: 3px solid #ccc; color: #444; }
.table-block {
  /* A table is allowed to start in the remaining body space.  Individual rows are
     still kept together below, so this uses empty space without cutting a row. */
  page-break-inside: auto;
  break-inside: auto;
}
.table-continued { page-break-before: auto; break-before: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.6em 0 1em;
  font-size: 10pt;
  page-break-inside: auto;
  break-inside: auto;
}
thead { display: table-header-group; }
tr { page-break-inside: avoid; break-inside: avoid; }
th, td {
  border: 1px solid #000;
  padding: 4px 6px;
  text-align: left;
  vertical-align: top;
  overflow-wrap: break-word;
  word-break: break-word;
}
th { background: #ffc000; color: #000; font-weight: bold; text-align: center; }
tbody tr:nth-child(odd) { background: #d9e2f3; }
tbody tr:nth-child(even) { background: #fff; }
.meta { color: #444; font-size: 10pt; margin-bottom: 1em; }
.grade { font-style: italic; color: #666; font-size: 10pt; }
.cover-page {
  text-align: center;
  padding-top: 55mm;
}
.cover-page h1 {
  font-size: 18pt;
  letter-spacing: 0;
  margin: 0;
}
.cover-subject {
  margin-top: 14mm;
  font-size: 16pt;
  font-weight: bold;
  text-align: center !important;
}
.cover-company {
  margin-top: 14mm;
  font-size: 16pt;
  font-weight: bold;
  text-transform: uppercase;
  text-align: center !important;
}
.toc-table { border: 0; margin-top: 4mm; }
.toc-table th, .toc-table td { border: 0; padding: 6px 8px; }
.toc-table thead th {
  background: #fff;
  color: #082c5c;
  text-align: left;
  font-size: 9pt;
  text-transform: uppercase;
}
.toc-table tbody tr:nth-child(odd) { background: #f3f4f6; }
.toc-table tbody tr:nth-child(even) { background: #fff; }
.toc-table .toc-page { text-align: right; font-weight: bold; }
.toc-note { margin-top: 8mm; font-size: 9pt; font-style: italic; color: #64748b; text-align: left !important; }
.section-block { page-break-inside: auto; }
.section-block > h2 { page-break-after: avoid; page-break-inside: avoid; }
.introduction-page > h2,
.intro-title {
  margin: 5mm 0 7mm;
  padding: 0;
  border: 0;
  color: #15365b;
  font-size: 16pt;
  font-weight: bold;
  text-align: center;
  text-transform: uppercase;
  text-decoration: underline;
  line-height: 1.15;
}
.intro-letter {
  position: relative;
  margin: 0;
  padding: 0;
  font-size: 10.5pt;
  line-height: 1.35;
}
.intro-letter p { margin: 0 0 1.5mm; line-height: 1.35; }
.intro-letter .intro-date { text-align: right; font-weight: 600; margin: 0 0 7mm; }
.intro-address { margin: 0 0 6mm; }
.intro-address p { margin: 0 0 0.6mm; text-align: left; }
.intro-letter .intro-subject { margin: 0 0 7mm; text-align: center; font-weight: normal; }
.intro-subject strong { font-weight: bold; }
.intro-salutation { margin: 0 0 5mm; }
.intro-salutation p { text-align: left; word-spacing: 0.12em; }
.intro-scope, .intro-terms { margin: 0 0 5mm; }
.intro-label { margin: 0 0 2mm !important; font-weight: bold; text-align: left !important; }
.intro-numbered { margin-left: 4mm !important; text-align: left !important; }
.intro-signoff {
  margin-top: 8mm;
  text-align: right;
  font-weight: bold;
}
.intro-signoff p { margin: 0 0 0.5mm; text-align: right; }
.forensic-content table { page-break-inside: auto; }
.forensic-content table + table { margin-top: 1.2em; }
.footer {
  margin-top: 2em;
  font-size: 9pt;
  color: #666;
  border-top: 1px solid #ccc;
  padding-top: 0.6em;
}
"""
