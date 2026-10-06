"""PDF/DOCX export with defensibility manifest, parser versions, and CoC hooks.

HTML is an internal PDF-rendering detail only; it is not a downloadable report format.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import re
from datetime import datetime, timezone

from app.config import get_settings
from app.parsers import PARSER_VERSION
from app.services.report_renderer import SECTION_ORDER, section_order_for_job, section_title
from app.services.storage import put_bytes

log = logging.getLogger("report_export")

_EXPORT_MEDIA: dict[str, tuple[str, str]] = {
    "pdf": ("application/pdf", "pdf"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    "json": ("application/json", "json"),
    "package": ("application/json", "json"),
}

DOWNLOADABLE_REPORT_FORMATS = frozenset({"pdf", "docx"})
SUPPORTED_EXPORT_FORMATS = frozenset({"pdf", "docx", "json", "package"})


def _metadata_dict(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}




def _display_artifact_group_title(title: str) -> str:
    clean = str(title or "").strip()
    if clean == "Application Usage":
        return "Application Usages"
    return clean


def _artifact_groups_from_structured(structured: dict | None) -> list[dict]:
    structured = structured if isinstance(structured, dict) else {}
    catalog = structured.get("catalog") if isinstance(structured, dict) else {}
    groups = (catalog or {}).get("sections") if isinstance(catalog, dict) else []
    if isinstance(groups, list) and groups:
        return [group for group in groups if isinstance(group, dict)]
    categories = structured.get("categories") if isinstance(structured, dict) else []
    if not isinstance(categories, list):
        return []
    return [
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


_HIDDEN_UI_SECTIONS = frozenset({"limitations", "evidence_details"})

_UI_TOC_ROWS: tuple[tuple[str, str], ...] = (
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


def _section_structured(section: dict | None) -> dict:
    raw = (section or {}).get("structured_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    return raw if isinstance(raw, dict) else {}


def _cover_from_markdown(content: str, *, mobile: bool) -> dict[str, str]:
    title = "MOBILE FORENSIC ANALYSIS REPORT" if mobile else "CYBER FORENSIC ANALYSIS REPORT"
    subject = ""
    company = ""
    for line in (content or "").replace("\r\n", "\n").split("\n"):
        s = line.strip()
        if not s:
            continue
        if s.startswith("# "):
            title = s[2:].strip()
        elif s.startswith("**") and s.endswith("**"):
            subject = s[2:-2].strip().strip('"')
        elif not s.startswith("#") and not s.startswith("|") and not s.startswith("*"):
            company = s.replace("**", "").strip().strip('"')
    return {"title": title, "subject": subject, "company": company}


def _cover_html(section: dict, *, mobile: bool) -> str:
    structured = _section_structured(section)
    parsed = _cover_from_markdown(section.get("content_md") or "", mobile=mobile)
    title = str(structured.get("title") or parsed["title"] or section_title("cover_page", mobile=mobile))
    subject = str(structured.get("subject") or parsed["subject"] or "").strip()
    company = str(structured.get("company") or parsed["company"] or "").strip()
    parts = ["<div class='report-a4-sheet cover-page'>", f"<h1>{html.escape(title)}</h1>"]
    if subject:
        parts.append(f"<p class='cover-subject'>“{html.escape(subject)}”</p>")
    if company:
        parts.append(f"<p class='cover-company'>{html.escape(company)}</p>")
    parts.append("</div>")
    return "".join(parts)


def _structured_tables(section: dict) -> list[dict]:
    tables = _section_structured(section).get("tables") or []
    out: list[dict] = []
    for table in tables:
        if not isinstance(table, dict):
            continue
        columns = table.get("columns") or []
        if not columns:
            continue
        title = str(table.get("title") or "").strip()
        if (
            section.get("section_key") == "forensic_imaging"
            and title.lower() == "target drive details"
        ):
            continue
        out.append(table)
    return out


def _estimate_section_pages(section: dict, key: str) -> int:
    if key == 'suspicious_activity':
        cards = _section_structured(section).get('suspicious_activity') or []
        if cards:
            from app.services.suspicious_activity import examiner_observations
            notes = {'content_md': examiner_observations(section)}
            return len(cards) + _estimate_section_pages(notes, 'examiner_observations')
    if key in {"cover_page", "table_of_contents"}:
        return 1
    groups = _artifact_groups_from_structured(_section_structured(section)) if key == "artifact_summary" else []
    if groups:
        pages = 1
        used = 0
        for group in groups:
            cost = 2 + 2 * len(group.get("subcategories") or [])
            if used and used + cost > 24:
                pages += 1
                used = 0
            used += cost
        return max(1, pages)
    tables = _structured_tables(section)
    rows = sum(len(table.get("rows") or []) for table in tables)
    if rows:
        from app.services.report_formation_agent import TABLE_PAGE_UNITS, table_row_units

        pages = 1
        used = 3
        for table in tables:
            for row in table.get("rows") or []:
                cost = table_row_units(row)
                if used and used + cost > TABLE_PAGE_UNITS:
                    pages += 1
                    used = 3
                used += cost
        return max(1, pages)
    lines = [ln for ln in str(section.get("content_md") or "").splitlines() if ln.strip() and not ln.strip().startswith("|")]
    return max(1, (len(lines) + 25) // 26)


def _toc_html(sections: list[dict], *, order: list[str], mobile: bool) -> str:
    by_key = {str(s.get("section_key") or ""): s for s in sections}
    visible = [key for key in order if key in by_key and key not in _HIDDEN_UI_SECTIONS]
    page = 1
    starts: dict[str, int] = {}
    for key in visible:
        starts[key] = page
        page += _estimate_section_pages(by_key[key], key)
    rows = [(key,section_title(key,mobile=mobile)) for key in order if key not in {'cover_page','table_of_contents'}]
    parts = [
        "<div class='report-a4-sheet section-block'>",
        f"<h2>{html.escape(section_title('table_of_contents', mobile=mobile))}</h2>",
        "<table class='toc-table'><thead><tr><th>Sr No</th><th>Description</th><th>Page</th></tr></thead><tbody>",
    ]
    idx = 0
    for key, label in rows:
        if key not in starts:
            continue
        idx += 1
        parts.append(
            f"<tr><td>{idx}</td><td>{html.escape(label)}</td>"
            f"<td class='toc-page'>{starts[key]}</td></tr>"
        )
    parts.append("</tbody></table>")
    parts.append("<p class='toc-note'>Page numbers follow the live report preview layout.</p>")
    parts.append("</div>")
    return "".join(parts)


def _render_tables_html(tables: list[dict]) -> str:
    from app.services.report_markdown_html import _render_table

    parts: list[str] = []
    for table in tables:
        columns = [str(c) for c in (table.get("columns") or [])]
        rows = [[str(c) for c in (row or [])] for row in (table.get("rows") or [])]
        title = str(table.get("title") or "").strip() or None
        note = str(table.get("note") or "").strip()
        if note and not table.get("continued"):
            parts.append(f"<p class='toc-note'>{html.escape(note)}</p>")
        parts.append(_render_table(columns, rows, title=title))
    return "".join(parts)


def _render_artifact_summary_html(section: dict) -> str:
    groups = _artifact_groups_from_structured(_section_structured(section))
    if not groups:
        from app.services.report_markdown_html import markdown_to_html
        return markdown_to_html(section.get("content_md") or "")
    parts: list[str] = []
    for gi, group in enumerate(groups, 1):
        title = html.escape(_display_artifact_group_title(group.get("title") or "Artifacts"))
        parts.append(f'<div class="artifact-category"><h3>{gi}. {title}:</h3>')
        for si, sub in enumerate(group.get("subcategories") or [], 1):
            name = html.escape(str(sub.get("name") or "Artifact"))
            count = sub.get("usage_count")
            if count is None:
                count = sub.get("count")
            count_text = "Reviewed" if isinstance(count, (int, float)) and count < 0 else html.escape(str(count if count is not None else 0))
            desc = html.escape(str(sub.get("description") or "Artifacts examined during forensic review."))
            parts.append(
                '<div class="artifact-entry">'
                f'<div class="artifact-name">{si}. {name}</div>'
                f'<div class="artifact-count"><strong>Count:</strong> {count_text}</div>'
                f'<div class="artifact-description"><strong>Description:</strong> {desc}</div>'
                '</div>'
            )
        parts.append('</div>')
    return ''.join(parts)

def _safe_filename(value: str, *, max_len: int = 150) -> str:
    value = re.sub(r"[\\/:*?\"<>|]+", " ", value or "")
    value = re.sub(r"\s+", " ", value).strip(" .")
    return (value or "Forensic Report")[:max_len].rstrip(" .")


def _report_download_stem(intake: dict | None) -> str:
    """Human-friendly report filename such as ``RRP - Mr. Seger Forensic Report``."""
    intake = intake or {}
    org = str(intake.get("organization") or intake.get("requesting_agency") or "").strip()
    subject = ""
    raw_subjects = intake.get("subjects")
    if isinstance(raw_subjects, str):
        try:
            raw_subjects = json.loads(raw_subjects)
        except (json.JSONDecodeError, TypeError):
            raw_subjects = []
    if isinstance(raw_subjects, list) and raw_subjects and isinstance(raw_subjects[0], dict):
        subject = str(raw_subjects[0].get("name") or "").strip()
    if not subject:
        incident = f"{intake.get('incident_summary') or ''} {intake.get('background') or ''}"
        match = re.search(r"\b(Mr\.?\s+[A-Za-z][A-Za-z .'-]*|Mrs\.?\s+[A-Za-z][A-Za-z .'-]*)", incident)
        if match:
            subject = match.group(1).strip().rstrip(".,;:")
    prefix = " - ".join(b for b in (org, subject) if b)
    return _safe_filename(f"{prefix} Forensic Report" if prefix else "Forensic Report")


def export_download_filename(row: dict) -> tuple[str, str]:
    """Return browser filename and media type for a stored report export."""
    fmt = (row.get("format") or "bin").lower()
    media_type, ext = _EXPORT_MEDIA.get(fmt, ("application/octet-stream", fmt))
    meta = _metadata_dict(row.get("metadata"))
    preferred = str(meta.get("download_filename") or "").strip()
    if preferred:
        filename = _safe_filename(preferred)
        if not filename.lower().endswith(f".{ext}"):
            filename = f"{filename}.{ext}"
        return filename, media_type
    job_id = str(row.get("job_id") or "report")
    created = row.get("created_at")
    stamp = created.strftime("%Y%m%d-%H%M%S") if hasattr(created, "strftime") else "export"
    filename = f"forensic-report-{job_id[:8]}-{fmt}-{stamp}.{ext}"
    return filename, media_type


def _sections_md(
    sections: list[dict],
    *,
    intake: dict | None = None,
    order: list[str] | None = None,
    mobile: bool = False,
) -> str:
    lines = ["# Forensic Examination Report\n"]
    if mobile:
        lines = ["# MOBILE FORENSIC ANALYSIS REPORT\n"]
    if intake:
        if intake.get("case_number"):
            lines.append(f"**Case number:** {intake['case_number']}\n")
        if intake.get("requesting_agency"):
            lines.append(f"**Requesting agency:** {intake['requesting_agency']}\n")
        if intake.get("examiner_name"):
            lines.append(f"**Examiner:** {intake['examiner_name']}\n")
    for key in order or SECTION_ORDER:
        sec = next((s for s in sections if s.get("section_key") == key), None)
        if not sec:
            continue
        lines.append(f"\n## {section_title(key, mobile=mobile)}\n")
        lines.append(sec.get("content_md") or "")
        grade = sec.get("confidence_grade")
        if grade:
            lines.append(f"\n*Confidence: {grade}*\n")
    return "\n".join(lines)


def _add_markdown_to_docx(doc, content: str) -> None:
    """Write the saved draft into DOCX, keeping tables as real tables."""
    from app.services.report_markdown_html import _is_table_sep, _parse_table_row

    lines = (content or "").replace("\r\n", "\n").split("\n")
    i = 0
    para: list[str] = []

    def flush_para() -> None:
        text = " ".join(para).strip()
        para.clear()
        if text:
            doc.add_paragraph(text)

    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("|") and i + 1 < len(lines) and _is_table_sep(lines[i + 1]):
            flush_para()
            header = _parse_table_row(stripped)
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|") and not _is_table_sep(lines[i]):
                rows.append(_parse_table_row(lines[i]))
                i += 1
            cols = max(len(header), 1)
            table = doc.add_table(rows=1 + len(rows), cols=cols)
            for ci, cell in enumerate(header[:cols]):
                table.rows[0].cells[ci].text = cell
            for ri, row in enumerate(rows):
                for ci, cell in enumerate(row[:cols]):
                    table.rows[ri + 1].cells[ci].text = cell
            continue
        if not stripped:
            flush_para()
            i += 1
            continue
        if stripped.startswith("### "):
            flush_para()
            doc.add_heading(stripped[4:].strip(), level=2)
            i += 1
            continue
        if stripped.startswith("## "):
            flush_para()
            doc.add_heading(stripped[3:].strip(), level=2)
            i += 1
            continue
        para.append(stripped)
        i += 1
    flush_para()


def _introduction_html(content: str) -> str:
    """Render the reference-trained formal introduction letter.

    The saved text is not rewritten.  This function only assigns the same text to
    formal-letter layout regions learned from the supplied forensic reports.
    """

    def _plain(line: str) -> str:
        return line.replace("**", "").strip()

    def _is_marker(line: str, marker: str) -> bool:
        return _plain(line).rstrip(":").lower() == marker.lower()

    lines = [_plain(ln) for ln in content.replace("\r\n", "\n").split("\n")]
    lines = [ln for ln in lines if ln and not ln.startswith("##")]
    date_line = next((ln for ln in lines if ln.lower().startswith("date:")), "")
    subject_line = next((ln for ln in lines if ln.lower().startswith("subject:")), "")

    to_idx = next((i for i, ln in enumerate(lines) if _is_marker(ln, "to") or _is_marker(ln, "to,")), -1)
    subject_idx = next((i for i, ln in enumerate(lines) if ln.lower().startswith("subject:")), -1)
    dear_idx = next((i for i, ln in enumerate(lines) if ln.lower().startswith("dear sir")), -1)
    scope_idx = next((i for i, ln in enumerate(lines) if _is_marker(ln, "scope of work")), -1)
    terms_idx = next(
        (i for i, ln in enumerate(lines) if _is_marker(ln, "terms and condition") or _is_marker(ln, "terms and conditions")),
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
        ln for ln in lines[address_start:address_end]
        if ln != date_line and len(ln) <= 120 and not narrative_re.search(ln)
    ]

    salutation_end = scope_idx if scope_idx >= 0 else terms_idx if terms_idx >= 0 else len(lines)
    salutation_start = dear_idx if dear_idx >= 0 else subject_idx + 1 if subject_idx >= 0 else 0
    salutation = lines[salutation_start:salutation_end]

    scope = lines[scope_idx:terms_idx] if scope_idx >= 0 and terms_idx >= 0 else lines[scope_idx:] if scope_idx >= 0 else []
    terms = lines[terms_idx:] if terms_idx >= 0 else []

    signoff: list[str] = []
    if terms_idx >= 0:
        after_terms = [ln for ln in lines[terms_idx + 1:] if not re.match(r"^\d+\.\s", ln)]
        signoff = after_terms[-2:] if len(after_terms) >= 2 else after_terms
        if signoff:
            terms = [ln for ln in terms if ln not in signoff]

    def _subject_html(value: str) -> str:
        match = re.match(r"^(Subject:)\s*(.*)$", value, re.I)
        if not match:
            return html.escape(value)
        return f"<strong>{html.escape(match.group(1))}</strong> {html.escape(match.group(2))}"

    def _block(lines_: list[str], *, css_class: str) -> str:
        rendered: list[str] = [f"<div class='{css_class}'>"]
        for ln in lines_:
            plain = _plain(ln)
            if _is_marker(plain, "scope of work") or _is_marker(plain, "terms and condition") or _is_marker(plain, "terms and conditions"):
                rendered.append(f"<p class='intro-label'>{html.escape(plain)}</p>")
            elif re.match(r"^\d+\.\s", plain):
                rendered.append(f"<p class='intro-numbered'>{html.escape(plain)}</p>")
            else:
                rendered.append(f"<p>{html.escape(plain)}</p>")
        rendered.append("</div>")
        return "".join(rendered)

    parts = ["<div class='intro-letter'>"]
    if date_line:
        parts.append(f"<p class='intro-date'>{html.escape(date_line)}</p>")
    parts.append("<div class='intro-address'><p>To,</p>")
    if address:
        parts.extend(f"<p>{html.escape(ln)}</p>" for ln in address)
    parts.append("</div>")
    if subject_line:
        parts.append(f"<p class='intro-subject'>{_subject_html(subject_line)}</p>")
    if salutation:
        parts.append(_block(salutation, css_class="intro-salutation"))
    if scope:
        parts.append(_block(scope, css_class="intro-scope"))
    if terms:
        parts.append(_block(terms, css_class="intro-terms"))
    if signoff:
        parts.append("<div class='intro-signoff'>" + "".join(f"<p>{html.escape(s)}</p>" for s in signoff) + "</div>")
    parts.append("</div>")
    return "".join(parts)


def _sections_html(
    sections: list[dict],
    *,
    intake: dict | None = None,
    job_id: str = "",
    order: list[str] | None = None,
    mobile: bool = False,
) -> str:
    """Build the PDF HTML as a replica of the on-screen A4 report preview.

    Extra export-only chrome (Job ID, generation timestamp, confidence grades,
    platform footer) is omitted so the downloaded file matches the UI pages.
    """
    from app.services.report_markdown_html import A4_PRINT_CSS, markdown_to_html
    from app.services.report_renderer import strip_redundant_section_heading

    del intake, job_id  # UI report does not print these on the A4 sheets.

    report_title = "MOBILE FORENSIC ANALYSIS REPORT" if mobile else "CYBER FORENSIC ANALYSIS REPORT"
    artifact_css = (
        ".artifact-category { margin: 0 0 18px 0; } "
        ".artifact-category h3 { margin: 0 0 10px 0; color: #2f6fb2; font-size: 15pt; line-height: 1.2; "
        "text-transform: none; text-decoration: none; } "
        ".artifact-entry { margin: 0 0 14px 16px; } "
        ".artifact-name, .artifact-count, .artifact-description { font-size: 11pt; line-height: 1.4; color: #111; } "
        ".artifact-name, .artifact-count, .artifact-count strong, .artifact-description strong { font-weight: 700; }"
    )
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>{html.escape(report_title)}</title>",
        f"<style>{A4_PRINT_CSS}{artifact_css}</style>",
        "</head><body>",
    ]

    keys = list(order or SECTION_ORDER)
    first_section = True
    for key in keys:
        if key in _HIDDEN_UI_SECTIONS:
            continue
        sec = next((s for s in sections if s.get("section_key") == key), None)
        if not sec:
            continue
        title = section_title(key, mobile=mobile)
        body_content = strip_redundant_section_heading(sec.get("content_md") or "", title)
        h2_class = "no-break" if first_section else ""
        first_section = False

        if key == "cover_page":
            parts.append(_cover_html(sec, mobile=mobile))
            continue

        if key == "table_of_contents":
            parts.append(_toc_html(sections, order=keys, mobile=mobile))
            continue

        if key == "introduction":
            parts.append(
                f"<div class='report-a4-sheet section-block introduction-page'><h2 class='intro-title {h2_class}'>{html.escape(title)}</h2>"
                f"{_introduction_html(body_content)}</div>"
            )
            continue

        if key == "artifact_summary":
            artifact_html = _render_artifact_summary_html({**sec, "content_md": body_content})
            parts.append(
                f"<div class='report-a4-sheet section-block'><h2 class='{h2_class}'>{html.escape(title)}</h2>"
                f"{artifact_html}</div>"
            )
            continue

        if key == 'suspicious_activity' and _section_structured(sec).get('suspicious_activity'):
            from app.services.suspicious_activity import suspicious_html
            parts.append(suspicious_html(sec))
            continue

        tables = _structured_tables(sec)
        if tables and key != "introduction":
            # Same rule as the UI preview: tables come from structured_json;
            # leftover markdown table pipes are not reprinted as narrative.
            narrative_md = "\n".join(
                line for line in body_content.splitlines() if not line.strip().startswith("|")
            )
            narrative_html = markdown_to_html(narrative_md) if narrative_md.strip() else ""
            sheet_class = "forensic-content" if key == "forensic_imaging" else "section-block"
            parts.append(
                f"<div class='report-a4-sheet {sheet_class}'><h2 class='{h2_class}'>{html.escape(title)}</h2>"
                f"{narrative_html}{_render_tables_html(tables)}</div>"
            )
            continue

        body_html = markdown_to_html(body_content)
        sheet_class = "forensic-content" if key == "forensic_imaging" else "section-block"
        parts.append(
            f"<div class='report-a4-sheet {sheet_class}'><h2 class='{h2_class}'>{html.escape(title)}</h2>"
            f"<div>{body_html}</div></div>"
        )

    parts.append("</body></html>")
    return "".join(parts)


def _render_pdf(html_content: str) -> bytes | None:
    try:
        from xhtml2pdf import pisa  # type: ignore
        import io

        buf = io.BytesIO()
        pisa.CreatePDF(html_content, dest=buf, encoding="utf-8")
        if buf.tell() > 100:
            return buf.getvalue()
    except Exception as exc:
        log.warning("PDF render failed: %s", exc)
    return None


def _build_manifest(
    *,
    job_id: str,
    report_run_id: str,
    sections: list[dict],
    intake: dict | None,
    run_row: dict | None,
    parser_runs: list[dict],
    citations_count: int,
    file_hashes: dict[str, str],
) -> dict:
    settings = get_settings()
    return {
        "schema_version": "1.0",
        "job_id": job_id,
        "report_run_id": report_run_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "file_hashes_sha256": file_hashes,
        "parser_version": PARSER_VERSION,
        "parser_runs": parser_runs,
        "models": {
            "primary": run_row.get("primary_model") if run_row else settings.llm_primary_model,
            "review": run_row.get("review_model") if run_row else settings.llm_review_model,
            "fast": run_row.get("fast_model") if run_row else settings.llm_fast_model,
            "embedding": run_row.get("embedding_model") if run_row else settings.rag_embedding_model,
        },
        "sections": [
            {
                "section_key": s.get("section_key"),
                "confidence_grade": s.get("confidence_grade"),
                "primary_model": s.get("primary_model"),
                "review_model": s.get("review_model"),
                "review_passed": s.get("review_passed"),
            }
            for s in sections
        ],
        "citations_count": citations_count,
        "chain_of_custody": {
            "reference": (intake or {}).get("chain_of_custody_ref"),
            "evidence_received_date": str((intake or {}).get("evidence_received_date") or ""),
            "requesting_agency": (intake or {}).get("requesting_agency"),
            "case_number": (intake or {}).get("case_number"),
        },
        "vol18_intake": (intake or {}).get("vol18_form_json") or {},
    }


def store_preview_pdf(db, job_id: str, report_run_id: str, pdf_bytes: bytes) -> dict:
    """Store a PDF captured from the live UI A4 preview pages."""
    from app.db.sql_helpers import fetchone

    if not pdf_bytes or not pdf_bytes.startswith(b"%PDF"):
        raise RuntimeError("Preview PDF is not a valid PDF file")
    intake_row = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    intake = dict(intake_row) if intake_row else None
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    uri = put_bytes(f"exports/{job_id}/{report_run_id}/{ts}.pdf", pdf_bytes, "application/pdf")
    sha = hashlib.sha256(pdf_bytes).hexdigest()
    download_name = f"{_report_download_stem(intake)}.pdf"
    row = fetchone(
        db,
        """INSERT INTO report_exports (report_run_id, format, uri, sha256, metadata)
           VALUES (:rid, :fmt, :uri, :sha, CAST(:meta AS jsonb)) RETURNING id, created_at""",
        {
            "rid": report_run_id,
            "fmt": "pdf",
            "uri": uri,
            "sha": sha,
            "meta": json.dumps({
                "file_hashes": {"pdf": sha},
                "download_filename": download_name,
                "content_parity": "ui-a4-preview-pages",
            }),
        },
    )
    db.commit()
    return {"id": str(row["id"]), "format": "pdf", "uri": uri, "sha256": sha}


def export_report(db, job_id: str, report_run_id: str, *, fmt: str = "docx") -> dict:
    from app.db.sql_helpers import execute, fetchall, fetchone

    fmt = str(fmt or "docx").strip().lower()
    if fmt not in SUPPORTED_EXPORT_FORMATS:
        raise ValueError(f"Unsupported report export format: {fmt}. Use PDF or DOCX.")

    sections = fetchall(
        db,
        """SELECT section_key, title, content_md, structured_json, confidence_grade, primary_model, review_model, review_passed
           FROM report_sections WHERE report_run_id=:rid ORDER BY sort_order""",
        {"rid": report_run_id},
    )
    section_dicts = [dict(s) for s in sections]
    intake_row = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id})
    intake = dict(intake_row) if intake_row else None
    run_row = fetchone(db, "SELECT * FROM report_runs WHERE id=:id", {"id": report_run_id})
    parser_runs = fetchall(
        db,
        """SELECT parser_name, parser_version, files_processed, files_skipped, finished_at
           FROM parser_runs WHERE job_id=:jid ORDER BY finished_at DESC LIMIT 20""",
        {"jid": job_id},
    )
    cite_row = fetchone(
        db,
        """SELECT count(*) c FROM report_citations rc
           JOIN report_sections rs ON rs.id = rc.report_section_id
           WHERE rs.report_run_id=:rid""",
        {"rid": report_run_id},
    )
    citations_count = int(cite_row["c"]) if cite_row else 0

    # Mobile reports use MOBILE_SECTION_ORDER; disk/E01 keep SECTION_ORDER.
    from app.services.mobile_report_service import is_mobile_intake

    job_row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    mobile = is_mobile_intake(intake or {}, job_row)
    order = section_order_for_job(db, job_id) if job_id else list(SECTION_ORDER)

    # Formation Agent parity contract: PDF/DOCX are formed from the exact saved UI
    # section snapshot.  No export-only LLM/sanitizer may rewrite report prose.
    from app.services.report_formation_agent import FORMATION_AGENT_VERSION, snapshot_report

    formation_snapshot = snapshot_report(section_dicts, order=order)
    sha = formation_snapshot.sha256
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key_base = f"exports/{job_id}/{report_run_id}/{ts}"
    file_hashes: dict[str, str] = {}

    if fmt == "docx":
        from app.services.report_docx_export import build_report_docx

        data = build_report_docx(
            section_dicts, intake=intake, job_id=job_id, order=order, mobile=mobile,
        )
        if not data.startswith(b"PK"):
            raise RuntimeError("DOCX renderer did not produce a valid Office Open XML document")
        uri = put_bytes(
            f"{key_base}.docx",
            data,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        file_hashes["docx"] = hashlib.sha256(data).hexdigest()
    elif fmt == "pdf":
        # Native ReportLab text PDF (selectable / copyable).  xhtml2pdf is only
        # a fallback and must not rasterize pages as JPEG images.
        from app.services.report_pdf_export import build_report_pdf

        try:
            pdf_bytes = build_report_pdf(
                section_dicts, intake=intake, job_id=job_id, order=order, mobile=mobile,
            )
        except Exception as exc:
            log.warning("Native PDF render failed (%s); trying HTML fallback", exc)
            html_doc = _sections_html(
                section_dicts, intake=intake, job_id=job_id, order=order, mobile=mobile,
            )
            pdf_bytes = _render_pdf(html_doc)
        if not pdf_bytes:
            raise RuntimeError("PDF rendering failed; no PDF file was created")
        from app.services.report_letterhead import apply_forensic_letterhead

        pdf_bytes = apply_forensic_letterhead(pdf_bytes)
        if not pdf_bytes.startswith(b"%PDF"):
            raise RuntimeError("PDF renderer returned an invalid PDF file")
        uri = put_bytes(f"{key_base}.pdf", pdf_bytes, "application/pdf")
        file_hashes["pdf"] = hashlib.sha256(pdf_bytes).hexdigest()
    elif fmt == "json":
        manifest = _build_manifest(
            job_id=job_id,
            report_run_id=report_run_id,
            sections=section_dicts,
            intake=intake,
            run_row=dict(run_row) if run_row else None,
            parser_runs=[dict(p) for p in parser_runs],
            citations_count=citations_count,
            file_hashes=file_hashes,
        )
        data = json.dumps(manifest, indent=2, default=str).encode("utf-8")
        uri = put_bytes(f"{key_base}.manifest.json", data, "application/json")
        file_hashes["manifest.json"] = hashlib.sha256(data).hexdigest()
    elif fmt == "package":
        return export_defensibility_package(db, job_id, report_run_id)
    else:
        raise ValueError(f"Unsupported report export format: {fmt}")

    download_name = f"{_report_download_stem(intake)}.{_EXPORT_MEDIA.get(fmt, ('application/octet-stream', fmt))[1]}"
    row = fetchone(
        db,
        """INSERT INTO report_exports (report_run_id, format, uri, sha256, metadata)
           VALUES (:rid, :fmt, :uri, :sha, CAST(:meta AS jsonb)) RETURNING id, created_at""",
        {
            "rid": report_run_id,
            "fmt": fmt,
            "uri": uri,
            "sha": sha,
            "meta": json.dumps({
                "file_hashes": file_hashes,
                "download_filename": download_name,
                "ui_content_sha256": formation_snapshot.sha256,
                "formation_agent_version": FORMATION_AGENT_VERSION,
                "content_parity": "saved-ui-sections",
            }),
        },
    )
    db.commit()
    return {"id": str(row["id"]), "format": fmt, "uri": uri, "sha256": sha}


def export_defensibility_package(db, job_id: str, report_run_id: str) -> dict:
    """Export DOCX + PDF + manifest as a defensibility bundle (no HTML report)."""
    results = {}
    for fmt in ("docx", "pdf", "json"):
        results[fmt] = export_report(db, job_id, report_run_id, fmt=fmt)

    bundle = {
        "job_id": job_id,
        "report_run_id": report_run_id,
        "formats": results,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    bundle_bytes = json.dumps(bundle, indent=2).encode("utf-8")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle_uri = put_bytes(
        f"exports/{job_id}/{report_run_id}/{ts}/bundle.json",
        bundle_bytes,
        "application/json",
    )
    from app.db.sql_helpers import fetchone

    row = fetchone(
        db,
        """INSERT INTO report_exports (report_run_id, format, uri, sha256, manifest_uri, metadata)
           VALUES (:rid, 'package', :uri, :sha, :uri, CAST(:meta AS jsonb)) RETURNING id""",
        {
            "rid": report_run_id,
            "uri": bundle_uri,
            "sha": hashlib.sha256(bundle_bytes).hexdigest(),
            "meta": json.dumps({"formats": list(results.keys())}),
        },
    )
    db.commit()
    return {
        "id": str(row["id"]),
        "format": "package",
        "uri": bundle_uri,
        "sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "formats": results,
    }
