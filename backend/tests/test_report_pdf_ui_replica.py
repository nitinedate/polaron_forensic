import pytest

from app.services.report_export import _sections_html, store_preview_pdf
from app.services.report_markdown_html import A4_PRINT_CSS
from app.services.report_renderer import section_title


def _sample_sections():
    return [
        {
            "section_key": "cover_page",
            "content_md": '# CYBER FORENSIC ANALYSIS REPORT\n\n"Mr. Seger"\n\nPOLARON TECHNOLOGIES PVT. LTD.',
            "structured_json": {
                "title": "CYBER FORENSIC ANALYSIS REPORT",
                "subject": "Mr. Seger",
                "company": "POLARON TECHNOLOGIES PVT. LTD.",
            },
        },
        {
            "section_key": "table_of_contents",
            "content_md": "## TABLE OF CONTENTS\n",
        },
        {
            "section_key": "introduction",
            "content_md": (
                "## INTRODUCTION\n\n"
                "Date: 17/09/2026\n\n"
                "To,\nRRP Electronics\n\n"
                "Subject: Computer Forensic Extraction Report\n\n"
                "Dear Sir,\nThe examination was completed.\n"
            ),
        },
        {
            "section_key": "artifact_summary",
            "content_md": "## B. ARTIFACTS\n",
            "structured_json": {
                "catalog": {
                    "sections": [
                        {
                            "title": "Internet Activity",
                            "subcategories": [
                                {
                                    "name": "Web History",
                                    "usage_count": 1440,
                                    "description": "Browser history records examined during review.",
                                }
                            ],
                        }
                    ]
                }
            },
        },
        {
            "section_key": "annexure",
            "content_md": "## D. ANNEXURE\n\n| URL | Visits |\n| --- | --- |\n| https://www.youtube.com/ | 12 |\n",
            "structured_json": {
                "tables": [
                    {
                        "title": "Top Visited URLs",
                        "columns": ["URL", "Visits"],
                        "rows": [["https://www.youtube.com/", "12"]],
                    }
                ]
            },
        },
    ]


ORDER = [
    "cover_page",
    "table_of_contents",
    "introduction",
    "artifact_summary",
    "annexure",
]


def test_ui_section_titles_match_preview():
    assert section_title("cover_page") == "CYBER FORENSIC ANALYSIS REPORT"
    assert section_title("tools_used") == "TOOLS USED FOR ACQUISITION AND EXTRACTION"
    assert section_title("artifact_summary") == "B. ARTIFACTS"
    assert section_title("objectives_procedure_observation") == "C. OBJECTIVE, PROCEDURE & OBSERVATION"
    assert section_title("cover_page", mobile=True) == "MOBILE FORENSIC ANALYSIS REPORT"


def test_pdf_html_replicas_ui_pages_not_export_metadata():
    html = _sections_html(_sample_sections(), intake={"case_number": "CASE-1"}, job_id="job-99", order=ORDER)

    assert "Job ID" not in html
    assert "Generated:" not in html
    assert "Confidence:" not in html
    assert "Exported by Forensic Automation Platform" not in html
    assert "Forensic Examination Report" not in html

    assert "CYBER FORENSIC ANALYSIS REPORT" in html
    assert "Mr. Seger" in html
    assert "POLARON TECHNOLOGIES PVT. LTD." in html
    assert "TABLE OF CONTENTS" in html
    assert "Sr No" in html
    assert "B. ARTIFACTS" in html
    assert "Web History" in html
    assert "Count:" in html
    assert "1440" in html
    assert "Top Visited URLs" in html
    assert "youtube.com" in html.replace("\u200b", "")


def test_pdf_html_survives_null_artifact_categories():
    sections = _sample_sections()
    sections[3]["structured_json"] = {"catalog": {"sections": None}, "categories": None}
    html = _sections_html(sections, job_id="job-99", order=ORDER)
    assert "TABLE OF CONTENTS" in html
    assert "B. ARTIFACTS" in html


def test_store_preview_pdf_rejects_non_pdf():
    with pytest.raises(RuntimeError, match="not a valid PDF"):
        store_preview_pdf(None, "job", "run", b"<html>not a pdf</html>")


def test_pdf_print_css_matches_ui_table_and_page_chrome():
    assert "margin: 44mm 16mm 36mm 16mm" in A4_PRINT_CSS
    assert "min-height: 217mm" in A4_PRINT_CSS
    assert "background: #ffc000" in A4_PRINT_CSS
    assert "background: #d9e2f3" in A4_PRINT_CSS
    assert ".cover-page" in A4_PRINT_CSS
    assert ".toc-table" in A4_PRINT_CSS
    # xhtml2pdf justify concatenates words; fallback CSS must stay left-aligned.
    assert "text-align: justify" not in A4_PRINT_CSS
