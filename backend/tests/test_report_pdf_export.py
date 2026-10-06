import fitz

from app.services.report_pdf_export import build_report_pdf


def _intro_sections():
    return [
        {
            "section_key": "introduction",
            "content_md": (
                "## INTRODUCTION\n\n"
                "Date: 19/09/2026\n\n"
                "To,\nTest\n\n"
                "Subject: Computer Forensic Extraction Report\n\n"
                "Dear Sir,\n\n"
                "With reference to the above subject, I have received a request from you to "
                "conduct cyber forensic audit relating to general computer forensic. I have "
                "completed your case as per standard procedures; our analysis has been "
                "reported on 19/09/2026.\n\n"
                "Scope of Work:\n\n"
                "Conduct forensic extraction of devices (Ex-5 Histotechlab1 512GB).\n\n"
                "Terms and Condition:\n\n"
                "1. The report has indicated the status of recovered data.\n"
                "2. All data taken from devices will be destroyed immediately after the report submission.\n\n"
                "Digital Forensic Analyst\nPOLARON TECHNOLOGIES PVT. LTD."
            ),
        }
    ]


def _pdf_text(data: bytes) -> str:
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        return "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()


def test_pdf_keeps_word_spaces_and_is_real_text():
    data = build_report_pdf(_intro_sections(), order=["introduction"], mobile=False)
    assert data.startswith(b"%PDF")
    assert b"/Type /Font" in data or b"/Subtype /Type1" in data
    text = _pdf_text(data)
    glued = "".join(text.split())
    assert "Computer Forensic Extraction Report" in text
    assert "Dear Sir" in text
    assert "With reference to the above subject" in text
    assert "POLARON TECHNOLOGIES" in text
    # The glued form exists only after we strip spaces ourselves, never in the PDF text.
    assert "Computer Forensic Extraction Report" in text
    assert "Computerforensicextractionreport" not in text
    assert "DearSir" not in text
    assert "Ihavereceivedarequest" not in text
    assert "ComputerForensicExtractionReport" in glued


def test_pdf_analysis_summary_keeps_every_serial():
    sections = [
        {
            "section_key": "final_analysis_summary",
            "content_md": (
                "## E. ANALYSIS SUMMARY\n\n"
                "| Sr. No. | Objective | Procedure | Observation |\n"
                "| --- | --- | --- | --- |\n"
                "| 7 | Email Artifacts (Local Clients) | Email records were examined. | "
                "The examination identified 32 distinct email messages.\n"
                "| 8 | Event Logs & Timeline Reconstruction | Event logs were examined. | "
                "The examination identified 3,861 distinct log events.\n"
                "| 9 | File Access and Handling | Recent documents were examined. | "
                "Recent-file evidence identified 11 distinct file references.\n"
            ),
        }
    ]
    data = build_report_pdf(sections, order=["final_analysis_summary"], mobile=False)
    text = " ".join(_pdf_text(data).split())
    assert "Event Logs & Timeline Reconstruction" in text
    assert "8" in text
    assert "File Access and Handling" in text


def test_pdf_is_not_a_jpeg_page_scan():
    data = build_report_pdf(_intro_sections(), order=["introduction"], mobile=False)
    assert b"/DCTDecode" not in data
    assert b"DeviceRGB" not in data or b"/Type /Font" in data


def test_pdf_toc_descriptions_each_start_on_a_new_page():
    sections = [
        {
            "section_key": "introduction",
            "content_md": "## INTRODUCTION\n\nDear Sir,\n\nIntro ALPHA_ONLY.\n",
        },
        {
            "section_key": "scope_of_work",
            "content_md": "## SCOPE OF WORK\n\nScope BETA_ONLY.\n",
        },
        {
            "section_key": "tools_used",
            "content_md": "## TOOLS USED\n\nTools GAMMA_ONLY.\n",
        },
        {
            "section_key": "forensic_imaging",
            "content_md": "## FORENSIC IMAGING\n\nImaging DELTA_ONLY.\n",
        },
    ]
    data = build_report_pdf(
        sections,
        order=["introduction", "scope_of_work", "tools_used", "forensic_imaging"],
        mobile=False,
    )
    doc = fitz.open(stream=data, filetype="pdf")
    try:
        pages = [page.get_text() for page in doc]
    finally:
        doc.close()
    assert len(pages) >= 4
    intro_page = next(i for i, text in enumerate(pages) if "ALPHA_ONLY" in text)
    scope_page = next(i for i, text in enumerate(pages) if "BETA_ONLY" in text)
    tools_page = next(i for i, text in enumerate(pages) if "GAMMA_ONLY" in text)
    imaging_page = next(i for i, text in enumerate(pages) if "DELTA_ONLY" in text)
    assert intro_page < scope_page < tools_page < imaging_page
    assert "BETA_ONLY" not in pages[intro_page]
    assert "GAMMA_ONLY" not in pages[scope_page]
    assert "DELTA_ONLY" not in pages[tools_page]
