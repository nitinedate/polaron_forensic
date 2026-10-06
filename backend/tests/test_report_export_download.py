"""Tests for forensic report export download helpers."""

from datetime import datetime, timezone

from app.services.report_export import (
    DOWNLOADABLE_REPORT_FORMATS,
    SUPPORTED_EXPORT_FORMATS,
    _report_download_stem,
    export_download_filename,
)


def test_export_download_filename_pdf_legacy_row():
    row = {
        "format": "pdf",
        "uri": "s3://bucket/exports/job/run/file.pdf",
        "job_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "created_at": datetime(2026, 7, 20, 7, 0, 0, tzinfo=timezone.utc),
    }
    filename, media_type = export_download_filename(row)
    assert filename.endswith(".pdf")
    assert "pdf" in filename
    assert media_type == "application/pdf"


def test_export_download_filename_uses_human_friendly_metadata():
    row = {
        "format": "docx",
        "metadata": {"download_filename": "RRP - Mr. Seger Forensic Report.docx"},
        "job_id": "job-id",
        "created_at": datetime(2026, 9, 16, tzinfo=timezone.utc),
    }
    filename, media_type = export_download_filename(row)
    assert filename == "RRP - Mr. Seger Forensic Report.docx"
    assert media_type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_store_preview_pdf_rejects_html_bytes():
    from app.services.report_export import store_preview_pdf

    try:
        store_preview_pdf(None, "job", "run", b"<html></html>")
        assert False, "expected invalid preview PDF to fail"
    except RuntimeError as exc:
        assert "valid PDF" in str(exc)


def test_pdf_never_falls_back_to_html_filename():
    row = {
        "format": "pdf",
        "uri": "file:///tmp/exports/job/run/file.pdf.html",
        "job_id": "job-id",
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    filename, media_type = export_download_filename(row)
    assert filename.endswith(".pdf")
    assert not filename.endswith(".html")
    assert media_type == "application/pdf"


def test_report_download_stem_uses_case_org_and_subject():
    intake = {
        "requesting_agency": "RRP",
        "subjects": [{"name": "Mr. Seger"}],
    }
    assert _report_download_stem(intake) == "RRP - Mr. Seger Forensic Report"


def test_html_is_not_a_report_download_format():
    assert DOWNLOADABLE_REPORT_FORMATS == {"pdf", "docx"}
    assert "html" not in SUPPORTED_EXPORT_FORMATS
