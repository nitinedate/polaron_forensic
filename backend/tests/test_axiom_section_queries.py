"""Tests for AXIOM report section B query helpers."""

from app.services.axiom_section_queries import (
    EMAIL_ATTACHMENT_WHERE,
    EMLX_FILE_WHERE,
    LOGFILE_ANALYSIS_WHERE,
    OUTLOOK_MSG_WHERE,
    WEB_RELATED_WHERE,
)
from app.services.email_inventory import EMAIL_COLLECTORS


def test_axiom_query_fragments_are_non_empty() -> None:
    for fragment in (
        EMAIL_ATTACHMENT_WHERE,
        EMLX_FILE_WHERE,
        LOGFILE_ANALYSIS_WHERE,
        OUTLOOK_MSG_WHERE,
        WEB_RELATED_WHERE,
    ):
        assert "file_path" in fragment.lower()
        assert "job_id" not in fragment.lower()


def test_report_email_collectors_cover_axiom_section_items() -> None:
    required = {
        "email attachments",
        "eml(x) files",
        "windows mail",
        "outlook emails",
        "outlook tasks",
        "outlook contacts",
        "outlook appointments",
    }
    assert required.issubset(set(EMAIL_COLLECTORS.keys()))
