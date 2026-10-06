"""Tests for EML/EMLX MIME discovery and attachment occurrence counting."""

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.parsers.email_mime_parser import (
    analyze_mime_message,
    extract_rfc_message_bytes,
    is_extensionless_email_candidate,
    parse_email_file,
)
from app.services.email_inventory import count_email_attachments, count_eml_files


def _sample_multipart_eml(*, attachments: int = 2) -> bytes:
    msg = MIMEMultipart()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test"
    msg["Message-ID"] = "<test-123@example.com>"
    msg.attach(MIMEText("Hello body", "plain"))
    for i in range(attachments):
        part = MIMEApplication(b"payload-%d" % i, _subtype="pdf")
        part.add_header("Content-Disposition", "attachment", filename=f"doc{i}.pdf")
        msg.attach(part)
    return msg.as_bytes()


def test_extract_emlx_embedded_message() -> None:
    rfc = _sample_multipart_eml(attachments=1)
    emlx = f"{len(rfc)}\n".encode("ascii") + rfc + b"\ntrailer"
    extracted = extract_rfc_message_bytes(emlx, "/Users/x/Library/Mail/V10/Messages/1.emlx")
    assert extracted == rfc


def test_analyze_mime_message_counts_attachments() -> None:
    info = analyze_mime_message(_sample_multipart_eml(attachments=3), "mail.eml")
    assert info["parse_ok"] is True
    assert info["message_occurrences"] == 1
    assert info["attachment_occurrences"] == 3
    assert info["unique_attachment_content"] == 3


def test_extensionless_candidate_requires_three_headers() -> None:
    assert is_extensionless_email_candidate(b"From: a@b.com\nTo: c@d.com\nSubject: x\n\nbody") is True
    assert is_extensionless_email_candidate(b"From: a@b.com\nTo: c@d.com\n\nbody") is False


def test_parse_email_file_records() -> None:
    records = parse_email_file(_sample_multipart_eml(attachments=2), "x.eml")
    types = {r["record_type"]: r for r in records}
    assert types["email_message"]["count"] == 1
    assert types["email_attachment"]["count"] == 2


def test_count_email_attachments_sums_browseable_path_and_mime(monkeypatch) -> None:
    class _Db:
        pass

    monkeypatch.setattr("app.services.email_inventory._count_sql", lambda *_a, **_k: 7)
    monkeypatch.setattr(
        "app.services.email_inventory._count_email_calendar_attachment_paths",
        lambda *_a, **_k: 7,
    )
    monkeypatch.setattr(
        "app.services.email_inventory._count_parsed_records",
        lambda *_a, **_k: 0,
    )
    monkeypatch.setattr(
        "app.services.email_inventory._sample_sql",
        lambda *_a, **_k: [],
    )
    monkeypatch.setattr(
        "app.services.email_mime_inventory.scan_job_email_mime_inventory",
        lambda *_a, **_k: {"attachment_occurrences": 15, "parse_failures": 0},
    )
    result = count_email_attachments(_Db(), "job")
    assert result["count"] == 22
    assert result["mime_attachment_occurrences"] == 15


def test_count_eml_files_reconciles_to_browseable_rows(monkeypatch) -> None:
    class _Db:
        pass

    monkeypatch.setattr("app.services.email_inventory._count_sql", lambda *_a, **_k: 12)
    monkeypatch.setattr("app.services.email_inventory._sample_sql", lambda *_a, **_k: [])
    monkeypatch.setattr(
        "app.services.email_mime_inventory.scan_job_email_mime_inventory",
        lambda *_a, **_k: {
            "message_occurrences": 12,
            "extensionless_messages": 3,
            "eml_emlx_files_scanned": 9,
            "mime_rows_promoted": 3,
            "parse_failures": 0,
        },
    )
    result = count_eml_files(_Db(), "job")
    assert result["count"] == 12
    assert result["filtered_files"] == 12
    assert result["extensionless_messages"] == 3
