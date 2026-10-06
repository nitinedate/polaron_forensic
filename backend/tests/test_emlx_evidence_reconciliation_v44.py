"""Regression tests for EML(X) count/list/parser reconciliation (V44)."""

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from app.parsers import run_parser
from app.parsers.email_mime_parser import parse_email_file
from app.services import artifact_evidence_browse as browse
from app.services.handbook_query_sql import EML_EMLX_FILE_WHERE, EML_RFC822_ANY_WHERE


def _mail(*, attachment: bool = False) -> bytes:
    msg = MIMEMultipart()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Evidence subject"
    msg["Date"] = "Fri, 21 Feb 2025 13:00:00 +0000"
    msg["Message-ID"] = "<evidence-1@example.com>"
    msg.attach(MIMEText("Forensic email body", "plain"))
    if attachment:
        part = MIMEApplication(b"pdf evidence", _subtype="pdf")
        part.add_header("Content-Disposition", "attachment", filename="evidence.pdf")
        msg.attach(part)
    return msg.as_bytes()


def test_canonical_eml_predicate_includes_mime_metadata_and_excludes_outlook_derived() -> None:
    low_any = EML_RFC822_ANY_WHERE.lower()
    low_catalog = EML_EMLX_FILE_WHERE.lower()
    assert "message/rfc822" in low_any
    assert "email_mime_validated" in low_any
    assert "detected_extension" in low_any
    assert "derived_from_mailbox" in low_catalog
    assert "not in ('true','1','t')" in low_catalog


def test_extensionless_rfc822_uses_email_parser_not_file_meta() -> None:
    parser_name, records = run_parser(
        "/Users/examiner/Downloads/message_without_extension",
        _mail(attachment=True),
    )
    assert parser_name == "email_mime"
    by_type = {str(r.get("record_type")): r for r in records}
    assert by_type["email_message"]["subject"] == "Evidence subject"
    assert "Forensic email body" in by_type["email_message"]["body_text"]
    assert by_type["email_attachment"]["count"] == 1


def test_email_parse_record_contains_headers_body_and_attachment_metadata() -> None:
    records = parse_email_file(_mail(attachment=True), "sample.eml")
    msg = records[0]
    assert msg["record_type"] == "email_message"
    assert msg["from"] == "alice@example.com"
    assert msg["to"] == "bob@example.com"
    assert msg["subject"] == "Evidence subject"
    assert "Forensic email body" in msg["text"]
    assert msg["attachment_count"] == 1
    assert msg["attachments"][0]["filename"] == "evidence.pdf"


def test_mime_inventory_reads_zero_copy_sources_not_only_minio() -> None:
    source = Path("backend/app/services/email_mime_inventory.py").read_text()
    assert "iter_artifact_content" in source
    assert "WHERE job_id=:j AND minio_uri IS NOT NULL" not in source
    assert "email_mime_validated" in source
    assert "email_mime_attachments" in source


def test_email_attachment_virtual_row_is_openable_mime_part(monkeypatch) -> None:
    class _Db:
        def rollback(self):
            pass

    calls = {"n": 0}

    def fake_fetchall(_db, sql, _params):
        calls["n"] += 1
        if "jsonb_typeof(metadata->'email_mime_attachments')" in sql:
            return [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "file_path": "/mail/message.eml",
                    "file_name": "message.eml",
                    "created_at": "2025-02-21T13:00:00Z",
                    "metadata": {
                        "email_subject": "Evidence subject",
                        "email_mime_attachments": [
                            {
                                "part_index": 2,
                                "filename": "evidence.pdf",
                                "content_type": "application/pdf",
                                "size": 12,
                                "disposition": "attachment",
                                "inline": False,
                            }
                        ],
                    },
                }
            ]
        return []

    monkeypatch.setattr(browse, "fetchall", fake_fetchall)
    monkeypatch.setattr(
        "app.services.email_mime_inventory.scan_job_email_mime_inventory",
        lambda *_a, **_k: {"attachment_occurrences": 1},
    )
    monkeypatch.setattr(
        "app.services.signature_carve_inventory.list_carve_evidence",
        lambda *_a, **_k: {"items": [], "total": 0},
    )

    rows = browse._email_attachment_file_rows(_Db(), "job")
    assert len(rows) == 1
    row = rows[0]
    assert row["artifact_type"] == "email_attachment_part"
    assert row["title"] == "evidence.pdf"
    assert row["metadata"]["source_artifact_id"] == "11111111-1111-1111-1111-111111111111"
    assert row["metadata"]["part_index"] == 2
    assert row["metadata"]["content_type"] == "application/pdf"


def test_frontend_opens_virtual_mime_attachment_not_parent_message() -> None:
    source = Path("frontend/src/components/forensic/ArtifactBrowsePanel.tsx").read_text()
    assert 'evidenceKind === "email_attachment_part"' in source
    assert "openEmailAttachmentContent" in source
    assert "partIndex" in source
