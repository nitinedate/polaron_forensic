"""Structured email preview for artifact browse."""

from __future__ import annotations

from email.message import EmailMessage

from app.parsers import email_mime_parser as em
from app.services import artifact_preview


class _FakeDb:
    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None


def _sample_eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Quarterly report"
    msg["Date"] = "Mon, 1 Jan 2024 12:00:00 +0000"
    msg.set_content("Plain body text")
    msg.add_attachment(b"pdf-bytes", maintype="application", subtype="pdf", filename="report.pdf")
    return msg.as_bytes()


def test_build_email_preview_details_parses_headers_and_attachments() -> None:
    details = em.build_email_preview_details(_sample_eml(), "Mail/Inbox/message.eml")
    assert details["parse_ok"] is True
    assert details["headers"]["from"] == "sender@example.com"
    assert details["headers"]["subject"] == "Quarterly report"
    assert "Plain body text" in details["body_text"]
    assert len(details["attachments"]) == 1
    assert details["attachments"][0]["filename"] == "report.pdf"
    assert details["attachments"][0]["size"] == len(b"pdf-bytes")


def test_load_mime_part_bytes_returns_attachment_payload() -> None:
    raw = _sample_eml()
    details = em.build_email_preview_details(raw, "message.eml")
    part_index = details["attachments"][0]["part_index"]
    payload, content_type, filename = em.load_mime_part_bytes(raw, "message.eml", part_index)
    assert payload == b"pdf-bytes"
    assert filename == "report.pdf"
    assert "pdf" in content_type


def test_build_artifact_preview_includes_email_block(monkeypatch) -> None:
    row = {
        "id": "a1",
        "file_path": "Mail/Inbox/message.eml",
        "file_name": "message.eml",
        "extension": ".eml",
        "minio_uri": None,
        "metadata": {},
    }
    raw = _sample_eml()

    monkeypatch.setattr(artifact_preview, "_load_artifact_row", lambda db, jid, aid: row)
    monkeypatch.setattr(artifact_preview, "resolve_artifact_bytes", lambda *args, **kwargs: raw)
    monkeypatch.setattr(artifact_preview, "_link_attachment_artifacts", lambda db, jid, path, atts: atts)

    preview = artifact_preview.build_artifact_preview(_FakeDb(), "job", "a1")
    assert preview["email"]["subject"] == "Quarterly report"
    assert preview["body_text"]
    assert preview["attachments"][0]["filename"] == "report.pdf"
    assert preview["attachment_count"] == 1
