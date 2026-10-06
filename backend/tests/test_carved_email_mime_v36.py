from __future__ import annotations

from email.message import EmailMessage

from app.services import carved_artifact_content as carved
from app.services.artifact_type_resolver import resolve_artifact_type
from app.services import signature_carve_inventory as sig


class _Db:
    def commit(self):
        return None

    def rollback(self):
        return None


def _eml() -> bytes:
    msg = EmailMessage()
    msg["From"] = "alice@example.com"
    msg["To"] = "bob@example.com"
    msg["Subject"] = "Recovered contract"
    msg["Date"] = "Sat, 27 Sep 2026 10:00:00 +0530"
    msg["Message-ID"] = "<recover-1@example.com>"
    msg.set_content("Recovered plain body")
    msg.add_alternative("<html><body><b>Recovered HTML body</b></body></html>", subtype="html")
    msg.add_attachment(b"%PDF-1.7\nattachment", maintype="application", subtype="pdf", filename="contract.pdf")
    return msg.as_bytes()


def test_extensionless_rfc822_is_resolved_as_email_not_text_plain() -> None:
    resolved = resolve_artifact_type(
        {"file_name": "f_000009", "file_path": "Cache_Data/f_000009", "metadata": {}},
        data=_eml()[:256 * 1024],
    )
    assert resolved.content_type == "message/rfc822"
    assert resolved.extension == ".eml"
    assert resolved.normalized_filename.endswith(".eml")


def test_carved_eml_preview_opens_headers_body_and_attachments(monkeypatch) -> None:
    raw = _eml()
    hit = {
        "id": "carve-eml-test",
        "kind": "eml",
        "source_path": "pagefile.sys",
        "source_artifact_id": None,
        "source_inode": None,
        "offset": 384893685,
        "max_size": 8_000_000,
    }
    monkeypatch.setattr(carved, "_hit_by_id", lambda *_a, **_k: dict(hit))
    monkeypatch.setattr(carved, "_read_hit_bytes", lambda *_a, **_k: raw + b"\x00trailing pagefile noise")

    preview = carved.build_carved_preview(_Db(), "job-1", "carve-eml-test")
    assert preview["content_type"] == "message/rfc822"
    assert preview["email"]["from"] == "alice@example.com"
    assert preview["email"]["to"] == "bob@example.com"
    assert preview["email"]["subject"] == "Recovered contract"
    assert "Recovered plain body" in preview["body_text"]
    assert "Recovered HTML body" in preview["body_html"]
    assert preview["attachment_count"] == 1
    assert preview["attachments"][0]["filename"] == "contract.pdf"
    assert preview["attachments"][0]["content_type"] == "application/pdf"


def test_carved_eml_attachment_endpoint_payload_is_real_attachment(monkeypatch) -> None:
    raw = _eml()
    hit = {
        "id": "carve-eml-test",
        "kind": "eml",
        "source_path": "pagefile.sys",
        "offset": 1000,
        "max_size": 8_000_000,
    }
    monkeypatch.setattr(carved, "_hit_by_id", lambda *_a, **_k: dict(hit))
    monkeypatch.setattr(carved, "_read_hit_bytes", lambda *_a, **_k: raw)
    preview = carved.build_carved_preview(_Db(), "job", "carve-eml-test")
    part_index = preview["attachments"][0]["part_index"]
    payload, content_type, filename = carved.load_carved_email_attachment(
        _Db(), "job", "carve-eml-test", part_index
    )
    assert payload.startswith(b"%PDF-1.7")
    assert content_type == "application/pdf"
    assert filename == "contract.pdf"


def test_signature_carve_records_real_unallocated_inode(monkeypatch) -> None:
    data = b"X" * 64 + _eml()
    hits = sig.scan_buffer_for_signatures(
        data,
        source_path="unallocated:inode:777",
        source_inode=777,
        base_offset=0,
    )
    eml_hits = [h for h in hits if h.get("kind") == "eml"]
    assert eml_hits
    assert eml_hits[0]["source_inode"] == 777
    assert eml_hits[0]["offset"] >= 0


def test_unknown_forensic_data_preview_is_inspectable_without_hex() -> None:
    from app.services.artifact_preview import _binary_preview_text

    text = _binary_preview_text(
        b"\x00\x01\xff" + b"ReadableEvidenceString123" + b"\x00" * 20,
        path="cache/f_000009",
    )
    assert "Forensic data inspector" in text
    assert "ReadableEvidenceString123" in text
    assert "hex" not in text.lower()


def test_carved_eml_record_uses_axiom_email_category(monkeypatch) -> None:
    hit = {
        "id": "carve-eml-test",
        "kind": "eml",
        "source_path": "pagefile.sys",
        "source_artifact_id": None,
        "source_inode": None,
        "offset": 42,
        "max_size": 8_000_000,
    }
    monkeypatch.setattr(carved, "_hit_by_id", lambda *_a, **_k: dict(hit))
    row = carved.carved_artifact_record(_Db(), "job", "carve-eml-test")
    assert row["axiom_category"] == "Email & Calendar"
    assert row["axiom_sub_category"] == "EML(X) Files"
