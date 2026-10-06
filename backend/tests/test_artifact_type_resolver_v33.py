from __future__ import annotations

from app.services.artifact_type_resolver import (
    FORENSIC_DATA_MIME,
    resolve_artifact_type,
)
from app.services.artifact_preview import _artifact_filename_and_type, _binary_preview_text


def _row(name: str, path: str | None = None, ext: str = "") -> dict:
    return {
        "file_name": name,
        "file_path": path or f"/evidence/{name}",
        "extension": ext,
        "metadata": {},
    }


def test_ntfs_metadata_names_get_forensic_types_not_octet_stream() -> None:
    expected = {
        "$AttrDef": "application/x-ntfs-attrdef",
        "$MFT": "application/x-ntfs-mft",
        "$Bitmap": "application/x-ntfs-bitmap",
        "$Boot": "application/x-ntfs-boot",
        "$ObjId": "application/x-ntfs-objid",
        "$Quota": "application/x-ntfs-quota",
        "$Reparse": "application/x-ntfs-reparse",
        "$Repair": "application/x-ntfs-repair",
        "$Tops": "application/x-ntfs-tops",
    }
    for name, mime in expected.items():
        resolved = resolve_artifact_type(_row(name, f"/$Extend/{name}"))
        assert resolved.content_type == mime
        assert "octet-stream" not in resolved.content_type
        assert resolved.label


def test_windows_registry_hive_is_identified_from_path() -> None:
    resolved = resolve_artifact_type(
        _row("SYSTEM", "/Windows/System32/config/SYSTEM")
    )
    assert resolved.content_type == "application/x-windows-registry"
    assert resolved.label == "Windows Registry hive"


def test_extensionless_pdf_gets_pdf_type_and_download_extension() -> None:
    resolved = resolve_artifact_type(_row("recovered-file"), data=b"%PDF-1.7\n")
    assert resolved.content_type == "application/pdf"
    assert resolved.normalized_filename.endswith(".pdf")


def test_generic_bin_is_renamed_when_magic_identifies_pdf() -> None:
    resolved = resolve_artifact_type(_row("report.bin", ext=".bin"), data=b"%PDF-1.5\n")
    assert resolved.normalized_filename == "report.pdf"
    assert resolved.content_type == "application/pdf"


def test_extensionless_sqlite_gets_database_type() -> None:
    resolved = resolve_artifact_type(
        _row("History"), data=b"SQLite format 3\x00" + b"\x00" * 64
    )
    assert resolved.content_type == "application/vnd.sqlite3"
    assert resolved.normalized_filename.endswith(".db")


def test_extensionless_evtx_gets_event_log_type() -> None:
    resolved = resolve_artifact_type(_row("event-data"), data=b"ElfFile\x00" + b"\x00" * 64)
    assert resolved.content_type == "application/x-ms-evtx"
    assert resolved.normalized_filename.endswith(".evtx")


def test_docx_extension_preserves_specific_office_mime_even_with_zip_signature() -> None:
    data = b"PK\x03\x04" + b"word/document.xml" + b"\x00" * 64
    resolved = resolve_artifact_type(_row("contract.docx", ext=".docx"), data=data)
    assert "wordprocessingml" in resolved.content_type
    assert resolved.extension == ".docx"


def test_mime_metadata_creates_proper_file_extension() -> None:
    resolved = resolve_artifact_type({
        "file_name": "attachment",
        "file_path": "/mail/attachment",
        "extension": "",
        "metadata": {"content_type": "application/pdf"},
    })
    assert resolved.content_type == "application/pdf"
    assert resolved.normalized_filename == "attachment.pdf"
    assert resolved.label == "PDF document"


def test_unknown_data_uses_forensic_data_type_not_octet_stream() -> None:
    resolved = resolve_artifact_type(_row("opaque.bin", ext=".bin"), data=b"\x00\x01\x02\x03\xff" * 20)
    assert resolved.content_type == FORENSIC_DATA_MIME
    assert "octet-stream" not in resolved.content_type
    assert "unrecognized" in resolved.label.lower()


def test_download_filename_and_type_use_resolver() -> None:
    filename, content_type = _artifact_filename_and_type(
        _row("carved.bin", ext=".bin"), head=b"\xff\xd8\xff\xe0" + b"\x00" * 64
    )
    assert filename == "carved.jpg"
    assert content_type == "image/jpeg"


def test_unknown_preview_never_calls_it_binary_or_hex_dump() -> None:
    text = _binary_preview_text(b"\x00\x01\xff" * 40, path="unknown.bin")
    assert "Binary file" not in text
    assert "hex dump" not in text.lower()
    assert "Forensic data file" in text


def test_media_properties_exposes_human_type_and_mime(monkeypatch) -> None:
    from app.services import artifact_media_properties as props

    row = {
        "id": "a1",
        "job_id": "j1",
        "file_name": "$AttrDef",
        "file_path": "/$AttrDef",
        "extension": "",
        "size_bytes": 2560,
        "sha256": "x",
        "metadata": {},
    }
    monkeypatch.setattr(props, "_load_artifact_row", lambda *_a, **_k: row)
    monkeypatch.setattr(props, "iter_artifact_content", lambda *_a, **_k: iter([b"\x00\x01\x02\x03" * 64]))
    monkeypatch.setattr(props, "fetchone", lambda *_a, **_k: None)
    result = props.get_artifact_media_properties(object(), "j1", "a1")
    assert result["content_type"] == "application/x-ntfs-attrdef"
    assert result["type_label"] == "NTFS Attribute Definitions"
    assert result["file_name"].endswith(".ntfs-attrdef")
