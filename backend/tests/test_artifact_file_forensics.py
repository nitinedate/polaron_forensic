"""Tests for deleted/modified/anomalous file forensics."""

from app.parsers.trash_info import is_trash_info_path, parse_trash_info
from app.services.artifact_file_forensics import (
    classify_file_row,
    detect_type_from_magic,
    filter_file_rows,
)


def test_detect_jpeg_and_pdf_magic():
    assert detect_type_from_magic("ffd8ffe000104a464946")[0] == ".jpg"
    assert detect_type_from_magic(None, head=b"%PDF-1.7...")[0] == ".pdf"


def test_extension_mismatch_and_extensionless():
    row = {
        "file_name": "invoice.pdf",
        "extension": ".pdf",
        "source_path": "/Users/x/Downloads/invoice.pdf",
        "metadata": {"magic_hex": "ffd8ffe000104a464946"},
    }
    out = classify_file_row(row)
    assert out["metadata"]["extension_mismatch"] is True
    assert out["metadata"]["detected_extension"] == ".jpg"
    assert out["metadata"]["is_anomalous"] is True

    empty = classify_file_row(
        {
            "file_name": "IMG_0001",
            "extension": "",
            "source_path": "/DCIM/IMG_0001",
            "metadata": {"magic_hex": "89504e470d0a1a0a0000"},
        }
    )
    assert empty["metadata"]["extensionless"] is True
    assert empty["metadata"]["detected_kind"] == "image"


def test_deleted_recycle_and_filter_tabs():
    rows = [
        {
            "file_name": "$RABCDEF.jpg",
            "extension": ".jpg",
            "source_path": "C:/$Recycle.Bin/S-1-5/$RABCDEF.jpg",
            "metadata": {
                "is_deleted": True,
                "deleted_at": "2026-08-01T10:00:00Z",
                "original_name": "secret.docx",
                "original_path": "C:/Users/a/Documents/secret.docx",
                "recovery_state": "recycle_bin",
                "magic_hex": "ffd8ffe00010",
            },
        },
        {
            "file_name": "notes.txt",
            "extension": ".txt",
            "source_path": "/home/u/notes.txt",
            "metadata": {},
        },
    ]
    deleted = filter_file_rows(rows, "deleted")
    assert len(deleted) == 1
    anomalous = filter_file_rows(rows, "anomalous")
    assert any(r["metadata"].get("extension_mismatch") for r in anomalous)
    modified = filter_file_rows(rows, "modified")
    assert len(modified) >= 1
    dated = filter_file_rows(rows, "with_dates")
    assert len(dated) == 1


def test_linux_trash_info_parser():
    path = "/home/u/.local/share/Trash/info/report.pdf.trashinfo"
    assert is_trash_info_path(path)
    data = b"[Trash Info]\nPath=/home/u/Documents/report.pdf\nDeletionDate=2026-08-05T14:22:11\n"
    recs = parse_trash_info(data, path)
    assert recs[0]["is_deleted"] is True
    assert recs[0]["recovery_state"] == "linux_trash"
    assert recs[0]["original_name"] == "report.pdf"
    assert recs[0]["original_extension"] == ".pdf"
    assert recs[0]["deleted_at"].startswith("2026-08-05")
