"""Portable ZIP package inventory + virtual disk zip reads (Aetheris layout)."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.mobile_forensic.package_inventory import (
    collect_portable_package_inventory,
    is_portable_zip_archive,
)
from app.services.virtual_disk import (
    VirtualDisk,
    enumerate_all_files,
    is_portable_zip_archive as vd_is_portable,
    read_full_file_from_disk,
    resolve_zip_archive_member,
)


def _make_msgstore_bytes() -> bytes:
    path = Path(tempfile.mkstemp(suffix=".db")[1])
    try:
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, text TEXT)")
        cur.executemany("INSERT INTO message(text) VALUES (?)", [("a",), ("b",), ("c",)])
        cur.execute("CREATE TABLE chat (id INTEGER PRIMARY KEY, jid TEXT)")
        cur.execute("INSERT INTO chat(jid) VALUES ('x@s.whatsapp.net')")
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def test_is_portable_zip_for_aetheris_pas_zip(tmp_path: Path) -> None:
    payload = _make_msgstore_bytes()
    for ext in (".zip", ".pas"):
        archive = tmp_path / f"run{ext}"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("data/data/com.whatsapp/databases/msgstore.db", payload)
            zf.writestr("DCIM/Camera/photo.jpg", b"\xff\xd8\xff\xd9")
        assert is_portable_zip_archive(archive)
        assert vd_is_portable(archive)


def test_enumerate_expands_zip_and_reads_member(tmp_path: Path) -> None:
    payload = _make_msgstore_bytes()
    archive = tmp_path / "case.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("Dump/data/data/com.whatsapp/databases/msgstore.db", payload)
        zf.writestr("Dump/media/photo.jpg", b"\xff\xd8\xff\xd9")

    vd = VirtualDisk(
        job_id="j1",
        mode="folder",
        segment_paths=[str(archive)],
        format="mobile",
        root_folder=str(tmp_path),
    )
    nodes = enumerate_all_files(vd)
    paths = {n["path"] for n in nodes}
    assert any(p.endswith("msgstore.db") for p in paths)
    assert any(p.endswith("photo.jpg") for p in paths)

    member_path = next(p for p in paths if p.endswith("msgstore.db"))
    split = resolve_zip_archive_member(tmp_path, member_path)
    assert split is not None
    data = read_full_file_from_disk(vd, member_path)
    assert data[:16].startswith(b"SQLite format")


def test_extensionless_ios_backup_blob_is_not_a_package(tmp_path: Path) -> None:
    blob = tmp_path / "aabbccddeeff00112233445566778899aabbccdd"
    with zipfile.ZipFile(blob, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("src/app.py", "print(1)\n")
    assert not is_portable_zip_archive(blob)
    assert not vd_is_portable(blob)
    real_zip = tmp_path / "export.zip"
    with zipfile.ZipFile(real_zip, "w") as zf:
        zf.writestr("ORIGINAL_PATH.txt", str(tmp_path / "original"))
    assert vd_is_portable(real_zip)


def test_enumerate_sealed_ios_image_does_not_unzip_inner_office_zips(tmp_path: Path) -> None:
    original = tmp_path / "CASE_RUN"
    hashed = original / "ios_image" / "UDID"
    hashed.mkdir(parents=True)
    blob = hashed / "aabbccddeeff00112233445566778899aabbccdd"
    with zipfile.ZipFile(blob, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("nested/src/app.py", "print(1)\n")
    (hashed / "Manifest.plist").write_bytes(b"plist")
    archive = tmp_path / "intake" / "case.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ORIGINAL_PATH.txt", str(original))
        zf.writestr("aetheris_package.json", json.dumps({"original_path": str(original)}))

    vd = VirtualDisk(
        job_id="j-ios",
        mode="folder",
        segment_paths=[str(archive)],
        format="zip",
        root_folder=str(archive.parent),
    )
    nodes = enumerate_all_files(vd)
    paths = {n["path"].replace("\\", "/") for n in nodes}
    assert any(p.endswith("aabbccddeeff00112233445566778899aabbccdd") for p in paths)
    assert any("Manifest.plist" in p for p in paths)
    assert not any("document.xml" in p for p in paths)
    assert not any(p.endswith("app.py") for p in paths)


def test_enumerate_payload_zip_does_not_walk_sealed_original(tmp_path: Path) -> None:
    original = tmp_path / "CASE_RUN"
    hashed = original / "ios_image" / "UDID"
    hashed.mkdir(parents=True)
    (hashed / "Manifest.plist").write_bytes(b"plist")
    (hashed / "aabbccddeeff00112233445566778899aabbccdd").write_bytes(b"blob")
    archive = tmp_path / "intake" / "case.zip"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ORIGINAL_PATH.txt", str(original))
        zf.writestr("aetheris_package.json", json.dumps({"original_path": str(original)}))
        zf.writestr("02_Original_Extraction/ios_image/UDID/Manifest.plist", b"plist")
        zf.writestr("02_Original_Extraction/ios_image/UDID/aabbccddeeff00112233445566778899aabbccdd", b"blob")
    (hashed / "AFTER_SEAL.bin").write_bytes(b"must-not-extract")

    vd = VirtualDisk(
        job_id="j-zip-only",
        mode="folder",
        segment_paths=[str(archive)],
        format="zip",
        root_folder=str(archive.parent),
    )
    nodes = enumerate_all_files(vd)
    paths = {n["path"].replace("\\", "/") for n in nodes}
    assert any(p.endswith("Manifest.plist") for p in paths)
    assert not any("_sealed/" in p for p in paths)
    assert not any(p.endswith("AFTER_SEAL.bin") for p in paths)


def test_collect_portable_package_inventory_from_zip(tmp_path: Path) -> None:
    payload = _make_msgstore_bytes()
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(
            "aetheris_package.json",
            json.dumps({"container_format": "aetheris.zip.v1", "original_path": str(tmp_path / "missing")}),
        )
        zf.writestr("Dump/data/data/com.whatsapp/databases/msgstore.db", payload)
        zf.writestr("Dump/DCIM/Camera/a.jpg", b"\xff\xd8\xff\xd9")

    db = MagicMock()
    with patch(
        "app.services.mobile_forensic.package_inventory.fetchall",
        return_value=[
            {
                "host_path": str(archive),
                "original_name": "evidence.zip",
                "size_bytes": archive.stat().st_size,
            }
        ],
    ), patch(
        "app.services.mobile_forensic.package_inventory._resolve_path",
        side_effect=lambda raw: Path(raw) if Path(raw).exists() else None,
    ):
        out = collect_portable_package_inventory(db, "job-1")

    assert out["packages_scanned"] >= 1
    assert out["counts"]["whatsapp_messages"] == 3
    assert out["counts"]["pictures"] >= 1
