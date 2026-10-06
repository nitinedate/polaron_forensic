"""Mobile forensic segment detection tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

from app.services.disk import segment_key, segment_readiness
from app.services.host_evidence import is_disk_image_filename
from app.services.mobile_segments import mobile_segment_key, mobile_segments_in_folder


def test_mobile_pas_single():
    sk = mobile_segment_key("28_01_2025Vivo.pas")
    assert sk == ("28_01_2025Vivo.pas", 1, "pas")


def test_mobile_pas_indexed_suffix():
    sk = mobile_segment_key("28_01_2025Vivo1.pas")
    assert sk == ("28_01_2025Vivo.pas", 2, "pas")


def test_mobile_pas_part_suffix():
    sk = mobile_segment_key("image.pas001")
    assert sk == ("image.pas", 1, "pas")


def test_mobile_ufd_and_zip():
    assert mobile_segment_key("vivo_V2403.ufd") == ("vivo_V2403.mobile", 1, "ufd")
    assert mobile_segment_key("Vivo.ufdx") == ("Vivo.mobile", 1, "ufdx")
    assert mobile_segment_key("export.zip") == ("export.mobile", 1, "zip")
    assert mobile_segment_key("export.part-00000.zip") == ("export.mobile", 1, "zip")
    assert mobile_segment_key("export.part-00021.zip") == ("export.mobile", 22, "zip")


def test_segment_key_prefers_mobile():
    sk = segment_key("28_01_2025Vivo.pas")
    assert sk == ("28_01_2025Vivo.pas", 1, "pas")


def test_mobile_pas_model_number_not_treated_as_segment_index():
    """vivo_V2403.pas is a single segment, not part 2404 of vivo_V.pas."""
    sk = mobile_segment_key("vivo_V2403.pas")
    assert sk == ("vivo_V2403.pas", 1, "pas")


def test_segment_readiness_mobile_folder(tmp_path: Path):
    folder = tmp_path / "FileSystem 01"
    folder.mkdir()
    (folder / "28_01_2025Vivo.pas").write_bytes(b"a")
    (folder / "28_01_2025Vivo1.pas").write_bytes(b"b")
    (folder / "vivo_V2403.pas").write_bytes(b"d")
    (folder / "vivo_V2403.ufd").write_bytes(b"c")
    archive = folder / "vivo_V2403"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("data/chat.db", b"hello")

    names = mobile_segments_in_folder(folder)
    assert "28_01_2025Vivo.pas" in names
    assert "28_01_2025Vivo1.pas" in names
    assert "vivo_V2403.ufd" in names
    assert "vivo_V2403" in names

    files = [{"original_name": n, "status": "registered"} for n in names]
    sr = segment_readiness(files)
    assert sr["ready"] is True
    assert sr["has_disk_segments"] is True


def test_is_disk_image_filename_mobile():
    assert is_disk_image_filename("28_01_2025Vivo.pas")
    assert is_disk_image_filename("vivo_V2403.ufd")
    assert is_disk_image_filename("Vivo.ufdx")


def test_export_dirs_near_working_copy_finds_payload_zips(tmp_path: Path):
    from app.services.mobile_segments import export_dirs_near, list_payload_zip_archives

    case = tmp_path / "CASE-IOS"
    run = "run1"
    working = case / "03_Working_Copy" / run
    exports = case / "05_Exports" / run
    working.mkdir(parents=True)
    exports.mkdir(parents=True)
    shard = exports / f"{run}.part-00000.zip"
    shard.write_bytes(b"payload-zip")

    near = export_dirs_near(working)
    assert any(p.resolve() == exports.resolve() for p in near)
    found = list_payload_zip_archives(working, [str(working)])
    assert any(p.name == shard.name for p in found)
