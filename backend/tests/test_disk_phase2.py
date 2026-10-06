"""Phase 2 disk pipeline unit tests (no database required)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from app.services.disk import segment_readiness, segment_key
from app.services.host_evidence import is_disk_image_filename
from app.services.virtual_disk import VirtualDisk, enumerate_all_files


def test_segment_key_ewf():
    sk = segment_key("Evidence.E01")
    assert sk is not None
    assert sk[1] == 1


def test_segment_readiness_complete():
    files = [{"original_name": "disk.E01", "status": "registered"}]
    sr = segment_readiness(files)
    assert sr["ready"] is True
    assert sr["has_disk_segments"] is True


def test_segment_readiness_missing_parts():
    files = [
        {"original_name": "disk.E01", "status": "registered"},
        {"original_name": "disk.E03", "status": "registered"},
    ]
    sr = segment_readiness(files)
    assert sr["ready"] is False
    assert sr["gaps"]


def test_is_disk_image_filename():
    assert is_disk_image_filename("image.E01")
    assert is_disk_image_filename("28_01_2025Vivo.pas")
    assert is_disk_image_filename("28_01_2025Vivo.pas001")
    assert not is_disk_image_filename("readme.txt")


def test_segment_key_pas():
    sk = segment_key("28_01_2025Vivo.pas001")
    assert sk is not None
    assert sk[1] == 1
    assert sk[2] == "pas"
    single = segment_key("28_01_2025Vivo.pas")
    assert single == ("28_01_2025Vivo.pas", 1, "pas")
    assert is_disk_image_filename("28_01_2025Vivo.pas")


def test_enumerate_folder_files():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "a.txt").write_text("hello", encoding="utf-8")
        (root / "b.txt").write_text("world", encoding="utf-8")
        vd = VirtualDisk(job_id="test", mode="folder", root_folder=str(root), segment_paths=[str(root)])
        nodes = enumerate_all_files(vd)
        paths = {n["path"] for n in nodes}
        assert "a.txt" in paths
        assert "b.txt" in paths


def test_find_folder_with_segment_files_by_hint(tmp_path, monkeypatch):
    from app.services import host_evidence as he

    drive = tmp_path / "host" / "d"
    folder = drive / "All" / "Fotrensics_Data" / "DISK2" / "SegerEx-1"
    folder.mkdir(parents=True)
    for i in range(1, 4):
        (folder / f"disk.E{i:02d}").write_bytes(b"x")

    names = ["disk.E01", "disk.E02", "disk.E03"]
    monkeypatch.setattr(he, "_accessible_drive_roots", lambda: [drive])
    monkeypatch.setattr(he, "_drive_catalog", lambda: [{"mounted": True, "bind_present": True}])

    result = he.find_folder_with_segment_files(
        names,
        folder_hint=r"All\Fotrensics_Data\DISK2\SegerEx-1",
    )
    assert result["path"] is not None
    assert result["segment_count"] == 3


def test_find_folder_by_anchor_search(tmp_path, monkeypatch):
    from app.services import host_evidence as he

    drive = tmp_path / "host" / "d"
    folder = drive / "deep" / "nested" / "segments"
    folder.mkdir(parents=True)
    (folder / "image.E01").write_bytes(b"a")
    (folder / "image.E02").write_bytes(b"b")

    monkeypatch.setattr(he, "_accessible_drive_roots", lambda: [drive])
    monkeypatch.setattr(he, "_drive_catalog", lambda: [{"mounted": True}])

    result = he.find_folder_with_segment_files(["image.E01", "image.E02"])
    assert result["error"] is None
    assert "nested" in (result["path"] or "")


def test_path_typo_variants():
    from app.services.host_evidence import _path_typo_variants

    variants = _path_typo_variants(r"D:\All\Forensics_Data\DISK2\DataExtraction\case")
    assert r"D:\All\Fotrensics_Data\DISK2\DataExtration\case" in variants


def test_shard_assignment_stable():
    paths = [f"Windows/System32/file{i}.dll" for i in range(100)]
    worker_count = 8
    buckets = [0] * worker_count
    for p in paths:
        buckets[hash(p) % worker_count] += 1
    assert sum(buckets) == 100
    assert all(b > 0 for b in buckets)
