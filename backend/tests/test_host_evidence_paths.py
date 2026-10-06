"""Strict vs fuzzy host path resolution for segment registration."""

from __future__ import annotations

from pathlib import Path

import os
import pytest

from app.services import host_evidence as he


@pytest.fixture
def mounted_d_drive(tmp_path, monkeypatch):
    """Simulate Docker /host/d with a real segment folder and a decoy elsewhere."""
    drive = tmp_path / "host" / "d"
    rel = "pytest_host_evidence_only/all/Fotrensics_Data/DISK2/DataExtration/SegerEx-1"
    segments = drive / rel.replace("/", os.sep)
    segments.mkdir(parents=True)
    for i in range(1, 4):
        (segments / f"Seger Ex-1.E{i:02d}").write_bytes(b"x")

    decoy = drive / "Users" / "ndate" / "Downloads"
    decoy.mkdir(parents=True)
    (decoy / "readme.txt").write_text("not segments", encoding="utf-8")

    monkeypatch.setattr(he, "_running_in_container", lambda: True)
    monkeypatch.setattr(he, "_host_mount_prefix", lambda: tmp_path / "host")
    monkeypatch.setattr(he, "_accessible_drive_roots", lambda: [drive])
    monkeypatch.setattr(he, "_path_candidates", lambda raw: [he._translate_windows_path(raw)])
    monkeypatch.setattr(
        he,
        "_drive_catalog",
        lambda: [{"key": "d", "label": "D:", "mounted": True, "bind_present": True}],
    )
    monkeypatch.setattr(he, "_lookup_path_only", lambda *a, **k: None)
    monkeypatch.setattr(he, "_heal_selected_host_path", lambda *_a, **_k: None)
    workstation = r"D:\pytest_host_evidence_only\all\Fotrensics_Data\DISK2\DataExtration\SegerEx-1"
    return drive, segments, workstation


def test_strict_rejects_nonexistent_path_without_fuzzy_remap(mounted_d_drive):
    _drive, segments, _workstation = mounted_d_drive
    wrong = r"D:\Forensics\Case001\EDISK.E01"

    with pytest.raises(ValueError, match="Path not found"):
        he.resolve_host_path(wrong, strict=True)

    resolved = he._resolve_raw_path(wrong, strict=True)
    assert resolved != segments
    assert not resolved.exists()


def test_strict_accepts_exact_segment_folder(mounted_d_drive):
    _drive, segments, workstation = mounted_d_drive

    resolved = he.resolve_host_path(workstation, strict=True)
    assert resolved.resolve() == segments.resolve()


def test_find_segment_folder_under_finds_segment_set(mounted_d_drive):
    drive, segments, _workstation = mounted_d_drive

    found = he._find_segment_folder_under(drive, max_depth=8)
    assert found is not None
    assert found.resolve() == segments.resolve()


def test_strict_allows_segment_file_in_existing_parent(mounted_d_drive):
    _drive, segments, workstation = mounted_d_drive
    segment_file = workstation + r"\Seger Ex-1.E01"

    resolved = he.resolve_host_path(segment_file, strict=True)
    assert resolved.resolve() == (segments / "Seger Ex-1.E01").resolve()


def test_resolve_host_path_accepts_staged_upload(tmp_path, monkeypatch):
    dest = tmp_path / "uploads" / "jid" / "intake" / "export.pas"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"x")
    monkeypatch.setattr(
        "app.services.client_intake.upload_root",
        lambda: (tmp_path / "uploads").resolve(),
    )
    resolved = he.resolve_host_path(str(dest), strict=True)
    assert resolved.resolve() == dest.resolve()


def test_resolve_missing_drive_mentions_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(he, "_running_in_container", lambda: True)
    monkeypatch.setattr(he, "_host_mount_prefix", lambda: tmp_path / "host")
    monkeypatch.setattr(he, "_lookup_path_only", lambda *a, **k: None)
    monkeypatch.setattr(he, "_heal_selected_host_path", lambda *_a, **_k: None)
    with pytest.raises(ValueError, match="Path not found") as err:
        he.resolve_host_path(r"G:\Evidence\case", strict=True)
    msg = str(err.value).lower()
    assert "refresh drive mounts" in msg
    assert "/host/g" in msg


def test_resolve_drive_base_does_not_require_mount(tmp_path, monkeypatch):
    monkeypatch.setattr(he, "_running_in_container", lambda: True)
    monkeypatch.setattr(he, "_host_mount_prefix", lambda: tmp_path / "host")
    monkeypatch.setattr(
        he,
        "_drive_catalog",
        lambda: [{"key": "g", "label": "G:", "mounted": False, "host_path": "", "bind_present": False}],
    )
    base = he._resolve_drive_base("g")
    assert "g" in str(base).replace("\\", "/").lower()


def test_placeholder_path_is_rejected():
    with pytest.raises(ValueError, match="only an example"):
        he.resolve_host_path(r"D:\path\to\your\E01-folder", strict=True)
    with pytest.raises(ValueError, match="only an example"):
        he.resolve_host_path(r"D:\all\Fotrensics_Data\...\SegerEx-1", strict=True)


def test_find_folder_absolute_path_does_not_scan_mounts(monkeypatch):
    scanned: list[str] = []

    def _roots():
        scanned.append("scanned")
        return []

    monkeypatch.setattr(he, "_accessible_drive_roots", _roots)
    monkeypatch.setattr(he, "_lookup_path_only", lambda *a, **k: None)
    monkeypatch.setattr(he, "_running_in_container", lambda: True)
    result = he.find_folder_with_segment_files(["a.E01"], folder_hint=r"D:\nope\folder")
    assert result["path"] is None
    assert "Path not found" in (result["error"] or "")
    assert scanned == []


def test_mountinfo_detection_accepts_modern_docker_desktop_filesystems():
    # Do not hard-code legacy drvfs/9p. Modern Docker Desktop can use VirtioFS
    # or gRPC-FUSE while the bind target remains exactly /host/<letter>.
    virtiofs = "123 45 0:99 / /host/g rw,relatime - virtiofs hostshare rw\n"
    grpc_fuse = "124 45 0:100 / /host/h rw,relatime - fuse.grpcfuse hostshare rw\n"
    legacy_9p = "125 45 0:101 / /host/i rw,relatime - 9p drvfs rw\n"

    assert he._mountinfo_has_mountpoint(virtiofs, "/host/g")
    assert he._mountinfo_has_mountpoint(grpc_fuse, "/host/h")
    assert he._mountinfo_has_mountpoint(legacy_9p, "/host/i")


def test_mountinfo_detection_requires_exact_drive_mountpoint():
    only_parent = "123 45 0:99 / /host rw,relatime - tmpfs tmpfs rw\n"
    nested = "124 45 0:100 / /host/g/subdir rw,relatime - virtiofs hostshare rw\n"

    assert not he._mountinfo_has_mountpoint(only_parent, "/host/g")
    assert not he._mountinfo_has_mountpoint(nested, "/host/g")


def test_evidence_folder_from_disk_source_prefers_saved_folder():
    assert he.evidence_folder_from_disk_source(
        {"evidence_folder": r"G:\case\e01", "last_host_path": r"D:\old"}
    ) == r"G:\case\e01"
    assert he.evidence_folder_from_disk_source({"last_host_path": r"D:\old"}) == r"D:\old"
    assert he.evidence_folder_from_disk_source({}) == ""
    assert he.evidence_folder_from_disk_source(None) == ""
    assert he.evidence_folder_from_disk_source(
        {
            "intake": "browser_upload",
            "staging_container_path": "/app/data/uploads/jid/intake",
            "evidence_folder": r"G:\client\path",
            "last_host_path": r"G:\client\path",
        }
    ) == "/app/data/uploads/jid/intake"


def test_empty_host_letter_stub_is_stale(tmp_path, monkeypatch):
    host = tmp_path / "host"
    host.mkdir()
    empty_g = host / "g"
    empty_g.mkdir()
    real_d = host / "d"
    real_d.mkdir()
    (real_d / "DISK2").mkdir()
    other = host / "volumes"
    other.mkdir()

    monkeypatch.setattr(he, "_host_mount_prefix", lambda: host)

    assert he._is_host_drive_letter_mount(empty_g) is True
    assert he._is_stale_host_mount(empty_g) is True
    assert he._drive_mount_accessible(empty_g) is False
    assert he._is_stale_host_mount(real_d) is False
    assert he._drive_mount_accessible(real_d) is True
    assert he._is_stale_host_mount(other) is False

    mappings = he._auto_detect_container_mappings()
    mapped = " ".join(f"{src}->{dst}" for src, dst in mappings)
    assert "D:" in mapped
    assert "G:" not in mapped


def test_auto_detect_skips_stale_enodev_drive(tmp_path, monkeypatch):
    host = tmp_path / "host"
    host.mkdir()
    good = host / "d"
    good.mkdir()
    (good / "DISK2").mkdir()
    stale = host / "g"
    stale.mkdir()

    real_is_dir = he.Path.is_dir
    real_stat = he.Path.stat

    def is_dir(self):
        if self == stale:
            raise OSError(19, "No such device", str(self))
        return real_is_dir(self)

    def stat(self, *args, **kwargs):
        if self == stale:
            raise OSError(19, "No such device", str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(he, "_host_mount_prefix", lambda: host)
    monkeypatch.setattr(he.Path, "is_dir", is_dir)
    monkeypatch.setattr(he.Path, "stat", stat)

    assert he._safe_is_dir(good) is True
    assert he._safe_is_dir(stale) is False
    assert he._is_stale_host_mount(stale) is True
    mappings = he._auto_detect_container_mappings()
    mapped = " ".join(f"{src}->{dst}" for src, dst in mappings)
    assert "D:" in mapped
    assert "G:" not in mapped


def test_readable_segment_paths_keeps_files_and_reports_vanished(tmp_path):
    keep = tmp_path / "keep.E01"
    keep.write_bytes(b"x")
    gone = tmp_path / "gone.E02"
    readable, vanished = he.readable_segment_paths([keep, gone])
    assert readable == [keep]
    assert vanished == ["gone.E02"]


def test_collect_segment_files_falls_back_to_any_regular_files(tmp_path):
    folder = tmp_path / "loose"
    folder.mkdir()
    (folder / "note.pdf").write_bytes(b"pdf")
    (folder / "photo.jpg").write_bytes(b"jpg")
    (folder / "Thumbs.db").write_bytes(b"x")
    found = he._collect_segment_files(folder, None, "disk")
    names = sorted(p.name.lower() for p in found)
    assert names == ["note.pdf", "photo.jpg"]


def test_collect_segment_files_prefers_e01_set(tmp_path):
    folder = tmp_path / "ewf"
    folder.mkdir()
    (folder / "case.E01").write_bytes(b"x")
    (folder / "case.E02").write_bytes(b"x")
    (folder / "readme.txt").write_bytes(b"x")
    found = he._collect_segment_files(folder, None, "disk")
    names = sorted(p.name for p in found)
    assert names == ["case.E01", "case.E02"]


def test_walk_folder_entries_lists_nested_files_in_parallel(tmp_path):
    root = tmp_path / "intake"
    nested = root / "disk" / "set"
    nested.mkdir(parents=True)
    (root / "case.E01").write_bytes(b"abc")
    (nested / "case.E02").write_bytes(b"abcd")
    (nested / "note.txt").write_bytes(b"hi")
    entries = he._walk_folder_entries(root)
    by_name = {row["name"]: row for row in entries}
    assert by_name["case.E01"]["size_bytes"] == 3
    assert by_name["case.E02"]["size_bytes"] == 4
    assert by_name["case.E02"]["relative_path"].replace("\\", "/").endswith("disk/set/case.E02")
    assert by_name["disk"]["kind"] == "dir"


def test_walk_folder_entries_scans_sibling_directories(tmp_path, monkeypatch):
    monkeypatch.setattr(he, "_list_folder_workers", lambda: 8)
    root = tmp_path / "intake"
    root.mkdir()
    for i in range(24):
        child = root / f"bucket-{i:02d}"
        child.mkdir()
        (child / f"part-{i:02d}.E01").write_bytes(b"ewf")
        nested = child / "meta"
        nested.mkdir()
        (nested / f"note-{i:02d}.txt").write_bytes(b"n")
    entries = he._walk_folder_entries(root)
    files = [row for row in entries if row.get("kind") == "file"]
    dirs = [row for row in entries if row.get("kind") == "dir"]
    assert len(files) == 48
    assert len(dirs) == 48
    segs = [row["name"] for row in files if row["name"].endswith(".E01")]
    assert len(segs) == 24


def test_listing_log_rows_group_plain_files():
    rows, segs = he._listing_log_rows(
        [
            {"name": "disk", "relative_path": "disk", "kind": "dir", "size_bytes": None},
            {"name": "case.E01", "relative_path": "disk/case.E01", "kind": "file", "size_bytes": 10},
            {"name": "a.txt", "relative_path": "disk/a.txt", "kind": "file", "size_bytes": 1},
            {"name": "b.txt", "relative_path": "disk/b.txt", "kind": "file", "size_bytes": 1},
        ]
    )
    assert segs == ["case.E01"]
    messages = [row["message"] for row in rows]
    assert any(m.startswith("  [DIR]") for m in messages)
    assert any("[SEG]" in m for m in messages)
    assert any(m.startswith("  [FILES]") and "a.txt" in m and "b.txt" in m for m in messages)


def test_walk_folder_entries_raises_if_missing(tmp_path):
    with pytest.raises(OSError, match="Not a directory"):
        he._walk_folder_entries(tmp_path / "missing")


def test_resolve_maps_windows_upload_dump_to_container(tmp_path, monkeypatch):
    intake = tmp_path / "uploads" / "jid" / "intake"
    intake.mkdir(parents=True)
    (intake / "a.E01").write_bytes(b"x")
    monkeypatch.setattr("app.services.client_intake.upload_root", lambda: (tmp_path / "uploads").resolve())
    raw = r"E:\projects\aetheris_project\data\uploads\jid\intake"
    resolved = he.resolve_staged_upload_raw(raw)
    assert resolved == intake.resolve()
    listed = he.resolve_host_path(raw, strict=True)
    assert listed == intake.resolve()


def test_collect_nested_segments_for_staged_dump(tmp_path, monkeypatch):
    intake = tmp_path / "uploads" / "jid" / "intake"
    nested = intake / "Case" / "disk"
    nested.mkdir(parents=True)
    (nested / "image.E01").write_bytes(b"x")
    monkeypatch.setattr("app.services.client_intake.upload_root", lambda: (tmp_path / "uploads").resolve())
    found = he._collect_segment_files(intake, None, "disk")
    assert [p.name for p in found] == ["image.E01"]


def test_client_upload_gate_is_fail_closed_until_complete_count_matches():
    assert he.is_client_upload_pending({"intake": "browser_upload", "upload_status": "receiving"})
    assert he.is_client_upload_pending({"intake": "browser_upload", "upload_status": "verifying"})
    assert he.is_client_upload_pending({"intake": "browser_upload"})
    assert he.is_client_upload_pending(
        {
            "intake": "browser_upload",
            "upload_status": "complete",
            "upload_expected_files": 9,
            "upload_received_files": 8,
        }
    )
    assert not he.is_client_upload_pending(
        {
            "intake": "browser_upload",
            "upload_status": "complete",
            "upload_expected_files": 9,
            "upload_received_files": 9,
        }
    )
    # Server/removable/network evidence never enters the browser-upload gate.
    assert not he.is_client_upload_pending(
        {"intake": "server_local", "evidence_folder": r"G:\disk"}
    )
