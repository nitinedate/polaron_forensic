from __future__ import annotations

import os
from pathlib import Path

from app.services.dir_walk import (
    entry_is_dir,
    iter_files_following_dir_links,
    remap_host_path,
    rewrite_container_host_path,
)


def test_iter_files_follows_directory_symlink(tmp_path):
    real = tmp_path / "ib" / "stamp"
    real.mkdir(parents=True)
    (real / "ChatStorage.sqlite").write_bytes(b"wa")
    (real / "aa").mkdir()
    (real / "aa" / "hashed").write_bytes(b"h")

    case = tmp_path / "case"
    case.mkdir()
    (case / "backup.out").write_text("log")
    link = case / "ios_image"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        os.system(f'cmd /c mklink /J "{link}" "{real}" >nul 2>nul')
        if not link.exists():
            return

    found = {rel.replace("\\", "/"): path for path, rel in iter_files_following_dir_links(case)}
    assert "backup.out" in found
    assert any(rel.endswith("ChatStorage.sqlite") for rel in found)
    assert any(rel.endswith("hashed") for rel in found)


def test_entry_is_dir_sees_junction(tmp_path):
    real = tmp_path / "target"
    real.mkdir()
    link = tmp_path / "ios_image"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        os.system(f'cmd /c mklink /J "{link}" "{real}" >nul 2>nul')
        if not link.exists():
            return
    with os.scandir(tmp_path) as it:
        entries = {e.name: e for e in it}
    assert entry_is_dir(entries["ios_image"]) is True
    assert entry_is_dir(entries["target"]) is True


def test_rewrite_docker_desktop_junction_target(monkeypatch, tmp_path):
    from app.services import dir_walk

    host = tmp_path / "host"
    dest = host / "e" / "ib" / "stamp"
    dest.mkdir(parents=True)
    monkeypatch.setattr(dir_walk, "HOST_MOUNT", host)

    assert rewrite_container_host_path("/mnt/host/e/ib/stamp") == dest
    assert remap_host_path("/mnt/host/e/ib/stamp") == dest
    assert remap_host_path(r"E:\ib\stamp") == dest
    assert remap_host_path("/tmp/not-a-host-path") == Path("/tmp/not-a-host-path")


def test_iter_files_follows_dangling_docker_desktop_symlink(monkeypatch, tmp_path):
    from app.services import dir_walk

    host = tmp_path / "host"
    real = host / "e" / "ib" / "stamp"
    real.mkdir(parents=True)
    (real / "ChatStorage.sqlite").write_bytes(b"wa")
    monkeypatch.setattr(dir_walk, "HOST_MOUNT", host)

    case = tmp_path / "case"
    case.mkdir()
    (case / "backup.out").write_text("log")
    link = case / "ios_image"
    try:
        os.symlink("/mnt/host/e/ib/stamp", link, target_is_directory=True)
    except OSError:
        return
    found = {rel.replace("\\", "/"): path for path, rel in iter_files_following_dir_links(case)}
    assert "backup.out" in found
    assert any(rel.endswith("ChatStorage.sqlite") for rel in found)
