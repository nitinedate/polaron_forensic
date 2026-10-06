"""Browser upload staging — paths must stay under DATA_ROOT/uploads."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

from app.services.client_intake import (
    count_staged_files,
    is_staged_upload_path,
    safe_relative_path,
    stage_upload_file,
    staged_file_records,
    upload_root,
)


def test_safe_relative_path_strips_traversal():
    assert safe_relative_path("../etc/passwd") == "etc/passwd"
    assert ".." not in safe_relative_path("a/../../b.png")
    assert safe_relative_path("photos/case 1/IMG_01.jpg") == "photos/case 1/IMG_01.jpg"
    assert safe_relative_path("C:\\foo\\bar.jpg") == "C_/foo/bar.jpg"


def test_stage_upload_and_resolve(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr("app.services.client_intake.put_file", lambda key, dest, mime: f"file://{dest}")

    staged = stage_upload_file(
        namespace="job-1/intake",
        relative_path="UFED/export.pas",
        src=BytesIO(b"mobile-package"),
    )
    local = Path(staged["local_path"])
    assert local.is_file()
    assert local.read_bytes() == b"mobile-package"
    assert is_staged_upload_path(local)
    assert upload_root() == (tmp_path / "uploads").resolve()
    assert not is_staged_upload_path(tmp_path / "other" / "file.bin")
    get_settings.cache_clear()


def test_staging_locations_and_purge(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    from app.config import get_settings
    from app.services.client_intake import job_staging_dir, purge_job_staging, staging_locations

    get_settings.cache_clear()
    job_id = "job-abc"
    intake = job_staging_dir(job_id) / "intake"
    intake.mkdir(parents=True)
    (intake / "image.E01").write_bytes(b"ewf")
    locs = staging_locations(job_id)
    assert Path(locs["container_path"]) == intake
    assert "client-uploads/job-abc/" in locs["object_prefix"]
    monkeypatch.setattr("app.services.storage.delete_prefix", lambda prefix: 3)
    cleaned = purge_job_staging(job_id)
    assert cleaned["removed_local"] is True
    assert not job_staging_dir(job_id).exists()
    assert cleaned["objects"] == 3
    assert cleaned["object_purge_ok"] is True
    assert cleaned["purged"] is True
    get_settings.cache_clear()


def test_disk_stage_can_skip_object_store_mirror(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    from app.config import get_settings

    get_settings.cache_clear()
    calls = []
    monkeypatch.setattr(
        "app.services.client_intake.put_file",
        lambda key, dest, mime: calls.append((key, dest, mime)) or "should-not-be-used",
    )
    staged = stage_upload_file(
        namespace="job-disk/intake",
        relative_path="case.E01",
        src=BytesIO(b"disk-segment"),
        mirror_to_object_storage=False,
    )
    assert calls == []
    assert staged["storage_uri"].startswith("file://")
    assert staged["mirrored_to_object_storage"] is False
    assert Path(staged["local_path"]).read_bytes() == b"disk-segment"
    get_settings.cache_clear()


def test_purge_is_idempotent_when_staging_already_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    from app.config import get_settings
    from app.services.client_intake import purge_job_staging

    get_settings.cache_clear()
    monkeypatch.setattr("app.services.storage.delete_prefix", lambda prefix: 0)
    cleaned = purge_job_staging("job-already-clean")
    assert cleaned["removed_local"] is True
    assert cleaned["object_purge_ok"] is True
    assert cleaned["purged"] is True
    get_settings.cache_clear()


def test_partial_upload_files_are_not_counted_or_exposed(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    from app.config import get_settings

    get_settings.cache_clear()
    intake = tmp_path / "uploads" / "job-partial" / "intake"
    intake.mkdir(parents=True)
    (intake / "case.E01").write_bytes(b"complete")
    (intake / "case.E02.uploading-deadbeef").write_bytes(b"partial")

    assert count_staged_files("job-partial") == 1
    assert [r["name"] for r in staged_file_records("job-partial")] == ["case.E01"]
    get_settings.cache_clear()


def test_stage_upload_publishes_final_name_only_after_complete(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_ROOT", str(tmp_path))
    from app.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr("app.services.client_intake.put_file", lambda key, dest, mime: f"file://{dest}")
    staged = stage_upload_file(
        namespace="job-atomic/intake",
        relative_path="case.E01",
        src=BytesIO(b"x" * 1024),
        mirror_to_object_storage=False,
    )
    intake = tmp_path / "uploads" / "job-atomic" / "intake"
    assert Path(staged["local_path"]).name == "case.E01"
    assert count_staged_files("job-atomic") == 1
    assert not any(".uploading-" in p.name for p in intake.iterdir())
    get_settings.cache_clear()
