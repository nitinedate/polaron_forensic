"""Persist/load of mobile board sample paths must keep artifact ids for Open."""

from app.services.mobile_forensic.inventory import (
    _ids_for_paths_from_files,
    _normalize_sample_entry,
)


def test_normalize_legacy_path_list():
    paths, ids = _normalize_sample_entry(["a/b.jpg", "c/d.png"])
    assert paths == ["a/b.jpg", "c/d.png"]
    assert ids == []


def test_normalize_dict_with_ids():
    paths, ids = _normalize_sample_entry({"paths": ["a/b.jpg"], "ids": ["uuid-1"]})
    assert paths == ["a/b.jpg"]
    assert ids == ["uuid-1"]


def test_normalize_in_memory_tuple():
    paths, ids = _normalize_sample_entry((["a/b.jpg"], ["uuid-1"]))
    assert paths == ["a/b.jpg"]
    assert ids == ["uuid-1"]


def test_ids_for_paths_suffix_match():
    files = [
        {"id": "1", "file_path": "vivo.zip/Dump/Pictures/.trashed-1.jpg"},
        {"id": "2", "file_path": "other/path.txt"},
    ]
    ids = _ids_for_paths_from_files(files, ["Dump/Pictures/.trashed-1.jpg"])
    assert ids == ["1"]
