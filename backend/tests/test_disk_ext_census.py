"""Combined disk extension census avoids repeated full-disk walks."""

from unittest.mock import MagicMock, patch

from app.services.disk_ext_census import ensure_disk_extension_censuses


def test_ensure_returns_cached_without_walk() -> None:
    db = MagicMock()
    cached = {
        "document_disk_inventory": {
            "by_ext_key": {".pdf": 3},
            "enumerated_files": 100,
            "source": "full_disk_enumeration",
        },
        "media_disk_inventory": {
            "picture": 10,
            "audio": 1,
            "video": 2,
            "photoshop": 0,
            "enumerated_files": 100,
        },
        "lnk_disk_count": 4,
    }
    with patch("app.services.disk_ext_census._load_disk_source", return_value=cached), patch(
        "app.services.virtual_disk.open_virtual_disk"
    ) as open_vd:
        result = ensure_disk_extension_censuses(db, "job-1")
    open_vd.assert_not_called()
    assert result["lnk_disk_count"] == 4
    assert result["media_disk_inventory"]["picture"] == 10


def test_ensure_one_walk_fills_doc_media_lnk() -> None:
    db = MagicMock()
    nodes = [
        {"path": "Users/a/file.pdf"},
        {"path": "Users/a/pic.jpg"},
        {"path": "Users/a/clip.mp4"},
        {"path": "Users/a/shortcut.lnk"},
        {"path": "Users/a/song.mp3"},
    ]
    with patch("app.services.disk_ext_census._load_disk_source", return_value={}), patch(
        "app.services.disk_ext_census._save_disk_source"
    ) as save, patch(
        "app.services.virtual_disk.open_virtual_disk", return_value=MagicMock()
    ), patch(
        "app.services.virtual_disk.enumerate_all_files", return_value=nodes
    ) as enum:
        result = ensure_disk_extension_censuses(db, "job-1")
    enum.assert_called_once()
    assert result["lnk_disk_count"] == 1
    assert result["media_disk_inventory"]["picture"] == 1
    assert result["media_disk_inventory"]["video"] == 1
    assert result["media_disk_inventory"]["audio"] == 1
    assert result["document_disk_inventory"]["enumerated_files"] == 5
    save.assert_called()
