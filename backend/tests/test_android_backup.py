from pathlib import Path

from app.services.mobile_acquire.android_backup import extract_android_backup


def test_extract_android_backup_rejects_empty(tmp_path: Path):
    ab = tmp_path / "empty.ab"
    ab.write_bytes(b"nope")
    result = extract_android_backup(ab, tmp_path / "out")
    assert result["ok"] is False
    assert result["files"] == 0


def test_extract_android_backup_rejects_encrypted(tmp_path: Path):
    ab = tmp_path / "enc.ab"
    ab.write_bytes(b"ANDROID BACKUP\n5\n1\nAES-256\n" + (b"x" * 80))
    result = extract_android_backup(ab, tmp_path / "out")
    assert result["ok"] is False
    assert "encrypted" in result["error"]
