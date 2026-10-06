from __future__ import annotations

import io
import tarfile
from pathlib import Path

from app.services.mobile_acquire.adb_tar_pull import (
    copy_tree_longpath,
    count_tree,
    extract_tar_stream,
    windows_long_path,
)


def test_extract_tar_stream_nested_whatsapp(tmp_path: Path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        payload = b"crypt14-placeholder"
        info = tarfile.TarInfo(name="com.whatsapp/WhatsApp/Databases/msgstore.db.crypt14")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    dest = tmp_path / "out"
    n = extract_tar_stream(buf, dest)
    assert n == 1
    landed = dest / "com.whatsapp" / "WhatsApp" / "Databases" / "msgstore.db.crypt14"
    assert landed.is_file()
    assert landed.read_bytes() == b"crypt14-placeholder"


def test_copy_tree_longpath(tmp_path: Path):
    src = tmp_path / "src" / "com.whatsapp" / "WhatsApp" / "Databases"
    src.mkdir(parents=True)
    payload = b"crypt14-bytes"
    (src / "msgstore.db.crypt14").write_bytes(payload)
    dest = tmp_path / "dest"
    result = copy_tree_longpath(tmp_path / "src", dest)
    assert result["ok"] is True
    assert result["files"] == 1
    landed = dest / "com.whatsapp" / "WhatsApp" / "Databases" / "msgstore.db.crypt14"
    assert landed.read_bytes() == payload
    counted = count_tree(dest)
    assert counted["files"] == 1


def test_windows_long_path_prefix():
    value = windows_long_path(Path("C:/tmp/wa"))
    assert isinstance(value, str)
    if value.startswith("C:") or value.startswith("\\\\?\\"):
        assert "tmp" in value.replace("/", "\\").lower() or "tmp" in value.lower()
