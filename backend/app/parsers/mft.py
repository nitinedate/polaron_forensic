"""MFT / filesystem metadata parser — path-based metadata extraction."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any


def parse_mft_metadata(path: str, size_bytes: int = 0) -> list[dict[str, Any]]:
    norm = path.replace("\\", "/")
    name = PurePosixPath(norm).name
    parent = str(PurePosixPath(norm).parent)

    record: dict[str, Any] = {
        "file_path": path,
        "file_name": name,
        "parent_path": parent,
        "size_bytes": size_bytes,
    }

    if re.search(r"\$MFT|\$LogFile|\$UsnJrnl|\$Extend", norm, re.I):
        record["ntfs_system"] = True
    if re.search(r"\\Users\\([^\\]+)", norm, re.I):
        record["user_profile"] = re.search(r"\\Users\\([^\\]+)", norm, re.I).group(1)
    if re.search(r"\\Windows\\", norm, re.I):
        record["os_component"] = "windows"
    if re.search(r"\\Program Files", norm, re.I):
        record["installed_software_path"] = True

    return [record]
