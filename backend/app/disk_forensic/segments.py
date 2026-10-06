"""Disk image segment filename helpers (no UFED/mobile package extensions)."""

from __future__ import annotations

import re

# Host-disk images only — mobile packages (.pas/.ufd/.zip) belong in mobile_forensic.
DISK_IMAGE_EXT_RE = re.compile(
    r"\.(?:E\d{2}|e\d{2}|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx)$",
    re.IGNORECASE,
)


def is_disk_image_filename(name: str) -> bool:
    return bool(name and DISK_IMAGE_EXT_RE.search(name))
