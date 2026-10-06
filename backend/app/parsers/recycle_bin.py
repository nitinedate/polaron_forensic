"""Windows Recycle Bin $I* metadata parser (Vista / Win7 / Win10+)."""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any

# Windows FILETIME epoch: 1601-01-01
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_iso(ft: int) -> str | None:
    if ft <= 0:
        return None
    try:
        # 100-nanosecond intervals
        seconds = ft / 10_000_000
        dt = _FILETIME_EPOCH.timestamp() + seconds
        return datetime.fromtimestamp(dt, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def _decode_utf16_path(data: bytes, offset: int, *, char_count: int | None = None) -> str:
    if offset >= len(data):
        return ""
    raw = data[offset:]
    if char_count is not None and char_count > 0:
        raw = raw[: char_count * 2]
    try:
        text = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        return ""
    return text.split("\x00", 1)[0].strip()


def parse_recycle_bin_i(data: bytes, path: str) -> list[dict[str, Any]]:
    """Parse a Recycle Bin $I* descriptor file into structured recovery metadata."""
    base: dict[str, Any] = {
        "record_type": "recycle_bin_item",
        "path": path,
        "size_bytes": len(data),
        "is_deleted": True,
        "recovery_state": "recycle_bin",
        "text": f"Recycle Bin metadata: {path}",
    }
    if len(data) < 0x18:
        base["valid"] = False
        return [base]

    try:
        version = struct.unpack_from("<Q", data, 0)[0]
    except struct.error:
        base["valid"] = False
        return [base]

    # Vista/7: version 1; Win10+: version 2. Some tools write other small ints.
    if version not in (1, 2) and version > 10:
        # INFO2 / legacy or unknown — still try Vista layout if size looks right
        version = 1 if len(data) >= 0x1C else 0

    try:
        file_size = struct.unpack_from("<Q", data, 8)[0]
        deleted_ft = struct.unpack_from("<Q", data, 16)[0]
    except struct.error:
        base["valid"] = False
        return [base]

    deleted_at = _filetime_to_iso(deleted_ft)
    original_path = ""
    if version == 2 and len(data) >= 0x1C:
        try:
            path_chars = struct.unpack_from("<I", data, 24)[0]
        except struct.error:
            path_chars = 0
        original_path = _decode_utf16_path(data, 28, char_count=path_chars or None)
    else:
        original_path = _decode_utf16_path(data, 24)

    original_name = ""
    original_extension = None
    if original_path:
        norm = original_path.replace("\\", "/")
        original_name = norm.rsplit("/", 1)[-1]
        if "." in original_name:
            original_extension = "." + original_name.rsplit(".", 1)[-1].lower()

    record: dict[str, Any] = {
        **base,
        "valid": True,
        "format_version": int(version) if version in (1, 2) else version,
        "original_size_bytes": int(file_size),
        "deleted_at": deleted_at,
        "original_path": original_path or None,
        "original_name": original_name or None,
        "original_extension": original_extension,
        "is_modified": True,
        "preview": (
            f"Deleted {original_name or 'file'}"
            + (f" ({deleted_at[:10]})" if deleted_at else "")
            + (f" — {original_path}" if original_path else "")
        ),
        "text": (
            f"Recycle Bin deleted file: {original_name or path}"
            + (f" deleted_at={deleted_at}" if deleted_at else "")
            + (f" original={original_path}" if original_path else "")
        ),
    }
    return [record]


def is_recycle_bin_i_path(path: str) -> bool:
    """True for Windows Recycle Bin $I* descriptor paths."""
    norm = (path or "").replace("\\", "/").lower()
    name = norm.rsplit("/", 1)[-1]
    if not name.startswith("$i"):
        return False
    return "$recycle.bin" in norm or "/recycle.bin/" in norm or "recycle bin" in norm
