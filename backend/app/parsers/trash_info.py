"""Linux FreeDesktop trash.info parser (.local/share/Trash/info/*.trashinfo)."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote


def is_trash_info_path(path: str) -> bool:
    norm = (path or "").replace("\\", "/").lower()
    name = PurePosixPath(norm).name
    return name.endswith(".trashinfo") or "/trash/info/" in norm or "/.local/share/trash/info/" in norm


def parse_trash_info(data: bytes, path: str) -> list[dict[str, Any]]:
    """Parse a .trashinfo file into deleted-file recovery metadata."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1", errors="replace")

    base: dict[str, Any] = {
        "record_type": "linux_trash_item",
        "path": path,
        "size_bytes": len(data),
        "is_deleted": True,
        "recovery_state": "linux_trash",
        "is_modified": True,
        "text": f"Linux trash metadata: {path}",
    }

    path_line = None
    deletion_date = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("[") and line.endswith("]"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key_l = key.strip().lower()
        val = val.strip()
        if key_l == "path":
            path_line = unquote(val)
        elif key_l == "deletiondate":
            deletion_date = val

    if not path_line and not deletion_date:
        base["valid"] = False
        return [base]

    original_path = path_line or None
    original_name = PurePosixPath((original_path or "").replace("\\", "/")).name or None
    original_ext = PurePosixPath(original_name or "").suffix.lower() or None

    # Normalize deletion date to ISO-ish
    deleted_at = deletion_date
    if deletion_date and "T" in deletion_date and not deletion_date.endswith("Z"):
        # FreeDesktop uses local time without timezone; keep as-is.
        deleted_at = deletion_date

    record = {
        **base,
        "valid": True,
        "deleted_at": deleted_at,
        "original_path": original_path,
        "original_name": original_name,
        "original_extension": original_ext,
        "preview": (
            f"Deleted {original_name or 'file'}"
            + (f" ({str(deleted_at)[:10]})" if deleted_at else "")
            + (f" — {original_path}" if original_path else "")
        ),
        "text": (
            f"Linux Trash deleted file: {original_name or path}"
            + (f" deleted_at={deleted_at}" if deleted_at else "")
            + (f" original={original_path}" if original_path else "")
        ),
    }
    return [record]
