"""Complete filesystem/object inventory for mobile dumps."""

from __future__ import annotations

import logging
import mimetypes
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from app.services.mobile_forensic.models import InventoryItem

log = logging.getLogger("mobile_forensic.discovery")

ProgressCb = Callable[[str, dict[str, Any] | None], None]


def _ext(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).suffix.lower()


def _mime_hint(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    return mime or ""


def inventory_from_job_artifacts(db, job_id: str) -> list[InventoryItem]:
    """Build discovery inventory from materialized job_artifacts (working copy)."""
    from app.db.sql_helpers import fetchall

    # Columns vary by firm schema revision — use the common baseline only.
    rows = fetchall(
        db,
        """SELECT file_path, size_bytes, extension, sha256,metadata
           FROM job_artifacts WHERE job_id=:jid ORDER BY file_path""",
        {"jid": job_id},
    )
    items: list[InventoryItem] = []
    for r in rows:
        path = str(r.get("file_path") or "")
        if not path:
            continue
        ext = (r.get("extension") or _ext(path) or "").lower()
        if ext and not ext.startswith("."):
            ext = f".{ext}"
        items.append(
            InventoryItem(
                path=path.replace("\\", "/"),
                size=int(r.get("size_bytes") or 0),
                extension=ext,
                mime_hint=_mime_hint(path),
                sha256=r.get("sha256"),
                status="discovered",
                meta=r.get("metadata") or {},
            )
        )
    return items


def inventory_from_zip(zip_path: Path, *, logical_root: str = "Dump") -> list[InventoryItem]:
    """Enumerate a UFED FileDump / portable zip without extracting."""
    items: list[InventoryItem] = []
    prefix = (logical_root or "").replace("\\", "/").strip("/")
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename.replace("\\", "/")
                if prefix and not (name == prefix or name.startswith(prefix + "/")):
                    # Still inventory; many dumps omit Dump/ prefix
                    pass
                items.append(
                    InventoryItem(
                        path=name,
                        size=int(info.file_size or 0),
                        extension=_ext(name),
                        mime_hint=_mime_hint(name),
                        status="discovered",
                        meta={"archive": str(zip_path), "compressed_size": info.compress_size},
                    )
                )
    except Exception as exc:
        log.warning("zip inventory failed %s: %s", zip_path, exc)
    return items


def summarize_inventory(items: list[InventoryItem]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_ext: dict[str, int] = {}
    for it in items:
        by_status[it.status] = by_status.get(it.status, 0) + 1
        ext = it.extension or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
    return {
        "total": len(items),
        "by_status": by_status,
        "extension_count": len(by_ext),
        "top_extensions": sorted(by_ext.items(), key=lambda kv: -kv[1])[:20],
    }
