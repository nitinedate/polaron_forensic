"""Stage browser uploads under DATA_ROOT so any client can send evidence.

Host-path ingest still works on the examiner workstation. Remote browsers
cannot see server disks — they upload bytes here instead.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import uuid
from pathlib import Path

from app.config import get_settings
from app.services.storage import put_file

_SAFE_PART = re.compile(r"[^A-Za-z0-9._\- ]+")
_PARTIAL_UPLOAD_MARKER = ".uploading-"


def _is_partial_upload_file(path: Path) -> bool:
    return _PARTIAL_UPLOAD_MARKER in path.name


def safe_relative_path(name: str) -> str:
    cleaned = (name or "unnamed").replace("\\", "/").lstrip("/")
    parts: list[str] = []
    for raw in cleaned.split("/"):
        part = _SAFE_PART.sub("_", raw).strip(" .")
        if not part or part in {".", ".."}:
            continue
        parts.append(part[:180])
    return "/".join(parts) or "unnamed"


def upload_root() -> Path:
    root = Path(get_settings().data_root) / "uploads"
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


def job_staging_dir(job_id: str) -> Path:
    return upload_root() / job_id


def host_upload_root() -> Path:
    """Examiner-facing dump root on the office host (compose bind ./data -> /app/data)."""
    settings = get_settings()
    explicit = str(getattr(settings, "host_data_root", "") or "").strip()
    if explicit:
        return Path(explicit) / "uploads"
    root = Path(settings.data_root)
    text = str(root).replace("\\", "/").rstrip("/")
    if text == "/app/data":
        return Path("data") / "uploads"
    return root / "uploads"


def staging_locations(job_id: str) -> dict:
    container = job_staging_dir(job_id)
    host = host_upload_root() / job_id
    return {
        "container_path": str(container / "intake"),
        "host_path": str(host / "intake"),
        "object_prefix": f"client-uploads/{job_id}/",
    }


def purge_job_staging(job_id: str) -> dict:
    """Remove the browser-upload dump after the pipeline finishes.

    Extracted artifacts in MinIO ``jobs/{id}/`` are kept. Only the inbound
    staging tree and ``client-uploads/{id}/`` copies are deleted.
    """
    import logging
    import shutil

    log = logging.getLogger("client_intake")
    folder = job_staging_dir(job_id)
    # Cleanup is intentionally idempotent. If a previous attempt removed the
    # staging tree but the job-state update failed, a retry must still count
    # the local side as clean instead of leaving the job permanently pending.
    removed_local = not folder.exists()
    if folder.exists():
        shutil.rmtree(folder, ignore_errors=True)
        removed_local = not folder.exists()
        if not removed_local:
            log.warning("staging folder still present after purge: %s", folder)
    objects = 0
    object_purge_ok = True
    object_purge_error = None
    try:
        from app.services.storage import delete_prefix

        objects = int(delete_prefix(f"client-uploads/{job_id}/") or 0)
    except Exception as exc:
        object_purge_ok = False
        object_purge_error = str(exc)
        log.warning("staging object purge failed for job %s: %s", job_id, exc)
    return {
        "job_id": job_id,
        "local_path": str(folder),
        "removed_local": removed_local,
        "objects": objects,
        "object_purge_ok": object_purge_ok,
        "object_purge_error": object_purge_error,
        "purged": bool(removed_local and object_purge_ok),
    }


def is_staged_upload_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(upload_root())
        return True
    except Exception:
        return False


def job_intake_dir(job_id: str) -> Path:
    return job_staging_dir(job_id) / "intake"


def count_staged_files(job_id: str) -> int:
    folder = job_intake_dir(job_id)
    if not folder.is_dir():
        return 0
    n = 0
    try:
        for p in folder.rglob("*"):
            if p.is_file() and not _is_partial_upload_file(p):
                n += 1
    except OSError:
        return n
    return n


def staged_file_records(job_id: str) -> list[dict]:
    folder = job_intake_dir(job_id)
    out: list[dict] = []
    if not folder.is_dir():
        return out
    try:
        for p in folder.rglob("*"):
            if not p.is_file() or _is_partial_upload_file(p):
                continue
            try:
                rel = str(p.relative_to(folder)).replace("\\", "/")
                size = int(p.stat().st_size)
            except OSError:
                continue
            out.append({"name": p.name, "relative_path": rel, "size_bytes": size})
    except OSError:
        return out
    return out


def stage_upload_file(
    *,
    namespace: str,
    relative_path: str,
    src,
    mirror_to_object_storage: bool = True,
) -> dict:
    """Write an UploadFile / file-like object to DATA_ROOT and object storage.

    ``src`` must support ``read(size)``.
    """
    rel = safe_relative_path(relative_path)
    dest = upload_root() / namespace / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Never expose an in-flight segment at its final name. A complete-upload
    # request can therefore count/verify only atomically finished files and no
    # extractor can accidentally open a partially written E01/EWF segment.
    temp = dest.with_name(f"{dest.name}{_PARTIAL_UPLOAD_MARKER}{uuid.uuid4().hex}")
    sha = hashlib.sha256()
    size = 0
    try:
        with temp.open("wb") as out:
            while True:
                chunk = src.read(8 * 1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                sha.update(chunk)
                size += len(chunk)
            out.flush()
            try:
                os.fsync(out.fileno())
            except OSError:
                pass
        os.replace(temp, dest)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    digest = sha.hexdigest()
    mime, _ = mimetypes.guess_type(dest.name)
    key = f"client-uploads/{namespace}/{digest[:2]}/{digest}/{dest.name}"
    if mirror_to_object_storage:
        uri = put_file(key, dest, mime or "application/octet-stream")
    else:
        # Disk-image intake is already on the forensic server filesystem.
        # Avoid a second full E01/EWF copy into object storage before extraction.
        uri = f"file://{dest}"
    return {
        "relative_path": rel,
        "name": dest.name,
        "local_path": str(dest),
        "storage_uri": uri,
        "sha256": digest,
        "size_bytes": size,
        "mime_type": mime,
        "mirrored_to_object_storage": bool(mirror_to_object_storage),
    }
