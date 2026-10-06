"""Read-only virtual disk access from registered host segment paths (no local image copy)."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall

log = logging.getLogger("virtual_disk")

MOBILE_FOLDER_FORMATS = frozenset({"pas", "ufd", "ufdx", "zip", "mobile"})
PORTABLE_ZIP_SUFFIXES = frozenset({".zip", ".pas", ".ufd"})

SEGMENT_NAME_RE = re.compile(r"\.(?:e\d{2}|E\d{2}|\d{3})$", re.I)

ProgressCb = Callable[[str, dict[str, Any] | None], None]

_pyewf = None
_pytsk3 = None
try:
    import pyewf  # type: ignore

    _pyewf = pyewf
except ImportError:
    pass
try:
    import pytsk3  # type: ignore

    _pytsk3 = pytsk3
except ImportError:
    pass


@dataclass
class VirtualDisk:
    job_id: str
    mode: str  # ewf | raw | folder
    segment_paths: list[str] = field(default_factory=list)
    segment_hashes: list[str] = field(default_factory=list)
    base_name: str = ""
    format: str = ""
    root_folder: str | None = None
    _img_info: object | None = field(default=None, repr=False)
    _fs_info: object | None = field(default=None, repr=False)
    # Reuse ZipFile handles — reopening a 130k-entry UFED dump for every member is ~100× slower.
    _zip_handles: dict[str, zipfile.ZipFile] = field(default_factory=dict, repr=False)
    _zip_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _zip_resolve_cache: dict[str, tuple[str, str]] = field(default_factory=dict, repr=False)
    _sealed_roots: dict[str, Path] = field(default_factory=dict, repr=False)

    def open_zip(self, archive: Path) -> zipfile.ZipFile:
        key = str(archive.resolve()) if archive.exists() else str(archive)
        with self._zip_lock:
            zf = self._zip_handles.get(key)
            if zf is None:
                zf = zipfile.ZipFile(archive, "r", allowZip64=True)
                self._zip_handles[key] = zf
            return zf

    def sealed_root(self, name: str) -> Path | None:
        """Resolve ORIGINAL_PATH for a metadata ZIP once, then reuse it per file."""
        if not name:
            return None
        hit = self._sealed_roots.get(name)
        if hit is not None:
            return hit
        with self._zip_lock:
            hit = self._sealed_roots.get(name)
            if hit is not None:
                return hit
            for seg in self.segment_paths:
                try:
                    archive = _resolve_evidence_path(seg)
                except Exception:
                    archive = Path(seg)
                if not is_portable_zip_archive(archive):
                    continue
                for sealed in _package_original_dirs(archive):
                    self._sealed_roots.setdefault(sealed.name, sealed)
            return self._sealed_roots.get(name)

    def close(self) -> None:
        with self._zip_lock:
            for zf in self._zip_handles.values():
                try:
                    zf.close()
                except Exception:
                    pass
            self._zip_handles.clear()
            self._zip_resolve_cache.clear()
            self._sealed_roots.clear()
        img = self._img_info
        if img is not None and hasattr(img, "close"):
            try:
                img.close()  # type: ignore[union-attr]
            except Exception:
                pass
            self._img_info = None
        self._fs_info = None


def forensic_libs_available() -> dict[str, bool]:
    return {"pyewf": _pyewf is not None, "pytsk3": _pytsk3 is not None}


def _emit(on_progress: ProgressCb | None, message: str, metadata: dict[str, Any] | None = None) -> None:
    if on_progress:
        try:
            on_progress(message, metadata)
        except Exception:
            log.debug("progress callback failed", exc_info=True)



if _pytsk3 is not None:

    class EwfImgInfo(_pytsk3.Img_Info):
        def __init__(self, ewf_handle):
            self._ewf_handle = ewf_handle
            super().__init__(url="", type=_pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset, size):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self):
            return self._ewf_handle.get_media_size()

else:

    class EwfImgInfo:  # type: ignore[no-redef]
        def __init__(self, ewf_handle):
            raise RuntimeError("pytsk3 unavailable")


def _path_from_uri(uri: str) -> Path:
    if uri.startswith("file://"):
        return Path(uri[7:])
    return Path(uri)


_evidence_path_cache: dict[str, Path] = {}


def _resolve_evidence_path(raw: str) -> Path:
    """Resolve a registered host_path to a path visible in this container.

    Prefer the stored /host/<drive>/… mount. If that mount is missing (e.g. worker
    without drive binds), fall back to the shared /evidence volume when the path
    sits under …/evidence/….
    """
    stripped = (raw or "").strip()
    if not stripped:
        raise ValueError("empty evidence path")
    cached = _evidence_path_cache.get(stripped)
    if cached is not None:
        return cached

    primary = _path_from_uri(f"file://{stripped}" if not stripped.startswith("file://") else stripped)
    try:
        if primary.exists():
            _evidence_path_cache[stripped] = primary
            return primary
    except OSError:
        pass

    norm = stripped.replace("\\", "/")
    marker = "/evidence/"
    idx = norm.lower().find(marker)
    if idx >= 0:
        alt = Path("/evidence") / norm[idx + len(marker) :]
        try:
            if alt.exists():
                if stripped not in _evidence_path_cache:
                    log.info("Resolved evidence via /evidence fallback: %s → %s", stripped, alt)
                _evidence_path_cache[stripped] = alt
                return alt
        except OSError:
            pass

    try:
        from app.services.host_evidence import resolve_host_path

        resolved = resolve_host_path(stripped, strict=False)
        _evidence_path_cache[stripped] = resolved
        return resolved
    except Exception:
        _evidence_path_cache[stripped] = primary
        return primary


def _segment_sort_key(path: Path) -> tuple:
    name = path.name
    m = re.match(r"^(?P<base>.+)\.(?P<part>e\d{2})$", name, re.I)
    if m:
        return (m.group("base").lower(), int(m.group("part")[1:]))
    m = re.match(r"^(?P<base>.+)\.(?P<part>\d{3})$", name)
    if m:
        return (m.group("base").lower(), int(m.group("part")))
    m = re.match(r"^(?P<base>.+)\.pas(?P<part>\d+)$", name, re.I)
    if m:
        return (m.group("base").lower(), int(m.group("part")))
    return (name.lower(), 0)


def is_portable_zip_archive(path: Path) -> bool:
    """True for ZIP containers used as mobile dumps (UFED FileDump .zip / Aetheris packages).

    Native Cellebrite ``.pas`` (PA BinaryFormatter) and ``.ufd`` (INI) are NOT zips —
    the payload is the sibling FileDump ``.zip`` referenced by the ``.ufd``.
    """
    try:
        if not path.is_file():
            return False
        lower = path.suffix.lower()
        if lower in {".ufdx"}:
            return False
        if lower == ".ufd":
            head = path.read_bytes()[:64]
            if head.startswith(b"[DeviceInfo]") or b"[Dumps]" in head or b"[FileDump]" in head:
                return False
        if lower == ".pas":
            head = path.read_bytes()[:64]
            if head.startswith(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff") or b"Logic" in head or b"PA.Data" in head:
                return False
        # Never treat extensionless iOS backup blobs (40-hex names) as packages.
        # zipfile.is_zipfile() on those opens every hashed file and expands
        # nested docx/xlsx/jar into the extract plan — hours of false unzip.
        if lower in PORTABLE_ZIP_SUFFIXES or lower == ".zip":
            return zipfile.is_zipfile(path)
    except OSError:
        return False
    return False


def resolve_zip_archive_member(
    root: Path,
    rel_path: str,
    *,
    cache: dict[str, tuple[str, str]] | None = None,
) -> tuple[Path, str] | None:
    """Split ``archive.zip/inner/path`` into (archive_path, member) under root."""
    rel = rel_path.replace("\\", "/").lstrip("/")
    if not rel:
        return None
    if cache is not None and rel in cache:
        archive_s, member = cache[rel]
        return Path(archive_s), member
    # Fast path: first path component is often the dump zip name.
    parts = rel.split("/")
    if len(parts) >= 2:
        head = root / parts[0]
        try:
            if head.is_file() and is_portable_zip_archive(head):
                member = "/".join(parts[1:])
                if member:
                    if cache is not None:
                        cache[rel] = (str(head), member)
                    return head, member
        except OSError:
            pass
    for i in range(1, len(parts)):
        candidate = root.joinpath(*parts[:i])
        try:
            if candidate.is_file() and is_portable_zip_archive(candidate):
                member = "/".join(parts[i:])
                if member:
                    if cache is not None:
                        cache[rel] = (str(candidate), member)
                    return candidate, member
        except OSError:
            continue
    return None


_package_original_cache: dict[str, tuple[float, tuple[str, ...]]] = {}


def _package_original_dirs(archive: Path) -> list[Path]:
    """Resolve sealed ORIGINAL_PATH / aetheris_package.json targets from a portable ZIP."""
    out: list[Path] = []
    if not is_portable_zip_archive(archive):
        return out
    try:
        cache_key = str(archive.resolve())
        mtime = float(archive.stat().st_mtime)
    except OSError:
        cache_key = str(archive)
        mtime = 0.0
    cached = _package_original_cache.get(cache_key)
    if cached and cached[0] == mtime:
        return [Path(item) for item in cached[1]]
    try:
        with zipfile.ZipFile(archive, "r") as zf:
            names = {n.replace("\\", "/") for n in zf.namelist()}
            candidates: list[str] = []
            if "ORIGINAL_PATH.txt" in names:
                candidates.append(zf.read("ORIGINAL_PATH.txt").decode("utf-8", errors="replace").strip())
            if "aetheris_package.json" in names:
                try:
                    meta = json.loads(zf.read("aetheris_package.json"))
                except Exception:
                    meta = {}
                if isinstance(meta, dict) and meta.get("original_path"):
                    candidates.append(str(meta["original_path"]))
        for raw in candidates:
            if not raw:
                continue
            try:
                resolved = _resolve_evidence_path(raw)
            except Exception:
                resolved = Path(raw)
            try:
                if resolved.is_dir():
                    out.append(resolved)
            except OSError:
                continue
    except (OSError, zipfile.BadZipFile) as exc:
        log.debug("package original lookup failed %s: %s", archive, exc)
    seen: set[str] = set()
    uniq: list[Path] = []
    for p in out:
        try:
            key = str(p.resolve())
        except OSError:
            key = str(p)
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    _package_original_cache[cache_key] = (mtime, tuple(str(p) for p in uniq))
    return uniq


def _is_ewf_segment(path: Path) -> bool:
    return bool(SEGMENT_NAME_RE.search(path.name)) or path.suffix.lower() in (".e01", ".ex01")


def _sorted_segment_paths(paths: list[Path]) -> list[Path]:
    return sorted(paths, key=_segment_sort_key)


def _open_filesystem(img) -> object | None:
    if not _pytsk3:
        return None
    try:
        return _pytsk3.FS_Info(img)
    except Exception:
        pass
    try:
        volume = _pytsk3.Volume_Info(img)
        block_size = getattr(volume.info, "block_size", 512) or 512
        candidates: list[tuple[int, str, object]] = []
        for part in volume:
            if part.len <= 0:
                continue
            desc = part.desc.decode("utf-8", errors="replace")
            lower = desc.lower()
            if any(
                token in lower
                for token in (
                    "unallocated",
                    "extended",
                    "meta",
                    "gpt header",
                    "partition table",
                    "safety table",
                )
            ):
                continue
            try:
                fs = _pytsk3.FS_Info(img, offset=part.start * block_size)
                candidates.append((part.len, desc, fs))
            except Exception:
                continue
        if not candidates:
            return None

        def partition_score(item: tuple[int, str, object]) -> int:
            length, desc, _ = item
            lower = desc.lower()
            bonus = 0
            if "basic data" in lower or "ntfs" in lower:
                bonus = 10**18
            elif "microsoft" in lower and "reserved" not in lower:
                bonus = 10**16
            if "efi" in lower or "reserved" in lower or "recovery" in lower:
                bonus -= 10**15
            return bonus + length

        candidates.sort(key=partition_score, reverse=True)
        return candidates[0][2]
    except Exception as exc:
        log.warning("partition scan failed: %s", exc)
    return None


def _open_img_info(paths: list[Path]):
    if not paths:
        raise ValueError("no segment paths")
    sorted_paths = _sorted_segment_paths(paths)

    if _pyewf and _pytsk3 and any(_is_ewf_segment(p) for p in sorted_paths):
        try:
            filenames = [str(p) for p in sorted_paths]
            ewf_handle = _pyewf.handle()
            ewf_handle.open(filenames)
            return EwfImgInfo(ewf_handle), "ewf"
        except Exception as e:
            log.warning("pyewf open failed, falling back to folder mode: %s", e)
            return None, "folder"

    if _pytsk3 and sorted_paths[0].suffix.lower() in (".dd", ".raw", ".vmdk", ".vhdx", ".aff", ".aff4"):
        try:
            return _pytsk3.Img_Info(str(sorted_paths[0])), "raw"
        except Exception as e:
            log.warning("pytsk3 raw open failed: %s", e)
            return None, "folder"
    return None, "folder"


def open_virtual_disk(
    db: Session,
    job_id: str,
    *,
    on_progress: ProgressCb | None = None,
) -> VirtualDisk:
    files = fetchall(
        db,
        """SELECT * FROM evidence_files WHERE job_id=:job_id AND status IN ('registered','assembled')
           ORDER BY segment_part NULLS LAST, original_name""",
        {"job_id": job_id},
    )
    if not files:
        raise ValueError("no registered evidence files")

    _emit(on_progress, f"Resolving {len(files)} evidence segment path(s)…", {"segments": len(files)})

    paths: list[str] = []
    hashes: list[str] = []
    for f in files:
        hp = f.get("host_path") or (f.get("storage_uri") or "")[7:]
        if hp:
            paths.append(hp)
            hashes.append(f.get("sha256") or "")

    if not paths:
        raise ValueError("no host paths on registered evidence files")

    path_objs = [_resolve_evidence_path(p) for p in paths]
    missing = [str(p) for p in path_objs if not p.exists()]
    if missing:
        raise ValueError(
            "Evidence path(s) not accessible in this worker "
            f"(path not visible at the registered location): {missing[0]}"
            + (f" (+{len(missing) - 1} more)" if len(missing) > 1 else "")
        )

    # Prefer resolved container paths for subsequent open/walk
    paths = [str(p) for p in path_objs]
    first = path_objs[0]

    if first.is_dir():
        _emit(on_progress, "Using folder-mode virtual disk (directory evidence)", {"mode": "folder"})
        return VirtualDisk(
            job_id=job_id,
            mode="folder",
            segment_paths=paths,
            segment_hashes=hashes,
            base_name=files[0].get("segment_base") or first.name,
            format="backup",
            root_folder=str(first),
        )

    base_name = files[0].get("segment_base") or first.stem
    fmt = first.suffix.lstrip(".").lower() or "raw"

    vd = VirtualDisk(
        job_id=job_id,
        mode="folder",
        segment_paths=paths,
        segment_hashes=hashes,
        base_name=base_name,
        format=fmt,
    )

    if all(p.is_file() for p in path_objs):
        suffixes = {p.suffix.lower() for p in path_objs}
        mobile_only = suffixes.issubset(MOBILE_FOLDER_FORMATS | {".ufd", ".ufdx", ".zip", ".pas", ""})
        if mobile_only or suffixes & {".pas", ".ufd", ".ufdx", ".zip"}:
            vd.mode = "folder"
            vd.root_folder = str(first.parent)
            vd.format = "mobile"
            _emit(on_progress, "Mobile extraction folder — using folder mode", {"mode": "folder", "format": "mobile"})
            return vd

    if all(p.is_file() for p in path_objs) and any(
        _is_ewf_segment(p) or p.suffix.lower() in (".dd", ".raw", ".vmdk", ".vhdx") for p in path_objs
    ):
        _emit(
            on_progress,
            f"Opening forensic image handle ({len(path_objs)} segment(s), format={fmt})…",
            {"segments": len(path_objs), "format": fmt},
        )
        img, mode = _open_img_info(path_objs)
        if img and _pytsk3 and mode != "folder":
            vd.mode = mode
            vd._img_info = img
            _emit(on_progress, f"Image handle ready — mode={mode}; scanning partitions…", {"mode": mode})
            fs = _open_filesystem(img)
            if fs:
                vd._fs_info = fs
                _emit(on_progress, "Filesystem mounted successfully", {"mode": mode})
            else:
                log.warning("FS_Info failed for job %s — no readable partition", job_id)
                vd.mode = "folder"
                vd.root_folder = str(first.parent)
                _emit(
                    on_progress,
                    "No readable partition found — falling back to folder mode",
                    {"mode": "folder"},
                )
        else:
            vd.mode = "folder"
            vd.root_folder = str(first.parent)
            _emit(on_progress, "Image open unavailable — using folder mode", {"mode": "folder"})

    return vd


def open_virtual_disk_from_paths(
    job_id: str,
    paths: list[str],
    *,
    hashes: list[str] | None = None,
    base_name: str = "",
    fmt: str = "",
    root_folder: str | None = None,
) -> VirtualDisk:
    """V45: open a VirtualDisk from an already-resolved plan — no DB session.

    Shard threads use this so they never compete for the Celery worker's tiny
    Postgres pool. Mirrors ``open_virtual_disk`` after path resolution.
    """
    if not paths:
        raise ValueError("no segment paths")
    path_objs = [_resolve_evidence_path(p) for p in paths]
    missing = [str(p) for p in path_objs if not p.exists()]
    if missing:
        raise ValueError(f"Evidence path(s) not accessible in this worker: {missing[0]}")
    first = path_objs[0]
    resolved = [str(p) for p in path_objs]
    hashes = list(hashes or [])
    if root_folder or first.is_dir():
        return VirtualDisk(
            job_id=job_id,
            mode="folder",
            segment_paths=resolved,
            segment_hashes=hashes,
            base_name=base_name or first.name,
            format=fmt or "backup",
            root_folder=root_folder or str(first),
        )
    vd = VirtualDisk(
        job_id=job_id,
        mode="folder",
        segment_paths=resolved,
        segment_hashes=hashes,
        base_name=base_name or first.stem,
        format=fmt or (first.suffix.lstrip(".").lower() or "raw"),
    )
    if any(_is_ewf_segment(p) or p.suffix.lower() in (".dd", ".raw", ".vmdk", ".vhdx") for p in path_objs):
        img, mode = _open_img_info(path_objs)
        if img and _pytsk3 and mode != "folder":
            vd.mode = mode
            vd._img_info = img
            fs = _open_filesystem(img)
            if fs:
                vd._fs_info = fs
                return vd
    vd.mode = "folder"
    vd.root_folder = str(first.parent)
    return vd


def vd_plan(vd: VirtualDisk) -> dict:
    """Serializable description a shard can reopen the disk from (V45)."""
    return {
        "segment_paths": list(vd.segment_paths),
        "segment_hashes": list(vd.segment_hashes),
        "base_name": vd.base_name,
        "format": vd.format,
        "root_folder": vd.root_folder,
        "mode": vd.mode,
    }


_VD_CACHE: dict[str, tuple[VirtualDisk, float]] = {}
_VD_CACHE_LOCK = threading.Lock()
_VD_CACHE_TTL_SEC = 600.0
_VD_CACHE_MAX_JOBS = 2


def open_virtual_disk_cached(
    db: Session,
    job_id: str,
    *,
    on_progress: ProgressCb | None = None,
) -> VirtualDisk:
    """Reuse an open image handle across preview/content requests (avoids OOM from repeated EWF mounts)."""
    now = time.time()
    with _VD_CACHE_LOCK:
        entry = _VD_CACHE.get(job_id)
        if entry and now - entry[1] < _VD_CACHE_TTL_SEC:
            return entry[0]

        stale = [key for key, (_, ts) in _VD_CACHE.items() if now - ts >= _VD_CACHE_TTL_SEC]
        for key in stale:
            _VD_CACHE.pop(key, None)
        while len(_VD_CACHE) >= _VD_CACHE_MAX_JOBS:
            oldest = min(_VD_CACHE.items(), key=lambda item: item[1][1])[0]
            _VD_CACHE.pop(oldest, None)

        vd = open_virtual_disk(db, job_id, on_progress=on_progress)
        _VD_CACHE[job_id] = (vd, now)
        return vd


def clear_virtual_disk_cache(job_id: str | None = None) -> None:
    with _VD_CACHE_LOCK:
        if job_id:
            _VD_CACHE.pop(job_id, None)
        else:
            _VD_CACHE.clear()


def _tsk_meta_type(value) -> int:
    return value.value if hasattr(value, "value") else int(value)


def enumerate_all_files(
    vd: VirtualDisk,
    *,
    on_progress: ProgressCb | None = None,
    progress_every: int = 25_000,
    progress_interval_sec: float = 15.0,
) -> list[dict]:
    """Walk filesystem and return every regular file (complete disk index)."""
    nodes: list[dict] = []
    last_emit = time.monotonic()
    every_n = max(int(progress_every), 1_000)
    every_sec = max(float(progress_interval_sec), 5.0)

    def _maybe_progress(force: bool = False) -> None:
        nonlocal last_emit
        now = time.monotonic()
        count = len(nodes)
        if not force and count > 0 and count % every_n != 0 and (now - last_emit) < every_sec:
            return
        if count == 0 and not force:
            return
        last_emit = now
        _emit(
            on_progress,
            f"Filesystem walk — {count:,} files found so far…",
            {"files_found": count},
        )

    if vd._fs_info and _pytsk3:
        reg_type = _tsk_meta_type(_pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_REG)
        dir_type = _tsk_meta_type(_pytsk3.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR)
        _emit(on_progress, "Starting TSK filesystem walk…", {"mode": vd.mode})

        def walk_dir(directory, prefix: str = ""):
            for entry in directory:
                if not entry.info.name.name or entry.info.name.name in (b".", b".."):
                    continue
                name = entry.info.name.name.decode("utf-8", errors="replace")
                rel = f"{prefix}/{name}".lstrip("/")
                meta = entry.info.meta
                if meta and meta.type == reg_type:
                    nodes.append({
                        "path": rel,
                        "name": name,
                        "size_bytes": meta.size or 0,
                        # Inode enables open_meta() — far faster than path open on large NTFS/E01
                        "inode": int(meta.addr) if getattr(meta, "addr", None) is not None else None,
                    })
                    _maybe_progress()
                elif meta and meta.type == dir_type:
                    try:
                        walk_dir(entry.as_directory(), rel)
                    except Exception:
                        pass

        try:
            walk_dir(vd._fs_info.open_dir(path="/"))
        except Exception as e:
            log.warning("TSK walk failed: %s", e)
            _emit(on_progress, f"TSK walk failed: {e}", {"error": str(e)})
        _emit(
            on_progress,
            f"Filesystem walk complete — {len(nodes):,} files enumerated",
            {"files_found": len(nodes)},
        )
        return nodes

    root = Path(vd.root_folder) if vd.root_folder else _path_from_uri(f"file://{vd.segment_paths[0]}").parent
    if not root.is_dir():
        return nodes
    _emit(on_progress, f"Starting folder walk under {root}…", {"mode": "folder"})

    seen_sealed: set[str] = set()

    def _emit_directory_batches(
        archive_label: str,
        directories: list[str],
        *,
        batch_size: int = 40,
    ) -> None:
        """Write every discovered directory into extract logs (batched for UI readability)."""
        total = len(directories)
        if total == 0:
            _emit(
                on_progress,
                f"Unzip directories [{archive_label}] — none found",
                {"directories": 0, "archive": archive_label},
            )
            return
        _emit(
            on_progress,
            f"Unzip directories [{archive_label}] — {total:,} directories discovered; listing…",
            {"directories": total, "archive": archive_label},
        )
        for i in range(0, total, batch_size):
            batch = directories[i : i + batch_size]
            start = i + 1
            end = i + len(batch)
            _emit(
                on_progress,
                f"Unzip directories [{archive_label}] ({start:,}–{end:,} of {total:,}): "
                + " · ".join(batch),
                {
                    "archive": archive_label,
                    "directories": batch,
                    "directory_range": [start, end, total],
                },
            )

    def _collect_parent_dirs(member: str, into: set[str], *, include_self: bool = False) -> None:
        parts = [p for p in member.replace("\\", "/").strip("/").split("/") if p]
        end = len(parts) if include_self else max(len(parts) - 1, 0)
        for i in range(1, end + 1):
            into.add("/".join(parts[:i]))

    def _append_file(path: Path, rel: str) -> None:
        try:
            nodes.append({"path": rel, "name": path.name, "size_bytes": path.stat().st_size})
        except OSError:
            nodes.append({"path": rel, "name": path.name, "size_bytes": 0})
        _maybe_progress()

    def _walk_zip(archive: Path, prefix: str) -> None:
        label = archive.name
        try:
            size_mb = archive.stat().st_size / (1024 * 1024)
        except OSError:
            size_mb = 0.0
        _emit(
            on_progress,
            f"Opening mobile package for unzip — {label} ({size_mb:,.1f} MiB); listing members…",
            {"archive": str(archive), "prefix": prefix, "action": "unzip_open"},
        )
        dir_set: set[str] = set()
        file_count = 0
        last_member = ""
        try:
            with zipfile.ZipFile(archive, "r") as zf:
                infos = zf.infolist()
                _emit(
                    on_progress,
                    f"Unzip index loaded — {label}: {len(infos):,} ZIP entries; expanding directories/files…",
                    {"archive": label, "zip_entries": len(infos), "action": "unzip_index"},
                )
                for info in infos:
                    member = info.filename.replace("\\", "/").lstrip("/")
                    if not member:
                        continue
                    if info.is_dir():
                        _collect_parent_dirs(member.rstrip("/"), dir_set, include_self=True)
                        continue
                    _collect_parent_dirs(member, dir_set, include_self=False)
                    rel = f"{prefix}/{member}".replace("\\", "/").lstrip("/")
                    nodes.append({"path": rel, "name": Path(member).name, "size_bytes": info.file_size})
                    file_count += 1
                    last_member = member
                    if file_count == 1 or file_count % 5_000 == 0:
                        _emit(
                            on_progress,
                            f"Unzip listing [{label}] — taking entry #{file_count:,}: {member} "
                            f"({int(info.file_size or 0):,} bytes) · {len(dir_set):,} dirs so far",
                            {
                                "archive": label,
                                "files_found": file_count,
                                "directories": len(dir_set),
                                "current_path": member,
                                "action": "unzip_list",
                            },
                        )
                    _maybe_progress()
        except (OSError, zipfile.BadZipFile) as exc:
            log.warning("zip walk failed for %s: %s", archive, exc)
            _emit(
                on_progress,
                f"Unzip failed for {label}: {exc}",
                {"archive": str(archive), "error": str(exc), "action": "unzip_error"},
            )
            return

        directories = sorted(dir_set, key=lambda d: (d.count("/"), d.lower()))
        _emit_directory_batches(label, directories)
        _emit(
            on_progress,
            f"Unzip complete — {label}: {file_count:,} files, {len(directories):,} directories"
            + (f" · last={last_member}" if last_member else ""),
            {
                "archive": label,
                "files_found": file_count,
                "directories": len(directories),
                "action": "unzip_complete",
            },
        )

    def _walk_tree(base: Path, *, rel_prefix: str | None = None) -> None:
        """Walk a directory; expand UFED FileDump .zip / Aetheris ZIP packages like disk images."""
        from app.services.dir_walk import iter_files_following_dir_links

        folder_dirs: set[str] = set()
        files: list[tuple[Path, str]] = []
        skip_derived = frozenset({
            "readable_artifacts",
            "_package_marker",
            "05_exports",
            "03_working_copy",
            ".git",
            "__pycache__",
            "node_modules",
        })
        try:
            for idx, (p, found_rel) in enumerate(
                iter_files_following_dir_links(base, skip_dir_names=skip_derived),
                start=1,
            ):
                files.append((p, found_rel))
                if idx == 1 or idx % 5000 == 0:
                    _emit(
                        on_progress,
                        f"Folder walk — {idx:,} files so far · last={found_rel}",
                        {"files_found": idx, "last": found_rel, "action": "folder_walk_progress"},
                    )
                parent_rel = str(Path(found_rel).parent).replace("\\", "/")
                if parent_rel and parent_rel not in (".", ""):
                    folder_dirs.add(parent_rel)
                    _collect_parent_dirs(parent_rel, folder_dirs, include_self=True)
        except OSError as exc:
            log.warning("directory listing failed for %s: %s", base, exc)

        if folder_dirs:
            _emit_directory_batches(
                f"folder:{base.name}",
                sorted(folder_dirs, key=lambda d: (d.count("/"), d.lower())),
            )

        for p, found_rel in files:
            if not p.is_file():
                continue
            if SEGMENT_NAME_RE.search(p.name):
                continue
            rel = found_rel if not rel_prefix else f"{rel_prefix}/{found_rel}".replace("\\", "/").lstrip("/")
            rel_l = rel.replace("\\", "/").lower()
            sealed_walk = bool(
                (rel_prefix and str(rel_prefix).replace("\\", "/").lower().startswith("_sealed/"))
                or "/ios_image/" in rel_l
                or rel_l.startswith("ios_image/")
            )

            # Native Cellebrite .ufd → follow FileDump zip (Dump/…) — AXIOM/PA layout.
            if p.suffix.lower() == ".ufd" and not is_portable_zip_archive(p):
                _emit(
                    on_progress,
                    f"Found UFED unit descriptor — {rel}; resolving FileDump zip…",
                    {"ufd": rel, "action": "ufd_resolve"},
                )
                _append_file(p, rel)
                try:
                    from app.services.mobile_forensic.cellebrite_ufed import resolve_ufd_dump_zip

                    resolved = resolve_ufd_dump_zip(p)
                except Exception:
                    resolved = None
                if resolved:
                    dump_zip, logical = resolved
                    try:
                        dump_key = str(dump_zip.resolve())
                    except OSError:
                        dump_key = str(dump_zip)
                    if dump_key not in seen_sealed and is_portable_zip_archive(dump_zip):
                        seen_sealed.add(dump_key)
                        try:
                            dump_rel = str(dump_zip.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            dump_rel = dump_zip.name
                        _emit(
                            on_progress,
                            f"UFED FileDump zip — expanding {dump_zip.name} "
                            f"(logical root {logical}/) into extract plan…",
                            {
                                "mode": "folder",
                                "ufd": str(p),
                                "dump_zip": str(dump_zip),
                                "logical_root": logical,
                                "action": "ufd_expand",
                            },
                        )
                        _walk_zip(dump_zip, dump_rel)
                else:
                    _emit(
                        on_progress,
                        f"UFED descriptor {rel} has no readable FileDump zip beside it",
                        {"ufd": rel, "action": "ufd_missing_dump"},
                    )
                continue

            # Cellebrite .ufdx → follow Extraction Path= to sibling .ufd / .pas / dump zip.
            if p.suffix.lower() == ".ufdx":
                _emit(
                    on_progress,
                    f"Found UFED evidence index — {rel}; resolving Extraction paths…",
                    {"ufdx": rel, "action": "ufdx_resolve"},
                )
                _append_file(p, rel)
                try:
                    from app.services.mobile_forensic.cellebrite_ufed import (
                        resolve_ufd_dump_zip,
                        resolve_ufdx_referenced_paths,
                    )

                    refs = resolve_ufdx_referenced_paths(p)
                except Exception:
                    refs = []
                for ref in refs:
                    try:
                        ref_key = str(ref.resolve())
                    except OSError:
                        ref_key = str(ref)
                    if ref_key in seen_sealed:
                        continue
                    suf = ref.suffix.lower()
                    if suf == ".ufd":
                        seen_sealed.add(ref_key)
                        try:
                            resolved = resolve_ufd_dump_zip(ref)
                        except Exception:
                            resolved = None
                        if resolved:
                            dump_zip, logical = resolved
                            try:
                                dump_key = str(dump_zip.resolve())
                            except OSError:
                                dump_key = str(dump_zip)
                            if dump_key not in seen_sealed and is_portable_zip_archive(dump_zip):
                                seen_sealed.add(dump_key)
                                try:
                                    dump_rel = str(dump_zip.relative_to(root)).replace("\\", "/")
                                except ValueError:
                                    dump_rel = dump_zip.name
                                _emit(
                                    on_progress,
                                    f"UFEDX → FileDump zip — expanding {dump_zip.name} "
                                    f"(logical root {logical}/)…",
                                    {
                                        "ufdx": rel,
                                        "ufd": str(ref),
                                        "dump_zip": str(dump_zip),
                                        "action": "ufdx_expand",
                                    },
                                )
                                _walk_zip(dump_zip, dump_rel)
                    elif is_portable_zip_archive(ref):
                        seen_sealed.add(ref_key)
                        try:
                            dump_rel = str(ref.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            dump_rel = ref.name
                        _emit(
                            on_progress,
                            f"UFEDX → dump zip — expanding {ref.name}…",
                            {"ufdx": rel, "dump_zip": str(ref), "action": "ufdx_zip"},
                        )
                        _walk_zip(ref, dump_rel)
                    else:
                        # .pas or other referenced file — inventory only (native PAS is not a zip).
                        try:
                            ref_rel = str(ref.relative_to(root)).replace("\\", "/")
                        except ValueError:
                            ref_rel = ref.name
                        _append_file(ref, ref_rel)
                continue

            if (not sealed_walk) and is_portable_zip_archive(p):
                try:
                    zip_key = str(p.resolve())
                except OSError:
                    zip_key = str(p)
                if zip_key in seen_sealed:
                    continue
                seen_sealed.add(zip_key)
                sealed_dirs = _package_original_dirs(p)
                has_payload = True
                try:
                    from app.services.mobile_segments import mobile_package_has_payload

                    has_payload = mobile_package_has_payload(p)
                except Exception:
                    has_payload = True
                if has_payload or not sealed_dirs:
                    _emit(
                        on_progress,
                        f"Found portable ZIP package — {rel}; starting unzip listing…",
                        {"archive": rel, "action": "zip_found"},
                    )
                    _walk_zip(p, rel)
                    if has_payload:
                        continue
                else:
                    _emit(
                        on_progress,
                        f"Metadata package — skipping ZIP payload, walking sealed original ({rel})",
                        {"archive": rel, "action": "zip_metadata_skip"},
                    )
                for sealed in sealed_dirs:
                    try:
                        sealed_key = str(sealed.resolve())
                    except OSError:
                        sealed_key = str(sealed)
                    if sealed_key in seen_sealed:
                        continue
                    try:
                        sealed.relative_to(root)
                        seen_sealed.add(sealed_key)
                        continue
                    except ValueError:
                        pass
                    seen_sealed.add(sealed_key)
                    _emit(
                        on_progress,
                        f"Walking sealed original extraction — {sealed.name}",
                        {"mode": "folder", "sealed": str(sealed), "action": "sealed_walk"},
                    )
                    _walk_tree(sealed, rel_prefix=f"_sealed/{sealed.name}")
                continue
            _append_file(p, rel)

    dir_segs = [Path(p) for p in (vd.segment_paths or []) if Path(p).is_dir()]
    payload_zips: list[Path] = []
    try:
        from app.services.mobile_segments import list_payload_zip_archives

        payload_zips = list_payload_zip_archives(root, list(vd.segment_paths or []))
    except Exception:
        payload_zips = []
    if payload_zips:
        for archive in payload_zips:
            try:
                zip_key = str(archive.resolve())
            except OSError:
                zip_key = str(archive)
            if zip_key in seen_sealed:
                continue
            seen_sealed.add(zip_key)
            try:
                rel = str(archive.relative_to(root)).replace("\\", "/")
            except ValueError:
                rel = archive.name
            _emit(
                on_progress,
                f"Payload ZIP — enumerating members only ({archive.name}); sealed folder is not walked",
                {"archive": rel, "action": "zip_payload_only"},
            )
            _walk_zip(archive, rel)
        _emit(
            on_progress,
            f"Zip-only enumeration complete — {len(nodes):,} files from {len(payload_zips)} payload archive(s)",
            {"files_found": len(nodes), "payload_zips": len(payload_zips)},
        )
        return nodes
    if len(dir_segs) > 1:
        for seg in dir_segs:
            _walk_tree(seg, rel_prefix=seg.name)
    else:
        _walk_tree(root)
    _emit(
        on_progress,
        f"Folder walk complete — {len(nodes):,} files enumerated",
        {"files_found": len(nodes)},
    )
    return nodes


def iter_file_from_disk(
    vd: VirtualDisk,
    rel_path: str,
    *,
    inode: int | None = None,
    max_bytes: int | None = None,
    chunk_size: int = 1_048_576,
) -> Iterator[bytes]:
    """Yield file bytes in chunks (UFED zip members, folders, or disk FS)."""
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    remaining = max_bytes

    def _bounded_read(handle, n: int) -> bytes:
        nonlocal remaining
        if remaining is not None:
            if remaining <= 0:
                return b""
            n = min(n, remaining)
        data = handle.read(n)
        if remaining is not None and data:
            remaining -= len(data)
        return data

    if vd._fs_info and _pytsk3:
        if inode is not None:
            try:
                fentry = vd._fs_info.open_meta(inode)
            except Exception:
                fentry = vd._fs_info.open(rel_path)
        else:
            fentry = vd._fs_info.open(rel_path)
        size = fentry.info.meta.size or 0
        if size <= 0:
            return
        if max_bytes is not None:
            size = min(size, max_bytes)
        offset = 0
        while offset < size:
            n = min(chunk_size, size - offset)
            yield fentry.read_random(offset, n)
            offset += n
        return

    root = Path(vd.root_folder) if vd.root_folder else _path_from_uri(f"file://{vd.segment_paths[0]}").parent

    if rel_path.startswith("_sealed/"):
        parts = rel_path.split("/", 2)
        if len(parts) >= 3:
            sealed_name, inner = parts[1], parts[2]
            sealed = vd.sealed_root(sealed_name)
            if sealed is not None:
                full = sealed / inner.replace("/", os.sep)
                if full.is_file():
                    with full.open("rb") as handle:
                        while True:
                            chunk = _bounded_read(handle, chunk_size)
                            if not chunk:
                                return
                            yield chunk
                    return
                split = resolve_zip_archive_member(sealed, inner, cache=vd._zip_resolve_cache)
                if split:
                    archive_path, member = split
                    zf = vd.open_zip(archive_path)
                    with vd._zip_lock:
                        with zf.open(member) as handle:
                            while True:
                                chunk = _bounded_read(handle, chunk_size)
                                if not chunk:
                                    return
                                yield chunk
                    return

    full = root / rel_path.replace("/", os.sep)
    if full.is_file():
        with full.open("rb") as handle:
            while True:
                chunk = _bounded_read(handle, chunk_size)
                if not chunk:
                    return
                yield chunk
        return

    # Portable package members: ``vivo_V2403.zip/Dump/…`` — reuse cached ZipFile handle.
    split = resolve_zip_archive_member(root, rel_path, cache=vd._zip_resolve_cache)
    if split:
        archive_path, member = split
        try:
            zf = vd.open_zip(archive_path)
            with vd._zip_lock:
                with zf.open(member) as handle:
                    while True:
                        chunk = _bounded_read(handle, chunk_size)
                        if not chunk:
                            return
                        yield chunk
            return
        except KeyError as exc:
            raise FileNotFoundError(rel_path) from exc

    raise FileNotFoundError(rel_path)


def read_full_file_from_disk(
    vd: VirtualDisk,
    rel_path: str,
    *,
    inode: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    chunks = list(iter_file_from_disk(vd, rel_path, inode=inode, max_bytes=max_bytes))
    return b"".join(chunks)
