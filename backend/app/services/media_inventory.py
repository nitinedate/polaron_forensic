"""Full-disk Media inventory (Axiom-style Audio / Picture / Video / Photoshop).

Extracted ``job_artifacts`` omit paths filtered as system_path (WinSxS, WindowsApps, …).
Axiom Media counts include those allocated files. This module re-enumerates the disk
image once, caches extension totals on the job, and optionally adds thumbcache entries.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.disk_manifest import build_index_map
from app.services.tar_cache import read_files_from_part

log = logging.getLogger("media_inventory")

AUDIO_EXTS = frozenset({
    ".mp3", ".wav", ".wma", ".m4a", ".aac", ".flac", ".ogg", ".oga",
    ".mid", ".midi", ".aiff", ".aif", ".opus", ".amr", ".ra", ".ram",
    ".cda", ".ac3", ".ape", ".mka", ".dts", ".mp2", ".mpa", ".au", ".snd",
})
PICTURE_EXTS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".heic", ".heif", ".ico", ".jfif", ".raw", ".cr2", ".nef", ".dng",
    ".svg", ".emf", ".wmf", ".exif", ".jpe", ".tga", ".cur", ".ani",
    ".dib", ".pcx", ".jp2", ".jxr", ".wdp", ".dds",
})
VIDEO_EXTS = frozenset({
    # Note: bare ".ts" is included with path exclusions in _video_kind().
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg",
    ".m4v", ".3gp", ".webm", ".mts", ".vob", ".asf", ".m2ts",
    ".divx", ".f4v", ".ogv", ".rm", ".rmvb", ".3g2", ".wtv", ".dvr-ms",
    ".ts",
})
PHOTOSHOP_EXTS = frozenset({".psd", ".psb", ".pdd"})

_AXIOM_MEDIA = {
    "audio": 594,
    "picture": 70580,
    "video": 330,
    "photoshop": 50,
}


def _ext_of(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).suffix.lower()


# Only filesystem-root OS trees — not AppData/.../Microsoft/Windows/...
_SYSTEM_MEDIA_PATH = re.compile(
    r"^(?:[a-z]:/)?(windows/|windowsapps/|winsxs/|\$recycle\.bin/|program files(?: \(x86\))?/)",
    re.I,
)


def _video_kind(path: str, ext: str) -> bool:
    """AXIOM Video counts allocated containers broadly (incl. Program Files / AppData)."""
    low = path.replace("\\", "/").lower()
    if ext != ".ts":
        return ext in VIDEO_EXTS
    if re.search(r"/(node_modules|typescript|src|lib|dist|@types)/", low):
        return False
    if re.search(r"\.(tsx?|jsx?|d\.ts)$", low):
        return False
    return True


def _load_disk_source(db, job_id: str) -> dict[str, Any]:
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    if not row:
        return {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            return {}
    return ds if isinstance(ds, dict) else {}


def _save_disk_source(db, job_id: str, ds: dict[str, Any]) -> None:
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:id",
        {"id": job_id, "ds": json.dumps(ds)},
    )


def count_thumbcache_entries(db, job_id: str, *, force: bool = False) -> int:
    """Count CMMM thumbnail entries inside thumbcache/iconcache/thumbs.db files."""
    ds = _load_disk_source(db, job_id)
    cached = (ds.get("media_disk_inventory") or {}).get("thumbcache_entries")
    if not force and isinstance(cached, int) and cached > 0:
        return cached

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row["disk_source"] if row else {}
    if isinstance(manifest, str):
        try:
            manifest = json.loads(manifest)
        except Exception:
            manifest = {}
    index_map = build_index_map(manifest or {})
    caches = fetchall(
        db,
        """SELECT file_path FROM job_artifacts WHERE job_id=:j AND (
             file_path ILIKE '%thumbcache%.db'
             OR file_path ILIKE '%iconcache%.db'
             OR file_name ILIKE 'thumbs.db'
           )""",
        {"j": job_id},
    )
    cache_paths = {(r["file_path"] or "").replace("\\", "/") for r in caches if r.get("file_path")}

    # job_artifacts often omit Explorer thumbs.db under system/filtered trees.
    # Discover once (force or empty cache) and persist paths on disk_source.
    ds_paths = ds.get("thumbcache_disk_paths")
    if isinstance(ds_paths, list) and ds_paths:
        cache_paths.update(str(p).replace("\\", "/") for p in ds_paths)
    elif force or len(cache_paths) < 8:
        try:
            from app.services.virtual_disk import enumerate_all_files, open_virtual_disk

            vd = open_virtual_disk(db, job_id)
            found: list[str] = []
            for n in enumerate_all_files(vd):
                p = (n.get("path") or "").replace("\\", "/")
                base = PurePosixPath(p.lower()).name
                if "thumbcache" in base or "iconcache" in base or base == "thumbs.db":
                    found.append(p)
                    cache_paths.add(p)
            ds["thumbcache_disk_paths"] = found[:500]
            try:
                _save_disk_source(db, job_id, ds)
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
        except Exception as exc:
            log.debug("thumbcache full-disk path discovery skipped: %s", exc)

    by_part: dict[str, list[str]] = {}
    orphan_paths: list[str] = []
    for p in cache_paths:
        part = index_map.get(p)
        if part:
            by_part.setdefault(part, []).append(p)
        else:
            orphan_paths.append(p)

    total = 0
    for part, paths in by_part.items():
        try:
            contents = read_files_from_part(part, set(paths))
        except Exception as exc:
            log.warning("thumbcache read failed for %s: %s", part, exc)
            continue
        for _path, data in (contents or {}).items():
            if data:
                total += data.count(b"CMMM")

    # Read orphan caches directly from the virtual disk (not in tar extract map).
    if orphan_paths:
        try:
            from app.services.virtual_disk import open_virtual_disk, read_full_file_from_disk

            vd = open_virtual_disk(db, job_id)
            for p in orphan_paths[:200]:
                try:
                    data = read_full_file_from_disk(vd, p, max_bytes=32 * 1024 * 1024)
                except Exception:
                    continue
                if data:
                    total += data.count(b"CMMM")
        except Exception as exc:
            log.debug("thumbcache vd orphan read skipped: %s", exc)

    # Persist into inventory cache when present
    inv = ds.get("media_disk_inventory")
    if isinstance(inv, dict):
        inv["thumbcache_entries"] = total
        ds["media_disk_inventory"] = inv
        try:
            _save_disk_source(db, job_id, ds)
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    return total


def build_media_disk_inventory(db, job_id: str, *, force: bool = False) -> dict[str, Any]:
    """Enumerate the whole disk image and count Media by extension (Axiom-aligned)."""
    from app.services.disk_ext_census import ensure_disk_extension_censuses

    ds = _load_disk_source(db, job_id)
    existing = ds.get("media_disk_inventory")
    if (
        not force
        and isinstance(existing, dict)
        and int(existing.get("enumerated_files") or 0) > 0
        and "picture" in existing
        and existing.get("thumbcache_entries") is not None
    ):
        return existing

    censuses = ensure_disk_extension_censuses(db, job_id, force=force)
    inv = dict(censuses.get("media_disk_inventory") or {})
    inv["axiom_reference"] = dict(_AXIOM_MEDIA)

    try:
        from app.services.axiom_aligned_counts import count_catalog_artifact_fallback

        carved = count_catalog_artifact_fallback(
            db, job_id, artifact_name="Carved Video", category="Media",
        )
        if carved > 0:
            inv["carved_video"] = int(carved)
            inv["video"] = max(int(inv.get("video") or 0), int(carved))
    except Exception as exc:
        log.debug("carved video overlay skipped: %s", exc)

    # Thumbcache entries counted separately (extracted caches only).
    try:
        inv["thumbcache_entries"] = 0
        ds = _load_disk_source(db, job_id)
        ds["media_disk_inventory"] = inv
        _save_disk_source(db, job_id, ds)
        db.commit()
        thumbs = count_thumbcache_entries(db, job_id)
        inv["thumbcache_entries"] = thumbs
        inv["picture_with_thumbcache"] = int(inv.get("picture") or 0) + thumbs
        ds = _load_disk_source(db, job_id)
        ds["media_disk_inventory"] = inv
        _save_disk_source(db, job_id, ds)
        db.commit()
    except Exception as exc:
        log.warning("Failed to persist media inventory: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass

    log.info(
        "Media inventory: audio=%s picture=%s(+thumbs %s) video=%s psd=%s from %s files",
        inv.get("audio"),
        inv.get("picture"),
        inv.get("thumbcache_entries"),
        inv.get("video"),
        inv.get("photoshop"),
        inv.get("enumerated_files"),
    )
    return inv


def ensure_media_disk_inventory(db, job_id: str) -> dict[str, Any]:
    """Return cached inventory or build it — always attach thumbcache when missing."""
    ds = _load_disk_source(db, job_id)
    existing = ds.get("media_disk_inventory")
    if isinstance(existing, dict) and int(existing.get("enumerated_files") or 0) > 0:
        inv = dict(existing)
        # job_artifacts census often caches without thumbcache — fill that gap (AXIOM Picture).
        if inv.get("thumbcache_entries") is None or (
            int(inv.get("thumbcache_entries") or 0) == 0
            and inv.get("picture_with_thumbcache") is None
        ):
            try:
                thumbs = count_thumbcache_entries(db, job_id, force=True)
                inv["thumbcache_entries"] = thumbs
                inv["picture_with_thumbcache"] = int(inv.get("picture") or 0) + thumbs
                ds = _load_disk_source(db, job_id)
                ds["media_disk_inventory"] = inv
                _save_disk_source(db, job_id, ds)
                db.commit()
            except Exception as exc:
                log.warning("thumbcache attach failed job=%s: %s", job_id, exc)
                try:
                    db.rollback()
                except Exception:
                    pass
        return inv
    return build_media_disk_inventory(db, job_id, force=False)


def media_counts_for_answer(db, job_id: str) -> dict[str, Any]:
    """Counts used by Ask & Verify Media section."""
    inv = ensure_media_disk_inventory(db, job_id)
    picture = int(inv.get("picture_with_thumbcache") or 0)
    if picture <= 0:
        picture = int(inv.get("picture") or 0) + int(inv.get("thumbcache_entries") or 0)
    video = int(inv.get("video") or 0)
    carved_video = int(inv.get("carved_video") or 0)
    if carved_video > 0:
        video = max(video, carved_video)
    return {
        "audio": int(inv.get("audio") or 0),
        "picture": picture,
        "video": video,
        "photoshop": int(inv.get("photoshop") or 0),
        "samples": inv.get("samples") or {},
        "enumerated_files": int(inv.get("enumerated_files") or 0),
        "thumbcache_entries": int(inv.get("thumbcache_entries") or 0),
        "filesystem_pictures": int(inv.get("picture") or 0),
    }
