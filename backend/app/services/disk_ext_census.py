"""One-pass full-disk extension census for document + media + LNK counts.

Avoids repeated EWF/TSK walks during artifact inventory (each walk can take
many minutes on large images and looks like a UI hang).
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Callable

from app.db.sql_helpers import execute, fetchone

log = logging.getLogger("disk_ext_census")

ProgressCb = Callable[[str, dict[str, Any] | None], None]

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
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".mpeg", ".mpg",
    ".m4v", ".3gp", ".webm", ".mts", ".vob", ".asf", ".m2ts",
    ".divx", ".f4v", ".ogv", ".rm", ".rmvb", ".3g2", ".wtv", ".dvr-ms",
    ".ts",
})
PHOTOSHOP_EXTS = frozenset({".psd", ".psb", ".pdd"})

DOCUMENT_EXTENSIONS: dict[str, list[str]] = {
    "csv documents": [".csv"],
    "microsoft powerpoint documents": [".ppt", ".pptx"],
    "microsoft excel documents": [".xls", ".xlsx", ".xlsm"],
    "pdf documents": [".pdf"],
    "rtf documents": [".rtf"],
    "text documents": [".txt", ".log"],
    "microsoft word documents": [".doc", ".docx", ".docm"],
    "openoffice documents": [".odt", ".ods", ".odp"],
    "onenote documents": [".one"],
    "publisher documents": [".pub"],
}


def _document_ext_key(extensions: list[str]) -> str:
    return ",".join(sorted({e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}))


def _doc_ext_to_keys() -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for _name, exts in DOCUMENT_EXTENSIONS.items():
        key = _document_ext_key(exts)
        for e in exts:
            ext = e.lower() if e.startswith(".") else f".{e.lower()}"
            mapping.setdefault(ext, []).append(key)
    return mapping


_DOC_EXT_TO_KEYS = _doc_ext_to_keys()


# Only filesystem-root OS trees — not AppData/.../Microsoft/Windows/...
_SYSTEM_MEDIA_PATH = re.compile(
    r"^(?:[a-z]:/)?(windows/|windowsapps/|winsxs/|\$recycle\.bin/|program files(?: \(x86\))?/)",
    re.I,
)


def _video_kind(path: str, ext: str) -> bool:
    """AXIOM Video counts allocated containers broadly (incl. Program Files / AppData).

    Only suppress TypeScript/node false positives for bare ``.ts``.
    """
    low = path.replace("\\", "/").lower()
    if ext != ".ts":
        return ext in VIDEO_EXTS
    # Bare .ts is mostly TypeScript source — keep only plausible MPEG-TS paths.
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


def _doc_ready(inv: Any) -> bool:
    if not (isinstance(inv, dict) and int(inv.get("enumerated_files") or 0) > 0 and inv.get("by_ext_key") is not None):
        return False
    # Phase-1 job_artifacts census undercounts vs AXIOM full-volume walk.
    return str(inv.get("source") or "") != "job_artifacts"


def _media_ready(inv: Any) -> bool:
    if not (isinstance(inv, dict) and int(inv.get("enumerated_files") or 0) > 0 and "picture" in inv):
        return False
    return str(inv.get("source") or "") != "job_artifacts"


def _census_from_job_artifacts(db, job_id: str) -> dict[str, Any] | None:
    """Fast census from already-materialized job_artifacts — no EWF/TSK walk."""
    from app.db.sql_helpers import fetchall

    total_row = fetchone(
        db,
        "SELECT count(*) c FROM job_artifacts WHERE job_id=:jid",
        {"jid": job_id},
    )
    total = int(total_row["c"]) if total_row else 0
    if total <= 0:
        return None

    rows = fetchall(
        db,
        """SELECT lower(coalesce(nullif(trim(extension), ''), '')) AS ext,
                  count(*)::bigint AS c
           FROM job_artifacts
           WHERE job_id=:jid
           GROUP BY 1""",
        {"jid": job_id},
    )
    by_ext_key: Counter[str] = Counter()
    media_counts: Counter[str] = Counter()
    lnk = 0
    for row in rows:
        ext = (row.get("ext") or "").lower()
        if not ext or ext == ".":
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        cnt = int(row.get("c") or 0)
        if ext == ".lnk":
            lnk += cnt
        for key in _DOC_EXT_TO_KEYS.get(ext, ()):
            by_ext_key[key] += cnt
        if ext in AUDIO_EXTS:
            media_counts["audio"] += cnt
        elif ext in PICTURE_EXTS:
            media_counts["picture"] += cnt
        elif ext in VIDEO_EXTS:
            media_counts["video"] += cnt
        elif ext in PHOTOSHOP_EXTS:
            media_counts["photoshop"] += cnt

    return {
        "document_disk_inventory": {
            "by_ext_key": dict(by_ext_key),
            "enumerated_files": total,
            "source": "job_artifacts",
        },
        "media_disk_inventory": {
            "audio": int(media_counts["audio"]),
            "picture": int(media_counts["picture"]),
            "video": int(media_counts["video"]),
            "photoshop": int(media_counts["photoshop"]),
            "enumerated_files": total,
            "samples": {"audio": [], "picture": [], "video": [], "photoshop": []},
            "source": "job_artifacts",
        },
        "lnk_disk_count": int(lnk),
    }


def ensure_disk_extension_censuses(
    db,
    job_id: str,
    *,
    force: bool = False,
    on_progress: ProgressCb | None = None,
) -> dict[str, Any]:
    """Ensure document + media + LNK censuses exist.

    Prefer a fast SQL census from job_artifacts (always available after materialize).
    Full EWF walk is optional and skipped when artifacts are already registered —
    agent workers often lack evidence mounts and OOM on large images.
    """
    ds = _load_disk_source(db, job_id)
    doc_inv = ds.get("document_disk_inventory")
    media_inv = ds.get("media_disk_inventory")
    lnk_count = ds.get("lnk_disk_count")
    if (
        not force
        and _doc_ready(doc_inv)
        and _media_ready(media_inv)
        and isinstance(lnk_count, int)
    ):
        return {
            "document_disk_inventory": doc_inv,
            "media_disk_inventory": media_inv,
            "lnk_disk_count": lnk_count,
        }

    # AXIOM Section B counts allocated FS + carved. job_artifacts is phase-1 filtered
    # and undercounts Picture/Video/docs vs a full volume walk. Prefer full-disk
    # enumeration when the virtual disk opens; fall back to job_artifacts on failure
    # (agent workers without evidence mounts).
    artifact_census = None
    if not force:
        artifact_census = _census_from_job_artifacts(db, job_id)

    from app.services.virtual_disk import enumerate_all_files, open_virtual_disk

    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    log.info("Building combined disk extension census for job %s", job_id)
    if on_progress:
        on_progress(
            "Full-disk extension census — scanning filesystem once for documents, media, and LNK",
            {"phase": "disk_ext_census"},
        )

    try:
        vd = open_virtual_disk(db, job_id)
        last_log = time.monotonic()

        def _enum_progress(message: str, meta: dict[str, Any] | None = None) -> None:
            nonlocal last_log
            now = time.monotonic()
            if on_progress and (now - last_log >= 20.0 or "complete" in (message or "").lower()):
                last_log = now
                on_progress(message, meta)

        nodes = enumerate_all_files(vd, on_progress=_enum_progress if on_progress else None)
    except Exception as exc:
        log.warning("EWF census failed job=%s — falling back to job_artifacts: %s", job_id, exc)
        artifact_census = _census_from_job_artifacts(db, job_id)
        if artifact_census:
            ds = _load_disk_source(db, job_id)
            ds["document_disk_inventory"] = artifact_census["document_disk_inventory"]
            ds["media_disk_inventory"] = artifact_census["media_disk_inventory"]
            ds["lnk_disk_count"] = int(artifact_census["lnk_disk_count"])
            _save_disk_source(db, job_id, ds)
            db.commit()
            return artifact_census
        nodes = []

    by_ext_key: Counter[str] = Counter()
    media_counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = {
        "audio": [],
        "picture": [],
        "video": [],
        "photoshop": [],
    }
    lnk = 0

    for n in nodes:
        path = (n.get("path") or "").replace("\\", "/")
        ext = PurePosixPath(path).suffix.lower()
        if not ext:
            continue
        if ext == ".lnk":
            lnk += 1
        for key in _DOC_EXT_TO_KEYS.get(ext, ()):
            by_ext_key[key] += 1
        kind = None
        if ext in AUDIO_EXTS:
            kind = "audio"
        elif ext in PICTURE_EXTS:
            kind = "picture"
        elif _video_kind(path, ext):
            kind = "video"
        elif ext in PHOTOSHOP_EXTS:
            kind = "photoshop"
        if kind:
            media_counts[kind] += 1
            if len(samples[kind]) < 8:
                samples[kind].append(path)

    # Empty EWF walk (missing mounts) — prefer job_artifacts so we don't loop forever.
    if len(nodes) <= 0:
        artifact_census = _census_from_job_artifacts(db, job_id)
        if artifact_census:
            ds = _load_disk_source(db, job_id)
            ds["document_disk_inventory"] = artifact_census["document_disk_inventory"]
            ds["media_disk_inventory"] = artifact_census["media_disk_inventory"]
            ds["lnk_disk_count"] = int(artifact_census["lnk_disk_count"])
            _save_disk_source(db, job_id, ds)
            db.commit()
            return artifact_census

    doc_inv = {
        "by_ext_key": dict(by_ext_key),
        "enumerated_files": max(len(nodes), 1),  # mark ready so callers stop re-walking
        "source": "full_disk_enumeration",
    }
    media_inv = {
        "audio": int(media_counts["audio"]),
        "picture": int(media_counts["picture"]),
        "video": int(media_counts["video"]),
        "photoshop": int(media_counts["photoshop"]),
        "enumerated_files": max(len(nodes), 1),
        "samples": samples,
        "source": "full_disk_enumeration",
    }

    ds = _load_disk_source(db, job_id)
    ds["document_disk_inventory"] = doc_inv
    ds["media_disk_inventory"] = media_inv
    ds["lnk_disk_count"] = int(lnk)
    _save_disk_source(db, job_id, ds)
    db.commit()

    if on_progress:
        on_progress(
            f"Full-disk extension census complete — {len(nodes):,} files "
            f"(pictures={media_inv['picture']:,}, videos={media_inv['video']:,}, lnk={lnk:,})",
            {
                "enumerated_files": len(nodes),
                "picture": media_inv["picture"],
                "video": media_inv["video"],
                "lnk": lnk,
            },
        )
    log.info(
        "Combined census job=%s files=%s picture=%s video=%s audio=%s lnk=%s",
        job_id,
        len(nodes),
        media_inv["picture"],
        media_inv["video"],
        media_inv["audio"],
        lnk,
    )
    return {
        "document_disk_inventory": doc_inv,
        "media_disk_inventory": media_inv,
        "lnk_disk_count": int(lnk),
    }
