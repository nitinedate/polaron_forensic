"""Mobile deleted-data pipeline — chat residuals + trashed photos/videos.

Runs during mobile inventory for imported UFED/ZIP/backup jobs (not only live
acquisition). Surfaces:
  - Deleted / residual chat content from WhatsApp and other messaging DBs
  - Trashed / .trashed-* photos and videos
  - Freelist/WAL residual counts by app
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("mobile_forensic.deleted_pipeline")

_CHAT_DB_MARKERS = (
    "whatsapp",
    "msgstore",
    "chatstorage",
    "extchatdatabase",
    "telegram",
    "signal",
    "instagram",
    "facebook",
    "messenger",
    "snapchat",
    "discord",
    "viber",
    "wechat",
    "linkedin",
    "sms.db",
    "mmssms",
    "skype",
    "teams",
    "slack",
    "line",
)

_IMAGE_EXTS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".tif", ".tiff"})
_VIDEO_EXTS = frozenset({".mp4", ".mkv", ".3gp", ".mov", ".avi", ".m4v", ".webm"})
_DOC_EXTS = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"})

_TRASH_PATH_RE = re.compile(
    r"(deleted_recovery|/\.trash|/trash/|\.trashes|/\$recycle\.bin|\.trashed-)",
    re.I,
)


def _ext(path: str, name: str = "", extension: str = "") -> str:
    ext = (extension or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    if ext:
        return ext
    return PurePosixPath((name or path or "").replace("\\", "/")).suffix.lower()


def _upsert_parse_result(db, job_artifact_id: str, payload: list[dict[str, Any]]) -> None:
    existing = fetchone(
        db,
        """SELECT id FROM artifact_parse_results
           WHERE job_artifact_id=:aid AND parser_name='mobile_deleted_pipeline'
           LIMIT 1""",
        {"aid": job_artifact_id},
    )
    record_count = len(payload)
    if existing:
        execute(
            db,
            """UPDATE artifact_parse_results
               SET normalized = CAST(:norm AS jsonb),
                   record_count = :rc,
                   parser_version = '1'
               WHERE id=:id""",
            {"id": existing["id"], "norm": json.dumps(payload), "rc": record_count},
        )
        return
    execute(
        db,
        """INSERT INTO artifact_parse_results
           (job_artifact_id, parser_name, parser_version, record_count, normalized, created_at)
           VALUES (:aid, 'mobile_deleted_pipeline', '1', :rc, CAST(:norm AS jsonb), NOW())""",
        {"aid": job_artifact_id, "norm": json.dumps(payload), "rc": record_count},
    )


def _patch_artifact_metadata(db, artifact_id: str, patch: dict[str, Any]) -> None:
    row = fetchone(db, "SELECT metadata FROM job_artifacts WHERE id=:id", {"id": artifact_id})
    meta = row.get("metadata") if row else {}
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    if not isinstance(meta, dict):
        meta = {}
    merged = dict(meta)
    for k, v in patch.items():
        if v is None:
            continue
        if k not in merged or merged.get(k) in (None, "", {}, []):
            merged[k] = v
        elif k == "is_deleted":
            merged[k] = bool(merged.get(k) or v)
    execute(
        db,
        "UPDATE job_artifacts SET metadata=CAST(:m AS jsonb) WHERE id=:id",
        {"m": json.dumps(merged), "id": artifact_id},
    )


def _count_trashed_media(files: list[dict[str, Any]]) -> dict[str, Any]:
    photos: list[dict[str, Any]] = []
    videos: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []
    for f in files:
        path = str(f.get("file_path") or "").replace("\\", "/")
        name = str(f.get("file_name") or "")
        low = f"{path} {name}".lower()
        meta = f.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        is_deleted = bool(
            (isinstance(meta, dict) and (meta.get("is_deleted") or meta.get("deleted_at")))
            or _TRASH_PATH_RE.search(low)
            or name.lower().startswith(".trashed-")
        )
        if not is_deleted:
            continue
        ext = _ext(path, name, str(f.get("extension") or ""))
        row = {
            "id": str(f.get("id") or ""),
            "file_path": path,
            "file_name": name,
            "deleted_at": (meta or {}).get("deleted_at") if isinstance(meta, dict) else None,
        }
        if ext in _IMAGE_EXTS:
            photos.append(row)
        elif ext in _VIDEO_EXTS:
            videos.append(row)
        elif ext in _DOC_EXTS:
            documents.append(row)
    return {
        "deleted_photos": len(photos),
        "deleted_videos": len(videos),
        "deleted_documents": len(documents),
        "photo_samples": photos[:12],
        "video_samples": videos[:12],
        "document_samples": documents[:12],
    }


_PRIMARY_CHAT_DB_NAMES = frozenset(
    {
        "msgstore.db",
        "chatstorage.sqlite",
        "extchatdatabase.sqlite",
        "chatsearchv5f.sqlite",
        "wa.db",
        "sms.db",
        "mmssms.db",
        "callhistory.sqlite",
        "lid.sqlite",
    }
)

_SKIP_CHAT_DB_NAMES = frozenset(
    {
        "localstorage.sqlite3",
        "localstorage.sqlite",
        "websql.db",
        "indexeddb.leveldb",
        "observations.db",
        "pcm.db",
        "assets.db",
        "sticker.sqlite",
        "deviceagents.sqlite",
    }
)


def _select_chat_dbs(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Select real messaging stores for freelist carve — not every WhatsApp/WebKit sqlite."""
    out: list[dict[str, Any]] = []
    for f in files:
        path = str(f.get("file_path") or "").replace("\\", "/")
        name = str(f.get("file_name") or "")
        low = f"{path}/{name}".lower()
        base = PurePosixPath(low).name
        if base.endswith(".enc") or ".sqlite.enc" in low:
            continue
        if base in _SKIP_CHAT_DB_NAMES:
            continue
        if any(x in low for x in ("/webkit/", "websitedata", "indexeddb", "localstorage", "cache/")):
            continue
        ext = _ext(path, name, str(f.get("extension") or ""))
        is_primary = base in _PRIMARY_CHAT_DB_NAMES
        if not is_primary:
            if ext not in {".db", ".sqlite", ".sqlite3", ".sqlitedb"} and not any(
                low.endswith(s) for s in (".db", ".sqlite", ".sqlite3", ".sqlitedb")
            ):
                continue
            if not any(m in low for m in _CHAT_DB_MARKERS):
                continue
            # Non-primary: only classic messenger DB folders, not random app sqlite under marker paths.
            if not any(
                m in low
                for m in (
                    "/databases/",
                    "msgstore",
                    "chatstorage",
                    "mmssms",
                    "sms.db",
                    "orca",
                    "telegram",
                    "signal",
                )
            ):
                continue
        if "deleted_recovery" in low:
            continue
        if low.endswith(("-wal", "-journal")):
            continue
        size = int(f.get("size_bytes") or 0)
        if size and size < 512:
            continue
        out.append(f)
    # Prefer larger messaging DBs
    out.sort(key=lambda r: int(r.get("size_bytes") or 0), reverse=True)
    return out[:40]


def ensure_mobile_deleted_pipeline(
    db, job_id: str, *, force: bool = False, carve_sqlite: bool = True
) -> dict[str, Any]:
    """Scan mobile job evidence for deleted chat residuals + trashed media.

    ``carve_sqlite=False`` still tags trash-path media (cheap) and skips
    freelist/WAL carving so large logical extracts do not stall inventory.
    """
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        ds = {}

    cached = ds.get("mobile_deleted_pipeline")
    if (
        not force
        and isinstance(cached, dict)
        and cached.get("ok") is not None
        and int(cached.get("databases_scanned") or 0) >= 0
    ):
        # Re-run when a prior pass skipped SQLite carve and we now want it.
        if not carve_sqlite or cached.get("carve_sqlite") is not False:
            return dict(cached)

    files = fetchall(
        db,
        """SELECT id, file_path, file_name, extension, size_bytes, metadata
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )

    # Tag trash-path media with deleted metadata so counts/titles work.
    for f in files:
        path = str(f.get("file_path") or "").replace("\\", "/")
        name = str(f.get("file_name") or "")
        low = f"{path} {name}".lower()
        if not (_TRASH_PATH_RE.search(low) or name.lower().startswith(".trashed-")):
            continue
        from app.services.deleted_evidence import detect_deleted_path_hint

        hint = detect_deleted_path_hint(path) or {
            "is_deleted": True,
            "recovery_state": "trashed",
            "deleted_source": "mobile_trash_path",
        }
        try:
            _patch_artifact_metadata(db, str(f["id"]), hint)
        except Exception as exc:
            log.debug("trash metadata patch failed %s: %s", f.get("id"), exc)

    media = _count_trashed_media(files)
    if not carve_sqlite:
        result = {
            "ok": True,
            "carve_sqlite": False,
            "databases_scanned": 0,
            "total_carved": 0,
            "total_chat_like": 0,
            "by_app": {},
            "deleted_photos": int(media.get("deleted_photos") or 0),
            "deleted_videos": int(media.get("deleted_videos") or 0),
            "deleted_documents": int(media.get("deleted_documents") or 0),
            "photo_samples": media.get("photo_samples") or [],
            "video_samples": media.get("video_samples") or [],
            "document_samples": media.get("document_samples") or [],
            "chat_samples": [],
            "note": (
                "Trash-path photos/videos/documents counted. SQLite freelist/WAL carve "
                "deferred on this large extract (no plaintext messaging DBs to carve)."
            ),
        }
        ds["mobile_deleted_pipeline"] = {
            **{k: v for k, v in result.items() if k not in {"photo_samples", "video_samples", "chat_samples"}},
            "photo_samples": (media.get("photo_samples") or [])[:8],
            "video_samples": (media.get("video_samples") or [])[:8],
            "chat_samples": [],
        }
        try:
            execute(
                db,
                "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
                {"ds": json.dumps(ds), "jid": job_id},
            )
            db.commit()
        except Exception as exc:
            log.warning("persist mobile_deleted_pipeline (trash-only) failed job=%s: %s", job_id, exc)
            try:
                db.rollback()
            except Exception:
                pass
        return result

    chat_dbs = _select_chat_dbs(files)

    from app.services.artifact_live_counts import _read_job_files
    from app.services.mobile_acquire.sqlite_deleted import recover_sqlite_bytes, infer_social_app

    by_app: dict[str, int] = {}
    total_carved = 0
    total_chat_like = 0
    databases_scanned = 0
    samples: list[dict[str, Any]] = []

    # Build companion map (path -> bytes) for -wal/-journal next to selected DBs
    companion_rows = [
        f
        for f in files
        if str(f.get("file_path") or "").lower().endswith(("-wal", "-journal"))
        or str(f.get("file_name") or "").lower().endswith(("-wal", "-journal"))
    ]
    companion_contents: dict[str, bytes] = {}
    if companion_rows:
        try:
            companion_contents = {
                k: v
                for k, v in _read_job_files(db, job_id, companion_rows, max_bytes=32 * 1024 * 1024).items()
                if v
            }
        except Exception as exc:
            log.info("companion WAL/journal read skipped job=%s: %s", job_id, exc)

    if chat_dbs:
        try:
            contents = _read_job_files(db, job_id, chat_dbs, max_bytes=512_000_000)
        except Exception as exc:
            log.warning("chat DB read failed job=%s: %s", job_id, exc)
            contents = {}

        for f in chat_dbs:
            path = (f.get("file_path") or "").replace("\\", "/")
            data = contents.get(path)
            if not data or len(data) < 100:
                continue
            companions: dict[str, bytes] = {}
            for cpath, cbytes in companion_contents.items():
                cl = cpath.lower().replace("\\", "/")
                base = path.lower()
                if cl == base + "-wal" or cl.endswith("/" + PurePosixPath(base).name + "-wal"):
                    companions["wal"] = cbytes
                elif cl == base + "-journal" or cl.endswith("/" + PurePosixPath(base).name + "-journal"):
                    companions["journal"] = cbytes
            try:
                recovered = recover_sqlite_bytes(
                    data, source_label=path, companion_bytes=companions or None
                )
            except Exception as exc:
                log.debug("recover failed %s: %s", path, exc)
                continue
            databases_scanned += 1
            carved = int(recovered.get("carved_strings") or 0)
            chat_like = int(recovered.get("chat_like_residuals") or 0)
            total_carved += carved
            total_chat_like += chat_like
            app = recovered.get("social_app") or infer_social_app(path) or "unknown"
            # Never inflate board counts with raw freelist string volume — chat_like only.
            by_app[app] = by_app.get(app, 0) + max(chat_like, 0)

            items = list(recovered.get("items") or [])[:120]
            # Prefer chat-like residuals for examiner-facing rows.
            chat_items = [it for it in items if (it or {}).get("chat_like")]
            persist_items = chat_items or items[:20]
            if persist_items:
                try:
                    _upsert_parse_result(db, str(f["id"]), persist_items)
                    # Do NOT mark the live ChatStorage/msgstore as deleted — residuals are
                    # separate recovery candidates. Tag carve metadata only.
                    _patch_artifact_metadata(
                        db,
                        str(f["id"]),
                        {
                            "recovery_state": "sqlite_freelist",
                            "has_freelist_residuals": True,
                            "social_app": app,
                            "carved_strings": carved,
                            "chat_like_residuals": chat_like,
                            "deleted_source": "mobile_deleted_pipeline",
                        },
                    )
                except Exception as exc:
                    log.debug("persist deleted parse failed %s: %s", path, exc)
                if len(samples) < 15:
                    samples.append(
                        {
                            "id": str(f["id"]),
                            "file_path": path,
                            "social_app": app,
                            "carved_strings": carved,
                            "chat_like_residuals": chat_like,
                        }
                    )

    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    result = {
        "ok": True,
        "carve_sqlite": True,
        "databases_scanned": databases_scanned,
        "total_carved": total_carved,
        "total_chat_like": total_chat_like,
        "by_app": by_app,
        "deleted_photos": int(media.get("deleted_photos") or 0),
        "deleted_videos": int(media.get("deleted_videos") or 0),
        "deleted_documents": int(media.get("deleted_documents") or 0),
        "photo_samples": media.get("photo_samples") or [],
        "video_samples": media.get("video_samples") or [],
        "document_samples": media.get("document_samples") or [],
        "chat_samples": samples,
        "note": (
            "Mobile deleted recovery: trash-path photos/videos/documents + SQLite freelist/WAL "
            "residuals from messaging DBs (WhatsApp, Telegram, Signal, …). "
            "Full unallocated-cluster carve requires physical/full-filesystem extract."
        ),
    }
    ds["mobile_deleted_pipeline"] = {
        **{k: v for k, v in result.items() if k not in {"photo_samples", "video_samples", "chat_samples"}},
        "photo_samples": (media.get("photo_samples") or [])[:8],
        "video_samples": (media.get("video_samples") or [])[:8],
        "chat_samples": samples[:8],
    }
    try:
        execute(
            db,
            "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
            {"ds": json.dumps(ds), "jid": job_id},
        )
        db.commit()
    except Exception as exc:
        log.warning("persist mobile_deleted_pipeline failed job=%s: %s", job_id, exc)
        try:
            db.rollback()
        except Exception:
            pass
    return result
