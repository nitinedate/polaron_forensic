"""Mobile AXIOM catalog counting — separate from disk/EWF collectors."""

from __future__ import annotations

import json
import logging
import re
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.mobile_forensic.detection import is_mobile_job, mobile_platform
from app.services.mobile_forensic.sqlite_counts import collect_mobile_sqlite_inventory

log = logging.getLogger("mobile_forensic.inventory")

_JOB_CACHE: dict[str, dict[str, Any]] = {}


def clear_mobile_inventory_cache(job_id: str | None = None) -> None:
    if job_id:
        _JOB_CACHE.pop(job_id, None)
    else:
        _JOB_CACHE.clear()


def _norm(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def _path_blob(row: dict[str, Any]) -> str:
    return f"{row.get('file_path') or ''} {row.get('file_name') or ''}".lower().replace("\\", "/")


def _ext(row: dict[str, Any]) -> str:
    ext = (row.get("extension") or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"
    if ext:
        return ext
    return PurePosixPath(str(row.get("file_name") or row.get("file_path") or "")).suffix.lower()


def _load_files(db, job_id: str) -> list[dict[str, Any]]:
    return fetchall(
        db,
        """SELECT id, file_path, file_name, extension, size_bytes
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )


def _is_runtime_junk_path(blob: str) -> bool:
    p = (blob or "").replace("\\", "/").lower()
    if any(
        x in p
        for x in (
            "/dalvik-cache/",
            "/oat/",
            "/data/app/",
            "/preload/",
            ".apk@",
            "classes.dex",
            "facebook-appmanager",
            "facebook.appmanager",
            "facebook-services",
            "facebook-installer",
        )
    ):
        return True
    if p.endswith((".apk", ".dex", ".odex", ".vdex", ".art", ".oat", ".so", ".jar", ".prof")):
        return True
    return False


def _count_paths(
    files: list[dict[str, Any]],
    *,
    markers: tuple[str, ...],
    exts: frozenset[str] | None = None,
    databases_only: bool = False,
    app_databases: bool = False,
    exclude_runtime_junk: bool = False,
    exclude_trash: bool = False,
) -> tuple[int, list[str], list[str]]:
    matched = []
    for f in files:
        blob = _path_blob(f)
        if markers and not any(m in blob for m in markers):
            continue
        if exclude_runtime_junk and _is_runtime_junk_path(blob):
            continue
        pl = blob.replace("\\", "/")
        name = pl.rsplit("/", 1)[-1]
        if exclude_trash and (
            any(
                m in pl
                for m in (
                    "$recycle.bin",
                    "/.trash",
                    "/trash/",
                    ".trashes",
                    "deleted_recovery",
                )
            )
            or name.startswith(".trashed-")
            or name.startswith(".$trashed")
        ):
            continue
        if databases_only or app_databases:
            # Android: /databases/… ; iOS UFED: Documents/Library/*.db under AppDomain-*
            android_db = "/databases/" in pl or "/db/" in pl
            ios_app_db = (
                "appdomain-" in pl
                or "/readable_artifacts/" in pl
                or "/documents/" in pl
                or "/library/application support/" in pl
            )
            if databases_only and not android_db:
                continue
            if app_databases and not (android_db or ios_app_db):
                continue
            if not (
                name.endswith(".db")
                or name.endswith(".sqlite")
                or name.endswith(".sqlite3")
                or name.endswith(".sqlitedb")
                or ".db-" in name
            ):
                continue
            if name.endswith(("-wal", "-shm", "-journal")):
                continue
            # Skip WebKit telemetry / shadow DBs — not messaging evidence.
            if any(
                x in pl
                for x in (
                    "/webkit/",
                    "resourceloadstatistics",
                    "observations.db",
                    "localstorage",
                    "tips-store",
                    "enhancedsecurity",
                )
            ):
                continue
        if exts is not None and _ext(f) not in exts:
            continue
        matched.append(f)
    # Prefer unique logical paths (drop zip/_sealed duplicates) for count + samples.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in matched:
        key = str(f.get("file_path") or "").replace("\\", "/").lower()
        # Normalize sealed/zip duplicates to basename+app segment when possible.
        norm = key
        for prefix in ("_sealed/",):
            if prefix in norm:
                norm = norm.split(prefix, 1)[-1]
        if "/readable_artifacts/" in norm:
            norm = "readable_artifacts/" + norm.split("/readable_artifacts/", 1)[-1]
        if norm in seen:
            continue
        seen.add(norm)
        unique.append(f)
    paths = [str(f.get("file_path") or f.get("file_name") or "") for f in unique[:12]]
    ids = [str(f["id"]) for f in unique[:12] if f.get("id")]
    return len(unique), paths, ids


_IMAGE = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp", ".tif", ".tiff"})
_VIDEO = frozenset({".mp4", ".mkv", ".3gp", ".mov", ".avi", ".m4v", ".webm"})
_AUDIO = frozenset({".opus", ".mp3", ".m4a", ".wav", ".aac", ".amr", ".ogg", ".flac"})
_DOC = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"})


def _normalize_sample_entry(val: Any) -> tuple[list[str], list[str]]:
    """Normalize persisted/in-memory sample shapes → (paths, ids)."""
    if isinstance(val, dict):
        paths = [str(p) for p in (val.get("paths") or []) if p]
        ids = [str(i) for i in (val.get("ids") or []) if i]
        return paths, ids
    if isinstance(val, (list, tuple)) and val:
        # In-memory: ([paths], [ids]) — paths[0] is a string, not a nested list.
        if isinstance(val[0], (list, tuple)):
            paths = [str(p) for p in (val[0] or []) if p]
            ids = [str(i) for i in (val[1] if len(val) > 1 else []) if i]
            return paths, ids
        # Legacy persist: [path, path, ...]
        if all(isinstance(x, str) for x in val):
            return [str(p) for p in val if p], []
    return [], []


def _ids_for_paths_from_files(files: list[dict[str, Any]], paths: list[str]) -> list[str]:
    want = {str(p).replace("\\", "/").lower() for p in paths if p}
    if not want:
        return []
    out: list[str] = []
    for f in files:
        fp = str(f.get("file_path") or "").replace("\\", "/").lower()
        if not fp:
            continue
        if fp in want or any(fp.endswith(p) or p.endswith(fp) or p in fp for p in want):
            if f.get("id"):
                out.append(str(f["id"]))
        if len(out) >= 12:
            break
    return out


def _heal_sample_ids(db, job_id: str, snap: dict[str, Any]) -> dict[str, Any]:
    """Fill missing artifact ids from sample paths so Open can deep-link to files."""
    samples = dict(snap.get("samples") or {})
    files: list[dict[str, Any]] | None = None
    healed = False
    for key, val in list(samples.items()):
        paths, ids = _normalize_sample_entry(val)
        if paths and not ids:
            if files is None:
                files = _load_files(db, job_id)
            ids = _ids_for_paths_from_files(files, paths)
            healed = True
        samples[key] = (paths, ids)
    if healed or samples != snap.get("samples"):
        snap = {**snap, "samples": samples}
    return snap


# Persisted snapshots older than these keys must be rebuilt (e.g. Browser History).
_INVENTORY_SCHEMA = 4
_REQUIRED_BOARD_KEYS = frozenset({
    "browser",
    "sms_attachments",
    "email_attachments",
    "whatsapp_encrypted_backups",
    "whatsapp_media",
})


def _load_persisted_mobile_snapshot(db, job_id: str) -> dict[str, Any] | None:
    """Return previously persisted board snapshot from disk_source, if present."""
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        return None
    snap = ds.get("mobile_forensic_inventory")
    if not isinstance(snap, dict) or not snap.get("counts"):
        return None
    counts = dict(snap.get("counts") or {})
    # Stale snapshot from before Browser History / attachment split — rebuild.
    if int(snap.get("schema") or 0) < _INVENTORY_SCHEMA:
        return None
    if not _REQUIRED_BOARD_KEYS.issubset(counts.keys()):
        return None
    # Normalize persisted samples → in-memory {key: ([paths], [ids])}
    raw_samples = snap.get("samples") or {}
    samples: dict[str, Any] = {}
    for key, val in raw_samples.items():
        samples[key] = _normalize_sample_entry(val)
    loaded = {
        "platform": snap.get("platform") or mobile_platform(db, job_id),
        "total_files": int(snap.get("total_files") or 0),
        "counts": counts,
        "samples": samples,
        "limitations": list(snap.get("limitations") or []),
        "db_paths": dict(snap.get("db_paths") or {}),
        "package": dict(snap.get("package") or {}),
    }
    return _heal_sample_ids(db, job_id, loaded)


def build_mobile_inventory_snapshot(db, job_id: str, *, force: bool = False) -> dict[str, Any]:
    """Build / cache mobile inventory snapshot (SQLite + path counts)."""
    if not force and job_id in _JOB_CACHE:
        cached = _JOB_CACHE[job_id]
        # Re-heal in case older cache entries had paths without ids.
        healed = _heal_sample_ids(db, job_id, cached)
        _JOB_CACHE[job_id] = healed
        return healed
    if not force:
        persisted = _load_persisted_mobile_snapshot(db, job_id)
        if persisted:
            _JOB_CACHE[job_id] = persisted
            return persisted

    files = _load_files(db, job_id)
    sqlite_inv = collect_mobile_sqlite_inventory(db, job_id)

    # When extract only indexed package shells, count inside .pas/.ufd/.zip/.ufdx
    # (and sealed ORIGINAL_PATH) the same way disk inventory counts inside images.
    # Skip re-scanning multi-GB UFED zips when job_artifacts already has a full extract.
    package_inv: dict[str, Any] = {}
    try:
        from app.services.mobile_forensic.package_inventory import collect_portable_package_inventory

        registered = len(files)
        shell_like = 0
        if registered > 0:
            for f in files[:200]:
                blob = _path_blob(f)
                if any(blob.endswith(ext) for ext in (".pas", ".ufd", ".ufdx", ".zip")):
                    shell_like += 1
        # Full logical/backup extracts register thousands of inner files — zip scan is redundant
        # and can take hours on large UFED dumps while Artifact inventory stays at 0%.
        if registered >= 500 and shell_like < max(5, registered // 50):
            log.info(
                "Skipping UFED zip re-scan job=%s — %s files already registered in job_artifacts",
                job_id,
                f"{registered:,}",
            )
            package_inv = {
                "counts": {},
                "samples": {},
                "db_paths": {"whatsapp": [], "sms": [], "call_logs": []},
                "limitations": [
                    f"Used {registered:,} extracted files from job_artifacts (skipped dump zip re-scan)."
                ],
                "total_files": registered,
                "packages_scanned": 0,
            }
        else:
            package_inv = collect_portable_package_inventory(db, job_id)
    except Exception as exc:
        log.warning("portable package inventory skipped job=%s: %s", job_id, exc)
        package_inv = {}
    pkg_counts = dict(package_inv.get("counts") or {})

    # Additional mobile deleted recovery: trashed media + chat DB freelist/WAL.
    # Defer heavy carve during first inventory pass when extract already registered
    # thousands of files — otherwise Artifact inventory stays at 0% for hours.
    deleted_pipe: dict[str, Any] = {}
    try:
        from app.services.mobile_forensic.deleted_pipeline import ensure_mobile_deleted_pipeline

        # Always carve messaging DBs (ChatStorage / msgstore). Trash tagging is cheap;
        # skipping carve on large extracts hid deleted WhatsApp residuals.
        deleted_pipe = ensure_mobile_deleted_pipeline(
            db, job_id, force=force, carve_sqlite=True
        )
    except Exception as exc:
        log.warning("mobile deleted pipeline skipped job=%s: %s", job_id, exc)

    from app.services.deleted_evidence import (
        count_critical_file_artifacts,
        count_deleted_job_artifacts,
    )

    deleted_inv = count_deleted_job_artifacts(db, job_id)
    try:
        critical_inv = count_critical_file_artifacts(db, job_id)
    except Exception as exc:
        log.warning("critical file inventory skipped job=%s: %s", job_id, exc)
        critical_inv = {}

    pictures, pic_paths, pic_ids = _count_paths(files, markers=(), exts=_IMAGE, exclude_trash=True)
    wa_media_n, wa_media_paths, wa_media_ids = _count_paths(
        files,
        markers=("whatsapp", "net.whatsapp"),
        exts=_IMAGE | _VIDEO | _AUDIO,
        exclude_trash=True,
    )
    from app.services.mobile_forensic.whatsapp_crypt import crypt_extension
    crypt_exts = frozenset("." + ext for file in files if (ext := crypt_extension(str(file.get("file_path") or ""))))
    wa_crypt_n, wa_crypt_paths, wa_crypt_ids = _count_paths(files, markers=("msgstore",), exts=crypt_exts)
    wa_media = max(
        int(sqlite_inv.get("whatsapp_media_files") or 0),
        int(pkg_counts.get("whatsapp_media") or 0),
        wa_media_n,
    )
    dcim_n, dcim_paths, dcim_ids = _count_paths(
        files, markers=("dcim/", "pictures/", "/camera/"), exts=_IMAGE, exclude_trash=True
    )
    # Prefer real image files; WA media only when those files exist as media binaries.
    pictures = max(pictures, dcim_n, int(pkg_counts.get("pictures") or 0))
    if wa_media > 0 and pictures == 0:
        # Media counted under WhatsApp tree by extension — surface in pictures too.
        pictures = wa_media

    videos, vid_paths, vid_ids = _count_paths(files, markers=(), exts=_VIDEO, exclude_trash=True)
    videos = max(videos, int(pkg_counts.get("videos") or 0))
    audio, aud_paths, aud_ids = _count_paths(files, markers=(), exts=_AUDIO, exclude_trash=True)
    audio = max(audio, int(pkg_counts.get("audio") or 0))
    docs, doc_paths, doc_ids = _count_paths(files, markers=(), exts=_DOC, exclude_trash=True)
    docs = max(docs, int(pkg_counts.get("documents") or 0))
    emails = max(int(sqlite_inv.get("emails") or 0), int(pkg_counts.get("emails") or 0))
    email_paths = list(sqlite_inv.get("mail_db_paths") or [])[:12]
    if not email_paths:
        email_paths = list((package_inv.get("samples") or {}).get("emails") or [])[:12]
    # Real email/MIME attachments only — never SMS/MMS attachment table counts.
    email_attach_n = 0
    try:
        from app.services.email_inventory import count_email_attachments

        email_attach_n = int((count_email_attachments(db, job_id) or {}).get("count") or 0)
    except Exception:
        email_attach_n = 0
    # Path-level mobile mail attachments (strict — avoid UI assets like email.png).
    ea_paths_n, ea_paths, ea_ids = _count_paths(
        files,
        markers=("/attachments/", "/attach/", ":2,s", ":2,ps"),
        exts=_DOC | _IMAGE | {".eml", ".emlx", ".msg", ".pdf", ".zip"},
    )
    ea_clean = [
        p
        for p in ea_paths
        if "webkit" not in p.lower()
        and "resourceloadstatistics" not in p.lower()
        and "/defaults/" not in p.lower()
        and "/src/" not in p.lower()
        and not p.lower().endswith((".db", ".sqlite", ".js"))
    ]
    email_attach_n = max(email_attach_n, len(ea_clean), int(pkg_counts.get("email_attachments") or 0))

    apps_n, app_paths, app_ids = _count_paths(
        files,
        markers=("packages.xml", "/data/app/", ".apk", "application/", "bundle/application"),
        exts=None,
    )
    apps_n = max(apps_n, int(pkg_counts.get("installed_apps") or 0))
    telegram_n, tg_paths, tg_ids = _count_paths(
        files,
        markers=("telegram", "org.telegram", "appdomain-ph.telegra.telegraph"),
        app_databases=True,
        exclude_runtime_junk=True,
    )
    telegram_n = max(telegram_n, int(pkg_counts.get("telegram") or 0))
    signal_n, sig_paths, sig_ids = _count_paths(
        files,
        markers=("signal", "org.thoughtcrime", "appdomain-org.whispersystems.signal"),
        app_databases=True,
        exclude_runtime_junk=True,
    )
    signal_n = max(signal_n, int(pkg_counts.get("signal") or 0))
    ig_n, ig_paths, ig_ids = _count_paths(
        files,
        markers=("instagram", "com.instagram", "appdomain-com.burbn.instagram"),
        app_databases=True,
        exclude_runtime_junk=True,
    )
    ig_n = max(ig_n, int(pkg_counts.get("instagram") or 0))
    # iOS Facebook uses AppDomain-com.facebook.Facebook + fb-msys-*.db (not Android orca/katana).
    fb_n, fb_paths, fb_ids = _count_paths(
        files,
        markers=(
            "com.facebook.orca",
            "com.facebook.katana",
            "com.facebook.mlite",
            "com.facebook.facebook",
            "appdomain-com.facebook",
            "/readable_artifacts/facebook/",
            "fb-msys-",
            "messenger",
        ),
        app_databases=True,
        exclude_runtime_junk=True,
    )
    fb_n = max(fb_n, int(pkg_counts.get("facebook") or 0))
    li_n, li_paths, li_ids = _count_paths(
        files,
        markers=("linkedin", "com.linkedin", "appdomain-com.linkedin", "/readable_artifacts/linkedin/"),
        app_databases=True,
        exclude_runtime_junk=True,
    )
    li_n = max(li_n, int(pkg_counts.get("linkedin") or 0))
    device_n, dev_paths, dev_ids = _count_paths(
        files,
        markers=("build.prop", "info.plist", "device_info.json", "acquisition_manifest.json"),
        exts=None,
    )
    device_n = max(device_n, int(pkg_counts.get("device_info") or 0))
    sim_n, sim_paths, sim_ids = _count_paths(files, markers=("iccid", "imsi", "siminfo", "ef_iccid"), exts=None)
    sim_n = max(sim_n, int(pkg_counts.get("sim_info") or 0))

    def _pkg_sample(key: str) -> list[str]:
        return list((package_inv.get("samples") or {}).get(key) or [])[:12]

    def _ids_for_paths(paths: list[str]) -> list[str]:
        return _ids_for_paths_from_files(files, paths)

    wa_db_paths = list(sqlite_inv.get("whatsapp_db_paths") or [])[:12]
    if not wa_db_paths:
        wa_db_paths = list((package_inv.get("db_paths") or {}).get("whatsapp") or [])[:12]
    if not wa_db_paths:
        wa_db_paths = list(sqlite_inv.get("whatsapp_crypt_paths") or [])[:12] or wa_crypt_paths
    sms_db_paths = list(sqlite_inv.get("sms_db_paths") or [])[:12]
    if not sms_db_paths:
        sms_db_paths = list((package_inv.get("db_paths") or {}).get("sms") or [])[:12]
    call_db_paths = list(sqlite_inv.get("calllog_db_paths") or [])[:12]
    if not call_db_paths:
        call_db_paths = list((package_inv.get("db_paths") or {}).get("call_logs") or [])[:12]
    wa_db_ids = _ids_for_paths(wa_db_paths)
    sms_db_ids = _ids_for_paths(sms_db_paths)
    call_db_ids = _ids_for_paths(call_db_paths)
    email_ids = _ids_for_paths(email_paths)

    # Prefer package-sample paths when job_artifacts has no openable rows yet.
    if not pic_paths:
        pic_paths = _pkg_sample("pictures")
    if not vid_paths:
        vid_paths = _pkg_sample("videos")
    if not aud_paths:
        aud_paths = _pkg_sample("audio")
    if not doc_paths:
        doc_paths = _pkg_sample("documents")
    if not app_paths:
        app_paths = _pkg_sample("installed_apps")
    if not tg_paths:
        tg_paths = _pkg_sample("telegram")
    if not sig_paths:
        sig_paths = _pkg_sample("signal")
    if not ig_paths:
        ig_paths = _pkg_sample("instagram")
    if not fb_paths:
        fb_paths = _pkg_sample("facebook")
    if not li_paths:
        li_paths = _pkg_sample("linkedin")
    if not dev_paths:
        dev_paths = _pkg_sample("device_info")
    if not sim_paths:
        sim_paths = _pkg_sample("sim_info")

    # Browser History — visited URLs (Safari/Chrome/Firefox) with content type metadata.
    browser_n = 0
    browser_paths: list[str] = []
    browser_ids: list[str] = []
    try:
        from app.services.browser_url_inventory import (
            _BROWSER_SOURCE_SQL,
            clear_browser_url_cache,
            collect_job_browser_url_records,
        )
        from app.db.sql_helpers import fetchall as _fetchall

        if force:
            clear_browser_url_cache(job_id)
        url_recs = collect_job_browser_url_records(db, job_id)
        browser_n = len(url_recs)
        seen_src: list[str] = []
        for rec in url_recs:
            src = str(rec.get("source") or "").replace("\\", "/")
            if src and src not in seen_src:
                seen_src.append(src)
            if len(seen_src) >= 12:
                break
        if not seen_src:
            for row in _fetchall(db, _BROWSER_SOURCE_SQL, {"j": job_id})[:12]:
                p = str(row.get("file_path") or "").replace("\\", "/")
                if p:
                    seen_src.append(p)
        browser_paths = seen_src
        browser_ids = _ids_for_paths(browser_paths)
        browser_n = max(browser_n, int(pkg_counts.get("browser") or 0))
    except Exception as exc:
        log.warning("browser URL inventory skipped job=%s: %s", job_id, exc)
        browser_n = int(pkg_counts.get("browser") or 0)

    snap = {
        "platform": mobile_platform(db, job_id),
        "total_files": max(len(files), int(package_inv.get("total_files") or 0)),
        "sqlite": sqlite_inv,
        "package": {
            "packages_scanned": int(package_inv.get("packages_scanned") or 0),
            "total_files": int(package_inv.get("total_files") or 0),
        },
        "counts": {
            "whatsapp_messages": max(
                int(sqlite_inv.get("whatsapp_messages") or 0),
                int(pkg_counts.get("whatsapp_messages") or 0),
            ),
            "whatsapp_chats": max(
                int(sqlite_inv.get("whatsapp_chats") or 0),
                int(pkg_counts.get("whatsapp_chats") or 0),
            ),
            "whatsapp_calls": max(
                int(sqlite_inv.get("whatsapp_calls") or 0),
                int(pkg_counts.get("whatsapp_calls") or 0),
            ),
            "whatsapp_contacts": max(
                int(sqlite_inv.get("whatsapp_contacts") or 0),
                int(pkg_counts.get("whatsapp_contacts") or 0),
            ),
            "whatsapp_groups": max(
                int(sqlite_inv.get("whatsapp_groups") or 0),
                int(pkg_counts.get("whatsapp_groups") or 0),
            ),
            "whatsapp_media": wa_media,
            "whatsapp_encrypted_backups": max(
                int(sqlite_inv.get("whatsapp_encrypted_backups") or 0),
                int(pkg_counts.get("whatsapp_encrypted_backups") or 0),
                wa_crypt_n,
            ),
            "whatsapp_deleted_messages": max(
                int(sqlite_inv.get("whatsapp_deleted_messages") or 0),
                int(pkg_counts.get("whatsapp_deleted_messages") or 0),
                int(deleted_inv.get("deleted_whatsapp") or 0),
                int((deleted_pipe.get("by_app") or {}).get("whatsapp") or 0),
            ),
            "sms": max(int(sqlite_inv.get("sms") or 0), int(pkg_counts.get("sms") or 0)),
            "sms_chats": max(int(sqlite_inv.get("sms_chats") or 0), int(pkg_counts.get("sms_chats") or 0)),
            "call_logs": max(int(sqlite_inv.get("call_logs") or 0), int(pkg_counts.get("call_logs") or 0)),
            "emails": emails,
            # SMS/MMS attachment table rows are NOT email attachments.
            "sms_attachments": max(
                int(sqlite_inv.get("sms_attachments") or 0),
                int(pkg_counts.get("sms_attachments") or 0),
            ),
            "email_attachments": email_attach_n,
            "contacts": max(int(sqlite_inv.get("contacts") or 0), int(pkg_counts.get("contacts") or 0)),
            "pictures": pictures,
            "videos": videos,
            "audio": audio,
            "documents": docs,
            "installed_apps": apps_n,
            "telegram": telegram_n,
            "signal": signal_n,
            "instagram": ig_n,
            "facebook": fb_n,
            "linkedin": li_n,
            "browser": browser_n,
            "device_info": device_n,
            "sim_info": sim_n,
            "deleted_files": int(deleted_inv.get("deleted_files") or 0),
            "deleted_social": max(
                int(deleted_inv.get("deleted_social") or 0),
                int(deleted_pipe.get("total_chat_like") or 0),
                int(deleted_inv.get("carved_chat_residuals") or 0),
            ),
            "deleted_photos": max(
                int(deleted_inv.get("deleted_photos") or 0),
                int(deleted_pipe.get("deleted_photos") or 0),
            ),
            "deleted_videos": max(
                int(deleted_inv.get("deleted_videos") or 0),
                int(deleted_pipe.get("deleted_videos") or 0),
            ),
            "deleted_documents": max(
                int(deleted_inv.get("deleted_documents") or 0),
                int(deleted_pipe.get("deleted_documents") or 0),
            ),
            "deleted_chat_residuals": max(
                int(deleted_pipe.get("total_chat_like") or 0),
                int(deleted_inv.get("carved_chat_residuals") or 0),
            ),
            "deleted_with_dates": int(deleted_inv.get("with_deleted_dates") or 0),
            "critical_files": int(critical_inv.get("critical_files") or 0),
            "anomalous_files": int(critical_inv.get("anomalous_files") or 0),
            "modified_files": int(critical_inv.get("modified_files") or 0),
            # Per-app deleted chat residual families (board + AXIOM mapping).
            "telegram_deleted": int((deleted_pipe.get("by_app") or {}).get("telegram") or 0),
            "signal_deleted": int((deleted_pipe.get("by_app") or {}).get("signal") or 0),
            "instagram_deleted": int((deleted_pipe.get("by_app") or {}).get("instagram") or 0),
            "facebook_deleted": int((deleted_pipe.get("by_app") or {}).get("facebook") or 0),
            "snapchat_deleted": int((deleted_pipe.get("by_app") or {}).get("snapchat") or 0),
            "discord_deleted": int((deleted_pipe.get("by_app") or {}).get("discord") or 0),
            "viber_deleted": int((deleted_pipe.get("by_app") or {}).get("viber") or 0),
            "wechat_deleted": int((deleted_pipe.get("by_app") or {}).get("wechat") or 0),
            "line_deleted": int((deleted_pipe.get("by_app") or {}).get("line") or 0),
            "tiktok_deleted": int((deleted_pipe.get("by_app") or {}).get("tiktok") or 0),
            "linkedin_deleted": int((deleted_pipe.get("by_app") or {}).get("linkedin") or 0),
            "sms_deleted": int((deleted_pipe.get("by_app") or {}).get("sms") or 0),
            "slack_deleted": int((deleted_pipe.get("by_app") or {}).get("slack") or 0),
            "teams_deleted": int((deleted_pipe.get("by_app") or {}).get("teams") or 0),
            "skype_deleted": int((deleted_pipe.get("by_app") or {}).get("skype") or 0),
        },
        "samples": {
            "pictures": (pic_paths or dcim_paths, pic_ids or dcim_ids),
            "videos": (vid_paths, vid_ids),
            "audio": (aud_paths, aud_ids),
            "documents": (doc_paths, doc_ids),
            "emails": (email_paths, email_ids),
            "email_attachments": (ea_clean[:12], (ea_ids or _ids_for_paths(ea_clean))[:12]),
            "sms_attachments": (sms_db_paths, sms_db_ids),
            "installed_apps": (app_paths, app_ids),
            "telegram": (tg_paths, tg_ids),
            "signal": (sig_paths, sig_ids),
            "instagram": (ig_paths, ig_ids),
            "facebook": (fb_paths, fb_ids),
            "linkedin": (li_paths, li_ids),
            "browser": (browser_paths, browser_ids),
            "device_info": (dev_paths, dev_ids),
            "sim_info": (sim_paths, sim_ids),
            "whatsapp_messages": (wa_db_paths, wa_db_ids),
            "whatsapp_chats": (wa_db_paths, wa_db_ids),
            "whatsapp_calls": (wa_db_paths, wa_db_ids),
            "whatsapp_contacts": (wa_db_paths, wa_db_ids),
            "whatsapp_groups": (wa_db_paths, wa_db_ids),
            "whatsapp_media": (wa_media_paths or wa_db_paths, wa_media_ids or wa_db_ids),
            "whatsapp_encrypted_backups": (
                list(sqlite_inv.get("whatsapp_crypt_paths") or [])[:12] or wa_crypt_paths,
                wa_crypt_ids,
            ),
            "sms": (sms_db_paths, sms_db_ids),
            "sms_chats": (sms_db_paths, sms_db_ids),
            "call_logs": (call_db_paths, call_db_ids),
            "deleted_files": (
                [s.get("file_path") for s in (deleted_inv.get("samples") or []) if s.get("file_path")],
                [s.get("id") for s in (deleted_inv.get("samples") or []) if s.get("id")],
            ),
            "whatsapp_deleted_messages": (
                wa_db_paths
                or [s.get("file_path") for s in (deleted_pipe.get("chat_samples") or []) if s.get("file_path")],
                wa_db_ids
                or [s.get("id") for s in (deleted_pipe.get("chat_samples") or []) if s.get("id")],
            ),
            "deleted_social": (
                [s.get("file_path") for s in (deleted_inv.get("samples") or []) if s.get("file_path")]
                or [s.get("file_path") for s in (deleted_pipe.get("chat_samples") or []) if s.get("file_path")],
                [s.get("id") for s in (deleted_inv.get("samples") or []) if s.get("id")]
                or [s.get("id") for s in (deleted_pipe.get("chat_samples") or []) if s.get("id")],
            ),
            "deleted_photos": (
                [s.get("file_path") for s in (deleted_pipe.get("photo_samples") or []) if s.get("file_path")],
                [s.get("id") for s in (deleted_pipe.get("photo_samples") or []) if s.get("id")],
            ),
            "deleted_videos": (
                [s.get("file_path") for s in (deleted_pipe.get("video_samples") or []) if s.get("file_path")],
                [s.get("id") for s in (deleted_pipe.get("video_samples") or []) if s.get("id")],
            ),
            "deleted_documents": (
                [s.get("file_path") for s in (deleted_pipe.get("document_samples") or []) if s.get("file_path")],
                [s.get("id") for s in (deleted_pipe.get("document_samples") or []) if s.get("id")],
            ),
            "deleted_chat_residuals": (
                [s.get("file_path") for s in (deleted_pipe.get("chat_samples") or []) if s.get("file_path")],
                [s.get("id") for s in (deleted_pipe.get("chat_samples") or []) if s.get("id")],
            ),
        },
        "limitations": list(sqlite_inv.get("limitations") or [])
        + list(package_inv.get("limitations") or [])
        + (
            [str(deleted_pipe["note"])]
            if deleted_pipe.get("note") and not deleted_pipe.get("total_chat_like") and not deleted_pipe.get("deleted_photos")
            else []
        )
        + (
            [
                "Browser History: Safari History.db was not included in this Advanced Logical "
                "extraction (only listed in Manifest). URLs shown are from Google searchhistory "
                "and/or links found inside SMS/WhatsApp messages when present."
            ]
            if int(browser_n or 0) == 0
            else [
                "Browser History includes URLs recovered from available browser DBs and "
                "links found in SMS/WhatsApp messages (Safari History.db may be absent "
                "from Advanced Logical dumps)."
            ]
        )
        + (
            [
                "Signal: no Signal app databases were found in this Advanced Logical dump "
                "(Signal message stores are often unavailable without a full file-system extraction)."
            ]
            if int(signal_n or 0) == 0
            else []
        ),
        "db_paths": {
            "whatsapp": wa_db_paths or list(sqlite_inv.get("whatsapp_db_paths") or []),
            "sms": sms_db_paths or list(sqlite_inv.get("sms_db_paths") or []),
            "call_logs": call_db_paths or list(sqlite_inv.get("calllog_db_paths") or []),
        },
    }
    _JOB_CACHE[job_id] = snap
    return snap


def persist_mobile_inventory_snapshot(db, job_id: str, *, force: bool = False) -> dict[str, Any]:
    """Persist mobile board counts.

    ``force=False`` (default) reuses the deleted-pipeline cache in disk_source so
    inventory resume cannot hang for minutes re-carving every chat DB.
    """
    snap = build_mobile_inventory_snapshot(db, job_id, force=force)
    # Normalized domain parsers + recovery — expensive on large extracts.
    # Run only when forced or when the extract is small; catalog inventory must finish first.
    try:
        total_files = int(snap.get("total_files") or 0)
        if force or total_files < 500:
            from app.services.mobile_forensic.pipeline import run_mobile_analysis_pipeline

            nested = None
            try:
                nested = db.begin_nested()
            except Exception:
                nested = None
            try:
                analysis = run_mobile_analysis_pipeline(
                    db, job_id, platform=snap.get("platform"), force=force
                )
                if nested is not None:
                    nested.commit()
            except Exception:
                if nested is not None:
                    nested.rollback()
                raise
            snap["normalized_analysis"] = {
                "status": analysis.get("status"),
                "artifacts": analysis.get("artifacts"),
                "inventory_total": analysis.get("inventory_total"),
                "summary": {
                    k: (analysis.get("summary") or {}).get(k)
                    for k in (
                        "parsed_artifacts",
                        "recovered_artifacts",
                        "unsupported_files",
                        "relationships",
                        "domain_counts",
                    )
                },
            }
        else:
            try:
                from app.tasks import mobile_analysis_task

                schema_row = fetchone(db, "SELECT current_schema() AS s")
                schema = str((schema_row or {}).get("s") or "")
                if schema.startswith("firm_"):
                    mobile_analysis_task.delay(schema, job_id)
                    snap["normalized_analysis"] = {
                        "status": "queued",
                        "artifacts": 0,
                        "inventory_total": total_files,
                    }
            except Exception as exc:
                log.warning("Could not queue mobile analysis job=%s: %s", job_id, exc)
            log.info(
                "Queued mobile analysis after inventory job=%s (%s files)",
                job_id,
                f"{total_files:,}",
            )
            snap.setdefault(
                "normalized_analysis",
                {"status": "queued", "reason": "large_extract_inventory_first"},
            )
    except Exception as exc:
        log.warning("mobile analysis pipeline skipped job=%s: %s", job_id, exc)
        snap["normalized_analysis"] = {"status": "error", "error": str(exc)[:300]}
        # Never roll back the outer artifact-inventory transaction.
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    if not isinstance(ds, dict):
        ds = {}
    # Persist path + id samples so Open keeps working after reload.
    sample_persist: dict[str, dict[str, list[str]]] = {}
    for key, val in (snap.get("samples") or {}).items():
        paths, ids = _normalize_sample_entry(val)
        if paths or ids:
            sample_persist[key] = {"paths": paths[:12], "ids": ids[:12]}
    ds["mobile_forensic_inventory"] = {
        "schema": _INVENTORY_SCHEMA,
        "platform": snap["platform"],
        "total_files": snap["total_files"],
        "counts": snap["counts"],
        "limitations": snap["limitations"],
        "db_paths": snap["db_paths"],
        "package": snap.get("package") or {},
        "samples": sample_persist,
        "normalized_analysis": snap.get("normalized_analysis") or {},
    }
    if snap.get("normalized_analysis"):
        ds["mobile_normalized_analysis"] = snap["normalized_analysis"]
    # Keep legacy board shape for UI.
    ds["mobile_artifact_board"] = {
        "total_files": snap["total_files"],
        "families_available": sum(1 for v in snap["counts"].values() if int(v or 0) > 0),
        "families_total": len(snap["counts"]),
        "rows": [
            {
                "key": key,
                "label": (
                    {
                        "whatsapp_deleted_messages": "WhatsApp Deleted Messages",
                        "email_attachments": "Email Attachments",
                        "sms_attachments": "SMS / MMS Attachments",
                        "browser": "Browser History",
                        "deleted_files": "Deleted Files (all types)",
                        "critical_files": "Deleted / Modified / Anomalous Files",
                        "anomalous_files": "Anomalous Files (ext mismatch / extensionless)",
                        "modified_files": "Modified / Renamed / ADS Files",
                        "deleted_social": "Deleted Social / Chat Data",
                        "deleted_photos": "Deleted Photos",
                        "deleted_videos": "Deleted Videos",
                        "deleted_documents": "Deleted Documents",
                        "deleted_chat_residuals": "Deleted Chat Residuals (all apps)",
                        "deleted_with_dates": "Deleted Items With Dates",
                        "telegram_deleted": "Telegram Deleted / Residuals",
                        "signal_deleted": "Signal Deleted / Residuals",
                        "instagram_deleted": "Instagram Deleted / Residuals",
                        "facebook_deleted": "Facebook/Messenger Deleted / Residuals",
                        "snapchat_deleted": "Snapchat Deleted / Residuals",
                        "discord_deleted": "Discord Deleted / Residuals",
                        "viber_deleted": "Viber Deleted / Residuals",
                        "wechat_deleted": "WeChat Deleted / Residuals",
                    }.get(key)
                    or key.replace("_", " ").title()
                ),
                "count": int(val or 0),
                "available": int(val or 0) > 0,
                "description": (
                    {
                        "whatsapp_deleted_messages": (
                            "Deleted WhatsApp messages from DB flags/tables + freelist/WAL residuals"
                        ),
                        "email_attachments": (
                            "MIME / mail-store attachment files (not SMS/MMS attachment rows)"
                        ),
                        "sms_attachments": (
                            "MMS / iMessage attachment records from sms.db (not email)"
                        ),
                        "browser": (
                            "Visited URLs from Safari/Chrome/Firefox history with content type "
                            "and visit counts"
                        ),
                        "deleted_files": (
                            "Trashed / Recycle Bin / .trashed-* / freelist-recovered files of any type"
                        ),
                        "critical_files": (
                            "Cross-platform critical file evidence: deleted, modified, extensionless, "
                            "spoofed extensions, Recycle Bin, Linux Trash, iOS .trashed (Win/iOS/Linux)"
                        ),
                        "anomalous_files": (
                            "Extensionless files, double extensions, or magic-byte vs declared-extension mismatches"
                        ),
                        "modified_files": (
                            "Renamed/moved recoveries, Zone.Identifier ADS, MFT/unallocated, trash original-name diffs"
                        ),
                        "deleted_social": (
                            "Deleted/residual chat evidence across WhatsApp, Telegram, Signal, "
                            "Instagram, Facebook/Messenger and other messaging apps"
                        ),
                        "deleted_photos": (
                            "Photos under trash / .trashed-* / deleted_recovery paths"
                        ),
                        "deleted_videos": (
                            "Videos under trash / .trashed-* / deleted_recovery paths"
                        ),
                        "deleted_documents": (
                            "Documents under trash / .trashed-* / deleted_recovery paths"
                        ),
                        "deleted_chat_residuals": (
                            "Chat-like strings carved from messaging SQLite freelist/WAL pages"
                        ),
                        "deleted_with_dates": (
                            "Deleted items where a deletion timestamp was recovered"
                        ),
                        "telegram_deleted": "Telegram DB freelist/WAL residual recovery",
                        "signal_deleted": "Signal DB freelist/WAL residual recovery",
                        "instagram_deleted": "Instagram DB freelist/WAL residual recovery",
                        "facebook_deleted": "Facebook/Messenger DB freelist/WAL residual recovery",
                        "snapchat_deleted": "Snapchat DB freelist/WAL residual recovery",
                        "discord_deleted": "Discord DB freelist/WAL residual recovery",
                        "viber_deleted": "Viber DB freelist/WAL residual recovery",
                        "wechat_deleted": "WeChat DB freelist/WAL residual recovery",
                    }.get(key)
                    or "Mobile forensic inventory (AXIOM-style)"
                ),
                "limitation": None if int(val or 0) > 0 else (
                    next((x for x in snap["limitations"] if key.split("_")[0] in x.lower()), None)
                ),
            }
            for key, val in snap["counts"].items()
        ],
    }
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:jid",
        {"ds": json.dumps(ds), "jid": job_id},
    )
    return snap


def _map_axiom_name_to_key(artifact_name: str) -> str | None:
    name = _norm(artifact_name)
    # Exact-ish WhatsApp family mapping (must be before generic "whatsapp")
    if "whatsapp" in name and "deleted" in name:
        return "whatsapp_deleted_messages"
    if "whatsapp" in name and (
        "encrypted backup" in name or "encrypted backups" in name or ".crypt" in name
    ):
        return "whatsapp_encrypted_backups"
    if "deleted" in name and "photo" in name:
        return "deleted_photos"
    if "deleted" in name and "video" in name:
        return "deleted_videos"
    if "deleted" in name and ("document" in name or "doc" in name):
        return "deleted_documents"
    if "deleted" in name and ("chat residual" in name or "freelist" in name):
        return "deleted_chat_residuals"
    if "telegram" in name and "deleted" in name:
        return "telegram_deleted"
    if "signal" in name and "deleted" in name:
        return "signal_deleted"
    if "instagram" in name and "deleted" in name:
        return "instagram_deleted"
    if ("facebook" in name or "messenger" in name) and "deleted" in name:
        return "facebook_deleted"
    if "snapchat" in name and "deleted" in name:
        return "snapchat_deleted"
    if "discord" in name and "deleted" in name:
        return "discord_deleted"
    if "viber" in name and "deleted" in name:
        return "viber_deleted"
    if ("wechat" in name or "we chat" in name) and "deleted" in name:
        return "wechat_deleted"
    if "line" in name and "deleted" in name:
        return "line_deleted"
    if "tiktok" in name and "deleted" in name:
        return "tiktok_deleted"
    if "linkedin" in name and "deleted" in name:
        return "linkedin_deleted"
    if ("sms" in name or "mms" in name or "imessage" in name) and "deleted" in name:
        return "sms_deleted"
    if "slack" in name and "deleted" in name:
        return "slack_deleted"
    if "teams" in name and "deleted" in name:
        return "teams_deleted"
    if "skype" in name and "deleted" in name:
        return "skype_deleted"
    if "whatsapp" in name and "call" in name:
        return "whatsapp_calls"
    if "whatsapp" in name and "contact" in name:
        return "whatsapp_contacts"
    if "whatsapp" in name and "group" in name:
        return "whatsapp_groups"
    if "whatsapp" in name and ("chat" in name and "message" not in name):
        return "whatsapp_chats"
    if "whatsapp" in name and ("media" in name or "profile picture" in name):
        return "whatsapp_media"
    if "whatsapp" in name and ("message" in name or name.endswith("whatsapp") or "whatsapp -" in name):
        return "whatsapp_messages"
    if "whatsapp" in name and "account" in name:
        return "whatsapp_contacts"
    if "whatsapp" in name:
        return "whatsapp_messages"
    if "recycle bin" in name or name in {"deleted files", "deleted files found in recycle bin"}:
        return "deleted_files"
    if "deleted" in name and any(
        x in name for x in ("social", "telegram", "signal", "instagram", "facebook", "chat", "messaging")
    ):
        return "deleted_social"

    if "sms" in name or "mms" in name or "imessage" in name:
        return "sms"
    if "call log" in name or name.endswith("call logs"):
        return "call_logs"
    if name in {"picture", "pictures"} or ("photo" in name and "profile" not in name):
        return "pictures"
    if name in {"video", "videos"} or "carved video" in name:
        return "videos"
    if name == "audio":
        return "audio"
    if "pdf" in name or "document" in name:
        return "documents"
    if "email attachment" in name:
        return "email_attachments"
    if "email" in name or "gmail" in name or "outlook" in name or (
        "mail" in name and "facebook" not in name and "whatsapp" not in name
    ):
        return "emails"
    if name in {"contacts", "contact", "address book", "device contacts"} or (
        "contact" in name and "whatsapp" not in name
    ):
        return "contacts"
    if "installed application" in name or "installed apps" in name or name == "application":
        return "installed_apps"
    if "telegram" in name:
        return "telegram"
    if "signal" in name:
        return "signal"
    if "instagram" in name:
        return "instagram"
    if "facebook" in name or "messenger" in name:
        return "facebook"
    if "linkedin" in name:
        return "linkedin"
    if (
        name in {"browser history", "browsing history", "visited urls", "url history", "web history"}
        or "browser history" in name
        or ("safari" in name and "history" in name)
        or ("chrome" in name and "history" in name)
        or (name.startswith("browser") and "url" not in name)
    ):
        return "browser"
    # Only exact device-info style names — avoid Alexa/Ring false positives.
    if name in {
        "android device information",
        "ios device information",
        "device information",
    } or name.endswith(" device information") and "whatsapp" not in name and "alexa" not in name:
        if any(x in name for x in ("alexa", "ring", "garmin", "fitbit", "tile")):
            return None
        if "android" in name or "ios" in name or name == "device information":
            return "device_info"
    if "sim card" in name or name.startswith("sim "):
        return "sim_info"
    return None


def count_mobile_axiom_artifact(
    db,
    job_id: str,
    *,
    artifact_name: str,
    category: str = "",
) -> dict[str, Any]:
    """Count one AXIOM mobile catalog artifact using mobile-only logic."""
    if not is_mobile_job(db, job_id):
        return {"count": 0, "domain": "artifact_record", "answer": None, "confidence": "LOW"}

    snap = build_mobile_inventory_snapshot(db, job_id)
    key = _map_axiom_name_to_key(artifact_name)
    counts = snap.get("counts") or {}
    count = int(counts.get(key) or 0) if key else 0

    samples = (snap.get("samples") or {}).get(key or "", ([], []))
    sample_paths = list(samples[0] if samples else [])
    db_paths = []
    if key and key.startswith("whatsapp"):
        db_paths = list((snap.get("db_paths") or {}).get("whatsapp") or [])
    elif key == "sms":
        db_paths = list((snap.get("db_paths") or {}).get("sms") or [])
    elif key == "call_logs":
        db_paths = list((snap.get("db_paths") or {}).get("call_logs") or [])

    limitations = snap.get("limitations") or []
    domain = "file_occurrence"
    if key in {
        "whatsapp_messages",
        "whatsapp_chats",
        "whatsapp_calls",
        "whatsapp_contacts",
        "whatsapp_groups",
        "whatsapp_deleted_messages",
        "sms",
        "call_logs",
        "browser",
        "deleted_files",
        "deleted_social",
        "deleted_photos",
        "deleted_videos",
        "deleted_documents",
        "deleted_chat_residuals",
        "telegram_deleted",
        "signal_deleted",
        "instagram_deleted",
        "facebook_deleted",
        "snapchat_deleted",
        "discord_deleted",
        "viber_deleted",
        "wechat_deleted",
        "line_deleted",
        "tiktok_deleted",
        "linkedin_deleted",
        "sms_deleted",
        "slack_deleted",
        "teams_deleted",
        "skype_deleted",
    }:
        domain = (
            "artifact_record"
            if key.startswith("whatsapp") or key in {"sms", "call_logs"}
            else "recovered"
        )

    conf = "HIGH" if count > 0 else "LOW"
    parts = [f"{count:,} {'records' if domain == 'artifact_record' else 'file occurrences'} ({artifact_name})"]
    if db_paths:
        parts.append(f"Source DB: {db_paths[0]}")
    elif sample_paths:
        parts.append(f"Sample: {sample_paths[0]}")
    if count == 0 and key and key.startswith("whatsapp"):
        for lim in limitations:
            if "whatsapp" in lim.lower() or "crypt" in lim.lower():
                parts.append(lim)
                break
    answer = " — ".join(parts)

    return {
        "count": count,
        "domain": domain,
        "answer": answer,
        "confidence": conf,
        "key": key,
        "sample_paths": sample_paths or db_paths[:3],
        "limitations": limitations,
        "query_snapshot": {
            "collector": "mobile_forensic.inventory",
            "mapped_key": key,
            "db_paths": db_paths,
            "platform": snap.get("platform"),
        },
    }
