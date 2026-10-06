"""Materialise readable copies of social/mail artefacts from iOS Manifest.db.

iTunes/Finder backups store files under hash names. This module copies
databases for catalogued social/email/messaging domains into
``readable_artifacts/`` with human paths, and inventories every matching domain.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from app.services.mobile_acquire.app_catalog import (
    category_for_ios_domain,
    is_db_path,
)


def _backup_root(original: Path) -> Path | None:
    candidates: list[Path] = []
    for name in ("ios_image", "ios_backup"):
        folder = original / name
        if folder.is_dir():
            candidates.extend(folder.rglob("Manifest.db"))
    if not candidates:
        candidates = list(original.rglob("Manifest.db"))
    real = [p for p in candidates if p.is_file() and p.stat().st_size > 64]
    if not real:
        return None
    real.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return real[0].parent


_SKIP_REL_PARTS = (
    "webkit",
    "websitedata",
    "/caches/",
    "/tmp/",
    "fflogger",
    "cookies.binarycookies",
)

_WA_MEDIA_SUFFIXES = (
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".heic",
    ".heif",
    ".webp",
    ".mp4",
    ".mov",
    ".m4v",
    ".3gp",
    ".opus",
    ".aac",
    ".m4a",
    ".mp3",
    ".amr",
    ".thumb",
)


def _safe_token(value: str, limit: int = 48) -> str:
    cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in (value or ""))
    return (cleaned or "item")[:limit]


def _should_materialize(rel: str, cat: str) -> bool:
    low = (rel or "").replace("\\", "/").lower()
    if any(part in low for part in _SKIP_REL_PARTS):
        return False
    if cat == "whatsapp":
        return low.endswith(
            (
                ".sqlite",
                ".sqlite3",
                ".sqlite-wal",
                ".sqlite-shm",
                ".db",
                ".db-wal",
                ".db-shm",
                ".sqlitedb",
            )
        )
    return is_db_path(rel)


def _rank_materialize(rel: str, cat: str) -> int:
    low = (rel or "").lower()
    if low.endswith("chatstorage.sqlite"):
        return 0
    if low.endswith("sms.db") or low.endswith("sms.db-wal"):
        return 1
    if any(tok in low for tok in ("contactsv2", "callhistory", "addressbook.sqlitedb")):
        return 2
    if cat == "whatsapp":
        return 3
    return 4


def _win_long(path: Path) -> str:
    text = str(path)
    if len(text) >= 240 and not text.startswith("\\\\?\\"):
        return "\\\\?\\" + str(path.resolve())
    return text


def _resolve_file(backup_root: Path, file_id: str) -> Path | None:
    fid = (file_id or "").strip()
    if len(fid) < 2:
        return None
    for path in (
        backup_root / fid[:2] / fid,
        backup_root / "Snapshot" / fid[:2] / fid,
        backup_root / fid,
    ):
        if path.is_file():
            return path
    return None


def _link_or_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    try:
        os.link(_win_long(src), _win_long(dest))
        return
    except OSError:
        shutil.copy2(_win_long(src), _win_long(dest))


def _ios_wa_path_sets(chatstorage: Path) -> tuple[set[str], set[str], int]:
    """Return (deleted_path_keys, live_path_keys, deleted_message_count) from ChatStorage."""
    deleted: set[str] = set()
    live: set[str] = set()
    deleted_n = 0
    try:
        con = sqlite3.connect(f"file:{chatstorage}?mode=ro", uri=True)
    except sqlite3.Error:
        return deleted, live, 0
    try:
        cur = con.cursor()
        tables = {r[0].lower(): r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        msg_t = tables.get("zwamessage")
        media_t = tables.get("zwamediaitem")
        if not msg_t:
            return deleted, live, 0
        msg_cols = {r[1].lower(): r[1] for r in cur.execute(f'PRAGMA table_info("{msg_t}")')}
        type_col = msg_cols.get("zmessagetype")
        if type_col:
            deleted_n = int(
                cur.execute(
                    f'SELECT COUNT(*) FROM "{msg_t}" WHERE CAST("{type_col}" AS INTEGER)=14'
                ).fetchone()[0]
                or 0
            )
        if not media_t or not type_col:
            return deleted, live, deleted_n
        media_cols = {r[1].lower(): r[1] for r in cur.execute(f'PRAGMA table_info("{media_t}")')}
        path_cols = [
            media_cols[c]
            for c in ("zmedialocalpath", "zthumbnaillocalpath", "zxmppthumbpath")
            if c in media_cols
        ]
        if not path_cols:
            return deleted, live, deleted_n
        pk = media_cols.get("z_pk") or "Z_PK"
        media_ref = msg_cols.get("zmediaitem")
        msg_pk = msg_cols.get("z_pk") or "Z_PK"
        back_ref = media_cols.get("zmessage")
        select = ", ".join(f'm."{c}"' for c in path_cols)
        joins = []
        if media_ref:
            joins.append(f'm."{pk}" = msg."{media_ref}"')
        if back_ref:
            joins.append(f'm."{back_ref}" = msg."{msg_pk}"')
        if not joins:
            return deleted, live, deleted_n
        cur.execute(
            f'''SELECT CAST(msg."{type_col}" AS INTEGER), {select}
                FROM "{msg_t}" msg
                JOIN "{media_t}" m ON ({" OR ".join(joins)})'''
        )
        for row in cur.fetchall():
            is_deleted = int(row[0] or 0) == 14
            target = deleted if is_deleted else live
            for raw in row[1:]:
                text = str(raw or "").replace("\\", "/").strip().lower()
                if not text or text.startswith("http"):
                    continue
                target.add(text)
                target.add(Path(text).name)
    except sqlite3.Error:
        return deleted, live, deleted_n
    finally:
        con.close()
    return deleted, live, deleted_n


def _materialize_whatsapp_deleted_media(
    backup_root: Path,
    readable: Path,
    original: Path,
    out: dict[str, Any],
    *,
    copy_one,
) -> None:
    """Copy every WhatsApp media file from the iOS backup (iosagent only).

    Delete-for-Everyone clears ZMEDIALOCALPATH. Files still in Message/Media that
    no live message references are tagged deleted leftovers. Live chat images
    are copied too so the examiner tree is complete.
    """
    chat = None
    for copied in out.get("copied") or []:
        dest = str(copied.get("dest") or "")
        if dest.lower().endswith("chatstorage.sqlite"):
            cand = original / dest if not Path(dest).is_absolute() else Path(dest)
            if not cand.is_file():
                cand = readable / "whatsapp" / Path(dest).name
            if cand.is_file():
                chat = cand
                break
    if chat is None:
        hits = list((readable / "whatsapp").glob("*ChatStorage.sqlite")) if (readable / "whatsapp").is_dir() else []
        chat = hits[0] if hits else None
    if chat is None:
        out["deleted_whatsapp_media"] = 0
        out["deleted_whatsapp_messages"] = 0
        return
    deleted_keys, live_keys, deleted_n = _ios_wa_path_sets(chat)
    out["deleted_whatsapp_messages"] = deleted_n
    manifest = backup_root / "Manifest.db"
    try:
        con = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        out["errors"].append(f"deleted media Manifest: {exc}")
        out["deleted_whatsapp_media"] = 0
        return
    copied_n = 0
    live_n = 0
    try:
        rows = con.execute(
            """SELECT fileID, domain, relativePath FROM Files
               WHERE flags=1 AND relativePath != '' AND domain LIKE '%whatsapp%'"""
        ).fetchall()
        for file_id, domain, rel in rows:
            rel_n = str(rel or "").replace("\\", "/").lower()
            name = Path(rel_n).name
            if not any(rel_n.endswith(suf) for suf in _WA_MEDIA_SUFFIXES):
                continue
            tail = rel_n[8:] if rel_n.startswith("message/") else rel_n
            explicit = name in deleted_keys or any(
                rel_n.endswith(k) or tail.endswith(k) for k in deleted_keys if "/" in k
            )
            live = name in live_keys or tail in live_keys or rel_n in live_keys
            leftover = (not live) and (
                "/media/" in rel_n or rel_n.startswith("media/") or "/outbox/" in rel_n or rel_n.startswith("gif/")
            )
            before = len(out.get("copied") or [])
            copy_one(str(file_id), str(domain), str(rel), "whatsapp")
            if len(out.get("copied") or []) <= before:
                continue
            last = out["copied"][-1]
            if explicit or leftover:
                last["deleted_whatsapp_media"] = True
                copied_n += 1
            else:
                live_n += 1
    finally:
        con.close()
    out["deleted_whatsapp_media"] = copied_n
    out["whatsapp_media_live"] = live_n


_IOS_CAMERA_DOMAIN_HINTS = ("cameraroll", "mediadomain", "photodata")
_IOS_CAMERA_PATH_HINTS = ("/dcim/", "dcim/", "photodata", "cameraroll", "/media/")


def _is_ios_camera_media(domain: str, rel: str) -> bool:
    blob = f"{domain} {rel}".lower().replace("\\", "/")
    if "whatsapp" in blob:
        return False
    if not any(blob.endswith(suf) or rel.lower().endswith(suf) for suf in _WA_MEDIA_SUFFIXES):
        return False
    return any(h in blob for h in _IOS_CAMERA_DOMAIN_HINTS) or any(h in blob for h in _IOS_CAMERA_PATH_HINTS)


def _materialize_ios_camera_media(
    backup_root: Path,
    out: dict[str, Any],
    *,
    copy_one,
) -> None:
    """Copy Camera Roll / MediaDomain photos and videos from Manifest (iosagent only)."""
    manifest = backup_root / "Manifest.db"
    try:
        con = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        out["errors"].append(f"camera media Manifest: {exc}")
        out["camera_media"] = 0
        return
    copied_n = 0
    try:
        rows = con.execute(
            "SELECT fileID, domain, relativePath FROM Files WHERE flags=1 AND relativePath != ''"
        ).fetchall()
        for file_id, domain, rel in rows:
            if not _is_ios_camera_media(str(domain), str(rel)):
                continue
            before = len(out.get("copied") or [])
            copy_one(str(file_id), str(domain), str(rel), "media")
            if len(out.get("copied") or []) > before:
                copied_n += 1
    finally:
        con.close()
    out["camera_media"] = copied_n


def _carve_ios_messaging_dbs(readable: Path, out: dict[str, Any]) -> None:
    """Freelist/WAL carve of iOS ChatStorage and sms.db only. Never touches Android DBs."""
    try:
        from app.services.mobile_acquire.sqlite_deleted import recover_sqlite_residuals
    except Exception as exc:
        out["errors"].append(f"ios sqlite carve unavailable: {exc}")
        return
    dest = readable / "deleted_recovery"
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        out["errors"].append(f"ios deleted_recovery: {exc}")
        return
    carved = 0
    chat_like = 0
    for folder_name in ("whatsapp", "sms_imessage"):
        folder = readable / folder_name
        if not folder.is_dir():
            continue
        for db in folder.iterdir():
            if not db.is_file():
                continue
            name = db.name.lower()
            if "chatstorage" not in name and "sms.db" not in name:
                continue
            if name.endswith(("-wal", "-shm", "-journal")):
                continue
            try:
                item = recover_sqlite_residuals(db, dest / db.stem)
            except Exception as exc:
                out["errors"].append(f"ios carve {db.name}: {exc}")
                continue
            carved += int(item.get("carved_strings") or 0)
            chat_like += int(item.get("chat_like_residuals") or 0)
    out["deleted_sqlite_residuals"] = carved
    out["deleted_sqlite_chat_like"] = chat_like


def materialize_ios_readable_artifacts(
    original: Path,
    *,
    dest_root: Path | None = None,
    max_files: int = 400,
) -> dict[str, Any]:
    """Copy social/email/messaging DBs into readable_artifacts/…"""
    original = Path(original)
    out: dict[str, Any] = {
        "ok": False,
        "copied": [],
        "missing": [],
        "domains_by_category": {},
        "whatsapp_domains": [],
        "readable_root": "",
        "errors": [],
    }
    backup_root = _backup_root(original)
    if not backup_root:
        out["errors"].append("No ios_backup/Manifest.db found — nothing to materialise.")
        return out

    manifest = backup_root / "Manifest.db"
    readable = Path(dest_root) if dest_root else None
    if readable is None:
        stamp = original.name[-15:] if len(original.name) > 20 else original.name
        readable = original / "readable_artifacts"
        if len(str(readable)) >= 160:
            for letter in ("E", "D", "C"):
                cand = Path(f"{letter}:/ib/rd") / stamp
                try:
                    if Path(f"{letter}:/").exists():
                        cand.mkdir(parents=True, exist_ok=True)
                        readable = cand
                        link = original / "readable_artifacts"
                        if not link.exists():
                            try:
                                link.symlink_to(cand, target_is_directory=True)
                            except OSError:
                                try:
                                    os.system(f'cmd /c mklink /J "{link}" "{cand}" >nul 2>nul')
                                except OSError:
                                    pass
                        break
                except OSError:
                    continue
    try:
        readable.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fallback = Path(os.environ.get("TEMP") or ".") / "ib" / "rd" / original.name[-12:]
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            readable = fallback
            out["errors"].append(f"Could not write under original ({exc}); using {fallback}")
        except OSError as exc2:
            out["errors"].append(f"Cannot create readable_artifacts: {exc2}")
            return out
    out["readable_root"] = str(readable)

    try:
        con = sqlite3.connect(f"file:{manifest}?mode=ro", uri=True)
    except Exception as exc:
        out["errors"].append(f"Cannot open Manifest.db: {exc}")
        return out

    try:
        cur = con.cursor()
        domains = [
            r[0]
            for r in cur.execute("SELECT DISTINCT domain FROM Files").fetchall()
            if r and r[0]
        ]
        by_cat: dict[str, list[str]] = {}
        for domain in domains:
            cat = category_for_ios_domain(domain)
            if not cat:
                continue
            by_cat.setdefault(cat, []).append(domain)
        out["domains_by_category"] = by_cat
        out["whatsapp_domains"] = list(by_cat.get("whatsapp") or [])

        # WhatsApp ChatStorage first so the 400-file cap never drops chats.
        seen: set[str] = set()
        rows = cur.execute(
            "SELECT fileID, domain, relativePath FROM Files WHERE relativePath != ''"
        ).fetchall()
        queued: list[tuple[int, str, str, str, str]] = []
        for file_id, domain, rel in rows:
            cat = category_for_ios_domain(str(domain), str(rel))
            if not cat or not _should_materialize(str(rel), cat):
                continue
            queued.append((_rank_materialize(str(rel), cat), str(file_id), str(domain), str(rel), cat))
        queued.sort(key=lambda item: item[0])

        def _copy_one(file_id: str, domain: str, rel: str, cat: str) -> None:
            src = _resolve_file(backup_root, file_id)
            if not src:
                out["missing"].append({
                    "domain": domain,
                    "relativePath": rel,
                    "fileID": file_id,
                    "category": cat,
                })
                return
            dest = readable / cat / f"{file_id[:16]}_{Path(rel).name}"
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    _link_or_copy(src, dest)
                dest_display = str(dest)
                try:
                    dest_display = str(dest.relative_to(original)).replace("\\", "/")
                except ValueError:
                    pass
                out["copied"].append({
                    "category": cat,
                    "domain": domain,
                    "relativePath": rel,
                    "dest": dest_display,
                    "bytes": dest.stat().st_size if dest.exists() else 0,
                })
            except OSError as exc:
                out["errors"].append(f"{cat}/{Path(rel).name}: {exc}")

        for _rank, file_id, domain, rel, cat in queued:
            key = f"{file_id}:{rel}"
            if key in seen:
                continue
            seen.add(key)
            _copy_one(file_id, domain, rel, cat)
            non_wa = sum(1 for item in out["copied"] if item.get("category") != "whatsapp")
            if non_wa >= max_files:
                out["errors"].append(
                    f"Materialisation capped at {max_files} non-WhatsApp DB files; remaining "
                    "catalogued domains are listed in domains_by_category / Manifest.db."
                )
                break

        # Always try native SMS/AddressBook even if category map missed naming.
        for domain_like, path_like, cat in (
            ("HomeDomain", "%Library/SMS/sms.db", "sms_imessage"),
            ("HomeDomain", "%AddressBook.sqlitedb", "contacts"),
            ("HomeDomain", "%CallHistory%", "calls"),
        ):
            for file_id, domain, rel in cur.execute(
                "SELECT fileID, domain, relativePath FROM Files "
                "WHERE domain LIKE ? AND relativePath LIKE ?",
                (domain_like, path_like),
            ).fetchall():
                key = f"{file_id}:{rel}"
                if key in seen:
                    continue
                seen.add(key)
                _copy_one(str(file_id), str(domain), str(rel), cat)
        _materialize_whatsapp_deleted_media(
            backup_root, readable, original, out, copy_one=_copy_one
        )
        _materialize_ios_camera_media(backup_root, out, copy_one=_copy_one)
        _carve_ios_messaging_dbs(readable, out)
    except Exception as exc:
        out["errors"].append(str(exc))
    finally:
        con.close()

    out["ok"] = bool(out["copied"]) or bool(out["domains_by_category"])
    return out
