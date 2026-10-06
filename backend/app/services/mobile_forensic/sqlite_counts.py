"""AXIOM-style mobile SQLite counting (WhatsApp / SMS / call logs / email).

Classic sources: Android msgstore.db, iOS ChatStorage.sqlite.
Modern iOS WhatsApp (UFED Advanced Logical) often ships ExtChatDatabase,
ChatSearch FTS (docs_content), CallHistory.sqlite, and LID.sqlite instead of
ChatStorage — those are counted here as well.
"""

from __future__ import annotations


import json
import logging
import os
import sqlite3
import tempfile
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import fetchall, fetchone

log = logging.getLogger("mobile_forensic.sqlite_counts")

# iOS ChatStorage.sqlite is commonly 100–400MB; truncating below file size yields
# a SQLite header with zero readable tables (messages stay 0 despite the DB existing).
_MAX_DB_BYTES = 512_000_000
_HARD_MAX_DB_BYTES = 768_000_000

_WA_MSG_TABLES = (
    "message",
    "messages",
    "msg",
    "chat_messages",
    "messages_quotes",
    "ZWAMESSAGE",
    "thread_messages",
    "docs_content",  # ChatSearch FTS body rows (wa_tokenizer virtual table sibling)
    "metadata",  # ChatSearch metadata — one row per indexed message
)
_WA_CHAT_TABLES = (
    "chat",
    "chats",
    "chat_list",
    "ZWACHATSESSION",
    "thread_id",
    "recently_searched_chats",
)
_WA_CALL_TABLES = (
    "call_log",
    "call_logs",
    "calls",
    "ZWACALLINFO",
    "ZWACDCALLEVENT",
    "ZWAAGGREGATECALLEVENT",
    "ZWAJOINABLECALLEVENT",
)
_WA_CONTACT_TABLES = (
    "wa_contacts",
    "contacts",
    "jid",
    "ZWACONTACT",
    "ZWAPHONENUMBERLIDPAIR",
    "contact_metadata",
    "ZWALIDTHREADPROPERTIES",
)

_SMS_TABLES = ("sms", "pdu", "message", "messages")
_CALLLOG_TABLES = ("calls", "call_log", "calllog", "ZWACALLRECORD", "ZCALLRECORD")

# Noise under WhatsApp trees — never treat as message stores.
_WA_SKIP_DB_NAMES = frozenset(
    {
        "observations.db",
        "pcm.db",
        "assets.db",
        "alternativeservice.sqlite",
        "avatarsearchtags.sqlite",
        "newsletterchatsearchv1f.sqlite",
    }
)

_MEDIA_EXTS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".heic",
        ".bmp",
        ".mp4",
        ".3gp",
        ".mov",
        ".m4v",
        ".mkv",
        ".opus",
        ".m4a",
        ".aac",
        ".mp3",
        ".wav",
        ".pdf",
        ".doc",
        ".docx",
        ".xlsx",
        ".ppt",
        ".pptx",
    }
)


def _norm_path(path: str) -> str:
    return (path or "").replace("\\", "/").lower()


def _is_whatsapp_msgstore(path: str) -> bool:
    p = _norm_path(path)
    name = PurePosixPath(p).name
    if name in {
        "msgstore.db",
        "messages.db",
        "chatstorage.sqlite",
        "extchatdatabase.sqlite",
        "chatsearchv5f.sqlite",
        "callhistory.sqlite",
        "lid.sqlite",
        "messaginginfradatabase.sqlite",
    }:
        return True
    if "whatsapp" in p and name.endswith(".db") and "msgstore" in name:
        return True
    return False


def _is_whatsapp_wa_db(path: str) -> bool:
    p = _norm_path(path)
    name = PurePosixPath(p).name
    return name == "wa.db" or (name.endswith(".db") and "/whatsapp/" in p and "contact" in name)


def _is_whatsapp_crypt(path: str) -> bool:
    from app.services.mobile_forensic.whatsapp_crypt import crypt_extension
    return bool(crypt_extension(_norm_path(path)))


def _is_whatsapp_msgstore_crypt(path: str) -> bool:
    """True only for chat-database crypt sidecars (not sticker/theme .crypt14)."""
    if not _is_whatsapp_crypt(path):
        return False
    name = PurePosixPath(_norm_path(path)).name
    return "msgstore" in name


def discover_whatsapp_keys(db, job_id: str):
    """Return all usable keys; multiple installs/users/backups can differ."""
    from app.services.mobile_forensic.integrity import load_intake_keys_from_disk_source
    from app.services.mobile_forensic.whatsapp_crypt import WhatsAppKeyCandidate, parse_key_material

    candidates = []
    seen = {}

    def add(material, source):
        key = parse_key_material(material)
        if not key:
            return
        previous = seen.get(key.raw32)
        if previous is None:
            seen[key.raw32] = len(candidates)
            candidates.append(WhatsAppKeyCandidate(material, source))
        elif (key.t1 is not None and parse_key_material(candidates[previous].material).t1 is None) or (
            source != "case_intake" and candidates[previous].source == "case_intake" and isinstance(material, bytes)
        ):
            # An automatically populated 64-hex intake value must not discard
            # the full key file and its crypt12 header-match checksum.
            candidates[previous] = WhatsAppKeyCandidate(material, source)

    ds_row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    ds = ds_row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except Exception:
            ds = {}
    pasted = load_intake_keys_from_disk_source(ds if isinstance(ds, dict) else {}).get("whatsapp_key_hex")
    add(pasted, "case_intake")
    intake = ds.get("case_intake") if isinstance(ds, dict) else {}
    intake = intake if isinstance(intake, dict) else {}
    from app.services.storage import get_bytes
    import hashlib

    for reference in intake.get("whatsapp_key_files", []):
        if not isinstance(reference, dict) or not reference.get("storage_uri"):
            continue
        try:
            material = get_bytes(reference["storage_uri"], max_bytes=513)
        except Exception as exc:
            log.warning("Captured WhatsApp key file could not be read: %s", type(exc).__name__)
            continue
        if material and len(material) <= 512 and hashlib.sha256(material).hexdigest() == reference.get("sha256"):
            add(material, reference.get("source_path") or "intake_key_file")

    rows = fetchall(
        db,
        """SELECT file_path, file_name, size_bytes FROM job_artifacts
           WHERE job_id=:jid
             AND (
               lower(file_name) = 'key'
               OR lower(replace(file_path, '\\', '/')) LIKE '%/files/key'
               OR lower(file_name) IN ('encrypted_backup.key', 'whatsapp.key', 'whatsapp_key.hex')
               OR (
                 lower(replace(file_path, '\\', '/')) LIKE '%whatsapp%'
                 AND lower(file_name) = 'key'
               )
             )
             AND COALESCE(size_bytes, 0) BETWEEN 24 AND 512
           ORDER BY file_path""",
        {"jid": job_id},
    )
    for row in rows or []:
        from app.services.mobile_forensic.key_intake import is_whatsapp_key_path
        path = str(row.get("file_path") or "")
        if not is_whatsapp_key_path(path):
            continue
        data = _read_artifact_bytes(db, job_id, path, max_bytes=512)
        if data is not None and len(data) <= 512:
            add(data, path)
    return candidates


def discover_whatsapp_key_hex(db, job_id: str) -> str | None:
    """Compatibility accessor; decrypting callers use all candidates instead."""
    from app.services.mobile_forensic.whatsapp_crypt import cipher_key_from_material

    candidates = discover_whatsapp_keys(db, job_id)
    return cipher_key_from_material(candidates[0].material).hex() if candidates else None


def whatsapp_key_gap_text(
    *,
    backup_count: int,
    key_size: int | None = None,
    key_head: bytes | None = None,
    empty_android_backup: bool = False,
) -> str:
    """Examiner-facing reason chats are still inside msgstore crypt files."""
    n = max(int(backup_count or 0), 0)
    head = bytes(key_head or b"")[:16]
    parts = [
        f"No plaintext chat rows yet — {n:,} encrypted msgstore backup(s) collected."
    ]
    if head.lower().startswith(b"run-as"):
        size_bit = f"{int(key_size)}-byte " if key_size else ""
        parts.append(
            f"A collected {size_bit}key file contains an adb \"run-as\" error, "
            "not the WhatsApp device key at /data/data/com.whatsapp/files/key "
            "(typically 158 bytes)."
        )
    elif key_size:
        parts.append(
            f"A {int(key_size)}-byte key candidate was collected; file size alone does not establish "
            "a matching key. Check the per-backup authentication result."
        )
    else:
        parts.append(
            "No collected device-key file was identified by this summary; check Case Intake keys and per-backup results."
        )
    if empty_android_backup:
        parts.append("The WhatsApp Android backup (whatsapp.ab) is empty.")
    parts.append(
        "crypt7/8/12/14 require matching files/key; crypt5 requires the original Android account; crypt15 requires encrypted_backup.key or the owner's "
        "64-character backup key. Save a valid key and reprocess, or import an owner-provided TXT chat export "
        "with media. Theme and sticker .crypt14 files are not chat backups."
    )
    return " ".join(parts)


def describe_whatsapp_key_gap(db, job_id: str, *, backup_count: int) -> str:
    """Read the collected key/backup stubs and explain why chats were not decrypted."""
    rows = fetchall(
        db,
        """SELECT file_name, file_path, size_bytes, metadata
           FROM job_artifacts
           WHERE job_id=:jid
             AND (
               lower(file_name) = 'key'
               OR lower(file_name) LIKE '%.ab'
             )
             AND lower(replace(file_path, '\\', '/')) LIKE '%whatsapp%'
           LIMIT 20""",
        {"jid": job_id},
    )
    key_size: int | None = None
    key_head = b""
    empty_ab = False
    for row in rows or []:
        name = str(row.get("file_name") or "").lower()
        size = int(row.get("size_bytes") or 0)
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if isinstance(row.get("metadata"), str):
            try:
                meta = json.loads(row["metadata"])
            except Exception:
                meta = {}
        if name == "key":
            magic = str((meta or {}).get("magic_hex") or "")
            try:
                head = bytes.fromhex(magic) if magic else b""
            except ValueError:
                head = b""
            if key_size is None or size < (key_size or 0) or head.lower().startswith(b"run-as"):
                key_size = size
                key_head = head
        if name.endswith(".ab") and size <= 0:
            empty_ab = True
    return whatsapp_key_gap_text(
        backup_count=backup_count,
        key_size=key_size,
        key_head=key_head,
        empty_android_backup=empty_ab,
    )


def _is_sms_db(path: str) -> bool:
    p = _norm_path(path)
    name = PurePosixPath(p).name
    return name in {"mmssms.db", "sms.db", "telephony.db"} or "mmssms" in name


def _is_calllog_db(path: str) -> bool:
    p = _norm_path(path)
    name = PurePosixPath(p).name
    if "whatsapp" in p:
        return False  # WhatsApp CallHistory.sqlite is handled by WA analyzer
    return (
        name in {"calllog.db", "calls.db", "callhistory.storedata", "callhistory.sqlite"}
        or "calllog" in name
    )


def _is_apple_mail_index(path: str) -> bool:
    p = _norm_path(path)
    name = PurePosixPath(p).name
    return name in {"envelope index", "envelope index-shm", "mailboxes"} or (
        "/mail/" in p and name in {"direct-db.sqlite", "pane_archives.sqlite3"}
    )


def _should_skip_wa_db(path: str) -> bool:
    name = PurePosixPath(_norm_path(path)).name
    if name in _WA_SKIP_DB_NAMES:
        return True
    p = _norm_path(path)
    if "/webkit/" in p or "websitedata" in p or "resourceLoadstatistics" in p.lower():
        return True
    return False


def _effective_db_read_cap(size_bytes: int | None, *, max_bytes: int) -> int:
    """Never truncate below known file size (up to hard cap) — truncated SQLite is useless."""
    cap = max(int(max_bytes or _MAX_DB_BYTES), _MAX_DB_BYTES)
    known = int(size_bytes or 0)
    if known > 0:
        cap = max(cap, known + 4096)
    return min(cap, _HARD_MAX_DB_BYTES)


def _read_artifact_bytes(db, job_id: str, file_path: str, *, max_bytes: int = _MAX_DB_BYTES) -> bytes | None:
    row = fetchone(
        db,
        """SELECT id, file_path, minio_uri, size_bytes, sha256, metadata FROM job_artifacts
           WHERE job_id=:jid AND replace(lower(file_path), '\\', '/') = :p
           LIMIT 1""",
        {"jid": job_id, "p": _norm_path(file_path)},
    )
    if not row:
        row = fetchone(
            db,
            """SELECT id, file_path, minio_uri, size_bytes, sha256, metadata FROM job_artifacts
               WHERE job_id=:jid AND lower(file_path) LIKE :p
               LIMIT 1""",
            {"jid": job_id, "p": f"%{_norm_path(file_path).split('/')[-1]}"},
        )
    if not row:
        return None
    read_cap = _effective_db_read_cap(row.get("size_bytes"), max_bytes=max_bytes)
    metadata = row.get("metadata") or {}
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    if metadata.get("whatsapp_derivation") and str(row.get("file_path") or "").startswith("derived/whatsapp_decrypted/"):
        from app.services.mobile_forensic.whatsapp_derivation import read_registered_derivation
        return read_registered_derivation(db, job_id, row, max_bytes=read_cap)
    from app.services.forensic_serial_policy import serial_enabled

    if serial_enabled():
        source = fetchone(db, "SELECT extracted_disk_uri,disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
        if source and source.get("extracted_disk_uri"):
            from app.services.disk_manifest import build_index_map
            from app.services.tar_cache import read_file_from_part

            if int(row.get("size_bytes") or 0) > read_cap:
                raise ValueError(f"Evidence exceeds the SQLite read ceiling ({read_cap:,} bytes): {file_path}")
            metadata = row.get("metadata") or {}
            if isinstance(metadata, str):
                metadata = json.loads(metadata)
            part_uri = metadata.get("extracted_part_uri")
            if not part_uri:
                manifest = source.get("disk_source") or {}
                if isinstance(manifest, str):
                    manifest = json.loads(manifest)
                cache = getattr(db, "info", {}).get("serial_extracted_index")
                if cache is None:
                    cache = {p.replace("\\", "/"): uri for p, uri in build_index_map(manifest).items()}
                    if hasattr(db, "info"):
                        db.info["serial_extracted_index"] = cache
                part_uri = cache.get(row["file_path"].replace("\\", "/"))
            # A finalized derived manifest is an absolute boundary. Never fall
            # through to the original folder, ZIP, E01 or raw image after this.
            if not part_uri:
                return None
            data = read_file_from_part(part_uri, row["file_path"], max_bytes=read_cap + 1)
            if data is not None and len(data) > read_cap:
                raise ValueError(f"Evidence exceeds the SQLite read ceiling: {file_path}")
            if data is not None and row.get("size_bytes") and len(data) != int(row["size_bytes"]):
                raise ValueError(f"Extracted evidence size does not match its manifest: {file_path}")
            expected_hash = row.get("sha256") or metadata.get("source_sha256")
            if data is not None and expected_hash:
                import hashlib

                if hashlib.sha256(data).hexdigest() != str(expected_hash):
                    raise ValueError(f"Extracted evidence hash does not match its manifest: {file_path}")
            return data
    uri = row.get("minio_uri")
    if uri:
        try:
            from app.services.storage import get_bytes

            data = get_bytes(uri)
            if data:
                if len(data) > read_cap:
                    log.warning(
                        "WhatsApp/SQLite artifact truncated at %s bytes (file %s bytes): %s",
                        read_cap,
                        len(data),
                        row.get("file_path"),
                    )
                return data[:read_cap]
        except Exception as exc:
            log.debug("minio read failed %s: %s", uri, exc)
    try:
        from app.services.virtual_disk import open_virtual_disk, read_full_file_from_disk

        vd = open_virtual_disk(db, job_id)
        return read_full_file_from_disk(vd, row["file_path"], max_bytes=read_cap)
    except Exception as exc:
        log.debug("vd read failed %s: %s", row.get("file_path"), exc)
        return None


def _table_names(cur: sqlite3.Cursor) -> list[str]:
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        return [str(r[0]) for r in cur.fetchall()]
    except sqlite3.Error:
        return []


def _count_first_table(cur: sqlite3.Cursor, candidates: tuple[str, ...], tables: list[str]) -> tuple[int, str | None]:
    lower_map = {t.lower(): t for t in tables}
    for cand in candidates:
        real = lower_map.get(cand.lower())
        if not real:
            continue
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{real}"')
            return int(cur.fetchone()[0] or 0), real
        except sqlite3.Error:
            continue
    return 0, None


def _count_distinct(cur: sqlite3.Cursor, table: str, column: str) -> int:
    try:
        cur.execute(f'SELECT COUNT(DISTINCT "{column}") FROM "{table}" WHERE "{column}" IS NOT NULL')
        return int(cur.fetchone()[0] or 0)
    except sqlite3.Error:
        return 0


def _count_groups(cur: sqlite3.Cursor, tables: list[str]) -> int:
    """Count WhatsApp groups — never use call-participant tables (false positives)."""
    lower_map = {t.lower(): t for t in tables}

    real = lower_map.get("group_metadata")
    if real:
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{real}"')
            n = int(cur.fetchone()[0] or 0)
            if n > 0:
                return n
        except sqlite3.Error:
            pass

    for cand in ("chat", "chats", "chat_list", "ZWACHATSESSION", "thread_messages", "message_parent_association"):
        real = lower_map.get(cand.lower())
        if not real:
            continue
        try:
            cur.execute(f'PRAGMA table_info("{real}")')
            cols = {str(r[1]).lower() for r in cur.fetchall()}
            if "group_id" in cols or "groupid" in cols:
                col = "group_id" if "group_id" in cols else "groupid"
                cur.execute(
                    f'SELECT COUNT(*) FROM "{real}" WHERE "{col}" IS NOT NULL AND TRIM(CAST("{col}" AS TEXT)) <> \'\''
                )
                n = int(cur.fetchone()[0] or 0)
                if n:
                    return n
            jid_names = {
                "jid",
                "chat_jid",
                "zcontactjid",
                "zpartnerjid",
                "zsessionid",
            }
            for jn in jid_names:
                if jn not in cols:
                    continue
                try:
                    cur.execute(
                        f'SELECT COUNT(*) FROM "{real}" WHERE CAST("{jn}" AS TEXT) LIKE \'%@g.us%\''
                    )
                    n = int(cur.fetchone()[0] or 0)
                except sqlite3.Error:
                    continue
                if n:
                    return n
            if "chat_jid" in cols:
                cur.execute(
                    f"SELECT COUNT(DISTINCT chat_jid) FROM \"{real}\" WHERE CAST(chat_jid AS TEXT) LIKE '%@g.us%'"
                )
                n = int(cur.fetchone()[0] or 0)
                if n:
                    return n
            if "subject" in cols and cand.lower().startswith("zwa"):
                cur.execute(f'SELECT COUNT(*) FROM "{real}" WHERE subject IS NOT NULL AND length(subject) > 0')
                n = int(cur.fetchone()[0] or 0)
                if n:
                    return n
        except sqlite3.Error:
            continue
    return 0


def _count_chats_from_jid_tables(cur: sqlite3.Cursor, tables: list[str]) -> int:
    lower_map = {t.lower(): t for t in tables}
    best = 0
    for cand in ("thread_messages", "message_parent_association", "message_media_map", "pending_messages"):
        real = lower_map.get(cand)
        if not real:
            continue
        try:
            cur.execute(f'PRAGMA table_info("{real}")')
            cols = {str(r[1]).lower() for r in cur.fetchall()}
            if "chat_jid" in cols:
                best = max(best, _count_distinct(cur, real, "chat_jid"))
        except sqlite3.Error:
            continue
    return best


def _open_sqlite(data: bytes):
    if not data or not data[:16].startswith(b"SQLite format"):
        return None, None
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            # Write the full buffer — callers must not pass truncated DBs.
            tmp.write(data)
            tmp_path = tmp.name
        # Ignore custom FTS tokenizers (wa_tokenizer) so docs_content/metadata still work.
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA writable_schema=0")
        except sqlite3.Error:
            pass
        # Probe: truncated/corrupt DBs often open but have no sqlite_master tables.
        try:
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
            if int(cur.fetchone()[0] or 0) == 0:
                log.warning("SQLite opened with 0 tables (likely truncated/corrupt DB), size=%s", len(data))
        except sqlite3.Error:
            pass
        return conn, tmp_path
    except Exception:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return None, None


def _count_whatsapp_deleted(cur: sqlite3.Cursor, tables: list[str]) -> int:
    """Count deleted WhatsApp rows from dedicated tables, flags, or iOS revoke type.

    Modern iOS ChatStorage has no ZISMESSAGEFROMMEDELETED column. Delete-for-Everyone
    is stored as ZMESSAGETYPE=14 placeholders (still linked to ZWAMEDIAITEM).
    Android keeps using deleted_* tables / is_deleted flags — this does not
    treat a generic ``messagetype`` column as revoked.
    """
    lower_map = {t.lower(): t for t in tables}
    best = 0
    for cand in (
        "deleted_messages",
        "message_deleted",
        "deleted_chat_messages",
        "zwamessagedeleted",
        "message_deletes",
    ):
        real = lower_map.get(cand)
        if not real:
            continue
        try:
            cur.execute(f'SELECT COUNT(*) FROM "{real}"')
            best = max(best, int(cur.fetchone()[0] or 0))
        except sqlite3.Error:
            continue
    for cand in ("message", "messages", "msg", "ZWAMESSAGE"):
        real = lower_map.get(cand.lower())
        if not real:
            continue
        try:
            cur.execute(f'PRAGMA table_info("{real}")')
            cols = {str(r[1]).lower(): str(r[1]) for r in cur.fetchall()}
            flag = next(
                (
                    cols[c]
                    for c in (
                        "deleted",
                        "is_deleted",
                        "zismissagefrommedeleted",
                        "zisdeleted",
                        "zdeleted",
                    )
                    if c in cols
                ),
                None,
            )
            # iOS Core Data only — do not apply to Android message.messagetype.
            type_col = cols.get("zmessagetype")
            clauses: list[str] = []
            if type_col:
                clauses.append(f'CAST("{type_col}" AS INTEGER) IN (14)')
            if flag:
                clauses.append(f'CAST("{flag}" AS INTEGER) != 0')
            if not clauses:
                continue
            cur.execute(f'SELECT COUNT(*) FROM "{real}" WHERE ' + " OR ".join(clauses))
            best = max(best, int(cur.fetchone()[0] or 0))
        except sqlite3.Error:
            continue
    return best


def analyze_whatsapp_db(data: bytes, path: str) -> dict[str, Any]:
    """Return AXIOM-style WhatsApp counters from one SQLite DB."""
    out = {
        "path": path,
        "messages": 0,
        "chats": 0,
        "calls": 0,
        "contacts": 0,
        "groups": 0,
        "deleted_messages": 0,
        "tables": [],
        "source_table": {},
    }
    conn, tmp_path = _open_sqlite(data)
    if not conn:
        return out
    try:
        cur = conn.cursor()
        tables = _table_names(cur)
        out["tables"] = tables
        msg_n, msg_t = _count_first_table(cur, _WA_MSG_TABLES, tables)
        chat_n, chat_t = _count_first_table(cur, _WA_CHAT_TABLES, tables)
        # Prefer distinct chat_jid when ExtChat-style schema is present.
        chat_n = max(chat_n, _count_chats_from_jid_tables(cur, tables))
        call_n, call_t = _count_first_table(cur, _WA_CALL_TABLES, tables)
        contact_n, contact_t = _count_first_table(cur, _WA_CONTACT_TABLES, tables)
        group_n = _count_groups(cur, tables)
        out["messages"] = msg_n
        out["chats"] = chat_n
        out["calls"] = call_n
        out["contacts"] = contact_n
        out["groups"] = group_n
        out["deleted_messages"] = _count_whatsapp_deleted(cur, tables)
        out["source_table"] = {
            "messages": msg_t,
            "chats": chat_t,
            "calls": call_t,
            "contacts": contact_t,
        }
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return out


def analyze_sms_db(data: bytes, path: str) -> dict[str, Any]:
    out = {"path": path, "sms": 0, "chats": 0, "attachments": 0, "source_table": None}
    conn, tmp_path = _open_sqlite(data)
    if not conn:
        return out
    try:
        cur = conn.cursor()
        tables = _table_names(cur)
        n, t = _count_first_table(cur, _SMS_TABLES, tables)
        out["sms"] = n
        out["source_table"] = t
        chat_n, _ = _count_first_table(cur, ("chat", "chats"), tables)
        out["chats"] = chat_n
        att_n, _ = _count_first_table(cur, ("attachment", "attachments"), tables)
        out["attachments"] = att_n
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return out


def analyze_calllog_db(data: bytes, path: str) -> dict[str, Any]:
    out = {"path": path, "calls": 0, "source_table": None}
    conn, tmp_path = _open_sqlite(data)
    if not conn:
        return out
    try:
        cur = conn.cursor()
        tables = _table_names(cur)
        n, t = _count_first_table(cur, _CALLLOG_TABLES, tables)
        out["calls"] = n
        out["source_table"] = t
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return out


def analyze_mail_db(data: bytes, path: str) -> dict[str, Any]:
    """Best-effort email message counts from local mail store indexes."""
    out = {"path": path, "emails": 0, "source_table": None}
    conn, tmp_path = _open_sqlite(data)
    if not conn:
        return out
    try:
        cur = conn.cursor()
        tables = _table_names(cur)
        # Apple Mail Envelope Index / Gmail pane_archives.record / common schemas
        n, t = _count_first_table(
            cur,
            (
                "messages",
                "message",
                "mail",
                "emails",
                "ZMESSAGE",
                "ZWAMESSAGE",
                "record",  # Gmail pane_archives.sqlite3
                "envelope",
            ),
            tables,
        )
        out["emails"] = n
        out["source_table"] = t
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return out


def analyze_addressbook_db(data: bytes, path: str) -> dict[str, Any]:
    out = {"path": path, "contacts": 0, "source_table": None}
    conn, tmp_path = _open_sqlite(data)
    if not conn:
        return out
    try:
        cur = conn.cursor()
        tables = _table_names(cur)
        n, t = _count_first_table(cur, ("ABPerson", "Person", "contacts", "ZCONTACT"), tables)
        out["contacts"] = n
        out["source_table"] = t
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return out


def count_ios_manifest_whatsapp_media(data: bytes) -> int:
    """Count WhatsApp image/video/audio rows in an iTunes Manifest.db (iOS only)."""
    conn, tmp_path = _open_sqlite(data)
    if not conn:
        return 0
    try:
        cur = conn.cursor()
        names = {n.lower() for n in _table_names(cur)}
        if "files" not in names:
            return 0
        cur.execute(
            """SELECT COUNT(*) FROM Files
               WHERE domain LIKE '%whatsapp%'
                 AND (
                   lower(relativePath) LIKE '%.jpg' OR lower(relativePath) LIKE '%.jpeg'
                   OR lower(relativePath) LIKE '%.png' OR lower(relativePath) LIKE '%.heic'
                   OR lower(relativePath) LIKE '%.webp' OR lower(relativePath) LIKE '%.gif'
                   OR lower(relativePath) LIKE '%.mp4' OR lower(relativePath) LIKE '%.mov'
                   OR lower(relativePath) LIKE '%.opus' OR lower(relativePath) LIKE '%.m4a'
                   OR lower(relativePath) LIKE '%.aac'
                 )"""
        )
        return int(cur.fetchone()[0] or 0)
    except sqlite3.Error:
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def collect_mobile_sqlite_inventory(db, job_id: str) -> dict[str, Any]:
    """Scan job_artifacts for mobile DBs and produce AXIOM-style counters."""
    rows = fetchall(
        db,
        """SELECT file_path, file_name, extension, size_bytes, minio_uri
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id},
    )
    result: dict[str, Any] = {
        "whatsapp_messages": 0,
        "whatsapp_chats": 0,
        "whatsapp_calls": 0,
        "whatsapp_contacts": 0,
        "whatsapp_groups": 0,
        "whatsapp_deleted_messages": 0,
        "whatsapp_media_files": 0,
        "whatsapp_encrypted_backups": 0,
        "whatsapp_db_paths": [],
        "whatsapp_crypt_paths": [],
        "whatsapp_key_present": False,
        "sms": 0,
        "sms_chats": 0,
        "sms_attachments": 0,
        "call_logs": 0,
        "emails": 0,
        "contacts": 0,
        "sms_db_paths": [],
        "calllog_db_paths": [],
        "mail_db_paths": [],
        "limitations": [],
    }

    saw_modern_wa = False
    saw_classic_wa = False
    ios_manifest_media = False
    seen_crypt_names: set[str] = set()
    wa_keys = discover_whatsapp_keys(db, job_id)
    result["whatsapp_key_present"] = bool(wa_keys)
    ds_row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id}) or {}
    from app.services.mobile_forensic.integrity import load_intake_keys_from_disk_source
    legacy_account = load_intake_keys_from_disk_source(ds_row.get("disk_source") if isinstance(ds_row.get("disk_source"), dict) else {}).get("whatsapp_legacy_account")

    for row in rows:
        path = str(row.get("file_path") or row.get("file_name") or "")
        p = _norm_path(path)
        name = PurePosixPath(p).name
        ext = (row.get("extension") or PurePosixPath(p).suffix or "").lower()
        if not ext.startswith(".") and ext:
            ext = f".{ext}"

        if _is_whatsapp_crypt(path):
            # Stickers/themes also use .crypt14 — only msgstore* holds chats.
            if not _is_whatsapp_msgstore_crypt(path):
                continue
            crypt_name = _norm_path(path)
            if crypt_name in seen_crypt_names:
                continue
            seen_crypt_names.add(crypt_name)
            result["whatsapp_encrypted_backups"] += 1
            result["whatsapp_crypt_paths"].append(path)
            if wa_keys or legacy_account:
                raw = _read_artifact_bytes(db, job_id, path)
                if raw:
                    from app.services.mobile_forensic.whatsapp_crypt import decrypt_with_candidates

                    plain = decrypt_with_candidates(raw, wa_keys, path=path, expected_size=int(row.get("size_bytes") or 0), legacy_account=legacy_account)
                    if plain:
                        analyzed = analyze_whatsapp_db(plain, path)
                        result["whatsapp_db_paths"].append(path)
                        result["whatsapp_messages"] = max(
                            result["whatsapp_messages"], analyzed["messages"]
                        )
                        result["whatsapp_chats"] = max(result["whatsapp_chats"], analyzed["chats"])
                        result["whatsapp_calls"] = max(result["whatsapp_calls"], analyzed["calls"])
                        result["whatsapp_contacts"] = max(
                            result["whatsapp_contacts"], analyzed["contacts"]
                        )
                        result["whatsapp_groups"] = max(
                            result["whatsapp_groups"], analyzed["groups"]
                        )
                        result["whatsapp_deleted_messages"] = max(
                            result["whatsapp_deleted_messages"],
                            int(analyzed.get("deleted_messages") or 0),
                        )
            continue

        if name == "manifest.db":
            data = _read_artifact_bytes(db, job_id, path)
            if data:
                counted = count_ios_manifest_whatsapp_media(data)
                if counted:
                    result["whatsapp_media_files"] = max(result["whatsapp_media_files"], counted)
                    ios_manifest_media = True

        # Real media files under WhatsApp trees only (extension-gated).
        if (not ios_manifest_media) and "whatsapp" in p and ext in _MEDIA_EXTS:
            result["whatsapp_media_files"] += 1

        if (
            _is_whatsapp_msgstore(path)
            or _is_whatsapp_wa_db(path)
            or ("whatsapp" in p and name.endswith((".db", ".sqlite")) and not _should_skip_wa_db(path))
        ):
            # Encrypted sidecar/backup DBs are not plaintext message stores.
            if name.endswith(".enc") or p.endswith(".enc") or ".sqlite.enc" in p:
                result["whatsapp_encrypted_backups"] += 1
                continue
            if name in {"chatstorage.sqlite", "msgstore.db"}:
                saw_classic_wa = True
            if name in {
                "extchatdatabase.sqlite",
                "chatsearchv5f.sqlite",
                "callhistory.sqlite",
                "lid.sqlite",
            }:
                saw_modern_wa = True
            data = _read_artifact_bytes(db, job_id, path)
            if not data:
                result["limitations"].append(f"Could not read WhatsApp DB for counting: {path}")
                continue
            if not data[:16].startswith(b"SQLite format"):
                result["limitations"].append(
                    f"WhatsApp DB is not plaintext SQLite (encrypted/binary): {path}"
                )
                continue
            analyzed = analyze_whatsapp_db(data, path)
            result["whatsapp_db_paths"].append(path)
            result["whatsapp_messages"] = max(result["whatsapp_messages"], analyzed["messages"])
            result["whatsapp_chats"] = max(result["whatsapp_chats"], analyzed["chats"])
            result["whatsapp_calls"] = max(result["whatsapp_calls"], analyzed["calls"])
            result["whatsapp_contacts"] = max(result["whatsapp_contacts"], analyzed["contacts"])
            result["whatsapp_groups"] = max(result["whatsapp_groups"], analyzed["groups"])
            result["whatsapp_deleted_messages"] = max(
                result["whatsapp_deleted_messages"],
                int(analyzed.get("deleted_messages") or 0),
            )
            continue

        if _is_sms_db(path):
            data = _read_artifact_bytes(db, job_id, path)
            if data:
                analyzed = analyze_sms_db(data, path)
                result["sms"] = max(result["sms"], analyzed["sms"])
                result["sms_chats"] = max(result["sms_chats"], int(analyzed.get("chats") or 0))
                result["sms_attachments"] = max(
                    result["sms_attachments"], int(analyzed.get("attachments") or 0)
                )
                result["sms_db_paths"].append(path)
            continue

        if _is_calllog_db(path):
            data = _read_artifact_bytes(db, job_id, path)
            if data:
                analyzed = analyze_calllog_db(data, path)
                result["call_logs"] = max(result["call_logs"], analyzed["calls"])
                result["calllog_db_paths"].append(path)
            continue

        if _is_apple_mail_index(path) or (
            "/mail/" in p
            and name.endswith((".sqlite", ".sqlite3", ".db"))
            and "webkit" not in p
        ):
            # Skip tiny WebKit noise; focus on mail store indexes.
            if "webkit" in p or "resourceloadstatistics" in p or "localstorage" in name:
                continue
            if "facebook" in p or "messenger" in p:
                # Messenger DBs land under paths containing "mail" — not email.
                continue
            data = _read_artifact_bytes(db, job_id, path)
            if data and data[:16].startswith(b"SQLite format"):
                analyzed = analyze_mail_db(data, path)
                if analyzed["emails"] > 0:
                    result["emails"] = max(result["emails"], analyzed["emails"])
                    result["mail_db_paths"].append(path)
            continue

        if name in {"addressbook.sqlitedb", "addressbook.sqlite"} or (
            "/addressbook/" in p and name.endswith((".sqlitedb", ".sqlite", ".db"))
        ):
            data = _read_artifact_bytes(db, job_id, path)
            if data and data[:16].startswith(b"SQLite format"):
                analyzed = analyze_addressbook_db(data, path)
                if analyzed["contacts"] > 0:
                    result["contacts"] = max(result["contacts"], analyzed["contacts"])

    # Prefer primary message stores first in UI samples (ChatStorage / msgstore).
    if result["whatsapp_db_paths"]:
        def _wa_path_rank(p: str) -> tuple[int, int]:
            n = PurePosixPath(_norm_path(p)).name
            primary = {
                "chatstorage.sqlite": 0,
                "msgstore.db": 0,
                "extchatdatabase.sqlite": 1,
                "chatsearchv5f.sqlite": 2,
            }.get(n, 9)
            return (primary, -len(p))

        result["whatsapp_db_paths"] = sorted(set(result["whatsapp_db_paths"]), key=_wa_path_rank)

    if result["whatsapp_encrypted_backups"] and result["whatsapp_messages"] == 0:
        if result.get("whatsapp_key_present"):
            result["limitations"].append(
                f"Found {result['whatsapp_encrypted_backups']} WhatsApp msgstore .crypt* "
                "backup(s) and a device key, but decrypt did not yield a readable SQLite store. "
                "Re-acquire /data/data/com.whatsapp or a UFED full-file-system image."
            )
        else:
            result["limitations"].append(
                describe_whatsapp_key_gap(
                    db, job_id, backup_count=int(result["whatsapp_encrypted_backups"] or 0)
                )
            )
    if not result["whatsapp_db_paths"] and result["whatsapp_messages"] == 0:
        result["limitations"].append(
            "No plaintext WhatsApp msgstore.db / ChatStorage.sqlite found. Shared-storage "
            "ADB/MTP pulls collect media + encrypted backups, not app-private chat DBs."
        )
    elif saw_modern_wa and not saw_classic_wa and result["whatsapp_messages"] > 0:
        result["limitations"].append(
            "Classic ChatStorage.sqlite / msgstore.db was not in this Advanced Logical export. "
            "Message counts come from modern WhatsApp iOS stores (ChatSearch FTS / ExtChatDatabase)."
        )
    elif saw_modern_wa and result["whatsapp_messages"] == 0:
        result["limitations"].append(
            "WhatsApp app containers were found, but classic ChatStorage.sqlite is missing and "
            "modern stores did not yield message rows. Re-extract with full app-domain / filesystem "
            "image if chats are expected."
        )
    if result["whatsapp_media_files"] == 0:
        result["limitations"].append(
            "No media files were found under WhatsApp paths in this acquisition. "
            "Device-wide pictures/videos may still appear under Pictures/Videos inventory "
            "(Advanced Logical often stores camera media outside the WhatsApp tree)."
        )
    return result
