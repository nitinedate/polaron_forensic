"""Recovery analyzers for explicit deleted data, SQLite residual sources and media remnants.

Important: presence of a WAL/journal is not itself proof that a deleted record was
recovered.  Source sidecars are therefore surfaced as UNVERIFIED recovery sources;
only rows from explicit deleted/residual tables are labelled database_deleted.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Iterator

from app.services.mobile_forensic.models import Confidence, InventoryItem, NormalizedArtifact
from app.services.mobile_forensic.parsers._sqlite_util import iter_query, open_sqlite_bytes, table_names
from app.services.mobile_forensic.plugins import ParseContext, RecoveryAnalyzer

_MEDIA = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif",
    ".mp4", ".mov", ".3gp", ".m4v", ".mkv", ".webm",
    ".mp3", ".m4a", ".aac", ".opus", ".wav", ".amr", ".ogg", ".flac",
}
_DOC = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"}
_TRASH_MARKERS = (".trashed-", "/.trash", "/trash/", ".trashes", "$recycle.bin", "deleted_recovery", "/recently deleted/")
_THUMB_MARKERS = ("thumbnail", "thumbnails", ".thumbnails", "preview", "caches/", "/cache/")
_MSG_MEDIA_MARKERS = ("whatsapp", "net.whatsapp", "com.whatsapp", "telegram", "signal", "/media/", "mediastore")


def _safe_raw(row: dict[str, Any], limit: int = 40) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in list(row.items())[:limit]:
        if isinstance(v, (bytes, bytearray, memoryview)):
            b = bytes(v)
            out[str(k)] = {"binary_length": len(b), "hex_prefix": b[:24].hex()}
        elif isinstance(v, (str, int, float, bool)) or v is None:
            out[str(k)] = v
        else:
            out[str(k)] = str(v)
    return out


class SqliteHistoryAnalyzer(RecoveryAnalyzer):
    name = "sqlite_history_analyzer"
    version = "2.1.0"

    def analyze(self, items: list[InventoryItem], parsed: list[NormalizedArtifact], context: ParseContext) -> Iterator[NormalizedArtifact]:
        normalized_items = {it.path.lower().replace("\\", "/"): it for it in items}

        for item in items:
            p = item.path.lower().replace("\\", "/")
            is_wal = p.endswith("-wal")
            is_journal = p.endswith("-journal")
            is_shm = p.endswith("-shm")
            is_db = p.endswith((".db", ".sqlite", ".sqlite3", ".sqlitedb"))
            if not (is_wal or is_journal or is_shm or is_db):
                continue

            if is_wal or is_journal or is_shm:
                kind = "wal" if is_wal else "journal" if is_journal else "shm"
                yield NormalizedArtifact.create(
                    artifact_type=f"sqlite_{kind}_source",
                    source_domain="system",
                    data={
                        "artifact_family": "sqlite_recovery_sources",
                        "path": item.path,
                        "name": PurePosixPath(item.path).name,
                        "size": item.size,
                        "sha256": item.sha256,
                        "sidecar_type": kind,
                        "note": "Recovery source present; presence alone does not prove a deleted record was recovered.",
                    },
                    state="unverified",
                    recovery_source=f"sqlite_{kind}_source",
                    source_path=item.path,
                    source_sha256=item.sha256,
                    parser=self.name,
                    parser_version=self.version,
                    confidence=Confidence(label="UNVERIFIED", score=0.35, validation=[f"{kind}_present"]),
                    job_id=context.job_id,
                    source_id=context.source_id,
                )
                continue

            data = context.read_artifact_bytes(item.path)
            if not data:
                continue
            lower_path = item.path.lower()
            is_whatsapp = "whatsapp" in lower_path or "msgstore" in lower_path or "chatstorage" in lower_path

            with open_sqlite_bytes(data) as conn:
                if not conn:
                    continue
                tables = table_names(conn)

                # Explicit tables created by apps/tools for deleted/residual content.
                for t in sorted(tables):
                    lt = t.lower()
                    if "deleted" not in lt and "freelist" not in lt and "recovered" not in lt:
                        continue
                    state = "database_deleted" if "deleted" in lt or "recovered" in lt else "freelist_candidate"
                    recovery_source = "deleted_table" if state == "database_deleted" else "freelist_table"
                    for r in iter_query(conn, f'SELECT rowid AS __row_id, * FROM "{t}"'):
                        rid = str(r.get("__row_id") or "")
                        yield NormalizedArtifact.create(
                            artifact_type="recovered_candidate",
                            source_domain="messaging_apps" if is_whatsapp or "message" in lt else "system",
                            data={
                                "application": "whatsapp" if is_whatsapp else None,
                                "artifact_family": "deleted_whatsapp" if is_whatsapp else "recovered_database_rows",
                                "table": t,
                                "raw": _safe_raw(r),
                            },
                            state=state,  # type: ignore[arg-type]
                            recovery_source=recovery_source,
                            source_path=item.path,
                            source_table=t,
                            source_row_id=rid,
                            source_sha256=item.sha256,
                            parser=self.name,
                            parser_version=self.version,
                            confidence=Confidence(
                                label="MEDIUM",
                                score=0.65 if state == "database_deleted" else 0.45,
                                validation=["explicit_deleted_or_residual_table"],
                            ),
                            job_id=context.job_id,
                            source_id=context.source_id,
                        )

                # PRAGMA freelist_count proves free pages exist, not their semantic contents.
                try:
                    row = conn.execute("PRAGMA freelist_count").fetchone()
                    freelist_count = int(row[0] if row else 0)
                except Exception:
                    freelist_count = 0
                if freelist_count > 0:
                    yield NormalizedArtifact.create(
                        artifact_type="sqlite_freelist_source",
                        source_domain="messaging_apps" if is_whatsapp else "system",
                        data={
                            "application": "whatsapp" if is_whatsapp else None,
                            "artifact_family": "deleted_whatsapp" if is_whatsapp else "sqlite_recovery_sources",
                            "path": item.path,
                            "freelist_pages": freelist_count,
                            "note": "Unallocated SQLite pages are present; records require carving/validation before acceptance.",
                        },
                        state="freelist_candidate",
                        recovery_source="sqlite_freelist_pages",
                        source_path=item.path,
                        source_sha256=item.sha256,
                        parser=self.name,
                        parser_version=self.version,
                        confidence=Confidence(
                            label="UNVERIFIED", score=0.35,
                            validation=["sqlite_freelist_count_positive"],
                            contradictions=["record_content_not_yet_carved"],
                        ),
                        job_id=context.job_id,
                        source_id=context.source_id,
                    )

            # Carve messaging DB freelist + matching WAL/journal bytes into normalized
            # candidates so deleted/residual chats are available to RAG.  These remain
            # UNVERIFIED because carving alone cannot prove deletion or record boundaries.
            try:
                from app.services.mobile_acquire.sqlite_deleted import infer_social_app, recover_sqlite_bytes

                app = infer_social_app(item.path)
                if app:
                    companions: dict[str, bytes] = {}
                    for suffix, label in (("-wal", "wal"), ("-journal", "journal")):
                        companion = normalized_items.get(p + suffix)
                        if companion:
                            blob = context.read_artifact_bytes(companion.path)
                            if blob:
                                companions[label] = blob
                    carved = recover_sqlite_bytes(
                        data,
                        source_label=item.path,
                        companion_bytes=companions or None,
                    )
                    sources_carved = list(carved.get("sources_carved") or [])
                    for rec in carved.get("items") or []:
                        if not isinstance(rec, dict):
                            continue
                        idx = int(rec.get("index") or 0)
                        rec_app = str(rec.get("social_app") or app or "unknown")
                        family = "deleted_whatsapp" if rec_app == "whatsapp" else "deleted_social"
                        body = rec.get("body") or rec.get("text_body") or rec.get("text")
                        yield NormalizedArtifact.create(
                            artifact_type="recovered_chat_candidate",
                            source_domain="messaging_apps",
                            data={
                                "application": rec_app,
                                "artifact_family": family,
                                "candidate_deleted": True,
                                "body": body,
                                "sender": rec.get("sender"),
                                "conversation_id": rec.get("conversation"),
                                "chat_jid": rec.get("chat_jid"),
                                "is_group": bool(rec.get("is_group")),
                                "candidate_deleted_at": rec.get("deleted_at"),
                                "carved_index": idx,
                                "sources_carved": sources_carved,
                                "note": "Residual chat-like content carved from SQLite freelist/WAL/journal; examiner validation required.",
                            },
                            state="unverified",
                            recovery_source="sqlite_residual_carve",
                            source_path=item.path,
                            source_offset=idx,
                            source_sha256=item.sha256,
                            parser=self.name,
                            parser_version=self.version,
                            timestamp_utc=rec.get("deleted_at"),
                            confidence=Confidence(
                                label="UNVERIFIED",
                                score=0.40,
                                validation=["chat_like_residual", "sqlite_residual_source"],
                                contradictions=["carving_does_not_prove_deletion_or_record_boundary"],
                            ),
                            job_id=context.job_id,
                            source_id=context.source_id,
                        )
            except Exception:
                # Recovery enrichment must never prevent normal live artifact parsing.
                continue


class OrphanMediaAnalyzer(RecoveryAnalyzer):
    """Messaging media with no parsed message filename/path reference."""

    name = "orphan_media_analyzer"
    version = "2.0.0"

    def analyze(self, items: list[InventoryItem], parsed: list[NormalizedArtifact], context: ParseContext) -> Iterator[NormalizedArtifact]:
        referenced: set[str] = set(str(x).lower() for x in context.extra.get("referenced_media_names", set()))
        for a in parsed:
            if a.artifact_type not in ("app_message", "sms", "mms"):
                continue
            for key in ("media_name", "media_path", "attachment", "path"):
                value = (a.data or {}).get(key)
                if value:
                    referenced.add(PurePosixPath(str(value).replace("\\", "/")).name.lower())

        for item in items:
            ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
            if ext not in _MEDIA:
                continue
            p = item.path.lower().replace("\\", "/")
            if not any(m in p for m in _MSG_MEDIA_MARKERS) or any(m in p for m in _TRASH_MARKERS):
                continue
            name = PurePosixPath(p).name.lower()
            if name in referenced:
                continue
            if ext in {".jpg", ".jpeg", ".png", ".heic", ".heif", ".webp", ".gif"}:
                media_type = "photo"
            elif ext in {".mp4", ".mov", ".3gp", ".m4v", ".mkv", ".webm"}:
                media_type = "video"
            else:
                media_type = "audio"
            yield NormalizedArtifact.create(
                artifact_type="orphaned_media",
                source_domain="media",
                data={
                    "artifact_family": "orphaned_messaging_media",
                    "path": item.path,
                    "name": PurePosixPath(item.path).name,
                    "media_type": media_type,
                    "size": item.size,
                    "sha256": item.sha256,
                    "note": "Messaging media has no matching parsed message filename/path reference.",
                },
                state="orphaned",
                recovery_source="orphan_media",
                source_path=item.path,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                confidence=Confidence(
                    label="MEDIUM", score=0.55,
                    validation=["messaging_media_path", "no_message_filename_match"],
                    contradictions=["may_be_live_unreferenced_file"],
                ),
                job_id=context.job_id,
                source_id=context.source_id,
            )


class TrashPathAnalyzer(RecoveryAnalyzer):
    """Handle trashed files not already covered by the normal media/document parser."""

    name = "trash_path_analyzer"
    version = "2.0.0"

    def analyze(self, items: list[InventoryItem], parsed: list[NormalizedArtifact], context: ParseContext) -> Iterator[NormalizedArtifact]:
        for item in items:
            p = item.path.lower().replace("\\", "/")
            if not any(m in p for m in _TRASH_MARKERS):
                continue
            ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
            # FilesMediaParser already creates a filesystem_recovered artifact for these.
            if ext in _MEDIA or ext in _DOC:
                continue
            yield NormalizedArtifact.create(
                artifact_type="recovered_file",
                source_domain="files",
                data={
                    "artifact_family": "deleted_files",
                    "path": item.path,
                    "name": PurePosixPath(item.path).name,
                    "size": item.size,
                    "sha256": item.sha256,
                },
                state="filesystem_recovered",
                recovery_source="trash_path",
                source_path=item.path,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                confidence=Confidence(label="HIGH", score=0.85, validation=["trash_path_marker"]),
                job_id=context.job_id,
                source_id=context.source_id,
            )


class CacheThumbnailAnalyzer(RecoveryAnalyzer):
    name = "cache_thumbnail_analyzer"
    version = "2.0.0"

    def analyze(self, items: list[InventoryItem], parsed: list[NormalizedArtifact], context: ParseContext) -> Iterator[NormalizedArtifact]:
        for item in items:
            p = item.path.lower().replace("\\", "/")
            if not any(m in p for m in _THUMB_MARKERS):
                continue
            ext = (item.extension or PurePosixPath(item.path).suffix or "").lower()
            if ext not in _MEDIA and "thumb" not in p:
                continue
            yield NormalizedArtifact.create(
                artifact_type="photo",
                source_domain="media",
                data={
                    "artifact_family": "cache_thumbnails",
                    "path": item.path,
                    "name": PurePosixPath(item.path).name,
                    "size": item.size,
                    "sha256": item.sha256,
                    "cache_derived": True,
                },
                state="cache_derived",
                recovery_source="thumbnail_cache",
                source_path=item.path,
                source_sha256=item.sha256,
                parser=self.name,
                parser_version=self.version,
                confidence=Confidence(
                    label="MEDIUM", score=0.5,
                    validation=["thumbnail_or_cache_path"],
                    contradictions=["not_original_media_file"],
                ),
                job_id=context.job_id,
                source_id=context.source_id,
            )
