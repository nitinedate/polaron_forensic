"""Source-linked priority evidence for disk and mobile, with text-only RAG."""

from __future__ import annotations

from app.services.mobile_forensic.crypt_formats import is_crypt_file

import json
import re
from pathlib import PurePosixPath

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.forensic_serial_policy import CHUNK_OVERLAP, CHUNK_POLICY, CHUNK_SIZE
from app.services.mobile_forensic.models import NormalizedArtifact
from app.services.mobile_forensic.storage import _dumps

PRIORITY_FAMILIES = (
    "whatsapp_messages",
    "deleted_whatsapp",
    "browser",
    "pictures",
    "videos",
    "audio",
    "documents",
    "messages", "emails", "binary", "structured_data", "downloads", "applications", "accounts",
)
PRIORITY_ORDER_SQL = """CASE
    WHEN lower(payload->0->>'path') SIMILAR TO '%(msgstore|chatstorage|wa.db)%' THEN 0
    WHEN lower(payload->0->>'path') SIMILAR TO '%(history|places.sqlite|bookmarks|browser)%' THEN 1
    WHEN lower(payload->0->>'path') LIKE '%whatsapp%' THEN 2
    WHEN lower(payload->0->>'path') SIMILAR TO '%(dcim|pictures|photos|trash|deleted)%' THEN 3
    WHEN lower(payload->0->>'extension') IN ('.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.odt','.ods','.epub','.rtf') THEN 4
    ELSE 5 END,id"""


def ensure_priority_schema(db):
    execute(
        db,
        """CREATE TABLE IF NOT EXISTS forensic_priority_records (
        artifact_id text PRIMARY KEY,job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        job_artifact_id uuid NOT NULL REFERENCES job_artifacts(id) ON DELETE CASCADE,
        artifact_type text NOT NULL,source_domain text NOT NULL,state text NOT NULL,
        timestamp_utc timestamptz,data jsonb NOT NULL,forensic jsonb NOT NULL)""",
    )
    execute(
        db,
        "CREATE INDEX IF NOT EXISTS ix_priority_job_record ON forensic_priority_records(job_id,artifact_id)",
    )


def add_record_links(art):
    data = art.data or {}
    if art.artifact_type in {
        "app_message",
        "recovered_chat_candidate",
        "browser_visit",
        "browser_url",
    }:
        text = " ".join(
            str(data.get(key) or "")
            for key in ("body", "text", "caption", "url", "media_url")
        )
        data["urls"] = list(
            dict.fromkeys(re.findall(r"https?://[^\s<>\"']+", text, re.I))
        )
    return art


def persist_disk_records(db, job_id, file_id, artifacts):
    from psycopg2.extras import execute_values

    records = {art.artifact_id: add_record_links(art) for art in artifacts}
    values = [
        (
            art.artifact_id,
            job_id,
            file_id,
            art.artifact_type,
            art.source_domain,
            art.forensic.get("state") or "allocated",
            art.timestamp_utc,
            _dumps(art.data),
            _dumps(art.forensic),
        )
        for art in records.values()
    ]
    if values:
        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                """INSERT INTO forensic_priority_records
                (artifact_id,job_id,job_artifact_id,artifact_type,source_domain,state,timestamp_utc,data,forensic)
                VALUES %s ON CONFLICT(artifact_id) DO UPDATE SET data=EXCLUDED.data,forensic=EXCLUDED.forensic""",
                values,
                template="(%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::jsonb,%s::jsonb)",
                page_size=500,
            )
    return len(values)


def _priority_inventory(db, job_id):
    """Page the artifact list and commit each page.

    One query for every file, including its metadata, left the transaction
    idle while Python built the list. The stage process is not Celery, so
    Postgres closed that connection and the parse stage died at the last step.
    """
    from app.services.mobile_forensic.discovery import _ext, _mime_hint
    from app.services.mobile_forensic.models import InventoryItem
    from app.services.progress_agent import note_operation

    items: list = []
    sources: dict = {}
    last = ""
    while True:
        rows = fetchall(
            db,
            """SELECT id::text AS id, file_path, size_bytes, extension, sha256,
                      coalesce(metadata->>'priority_parsed_v4','') AS priority_done
               FROM job_artifacts
               WHERE job_id=:jid AND file_path > :last
               ORDER BY file_path
               LIMIT 5000""",
            {"jid": job_id, "last": last},
        )
        db.commit()
        if not rows:
            break
        for row in rows:
            path = str(row.get("file_path") or "").replace("\\", "/")
            if not path:
                continue
            ext = (row.get("extension") or _ext(path) or "").lower()
            if ext and not ext.startswith("."):
                ext = f".{ext}"
            done = str(row.get("priority_done") or "").lower() in {"true", "t", "1"}
            items.append(
                InventoryItem(
                    path=path,
                    size=int(row.get("size_bytes") or 0),
                    extension=ext,
                    mime_hint=_mime_hint(path),
                    sha256=row.get("sha256"),
                    status="discovered",
                    meta={},
                )
            )
            sources[path] = {"id": row["id"], "metadata": {"priority_parsed_v4": done} if done else {}}
        last = str(rows[-1]["file_path"] or last)
        note_operation(
            db,
            job_id,
            "parse",
            f"Priority evidence indexed {len(items):,} files",
            timeout_seconds=900,
        )
    return items, sources


def disk_priority_web_document(path: str) -> bool:
    """User documents and shortcuts. Not every HTML file in source trees or caches.

    Pictures and ordinary documents are already in the native parse count.
    OCR and media review own those later. This pass is for text that is only
    sitting inside a saved page or a browser shortcut.
    """
    low = str(path or "").replace("\\", "/").lower()
    if not low.endswith((".url", ".webloc", ".html", ".htm")):
        return False
    return any(
        seg in low
        for seg in (
            "/documents/",
            "/desktop/",
            "/downloads/",
            "/favorites/",
            "/mail/",
            "/outlook/",
        )
    )


_DISK_PRIORITY_KEEP = {
    "browser_parser",
    "whatsapp_parser",
    "telegram_parser",
    "signal_parser",
    "messenger_parser",
    "instagram_parser",
    "snapchat_parser",
    "discord_parser",
    "viber_parser",
    "wechat_parser",
    "line_parser",
    "tiktok_parser",
    "linkedin_parser",
    "contacts_parser",
    "calendar_notes_parser",
    "sms_calls_parser",
}
_MAIL_EXTENSIONS = (".eml", ".emlx", ".msg", ".mbox", ".mbx")
_DB_SUFFIXES = (".db", ".sqlite", ".sqlite3", ".sqlitedb")
_BROWSER_STORES = {
    "history",
    "cookies",
    "bookmarks",
    "login data",
    "web data",
    "favicons",
    "top sites",
}


def disk_priority_mail(path: str) -> bool:
    low = str(path or "").replace("\\", "/").lower()
    if not low.endswith(_MAIL_EXTENSIONS):
        return False
    return any(
        seg in low
        for seg in (
            "/documents/",
            "/desktop/",
            "/downloads/",
            "/favorites/",
            "/mail/",
            "/outlook/",
        )
    )


def _file_name(path: str) -> str:
    return str(path or "").replace("\\", "/").lower().rsplit("/", 1)[-1]


def disk_priority_browser_store(path: str) -> bool:
    """Chrome/Firefox store names only. Not every SQLite file under a Chrome path.

    Version snapshots repeat the live profile. The live History, Cookies, and
    Web Data are the copies this pass reads.
    """
    low = str(path or "").replace("\\", "/").lower()
    if "/snapshots/" in low:
        return False
    return _file_name(path) in _BROWSER_STORES or _file_name(path) in {
        "history.db",
        "history.sqlite",
        "history.plist",
        "bookmarks.db",
        "bookmarks.plist",
        "places.sqlite",
        "cookies.sqlite",
        "browser.db",
        "browser2.db",
        "browserstate.db",
        "searchhistory.db",
        "downloads.db",
    }


def disk_priority_database(path: str) -> bool:
    name = _file_name(path)
    if name.endswith(_DB_SUFFIXES):
        return True
    if name not in _BROWSER_STORES:
        return False
    low = str(path or "").replace("\\", "/").lower()
    return any(
        seg in low
        for seg in (
            "/chrome/",
            "/edge/",
            "/firefox/",
            "/safari/",
            "/opera/",
            "/brave/",
            "/user data/",
            "/browser/",
        )
    )


def disk_priority_parsers(parsers, path: str = ""):
    """Keep browser, chat, and mail databases.

    Parser name checks are not enough: a contacts parser also matches any
    file whose name contains "addressbook", including pictures. Ordinary
    Windows logs, shortcuts, and images stay in the native parse count.
    """
    mail = disk_priority_mail(path)
    if not mail and not disk_priority_database(path):
        return []
    kept = []
    for parser in parsers:
        name = getattr(parser, "name", "")
        if name == "browser_parser" and not disk_priority_browser_store(path):
            continue
        if name in _DISK_PRIORITY_KEEP or (name == "communication_evidence" and mail):
            kept.append(parser)
    return kept


def run_disk_priority_evidence(db, job_id):
    from app.services.forensic_serial_mobile import _context, evidence_bundles
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.job_control import pipeline_should_stop
    from app.services.mobile_forensic.parsers.browser import BrowserHistoryParser
    from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
    from app.services.mobile_forensic.plugins import get_plugin_registry
    from app.services.mobile_forensic.recovery.analyzers import SqliteHistoryAnalyzer

    ensure_priority_schema(db)
    from app.services.progress_agent import note_operation

    note_operation(
        db,
        job_id,
        "parse",
        "Priority evidence from parsed sources",
        timeout_seconds=900,
    )
    items, sources = _priority_inventory(db, job_id)
    ds = (
        fetchone(db, "SELECT disk_source FROM jobs WHERE id=:jid", {"jid": job_id})[
            "disk_source"
        ]
        or {}
    )
    db.commit()
    if isinstance(ds, str):
        ds = json.loads(ds)
    context = _context(db, job_id, ds, evidence_paths=(it.path for it in items))
    browser, whatsapp = (
        BrowserHistoryParser(),
        WhatsAppParser(),
    )
    written = errors = processed = scanned = 0
    for bundle in evidence_bundles(items):
        item = bundle[0]
        scanned += 1
        if scanned % 20000 == 0:
            note_operation(
                db,
                job_id,
                "parse",
                f"Priority evidence scanned {scanned:,} files",
                advanced=True,
            )
        source = sources[item.path]
        if (source.get("metadata") or {}).get("priority_parsed_v4"):
            continue
        if (
            not disk_priority_database(item.path)
            and not disk_priority_web_document(item.path)
            and not disk_priority_mail(item.path)
        ):
            continue
        parsers = disk_priority_parsers(
            get_plugin_registry().route(item, context), item.path
        )
        web_text = disk_priority_web_document(item.path)
        if not parsers and not web_text:
            continue
        note_operation(
            db,
            job_id,
            "parse",
            "Priority source: " + item.path,
            timeout_seconds=900,
            advanced=True,
        )
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Priority evidence parsing paused by user")
        context.extra["read_errors"].clear()
        buffer = []
        reason = None
        try:
            if web_text:
                blob = context.read_artifact_bytes(item.path)
                if blob is None:
                    raise ValueError("Web document could not be read")
                text = blob.decode(
                    "utf-16"
                    if blob.startswith((b"\xff\xfe", b"\xfe\xff"))
                    else "utf-8",
                    "replace",
                )
                for idx, url in enumerate(
                    dict.fromkeys(re.findall(r"https?://[^\s<>\"']+", text, re.I))
                ):
                    buffer.append(
                        NormalizedArtifact.create(
                            artifact_type="web_link",
                            source_domain="browser",
                            data={
                                "artifact_family": "browser_document_links",
                                "url": url,
                            },
                            state="allocated",
                            source_path=item.path,
                            source_row_id=str(idx),
                            source_sha256=item.sha256,
                            parser="web_document_links",
                            job_id=job_id,
                        )
                    )
            for parser in parsers:
                for art in parser.parse(item, context):
                    if len(bundle) > 1:
                        art.forensic["source_companions"] = [
                            {
                                "path": it.path,
                                "sha256": it.sha256,
                                "size_bytes": it.size,
                            }
                            for it in bundle[1:]
                        ]
                    buffer.append(art)
                    if len(buffer) >= 500:
                        written += persist_disk_records(
                            db, job_id, source["id"], buffer
                        )
                        buffer.clear()
                        db.commit()
            if any(p.name == whatsapp.name for p in parsers) and not is_crypt_file(item.path):
                for art in SqliteHistoryAnalyzer().analyze(bundle, [], context):
                    buffer.append(art)
                    if len(buffer) >= 500:
                        written += persist_disk_records(
                            db, job_id, source["id"], buffer
                        )
                        buffer.clear()
                        db.commit()
            if context.extra["read_errors"]:
                raise ValueError("Acquired source/SQLite sidecar was unreadable")
        except Exception as exc:
            reason = str(exc)
            errors += 1
        if reason:
            buffer.append(
                NormalizedArtifact.create(
                    artifact_type="priority_source_exception",
                    source_domain="browser"
                    if any(p.name == browser.name for p in parsers)
                    else "messaging_apps",
                    data={
                        "artifact_family": "priority_exceptions",
                        "path": item.path,
                        "note": reason,
                        "reference_only": True,
                    },
                    state="unverified",
                    source_path=item.path,
                    source_sha256=item.sha256,
                    parser="priority_evidence",
                    job_id=job_id,
                )
            )
        written += persist_disk_records(db, job_id, source["id"], buffer)
        execute(
            db,
            """UPDATE job_artifacts SET metadata=COALESCE(metadata,'{}'::jsonb)
            || jsonb_build_object('priority_parsed_v4',true,'priority_parse_exception',CAST(:reason AS text)) WHERE id=:id""",
            {"id": source["id"], "reason": reason},
        )
        db.commit()
        processed += 1
        context.clear_byte_cache()
        note_operation(db, job_id, "parse", "Priority source parsed: " + item.path, advanced=True)
    return {
        "sources_processed": processed,
        "records_written": written,
        "errors": errors,
    }


def chunk_disk_priority_records(db, job_id):
    from psycopg2.extras import execute_values

    from app.services.dual_rag_index import _chunk_text
    from app.services.forensic_serial_pipeline import StageWaiting
    from app.services.job_control import pipeline_should_stop

    last = ""
    count = 0
    while True:
        if pipeline_should_stop(db, job_id):
            raise StageWaiting("Priority RAG chunking paused by user")
        rows = fetchall(
            db,
            """SELECT * FROM forensic_priority_records p WHERE p.job_id=:jid AND p.artifact_id>:last
            AND NOT EXISTS (SELECT 1 FROM rag_chunks rc WHERE rc.job_id=:jid AND rc.metadata->>'priority_artifact_id'=p.artifact_id AND rc.metadata->>'chunk_policy'=:policy)
            ORDER BY p.artifact_id LIMIT 128""",
            {"jid": job_id, "last": last, "policy": CHUNK_POLICY},
        )
        if not rows:
            break
        execute(
            db,
            "DELETE FROM rag_chunks WHERE job_id=:jid AND file_path=ANY(:paths)",
            {
                "jid": job_id,
                "paths": [f"priority://artifact/{r['artifact_id']}" for r in rows],
            },
        )
        values = []
        for row in rows:
            content = _dumps(
                {
                    "artifact_type": row["artifact_type"],
                    "timestamp_utc": row["timestamp_utc"],
                    "state": row["state"],
                    "data": row["data"],
                    "forensic": row["forensic"],
                }
            ).replace("\x00", "")
            meta = _dumps(
                {
                    "priority_artifact_id": row["artifact_id"],
                    "job_artifact_id": str(row["job_artifact_id"]),
                    "serial_pipeline": True,
                    "chunk_policy": CHUNK_POLICY,
                }
            )
            for idx, chunk in enumerate(
                _chunk_text(content, CHUNK_SIZE, CHUNK_OVERLAP)
            ):
                values.append(
                    (
                        job_id,
                        f"priority://artifact/{row['artifact_id']}",
                        idx,
                        chunk,
                        meta,
                    )
                )
        with db.connection().connection.cursor() as cur:
            execute_values(
                cur,
                "INSERT INTO rag_chunks(job_id,file_path,chunk_index,content,chunk_type,metadata) VALUES %s",
                values,
                template="(%s,%s,%s,%s,'evidence',%s::jsonb)",
                page_size=500,
            )
        count += len(values)
        last = rows[-1]["artifact_id"]
        db.commit()
    return count


def priority_record_table(db, job_id):
    from app.forensic_common.job_types import is_mobile_job

    name = (
        "mobile_normalized_artifacts"
        if is_mobile_job(db, job_id)
        else "forensic_priority_records"
    )
    exists = fetchone(db, "SELECT to_regclass(:name)::text AS name", {"name": name})
    return name if exists and exists["name"] else None


def priority_evidence_page(
    db, job_id, *, family="whatsapp_messages", page=1, page_size=50
):
    from app.forensic_common.job_types import is_mobile_job
    from app.services.mobile_forensic.parsers.files_media import (
        _AUDIO,
        _DOC,
        _IMAGE,
        _VIDEO,
    )

    table = priority_record_table(db, job_id)
    if not table:
        return {
            "items": [],
            "total": 0,
            "page": page,
            "families": {key: 0 for key in PRIORITY_FAMILIES},
        }
    predicates = {
        "whatsapp_messages": "data->>'application'='whatsapp' AND artifact_type IN ('app_message','app_chat') AND state NOT IN ('database_deleted','unverified','freelist_candidate')",
        "deleted_whatsapp": "data->>'artifact_family'='deleted_whatsapp' OR (data->>'application'='whatsapp' AND state IN ('database_deleted','unverified','freelist_candidate') AND artifact_type IN ('app_message','recovered_chat_candidate'))",
        "browser": "source_domain='browser'",
        "pictures": "artifact_type='photo' OR (artifact_type='media_reference' AND data->>'mime' LIKE 'image/%')",
        "videos": "artifact_type='video' OR (artifact_type='media_reference' AND data->>'mime' LIKE 'video/%')",
        "audio": "artifact_type='audio' OR (artifact_type='media_reference' AND data->>'mime' LIKE 'audio/%')",
        "documents": "artifact_type='document'",
        "messages": "artifact_type IN ('app_message','sms','mms','sms_message','mms_message')",
        "emails": "source_domain='email' OR artifact_type IN ('email_message','email_attachment')",
        "binary": "artifact_type IN ('binary_string','binary_field')",
        "structured_data": "artifact_type='structured_record'",
        "downloads": "artifact_type IN ('browser_download','download') OR data->>'is_download'='true' OR data->>'source_bucket'='download'",
        "applications": "artifact_type IN ('installed_app','installed_application','app_install','application','application_record')",
        "accounts": "artifact_type IN ('device_account','device_user')",
    }
    if family not in predicates:
        raise ValueError("Unknown priority evidence category")
    # All category counts in one job-filtered pass, not one round trip per tab.
    count_row=fetchone(db,'SELECT '+','.join(f'count(*) FILTER (WHERE {predicate}) AS {key}'
        for key,predicate in predicates.items())+f' FROM {table} WHERE job_id=:jid',{'jid':job_id})
    families={key:int(count_row.get(key) or 0) for key in predicates}
    disk_files = not is_mobile_job(db, job_id)
    file_categories = {
        "pictures": (_IMAGE, "image"),
        "videos": (_VIDEO, "video"),
        "audio": (_AUDIO, "audio"),
        "documents": (_DOC, "document"),
    }
    file_predicate = """(lower(CASE WHEN left(extension,1)='.' THEN extension ELSE '.'||extension END)=ANY(:extensions)
        OR metadata->>'file_kind'=:kind OR COALESCE(metadata->>'detected_mime',metadata->>'mime','') LIKE :mime
        OR (:kind='document' AND (COALESCE(metadata->>'detected_mime',metadata->>'mime','') LIKE 'text/%'
            OR COALESCE(metadata->>'detected_mime',metadata->>'mime','') IN ('application/pdf','application/msword','application/rtf','application/json','application/xml')
            OR COALESCE(metadata->>'detected_mime',metadata->>'mime','') LIKE 'application/vnd.%')))"""
    if disk_files:
        for key, (extensions, kind) in file_categories.items():
            families[key] = int(
                fetchone(
                    db,
                    f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid AND {file_predicate}",
                    {
                        "jid": job_id,
                        "extensions": sorted(extensions),
                        "kind": kind,
                        "mime": kind + "/%",
                    },
                )["c"]
            )
        if family in file_categories:
            extensions, kind = file_categories[family]
            files = fetchall(
                db,
                f"""SELECT id,file_path,file_name,sha256,size_bytes,metadata FROM job_artifacts WHERE job_id=:jid
                AND {file_predicate} ORDER BY file_path,id LIMIT :lim OFFSET :off""",
                {
                    "jid": job_id,
                    "extensions": sorted(extensions),
                    "kind": kind,
                    "mime": kind + "/%",
                    "lim": page_size,
                    "off": (page - 1) * page_size,
                },
            )
            items = []
            for file in files:
                metadata = file.get("metadata") or {}
                state = (
                    "filesystem_recovered"
                    if metadata.get("is_deleted") is True
                    else "allocated"
                )
                items.append(
                    {
                        "artifact_id": str(file["id"]),
                        "job_artifact_id": str(file["id"]),
                        "artifact_type": kind,
                        "timestamp_utc": None,
                        "state": state,
                        "data": {
                            "name": file["file_name"],
                            "path": file["file_path"],
                            "size": file["size_bytes"],
                            "metadata": metadata,
                        },
                        "forensic": {
                            "source_path": file["file_path"],
                            "source_sha256": file["sha256"]
                            or metadata.get("source_sha256"),
                            "state": state,
                        },
                        "linked_media": [],
                    }
                )
            return {
                "items": items,
                "total": families[family],
                "families": families,
                "page": page,
            }
    items = fetchall(
        db,
        f"""SELECT artifact_id,artifact_type,source_domain,timestamp_utc,state,data,forensic
        FROM {table} WHERE job_id=:jid AND ({predicates[family]}) ORDER BY timestamp_utc DESC NULLS LAST,artifact_id
        LIMIT :lim OFFSET :off""",
        {"jid": job_id, "lim": page_size, "off": (page - 1) * page_size},
    )
    for row in items:
        source = row["forensic"].get("source_path")
        file = fetchone(
            db,
            "SELECT id FROM job_artifacts WHERE job_id=:jid AND file_path=:path",
            {"jid": job_id, "path": source},
        )
        row["job_artifact_id"] = str(file["id"]) if file else None
        data = row["data"] or {}
        path = str(
            data.get("media_path")
            or data.get("attachment_path")
            or (data.get("path") if data.get("reference_only") else "")
            or ""
        ).replace("\\", "/")
        name = str(
            data.get("media_name")
            or PurePosixPath(path).name
            or (data.get("name") if data.get("reference_only") else "")
            or ""
        )
        row["linked_media"] = []
        if path or name:
            # Exact path and basename candidates are visibly distinguished.
            row["linked_media"] = [
                dict(
                    file,
                    match_basis="exact_path"
                    if file["file_path"].replace("\\", "/") == path
                    else "filename_candidate",
                )
                for file in fetchall(
                    db,
                    "SELECT id,file_path,sha256 FROM job_artifacts WHERE job_id=:jid AND (file_path=:path OR file_name=:name) ORDER BY file_path",
                    {"jid": job_id, "path": path, "name": name},
                )
            ]
    return {
        "items": items,
        "total": families[family],
        "families": families,
        "page": page,
    }


def mobile_priority_coverage(db, job_id):
    """Zero recovered records describes this acquisition, not absence on a phone."""
    from app.services.mobile_forensic.storage import upsert_coverage

    counts = priority_evidence_page(db, job_id, page_size=1)["families"]
    for family in PRIORITY_FAMILIES:
        count = counts[family]
        upsert_coverage(
            db,
            job_id,
            "priority_" + family,
            discovered=0,
            processed=0,
            artifacts=count,
            recovered=0,
            errors=0,
            status="available" if count else "acquisition_gap",
            details={
                "priority": True,
                "artifact_count": count,
                "note": "Records captured from acquired evidence."
                if count
                else "No readable records in this acquisition. Check private app access, source completeness and encryption keys; deleted data may have been overwritten.",
            },
        )
    return counts
