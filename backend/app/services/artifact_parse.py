"""Parallel artifact parsing from extracted disk."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from typing import Any

from app.config import get_settings
from app.db.sql_helpers import (
    execute,
    fetchall,
    fetchone,
    is_retryable_db_error,
    retry_on_deadlock,
    rollback_aborted_transaction,
)
from app.parsers import PARSER_VERSION
from app.services.disk_build_log import write_disk_log
from app.services.storage import TransientStreamError, get_bytes
from app.services.tar_cache import iter_files_from_part


log = logging.getLogger("artifact_parse")


def _advance_parse_stage(db, job_id: str, operation: str, *, publish_counts: bool = False) -> None:
    """Keep a long parse batch alive and, when files finish, show that on the stage.

    progressAgent cancels a running stage once its operation deadline passes.
    A shard stream or a multi-minute batch does not finish inside the initial
    five-minute window, so the counter stayed at 0 and the stage restarted.
    """
    try:
        if publish_counts:
            from app.services.forensic_serial_stages import report_progress

            row = fetchone(
                db,
                """SELECT count(*) FILTER (WHERE parse_status='parsed') AS done,
                count(*) FILTER (WHERE parse_status IN ('skipped','no_parser')) AS skipped,
                count(*) FILTER (WHERE parse_status IN ('failed','error')) AS failed,
                count(*) AS total FROM job_artifacts WHERE job_id=:jid""",
                {"jid": job_id},
            )
            report_progress(
                db,
                job_id,
                "parse",
                total=int(row["total"] or 0),
                completed=int(row["done"] or 0),
                failed=int(row["failed"] or 0),
                skipped=int(row["skipped"] or 0),
                label="Native forensic parsing",
            )
        from app.services.progress_agent import note_operation

        note_operation(
            db,
            job_id,
            "parse",
            operation,
            timeout_seconds=900,
            advanced=True,
        )
    except Exception:
        log.debug("parse stage progress update failed", exc_info=True)
        rollback_aborted_transaction(db)

IMAGE_EXT = frozenset({".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp", ".pdf"})

# Shared with forensic_inventory — paths/extensions worth parsing during background drain.
from app.services.critical_forensic_paths import FORENSIC_PARSE_PATH_SQL as _FORENSIC_PARSE_PATH_SQL
from app.services.critical_forensic_paths import is_critical_evtx_path
from app.services.critical_forensic_paths import is_forensic_full_read_path
from app.services.phase1_artifact_scope import PHASE1_PARSE_SIDECAR_SQL

_PARSE_ATTEMPT_MAX = 3
# Claimed 'parsing' rows older than this return to pending if a worker died.
_PARSE_CLAIM_STALE_SEC = 20 * 60
_LARGE_FILE_BYTES = 32 * 1024 * 1024  # serialize parse above this size to avoid OOM
_PARSE_BATCH_BYTE_BUDGET = 384 * 1024 * 1024  # max bytes held in memory for a parallel batch
# Postgres dies if we bind 40k Windows paths into one ANY() (5–7 MB query text).
PATH_ANY_CHUNK = 250

# Extensions with no structured parser — OCR/media only; skip CPU parse drain.
_MEDIA_SKIP_EXTENSIONS_SQL = """
lower(coalesce(extension, '')) IN (
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tif', '.tiff', '.webp', '.ico', '.svg',
  '.wav', '.mp3', '.mp4', '.m4a', '.avi', '.mkv', '.mov', '.wmv', '.flv',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.cur', '.ani'
)
"""

_TEXT_PARSER_KEYS = frozenset({
    ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".md", ".ini", ".cfg",
    ".conf", ".yaml", ".yml", ".ps1", ".bat", ".reg",
})

_FORENSIC_PARSE_ORDER_SQL = """
                 CASE
                   WHEN file_path ILIKE '%/config/SOFTWARE' OR file_path ILIKE '%/config/SYSTEM'
                        OR file_path ILIKE '%/config/SAM' THEN 0
                   WHEN file_path ILIKE '%Security.evtx' THEN 1
                   WHEN file_path ILIKE '%/History' OR file_path ILIKE '%places.sqlite' THEN 2
                   WHEN file_path ILIKE '%WhatsApp%' OR file_path ILIKE '%msgstore%' THEN 3
                   WHEN file_path ILIKE '%.pst' OR file_path ILIKE '%.eml' THEN 4
                   WHEN file_path ILIKE '%NTUSER.DAT' OR file_path ILIKE '%Amcache.hve' THEN 5
                   WHEN file_path ILIKE '%/Winevt/Logs/%' OR file_path ILIKE '%.evtx' THEN 9
                   ELSE 6
                 END,
                 size_bytes ASC NULLS LAST,
                 id
"""

_FORENSIC_PARSE_EXT_SQL = """
(
  ltrim(lower(coalesce(extension, '')), '.') IN (
    'evtx','evt','log','etl','dmp','pf','reg','dat','db','sqlite','sqlite3',
    'eml','msg','pst','ost','mbox','json','xml','csv','txt','html','htm','mht','mhtml',
    'ini','cfg','conf','lnk','hve','edb','mdb','accdb','pdf','doc','docx','xls','xlsx',
    'yaml','yml','ldb','url','website','one','kdbx','wallet','rtf','odt','ods'
  )
)
"""


def iter_path_chunks(paths: list[str] | None, chunk_size: int = PATH_ANY_CHUNK):
    """Yield non-empty path slices small enough for a single Postgres ANY() bind."""
    size = max(1, int(chunk_size or PATH_ANY_CHUNK))
    items = [p for p in (paths or []) if p]
    for i in range(0, len(items), size):
        chunk = items[i : i + size]
        if chunk:
            yield chunk


def _exec_locked(db, sql: str, params: dict | None = None) -> None:
    """Artifact-row write with deadlock rollback + retry."""
    retry_on_deadlock(db, lambda: execute(db, sql, params))


def recover_stale_parsing_claims(db, job_id: str, *, stale_sec: int = _PARSE_CLAIM_STALE_SEC) -> int:
    """Return crashed-worker 'parsing' rows to pending so drain can claim them again."""

    def _go() -> list[dict]:
        return fetchall(
            db,
            """WITH stale AS (
                    SELECT id FROM job_artifacts
                    WHERE job_id=:jid
                      AND parse_status='parsing'
                      AND updated_at < NOW() - make_interval(secs => :sec)
                    ORDER BY id
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE job_artifacts AS ja
                SET parse_status='pending', updated_at=NOW()
                FROM stale
                WHERE ja.id = stale.id
                RETURNING ja.id""",
            {"jid": job_id, "sec": max(60, int(stale_sec))},
        )

    return len(retry_on_deadlock(db, _go))


def _claim_pending_rows(
    db,
    job_id: str,
    *,
    extra_sql: str = "",
    params: dict | None = None,
    order_sql: str = "ORDER BY id",
    limit: int,
) -> list[dict]:
    """Atomically take pending rows so two parse workers cannot UPDATE the same tuple."""
    values = {"jid": job_id, "lim": max(1, int(limit))}
    values.update(params or {})
    sql = f"""WITH candidates AS (
                    SELECT id FROM job_artifacts
                    WHERE job_id=:jid AND parse_status='pending' {extra_sql}
                    {order_sql}
                    LIMIT :lim
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE job_artifacts AS ja
                SET parse_status='parsing', updated_at=NOW()
                FROM candidates c
                WHERE ja.id = c.id
                RETURNING ja.id, ja.file_path, ja.minio_uri, ja.size_bytes, ja.sha256, ja.metadata"""
    return retry_on_deadlock(db, lambda: fetchall(db, sql, values))


_FULL_SHARD_CAP = 100_000


def serial_parse_workers() -> int:
    """Threads for the one serial parse process.

    Leave at least two cores free on a laptop so the fan and the OS stay
    responsive. Eight is the ceiling even when more CPUs are visible.
    """
    import os

    cpus = os.cpu_count() or 4
    return max(2, min(8, cpus - 2 if cpus > 4 else cpus))


def parse_thermal_backoff(workers: int, *, busy_seconds: float = 0.0) -> tuple[int, float, str]:
    """How many parse threads to keep, and how long to rest.

    A busy CPU is the job running. Only chassis temperature sheds cores, and
    it does so before a laptop's own shutdown trip. When no sensor is visible,
    a short rest after a sustained run bleeds heat without giving the cores up.
    """
    from app.services.host_capacity import probe_host

    workers = max(1, int(workers or 1))
    try:
        snap = probe_host()
        settings = get_settings()
        throttle_c = int(getattr(settings, "cpu_thermal_throttle_c", 86) or 86)
        pause_c = int(getattr(settings, "cpu_thermal_pause_c", 94) or 94)
        gpu_pause_c = int(getattr(settings, "gpu_thermal_pause_c", 92) or 92)
    except Exception:
        return workers, 0.0, ""
    # Rest earlier than the configured 94C pause. Many laptops cut power near 95-100C.
    hard_c = min(pause_c, 90)
    temps = [int(t) for t in (snap.cpu_temp_c, snap.gpu_temp_c) if t is not None]
    if snap.gpu_temp_c is not None and int(snap.gpu_temp_c) >= gpu_pause_c:
        temps.append(hard_c)
    if not temps:
        if busy_seconds >= 75:
            return workers, 4.0, "cooling rest; CPU temperature is not visible"
        return workers, 0.0, ""
    hottest = max(temps)
    if hottest >= hard_c:
        return 1, 8.0, f"{hottest}C — resting parse so the laptop does not shut down"
    if hottest >= throttle_c:
        return max(1, min(workers, 2)), 2.0, f"{hottest}C — fewer parse cores"
    if hottest >= throttle_c - 6:
        return max(2, min(workers, max(2, workers // 2))), 0.5, ""
    return workers, 0.0, ""


def _claim_full_shard(db, job_id: str, forensic_filter: str) -> list[dict]:
    """Claim every pending file on the fullest extract shard.

    A shard is one compressed tar. Taking a few hundred paths and then reading
    that tar again for the next slice dominated parse time.
    """
    part = fetchone(
        db,
        f"""SELECT metadata->>'extracted_part_uri' AS part
            FROM job_artifacts
            WHERE job_id=:jid AND parse_status='pending'
              AND coalesce(metadata->>'extracted_part_uri','') <> ''
              {forensic_filter}
            GROUP BY 1
            ORDER BY MAX(CASE WHEN file_path ILIKE '%/config/SOFTWARE'
                OR file_path ILIKE '%/config/SYSTEM' OR file_path ILIKE '%/config/SAM'
                OR file_path ILIKE '%Security.evtx' THEN 1 ELSE 0 END) DESC,
              count(*) DESC
            LIMIT 1""",
        {"jid": job_id},
    )
    if not part or not part.get("part"):
        return []
    rows = fetchall(
        db,
        f"""SELECT id FROM job_artifacts
            WHERE job_id=:jid AND parse_status='pending'
              AND metadata->>'extracted_part_uri' = :part
              {forensic_filter}
            LIMIT :lim""",
        {"jid": job_id, "part": part["part"], "lim": _FULL_SHARD_CAP},
    )
    return _claim_artifacts_by_id(db, [row["id"] for row in rows])


def _claim_artifacts_by_id(db, ids: list[Any]) -> list[dict]:
    """Claim a preselected id set in id order so lock acquisition cannot cycle."""
    if not ids:
        return []
    return retry_on_deadlock(
        db,
        lambda: fetchall(
            db,
            """WITH candidates AS (
                    SELECT id FROM job_artifacts
                    WHERE id = ANY(:ids) AND parse_status='pending'
                    ORDER BY id
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE job_artifacts AS ja
                SET parse_status='parsing', updated_at=NOW()
                FROM candidates c
                WHERE ja.id = c.id
                RETURNING ja.id, ja.file_path, ja.minio_uri, ja.size_bytes, ja.sha256, ja.metadata""",
            {"ids": list(ids)},
        ),
    )


def _release_parsing_claims(db, ids: list[Any]) -> None:
    if not ids:
        return

    def _go():
        execute(
            db,
            """UPDATE job_artifacts
               SET parse_status='pending', updated_at=NOW()
               WHERE id = ANY(:ids) AND parse_status='parsing'""",
            {"ids": list(ids)},
        )

    retry_on_deadlock(db, _go)


def _refresh_parsing_claims(db, ids: list[Any]) -> None:
    """Keep live claims newer than the stale-recover window while this worker runs."""
    if not ids:
        return

    def _go():
        execute(
            db,
            """UPDATE job_artifacts SET updated_at=NOW()
               WHERE id = ANY(:ids) AND parse_status='parsing'""",
            {"ids": list(ids)},
        )

    retry_on_deadlock(db, _go)


def _fetch_pending_artifacts_for_paths(
    db,
    job_id: str,
    paths: list[str],
    *,
    extra_sql: str = "",
    limit: int,
) -> list[dict]:
    """Claim pending artifacts for a shard without one giant ANY(paths) bind."""
    found: list[dict] = []
    seen: set[str] = set()
    remaining = max(1, int(limit))
    for chunk in iter_path_chunks(paths, PATH_ANY_CHUNK):
        rows = _claim_pending_rows(
            db,
            job_id,
            extra_sql=f" AND file_path = ANY(:paths) {extra_sql}",
            params={"paths": chunk},
            order_sql="ORDER BY id",
            limit=remaining,
        )
        for row in rows:
            rid = str(row["id"])
            if rid in seen:
                continue
            seen.add(rid)
            found.append(row)
            if len(found) >= limit:
                return found
        remaining = limit - len(found)
        if remaining <= 0:
            return found
    return found


def _bulk_update_pending_in_batches(
    db,
    job_id: str,
    *,
    where_sql: str,
    set_sql: str,
    params: dict | None = None,
    batch_size: int = 10_000,
    from_status: str = "pending",
) -> int:
    """Update a large pending set in bounded commits instead of one giant lock."""
    total = 0
    values = {"jid": job_id, "batch": max(500, int(batch_size))}
    values.update(params or {})
    status_sql = "parse_status=:from_status"
    values["from_status"] = from_status
    # SKIP LOCKED lets parallel parse shards / drain skip the same leftover
    # rows without deadlocking on ShareLock.
    sql = f"""WITH candidates AS (
                    SELECT id FROM job_artifacts
                    WHERE job_id=:jid AND {status_sql} AND ({where_sql})
                    ORDER BY id
                    LIMIT :batch
                    FOR UPDATE SKIP LOCKED
                ), updated AS (
                    UPDATE job_artifacts
                    SET {set_sql}
                    WHERE id IN (SELECT id FROM candidates)
                    RETURNING 1
                )
                SELECT count(*)::int AS c FROM updated"""
    while True:
        row = None
        for attempt in range(5):
            try:
                row = fetchone(db, sql, values)
                break
            except Exception as exc:
                rollback_aborted_transaction(db)
                if not is_retryable_db_error(exc) or attempt >= 4:
                    raise
                time.sleep(0.25 * (attempt + 1))
        changed = int(row["c"]) if row else 0
        if changed <= 0:
            break
        total += changed
        # Release row locks frequently. Long evidence sets can contain hundreds of
        # thousands of low-value rows and must not block the API for minutes.
        db.commit()
        if changed < values["batch"]:
            break
    return total


def forensic_parse_keep_sql() -> str:
    """Rows forensic-only drain will actually parse (path, extension, or sidecar)."""
    return (
        f"({_FORENSIC_PARSE_PATH_SQL} OR {_FORENSIC_PARSE_EXT_SQL} "
        f"OR {PHASE1_PARSE_SIDECAR_SQL})"
    )


def skip_low_value_pending(db, job_id: str) -> int:
    """Mark non-forensic pending artifacts as skipped in bounded DB batches.

    Keep-set must match ``count_pending_parse(forensic_only=True)``. A previous
    ``size_bytes <= 8192`` exception left tens of thousands of tiny junk files
    pending forever: buckets saw 0 forensic work and returned no-ops while the
    supervisor kept re-queuing parse because raw pending stayed high.
    """
    skipped = _bulk_update_pending_in_batches(
        db,
        job_id,
        where_sql=f"NOT {forensic_parse_keep_sql()}",
        set_sql="parse_status='skipped', updated_at=NOW()",
    )
    if skipped:
        write_disk_log(
            db,
            job_id,
            f"Skipped {skipped:,} low-value pending artifacts (forensic-only enrichment)",
            stage="parse",
        )
        db.commit()
    return skipped


def prepare_forensic_parse_queue(db, job_id: str) -> dict[str, int]:
    """Skip leftovers forensic-only drain will never select, then skip media/EVTX."""
    skipped_low = skip_low_value_pending(db, job_id)
    skipped_media = bulk_skip_non_parser_pending(db, job_id)
    cleaned = {
        "skipped_low_value": skipped_low,
        "skipped_media": skipped_media,
    }
    if skipped_low or skipped_media:
        write_disk_log(
            db,
            job_id,
            f"Parse queue prepared — skipped {skipped_low:,} non-forensic, "
            f"{skipped_media:,} media/oversized EVTX",
            stage="parse",
        )
        db.commit()
    return cleaned


def _should_skip_oversized_evtx(path: str, size_bytes: int | None) -> bool:
    """Skip full parse for huge non-critical EVTX channels (each can burn 90s+ on CPU)."""
    settings = get_settings()
    max_bytes = int(getattr(settings, "parse_evtx_max_bytes", 0) or 0)
    if max_bytes <= 0:
        return False
    low = (path or "").replace("\\", "/").lower()
    if not low.endswith(".evtx"):
        return False
    size = int(size_bytes or 0)
    if size <= 0 or size <= max_bytes:
        return False
    return not is_critical_evtx_path(path)


def _read_budget_for_path(path: str, size_bytes: int | None) -> int | None:
    """Max bytes to read from storage; None = read entire object.

    Forensic artifacts (hives, EVTX, browser/chat SQLite, email containers, jump lists)
    are NEVER truncated — a 64 KiB prefix silently destroys OS/user/browser evidence.
    Only non-forensic media/unknown binaries use metadata/text caps.
    """
    from app.parsers import select_parser
    from app.services.critical_forensic_paths import is_forensic_full_read_path

    settings = get_settings()
    size = int(size_bytes or 0)
    if size <= 0:
        return None
    if is_forensic_full_read_path(path) or is_critical_evtx_path(path):
        return None

    sel = select_parser(path)
    if sel is not None:
        key, _fn = sel
        # Structured forensic parsers always get the full object.
        if key in {
            "registry", "sqlite", ".evtx", "setupapi", "jumplist",
            ".pf", ".lnk", ".eml", ".emlx", ".dat", ".db", ".sqlite",
            ".automaticdestinations-ms", ".customdestinations-ms",
        }:
            return None
        if key in _TEXT_PARSER_KEYS:
            # setupapi already covered; generic text/log preview caps only.
            text_cap = int(getattr(settings, "parse_text_max_bytes", 512_000) or 512_000)
            return text_cap if size > text_cap else None
        if key == "file_meta":
            meta_cap = int(getattr(settings, "parse_metadata_max_bytes", 65_536) or 65_536)
            return meta_cap if size > meta_cap else None
        # Known non-forensic parser with no special rule — full read up to hard ceiling.
        hard_cap = int(getattr(settings, "parse_hard_max_bytes", 512_000_000) or 512_000_000)
        if hard_cap > 0 and size > hard_cap:
            return hard_cap
        return None

    # Unknown / no parser: metadata sniff only (media/binaries).
    meta_cap = int(getattr(settings, "parse_metadata_max_bytes", 65_536) or 65_536)
    return meta_cap if size > meta_cap else None


def _read_budget_for_artifact(artifact: dict[str, Any]) -> int | None:
    """Read full MIME-validated email even when the source path is extensionless."""
    metadata = artifact.get("metadata")
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except Exception:
            metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    content_type = str(
        metadata.get("resolved_content_type") or metadata.get("content_type") or ""
    ).lower()
    detected_ext = str(metadata.get("detected_extension") or "").lower()
    validated = str(metadata.get("email_mime_validated") or "").lower() in {"true", "1", "t", "yes"}
    if content_type == "message/rfc822" or detected_ext in {".eml", ".emlx"} or validated:
        return None
    return _read_budget_for_path(str(artifact.get("file_path") or ""), artifact.get("size_bytes"))


def bulk_skip_non_parser_pending(db, job_id: str) -> int:
    """Bulk-skip media and oversized non-critical EVTX in bounded batches.

    `skip_low_value_pending()` already removes non-forensic artifacts before this
    function is called. The old single UPDATE repeated a large path predicate and
    could hold locks long enough to starve API reads on large evidence sets.
    """
    settings = get_settings()
    from app.services.ocr_gpu import ocr_status_sql_for_parse_skip

    ocr_case = ocr_status_sql_for_parse_skip()

    media_skipped = _bulk_update_pending_in_batches(
        db,
        job_id,
        where_sql=_MEDIA_SKIP_EXTENSIONS_SQL,
        set_sql=f"parse_status='skipped', ocr_status={ocr_case}, updated_at=NOW()",
    )
    evtx_skipped = _bulk_update_pending_in_batches(
        db,
        job_id,
        where_sql="""lower(coalesce(extension, '')) = '.evtx'
              AND coalesce(size_bytes, 0) > :evtx_max
              AND NOT (
                file_path ILIKE '%Security.evtx'
                OR file_path ILIKE '%System.evtx'
                OR file_path ILIKE '%Application.evtx'
              )""",
        set_sql="parse_status='skipped', ocr_status='na', updated_at=NOW()",
        params={
            "evtx_max": int(getattr(settings, "parse_evtx_max_bytes", 6_000_000) or 6_000_000),
        },
    )
    skipped = media_skipped + evtx_skipped
    if skipped:
        write_disk_log(
            db,
            job_id,
            f"Bulk-skipped {skipped:,} media/oversized EVTX pending artifacts (bounded batches)",
            stage="parse",
        )
        db.commit()
    return skipped


def skip_empty_pending_artifacts(db, job_id: str) -> int:
    """Mark zero-byte files skipped.

    An empty lock or log has nothing to parse. Treating it as a missing read
    puts it back to pending, the serial loop sees no progress, and the stage
    is failed after a few retries.
    """
    row = fetchone(
        db,
        """WITH updated AS (
               UPDATE job_artifacts
               SET parse_status='skipped', ocr_status='na',
                   metadata=coalesce(metadata, '{}'::jsonb)
                            || '{"skip_reason":"empty file"}'::jsonb,
                   updated_at=NOW()
               WHERE job_id=:jid AND parse_status IN ('pending','parsing')
                 AND coalesce(size_bytes, 0) = 0
               RETURNING 1
           )
           SELECT count(*)::int AS c FROM updated""",
        {"jid": job_id},
    )
    skipped = int(row["c"]) if row else 0
    if skipped:
        db.commit()
    return skipped


def _parse_attempts(artifact: dict) -> int:
    meta = artifact.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    if not isinstance(meta, dict):
        return 0
    try:
        return int(meta.get("parse_attempts") or 0)
    except (TypeError, ValueError):
        return 0


def _bump_parse_attempt(db, artifact: dict) -> int:
    """Increment metadata.parse_attempts; return new value."""
    attempts = _parse_attempts(artifact) + 1
    _exec_locked(
        db,
        """UPDATE job_artifacts
           SET metadata = coalesce(metadata, '{}'::jsonb)
                         || CAST(:meta AS jsonb),
               updated_at = NOW()
           WHERE id = :id""",
        {"id": artifact["id"], "meta": json.dumps({"parse_attempts": attempts})},
    )
    return attempts


def _defer_or_skip_forensic(
    db,
    artifact: dict,
    path: str,
    *,
    reason: str,
    defer_commit: bool = False,
) -> tuple[bool, str]:
    """On timeout/error for forensic paths: retry as pending (bounded), never silent drop."""
    attempts = _bump_parse_attempt(db, artifact)
    forensic = is_forensic_full_read_path(path) or is_critical_evtx_path(path)
    if forensic and attempts < _PARSE_ATTEMPT_MAX:
        _exec_locked(
            db,
            "UPDATE job_artifacts SET parse_status='pending', ocr_status='na', updated_at=NOW() WHERE id=:id",
            {"id": artifact["id"]},
        )
        # Persist a breadcrumb so operators see the retry.
        _exec_locked(
            db,
            """INSERT INTO artifact_parse_results (job_artifact_id, parser_name, parser_version,
               record_count, byte_offset, normalized)
               VALUES (:aid, :pname, :pver, 0, 0, CAST(:norm AS jsonb))""",
            {
                "aid": artifact["id"],
                "pname": reason,
                "pver": PARSER_VERSION,
                "norm": _json_for_pg([{
                    "record_type": "parse_retry",
                    "reason": reason,
                    "attempt": attempts,
                    "path": path,
                    "text": f"Parse {reason} — retry {attempts}/{_PARSE_ATTEMPT_MAX} (forensic full-read)",
                }]),
            },
        )
        if not defer_commit:
            db.commit()
        return False, "deferred"
    # Exhausted retries or non-forensic: mark skipped but leave a result note for critical.
    if forensic:
        _exec_locked(
            db,
            """INSERT INTO artifact_parse_results (job_artifact_id, parser_name, parser_version,
               record_count, byte_offset, normalized)
               VALUES (:aid, :pname, :pver, 0, 0, CAST(:norm AS jsonb))""",
            {
                "aid": artifact["id"],
                "pname": reason,
                "pver": PARSER_VERSION,
                "norm": _json_for_pg([{
                    "record_type": "parse_exhausted",
                    "reason": reason,
                    "attempt": attempts,
                    "path": path,
                    "partial": True,
                    "text": f"Parse {reason} after {attempts} attempts — marked skipped; re-queue manually if needed",
                }]),
            },
        )
    _exec_locked(
        db,
        "UPDATE job_artifacts SET parse_status='skipped', ocr_status='na', updated_at=NOW() WHERE id=:id",
        {"id": artifact["id"]},
    )
    if not defer_commit:
        db.commit()
    return False, reason

def _sanitize_for_jsonb(value):
    """PostgreSQL jsonb rejects NUL (\\u0000) in any string value."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").replace("\x00", "")
    if isinstance(value, str):
        return value.replace("\x00", "").replace("\u0000", "")
    if isinstance(value, list):
        return [_sanitize_for_jsonb(v) for v in value]
    if isinstance(value, dict):
        return {str(k).replace("\x00", ""): _sanitize_for_jsonb(v) for k, v in value.items()}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _sanitize_for_jsonb(str(value))


def _json_for_pg(value) -> str:
    """Serialize for CAST(... AS jsonb) — strip NUL escapes PostgreSQL rejects."""
    payload = json.dumps(_sanitize_for_jsonb(value), ensure_ascii=False, default=str)
    return payload.replace("\\u0000", "").replace("\x00", "")


def _run_parser_with_timeout(path: str, data: bytes, timeout_sec: int) -> tuple[str, list[dict[str, Any]]]:
    from app.parsers import run_parser

    if timeout_sec <= 0:
        return run_parser(path, data)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(run_parser, path, data)
        try:
            return fut.result(timeout=timeout_sec)
        except concurrent.futures.TimeoutError:
            log.warning("Parse timeout (%ss) path=%s size=%s", timeout_sec, path, len(data))
            return "timeout", []
        except Exception:
            raise


def _apply_parse_outcome(
    db,
    artifact: dict,
    path: str,
    parser_name: str,
    records: list[dict[str, Any]] | None,
    *,
    defer_commit: bool = False,
) -> tuple[bool, str]:
    """Persist parse result. Set defer_commit when batching commits in parallel drain."""
    if parser_name == "timeout":
        return _defer_or_skip_forensic(
            db, artifact, path, reason="timeout", defer_commit=defer_commit,
        )
    if not records:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        from app.services.ocr_gpu import ocr_status_for_artifact

        ocr_status = ocr_status_for_artifact(
            path,
            extension=f".{ext}" if ext else "",
            size_bytes=int(artifact.get("size_bytes") or 0),
        )
        # Forensic empty parse → retry; do not silently no_parser-drop hives/History.
        if is_forensic_full_read_path(path) or is_critical_evtx_path(path):
            return _defer_or_skip_forensic(
                db, artifact, path, reason="empty_parse", defer_commit=defer_commit,
            )
        _exec_locked(
            db,
            "UPDATE job_artifacts SET parse_status='no_parser', ocr_status=:ocr, updated_at=NOW() WHERE id=:id",
            {"id": artifact["id"], "ocr": ocr_status},
        )
        if not defer_commit:
            db.commit()
        return False, "no_parser"
    _exec_locked(
        db,
        """INSERT INTO artifact_parse_results (job_artifact_id, parser_name, parser_version,
           record_count, byte_offset, normalized)
           VALUES (:aid, :pname, :pver, :cnt, 0, CAST(:norm AS jsonb))""",
        {
            "aid": artifact["id"],
            "pname": parser_name,
            "pver": PARSER_VERSION,
            "cnt": len(records),
            "norm": _json_for_pg(records),
        },
    )
    # Promote deleted / recycle-bin fields into job_artifacts.metadata for UI titles.
    from app.services.deleted_evidence import (
        detect_deleted_path_hint,
        merge_metadata,
        metadata_from_parse_records,
    )

    path_hint = detect_deleted_path_hint(path) or {}
    del_patch = {**path_hint, **metadata_from_parse_records(records)}
    if del_patch:
        # Prefer original filename from Recycle Bin $I for examiner display.
        display_name = del_patch.get("original_name") or ""
        merged = merge_metadata(artifact.get("metadata"), del_patch)
        _exec_locked(
            db,
            """UPDATE job_artifacts
               SET parse_status='parsed',
                   metadata = coalesce(metadata, '{}'::jsonb) || CAST(:meta AS jsonb),
                   file_name = CASE
                     WHEN :pname = 'recycle_bin' AND :display_name <> '' THEN :display_name
                     ELSE file_name
                   END,
                   updated_at=NOW()
               WHERE id=:id""",
            {
                "id": artifact["id"],
                "meta": _json_for_pg(merged),
                "display_name": str(display_name or ""),
                "pname": parser_name,
            },
        )
    else:
        _exec_locked(
            db,
            "UPDATE job_artifacts SET parse_status='parsed', updated_at=NOW() WHERE id=:id",
            {"id": artifact["id"]},
        )
    if not defer_commit:
        db.commit()
    return True, "parsed"


def _store_parse_result(db, artifact: dict, path: str, data: bytes) -> tuple[bool, str]:
    """Parse bytes and persist result. Returns (success, outcome)."""
    timeout_sec = _timeout_for_path(
        path,
        _configured_parse_timeout_sec(),
        size_bytes=len(data) if data else artifact.get("size_bytes"),
    )
    try:
        parser_name, records = _run_parser_with_timeout(path, data, timeout_sec)
        return _apply_parse_outcome(db, artifact, path, parser_name, records)
    except Exception:
        db.rollback()
        try:
            return _defer_or_skip_forensic(db, artifact, path, reason="error")
        except Exception:
            db.rollback()
        return False, "skipped"


def _configured_parse_timeout_sec() -> int:
    raw = getattr(get_settings(), "parse_file_timeout_sec", 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _timeout_for_path(path: str, default_sec: int, *, size_bytes: int | None = None) -> int:
    """Longer wall clocks for large forensic artifacts — never starve SOFTWARE/Security.evtx.

    default_sec <= 0 means no timeout (wait until the parser finishes).
    """
    if default_sec <= 0:
        return 0
    low = (path or "").replace("\\", "/").lower()
    size = int(size_bytes or 0)
    forensic = is_forensic_full_read_path(path) or is_critical_evtx_path(path)
    if low.endswith(".evtx"):
        if is_critical_evtx_path(path):
            # Critical EVTX: allow up to 10 minutes for large Security logs.
            return max(default_sec, 300 if size > 8_000_000 else 180)
        return min(max(default_sec, 30), 60)
    if forensic:
        if size >= 100_000_000:
            return max(default_sec, 600)
        if size >= _LARGE_FILE_BYTES:
            return max(default_sec, 300)
        return max(default_sec, 180)
    return default_sec


def _parse_work_item(item: tuple[dict, str, bytes | None], timeout_sec: int) -> dict[str, Any]:
    """CPU-bound parse step — safe to run in a thread pool (no DB)."""
    artifact, path, data = item
    if data is None:
        return {"artifact": artifact, "path": path, "kind": "no_data"}
    if len(data) == 0:
        return {"artifact": artifact, "path": path, "kind": "empty"}
    effective_timeout = _timeout_for_path(
        path, timeout_sec, size_bytes=len(data) if data else artifact.get("size_bytes"),
    )
    try:
        parser_name, records = _run_parser_with_timeout(path, data, effective_timeout)
        return {
            "artifact": artifact,
            "path": path,
            "kind": "parsed",
            "parser_name": parser_name,
            "records": records,
        }
    except Exception as exc:
        log.debug("Parse worker error path=%s: %s", path, exc)
        return {"artifact": artifact, "path": path, "kind": "error"}

def _process_parse_work_parallel(
    db,
    job_id: str,
    work: list[tuple[dict, str, bytes | None]],
    *,
    parse_workers: int,
    timeout_sec: int,
    commit_batch: int,
    stats: dict[str, int],
    heartbeat_fn,
    backoff_fn,
    heartbeat_due_fn=None,
    worker_limit_fn=None,
) -> None:
    """Parse many artifacts in parallel; DB writes stay on the caller thread."""
    if not work:
        return

    if heartbeat_due_fn is None:
        heartbeat_due_fn = lambda: False
    settings = get_settings()
    parallel = bool(getattr(settings, "parse_parallel_enabled", True)) and parse_workers > 1
    chunk_size = max(parse_workers * 12, 48) if parallel else len(work)
    pending_commits = 0

    def _flush_artifact_writes() -> None:
        nonlocal pending_commits
        if pending_commits:
            db.commit()
            pending_commits = 0

    def _persist_result(result: dict[str, Any]) -> None:
        nonlocal pending_commits
        artifact = result["artifact"]
        path = result["path"]
        kind = result.get("kind")
        if kind == "empty":
            _exec_locked(
                db,
                """UPDATE job_artifacts
                   SET parse_status='skipped', ocr_status='na',
                       metadata=coalesce(metadata, '{}'::jsonb)
                                || '{"skip_reason":"empty file"}'::jsonb,
                       updated_at=NOW()
                   WHERE id=:id""",
                {"id": artifact["id"]},
            )
            stats["skipped"] += 1
        elif kind == "no_data":
            if is_forensic_full_read_path(path) or is_critical_evtx_path(path):
                _defer_or_skip_forensic(db, artifact, path, reason="no_data", defer_commit=True)
            else:
                _exec_locked(
                    db,
                    "UPDATE job_artifacts SET parse_status='skipped', ocr_status='na', updated_at=NOW() WHERE id=:id",
                    {"id": artifact["id"]},
                )
            stats["skipped"] += 1
        elif kind == "error":
            _defer_or_skip_forensic(db, artifact, path, reason="error", defer_commit=True)
            stats["skipped"] += 1
        else:
            try:
                ok, outcome = _apply_parse_outcome(
                    db,
                    artifact,
                    path,
                    str(result.get("parser_name") or ""),
                    result.get("records"),
                    defer_commit=True,
                )
                if ok:
                    stats["parsed"] += 1
                else:
                    stats["skipped"] += 1
            except Exception:
                rollback_aborted_transaction(db)
                try:
                    _defer_or_skip_forensic(db, artifact, path, reason="error", defer_commit=True)
                except Exception:
                    rollback_aborted_transaction(db)
                    _exec_locked(
                        db,
                        "UPDATE job_artifacts SET parse_status='skipped', ocr_status='na', updated_at=NOW() WHERE id=:id",
                        {"id": artifact["id"]},
                    )
                stats["skipped"] += 1
        pending_commits += 1
        # Commit a batch of artifact rows together. Flushing every file capped
        # the shard at roughly one file per database round-trip.
        # A heartbeat updates stage rows, so those artifact locks are committed
        # first and only when that heartbeat is actually due.
        if pending_commits >= commit_batch or heartbeat_due_fn():
            _flush_artifact_writes()
        heartbeat_fn()
        backoff_fn()

    # Large forensic blobs: one-at-a-time to avoid OOM from parallel SOFTWARE/History loads.
    large_items = [
        item for item in work
        if item[2] is not None and len(item[2]) >= _LARGE_FILE_BYTES
    ]
    small_items = [
        item for item in work
        if item[2] is None or len(item[2]) < _LARGE_FILE_BYTES
    ]
    for item in large_items:
        _persist_result(_parse_work_item(item, timeout_sec))

    for offset in range(0, len(small_items), chunk_size):
        chunk = small_items[offset : offset + chunk_size]
        if parallel and len(chunk) > 1:
            workers_now = parse_workers
            if worker_limit_fn is not None:
                try:
                    workers_now = max(1, min(parse_workers, int(worker_limit_fn())))
                except Exception:
                    workers_now = parse_workers
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers_now) as pool:
                futures = [pool.submit(_parse_work_item, item, timeout_sec) for item in chunk]
                results = [fut.result() for fut in concurrent.futures.as_completed(futures)]
            results.sort(key=lambda r: str((r.get("artifact") or {}).get("id") or ""))
            for result in results:
                _persist_result(result)
        else:
            for item in chunk:
                _persist_result(_parse_work_item(item, timeout_sec))

    if pending_commits:
        db.commit()

def parse_job_artifacts_for_paths(
    db,
    job_id: str,
    *,
    paths: list[str] | None,
    index_map: dict[str, str],
    update_status: bool = True,
    batch_limit: int | None = None,
    forensic_only: bool = False,
    parse_bucket: int | None = None,
    parse_buckets: int | None = None,
    full_shard: bool = False,
    worker_cap: int | None = None,
) -> dict:
    settings = get_settings()
    limit = int(batch_limit if batch_limit is not None else getattr(settings, "parse_batch_limit", 5000) or 5000)
    bucket_filter = ""
    if parse_bucket is not None and parse_buckets and int(parse_buckets) > 1:
        bucket_filter = f" AND mod(abs(hashtext(file_path)), {int(parse_buckets)}) = {int(parse_bucket)}"
    forensic_filter = (
        f" AND {forensic_parse_keep_sql()}"
        if forensic_only
        else ""
    ) + bucket_filter
    recover_stale_parsing_claims(db, job_id)
    # Whole-job skip is not safe while extract shards parse in parallel — every
    # shard used to UPDATE the same pending set and deadlock. Drain / bucket
    # callers already run prepare_forensic_parse_queue once. Path-scoped shard
    # work only selects forensic rows for its own paths.
    if forensic_only and not paths:
        skip_low_value_pending(db, job_id)
        bulk_skip_non_parser_pending(db, job_id)
    if paths:
        artifacts = _fetch_pending_artifacts_for_paths(
            db,
            job_id,
            paths,
            extra_sql=forensic_filter,
            limit=limit,
        )
    else:
        artifacts = []
        if full_shard:
            artifacts = _claim_full_shard(db, job_id, forensic_filter)
        if not artifacts:
            # Probe without locking, then claim only the coalesced shard ids in id order.
            probe_limit = max(limit * 6, limit, 2000) if index_map else limit
            probed = fetchall(
                db,
                f"""SELECT id, file_path, minio_uri, size_bytes, metadata FROM job_artifacts
                   WHERE job_id=:jid AND parse_status='pending'
                   {forensic_filter}
                   ORDER BY {_FORENSIC_PARSE_ORDER_SQL}
                   LIMIT :lim""",
                {"jid": job_id, "lim": probe_limit},
            )
            artifacts = probed
            if artifacts and index_map and len(artifacts) > limit:
                from collections import Counter

                part_of: dict[str, str] = {}
                counts: Counter[str] = Counter()
                for art in artifacts:
                    norm = str(art["file_path"]).replace("\\", "/")
                    part = index_map.get(norm) or index_map.get(art["file_path"]) or ""
                    if art.get("minio_uri"):
                        part = f"direct:{art['id']}"
                    part_of[str(art["id"])] = part
                    counts[part] += 1
                best_part, _ = counts.most_common(1)[0]
                coalesced = [a for a in artifacts if part_of.get(str(a["id"])) == best_part]
                shard_cap = max(limit, min(2500, len(coalesced)))
                artifacts = coalesced[:shard_cap]
            artifacts = _claim_artifacts_by_id(db, [a["id"] for a in artifacts])
    if artifacts:
        db.commit()
    if not artifacts:
        return {"status": "ok", "parsed": 0, "skipped": 0}
    claimed_ids = [a["id"] for a in artifacts]

    if update_status:
        write_disk_log(db, job_id, f"Parsing {len(artifacts):,} artifacts", stage="parse")
        db.commit()

    skipped = 0
    stats = {"parsed": 0, "skipped": 0}
    heartbeat_every = 10 if update_status else 999999
    last_heartbeat_at = time.monotonic()
    last_orchestration_at = 0
    last_cool_at = time.monotonic()
    settings = get_settings()
    parse_workers = max(int(getattr(settings, "parse_workers", 12) or 12), 1)
    from app.services.forensic_serial_policy import parallelism

    if worker_cap:
        parse_workers = max(1, int(worker_cap))
    else:
        # Cap total parse threads across buckets (Performance agent may raise PARSE_WORKERS).
        parse_workers = parallelism(parse_workers)
    # When path-hash buckets already fan out across Celery processes, shrink per-bucket
    # threads so total CPU threads ≈ parse_workers (keeps thermal load under control).
    if parse_buckets and int(parse_buckets) > 1:
        parse_workers = max(1, parse_workers // int(parse_buckets))
    if not worker_cap:
        # Serial parse sheds threads per batch from chassis temperature.
        # This start-of-batch cut also treats a busy CPU as heat, which stalls a cool laptop.
        try:
            from app.services.gpu_thermal import recommended_parallel_workers

            parse_workers = recommended_parallel_workers(parse_workers, min_workers=1)
        except Exception:
            pass
    try:
        from app.services.adaptive_semaphore import cap_parallelism

        parse_workers = cap_parallelism("parse_workers", parse_workers, min_workers=1)
    except Exception:
        pass
    if not worker_cap:
        parse_workers = parallelism(parse_workers)
    timeout_sec = _configured_parse_timeout_sec()
    commit_batch = max(int(getattr(settings, "parse_db_commit_batch", 25) or 25), 1)

    def _maybe_cpu_backoff() -> None:
        """Load alone must not stall parse. Temperature is applied per batch."""
        return

    def _thermal_worker_cap() -> int:
        nonlocal last_cool_at
        busy = time.monotonic() - last_cool_at
        cap, sleep_s, reason = parse_thermal_backoff(parse_workers, busy_seconds=busy)
        if not sleep_s:
            return cap
        if reason:
            log.info("Parse thermal: %s", reason)
        waited = 0.0
        while True:
            _maybe_heartbeat()
            step = min(sleep_s, 8.0)
            time.sleep(step)
            waited += step
            if sleep_s < 8 or waited >= 90:
                break
            cap, sleep_s, reason = parse_thermal_backoff(parse_workers, busy_seconds=0)
            if sleep_s < 8:
                break
        last_cool_at = time.monotonic()
        return max(1, min(parse_workers, cap))

    def _heartbeat_due() -> bool:
        total = stats["parsed"] + stats["skipped"]
        if total == 0:
            return (time.monotonic() - last_heartbeat_at) >= 30.0
        time_due = (time.monotonic() - last_heartbeat_at) >= 30.0
        count_due = update_status and total > 0 and total % heartbeat_every == 0
        return bool(count_due or time_due)

    def _maybe_heartbeat() -> None:
        nonlocal last_heartbeat_at, last_orchestration_at
        total = stats["parsed"] + stats["skipped"]
        if total == 0:
            if (time.monotonic() - last_heartbeat_at) >= 30.0:
                last_heartbeat_at = time.monotonic()
                _advance_parse_stage(db, job_id, "Native forensic parsing")
            return
        time_due = (time.monotonic() - last_heartbeat_at) >= 30.0
        count_due = update_status and total > 0 and total % heartbeat_every == 0
        if not count_due and not time_due:
            return
        last_heartbeat_at = time.monotonic()
        try:
            from app.services.job_locks import DEFAULT_PARSE_LOCK_TTL_SEC, refresh_job_lock

            refresh_job_lock("parse", job_id, ttl_sec=DEFAULT_PARSE_LOCK_TTL_SEC)
        except Exception:
            pass
            _refresh_parsing_claims(db, claimed_ids)
        write_disk_log(
            db,
            job_id,
            f"Parse in progress — {stats['parsed']:,} parsed, {stats['skipped']:,} skipped this batch "
            f"({parse_workers} workers)",
            stage="parse",
        )
        if update_status or (total - last_orchestration_at) >= 500:
            last_orchestration_at = total
            try:
                from app.services.pipeline_orchestrator import merge_orchestration_into_progress

                merge_orchestration_into_progress(db, job_id)
            except Exception as exc:
                log.debug("Parse heartbeat orchestration merge skipped: %s", exc)
        db.commit()
        _advance_parse_stage(
            db,
            job_id,
            f"Native forensic parsing — {stats['parsed']:,} parsed this batch",
            publish_counts=True,
        )

    try:
        return _run_claimed_parse_batch(
            db,
            job_id,
            artifacts=artifacts,
            claimed_ids=claimed_ids,
            index_map=index_map,
            update_status=update_status,
            stats=stats,
            skipped=skipped,
            parse_workers=parse_workers,
            timeout_sec=timeout_sec,
            commit_batch=commit_batch,
            heartbeat_fn=_maybe_heartbeat,
            backoff_fn=_maybe_cpu_backoff,
            heartbeat_due_fn=_heartbeat_due,
            worker_limit_fn=_thermal_worker_cap,
        )
    except Exception:
        rollback_aborted_transaction(db)
        raise
    finally:
        try:
            _release_parsing_claims(db, claimed_ids)
            db.commit()
        except Exception:
            rollback_aborted_transaction(db)


def _run_claimed_parse_batch(
    db,
    job_id: str,
    *,
    artifacts: list[dict],
    claimed_ids: list[Any],
    index_map: dict[str, str],
    update_status: bool,
    stats: dict[str, int],
    skipped: int,
    parse_workers: int,
    timeout_sec: int,
    commit_batch: int,
    heartbeat_fn,
    backoff_fn,
    heartbeat_due_fn=None,
    worker_limit_fn=None,
) -> dict:
    by_part_budget: dict[tuple[str, int | None], list[dict]] = {}
    direct_minio: list[dict] = []
    for artifact in artifacts:
        if _should_skip_oversized_evtx(artifact["file_path"], artifact.get("size_bytes")):
            skipped += 1
            _exec_locked(
                db,
                "UPDATE job_artifacts SET parse_status='skipped', ocr_status='na', updated_at=NOW() WHERE id=:id",
                {"id": artifact["id"]},
            )
            continue
        norm_path = artifact["file_path"].replace("\\", "/")
        part_uri = index_map.get(norm_path) or index_map.get(artifact["file_path"])
        if part_uri:
            budget = _read_budget_for_artifact(artifact)
            by_part_budget.setdefault((part_uri, budget), []).append(dict(artifact))
        elif artifact.get("minio_uri"):
            direct_minio.append(dict(artifact))
        else:
            skipped += 1
            _exec_locked(
                db,
                "UPDATE job_artifacts SET parse_status='skipped', updated_at=NOW() WHERE id=:id",
                {"id": artifact["id"]},
            )

    work: list[tuple[dict, str, bytes | None]] = []
    batch_bytes = 0

    def _flush_work() -> None:
        nonlocal work, batch_bytes
        if not work:
            return
        _process_parse_work_parallel(
            db,
            job_id,
            work,
            parse_workers=parse_workers,
            timeout_sec=timeout_sec,
            commit_batch=commit_batch,
            stats=stats,
            heartbeat_fn=heartbeat_fn,
            backoff_fn=backoff_fn,
            heartbeat_due_fn=heartbeat_due_fn,
            worker_limit_fn=worker_limit_fn,
        )
        work = []
        batch_bytes = 0

    def _enqueue(artifact: dict, path: str, data: bytes | None) -> None:
        nonlocal batch_bytes
        size = len(data) if data else int(artifact.get("size_bytes") or 0)
        # Flush before adding another large blob so we never hold multiple SOFTWARE-sized files.
        if work and (size >= _LARGE_FILE_BYTES or batch_bytes + size > _PARSE_BATCH_BYTE_BUDGET):
            _flush_work()
        work.append((artifact, path, data))
        batch_bytes += size
        if size >= _LARGE_FILE_BYTES or batch_bytes >= _PARSE_BATCH_BYTE_BUDGET:
            _flush_work()

    for artifact in direct_minio:
        path = artifact["file_path"]
        budget = _read_budget_for_artifact(artifact)
        try:
            execute(db, "UPDATE jobs SET updated_at=NOW() WHERE id=:id", {"id": job_id})
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        metadata = artifact.get("metadata") or {}
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        if metadata.get("whatsapp_derivation") and path.startswith("derived/whatsapp_decrypted/"):
            from app.services.mobile_forensic.whatsapp_derivation import read_registered_derivation, MAX_PAYLOAD_BYTES
            data = read_registered_derivation(db, job_id, artifact, max_bytes=budget if budget is not None else MAX_PAYLOAD_BYTES)
        else:
            data = get_bytes(artifact["minio_uri"], max_bytes=budget)
        _enqueue(artifact, path, data)

    for (part_uri, budget), part_artifacts in by_part_budget.items():
        # Stream MinIO→zstd→tar; parts are multi-GB (seen 5–13GB) — never get_bytes().
        by_path = {a["file_path"].replace("\\", "/"): a for a in part_artifacts}
        paths_set = set(by_path)
        try:
            execute(db, "UPDATE jobs SET updated_at=NOW() WHERE id=:id", {"id": job_id})
            write_disk_log(
                db,
                job_id,
                f"Parse streaming shard — {len(paths_set):,} file(s) from part",
                stage="parse",
                metadata={"part_uri": part_uri, "files": len(paths_set)},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

        def _shard_still_reading() -> None:
            _advance_parse_stage(
                db,
                job_id,
                f"Streaming extract shard — {len(paths_set):,} files for native parsing",
            )

        try:
            import queue
            import threading

            batches: queue.Queue = queue.Queue(maxsize=1)
            failed: list[BaseException] = []

            def _read_ahead() -> None:
                ahead: list[tuple[dict, str, bytes | None]] = []
                ahead_bytes = 0
                try:
                    for norm, data in iter_files_from_part(
                        part_uri, paths_set, max_bytes=budget
                    ):
                        artifact = by_path.get(norm)
                        if not artifact:
                            continue
                        size = len(data) if data else int(artifact.get("size_bytes") or 0)
                        if ahead and (
                            size >= _LARGE_FILE_BYTES or ahead_bytes + size > _PARSE_BATCH_BYTE_BUDGET
                        ):
                            batches.put(ahead)
                            ahead = []
                            ahead_bytes = 0
                        ahead.append((artifact, artifact["file_path"], data))
                        ahead_bytes += size
                        if size >= _LARGE_FILE_BYTES or ahead_bytes >= _PARSE_BATCH_BYTE_BUDGET:
                            batches.put(ahead)
                            ahead = []
                            ahead_bytes = 0
                    if ahead:
                        batches.put(ahead)
                except Exception as exc:
                    failed.append(exc)
                finally:
                    batches.put(None)

            reader = threading.Thread(target=_read_ahead, name="parse-shard-read", daemon=True)
            reader.start()
            while True:
                try:
                    nxt = batches.get(timeout=15)
                except queue.Empty:
                    _shard_still_reading()
                    continue
                if nxt is None:
                    break
                # The reader is already filling the next batch while this one parses.
                for artifact, path, data in nxt:
                    _enqueue(artifact, path, data)
                data = None
            reader.join(timeout=5)
            if failed:
                raise failed[0]
        except TransientStreamError as exc:
            # Keep files already pulled from this shard. Unread claims go back
            # to pending so the next pass retries them instead of skipping them
            # or failing the source.
            _flush_work()
            _release_parsing_claims(db, [a["id"] for a in part_artifacts])
            write_disk_log(
                db,
                job_id,
                "Parse shard read interrupted — unread files returned to pending",
                stage="parse",
                level="warning",
                metadata={"part_uri": part_uri, "error": str(exc)[:500]},
            )
            db.commit()
            raise

    _flush_work()
    parsed = stats["parsed"]
    skipped += stats["skipped"]

    if update_status:
        execute(
            db,
            """INSERT INTO parser_runs (job_id, parser_name, parser_version, files_processed, files_skipped, finished_at)
               VALUES (:jid, 'multi', :ver, :proc, :skip, NOW())""",
            {"jid": job_id, "ver": PARSER_VERSION, "proc": parsed, "skip": skipped},
        )
        write_disk_log(db, job_id, f"Parse complete — {parsed:,} parsed, {skipped:,} skipped/deferred", stage="parse")
        execute(db, "UPDATE jobs SET status='parsed', updated_at=NOW() WHERE id=:id", {"id": job_id})
        db.commit()
    return {"status": "ok", "parsed": parsed, "skipped": skipped}


def parse_job_artifacts(db, job_id: str, *, schema_name: str) -> dict:
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row["disk_source"]
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    from app.services.disk_manifest import build_index_map

    index_map = build_index_map(manifest)
    return parse_job_artifacts_for_paths(
        db, job_id, paths=None, index_map=index_map, update_status=True,
    )


def count_pending_parse(db, job_id: str, *, forensic_only: bool = True) -> int:
    forensic_filter = f" AND {forensic_parse_keep_sql()}" if forensic_only else ""
    row = fetchone(
        db,
        f"SELECT count(*) c FROM job_artifacts WHERE job_id=:jid AND parse_status='pending'{forensic_filter}",
        {"jid": job_id},
    )
    return int(row["c"]) if row else 0


def count_pending_in_bucket(
    db,
    job_id: str,
    *,
    bucket_id: int,
    num_buckets: int,
    forensic_only: bool = True,
) -> int:
    if num_buckets <= 1:
        return count_pending_parse(db, job_id, forensic_only=forensic_only)
    forensic_filter = f" AND {forensic_parse_keep_sql()}" if forensic_only else ""
    row = fetchone(
        db,
        f"""SELECT count(*) c FROM job_artifacts
            WHERE job_id=:jid AND parse_status='pending'
              AND mod(abs(hashtext(file_path)), :n) = :b{forensic_filter}""",
        {"jid": job_id, "n": int(num_buckets), "b": int(bucket_id)},
    )
    return int(row["c"]) if row else 0


def queue_parallel_parse_buckets(
    schema_name: str,
    job_id: str,
    *,
    num_buckets: int | None = None,
) -> int:
    """Fan out background parse across N Celery workers (path-hash buckets)."""
    settings = get_settings()
    buckets = max(int(num_buckets or getattr(settings, "parse_parallel_buckets", 4) or 4), 1)
    # Mobile dumps use multi-GB tar.zst shards — parallel buckets OOM even when
    # streamed (two 13GB decompressors). Always single-bucket for mobile.
    try:
        from app.db.session import firm_session
        from app.forensic_common.job_types import is_mobile_job

        with firm_session(schema_name) as db:
            if is_mobile_job(db, job_id):
                buckets = 1
    except Exception:
        buckets = 1
    buckets = max(1, min(buckets, 8))
    from app.tasks import parse_bucket_task

    for bucket_id in range(buckets):
        parse_bucket_task.delay(schema_name, job_id, bucket_id, buckets)
    return buckets


def drain_pending_parse(
    db,
    job_id: str,
    *,
    index_map: dict[str, str] | None = None,
    requeue_no_parser: bool | None = None,
    max_rounds: int | None = None,
    update_job_status: bool = True,
    forensic_only: bool | None = None,
    interleave_rag: bool | None = None,
    schema_name: str | None = None,
    parse_bucket: int | None = None,
    parse_buckets: int | None = None,
) -> dict:
    """Parse every pending artifact (and optionally re-queue prior no_parser rows)."""
    settings = get_settings()
    if index_map is None:
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
        manifest = row.get("disk_source") if row else {}
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        from app.services.disk_manifest import build_index_map

        index_map = build_index_map(manifest or {})

    forensic_only = (
        forensic_only if forensic_only is not None else bool(getattr(settings, "parse_drain_forensic_only", True))
    )
    interleave_rag = (
        interleave_rag if interleave_rag is not None else bool(getattr(settings, "parse_drain_interleave_rag", True))
    )
    if requeue_no_parser is None:
        requeue_no_parser = bool(getattr(settings, "parse_drain_requeue_no_parser", False))

    if forensic_only:
        prepare_forensic_parse_queue(db, job_id)

    recover_stale_parsing_claims(db, job_id)
    # Recover forensic artifacts previously skipped on timeout/error (bounded attempts).
    _bulk_update_pending_in_batches(
        db,
        job_id,
        where_sql=(
            f"({_FORENSIC_PARSE_PATH_SQL} OR {_FORENSIC_PARSE_EXT_SQL}) "
            f"AND coalesce((metadata->>'parse_attempts')::int, 0) < :max_attempts "
            f"AND updated_at > NOW() - INTERVAL '7 days'"
        ),
        set_sql="parse_status='pending', updated_at=NOW()",
        params={"max_attempts": _PARSE_ATTEMPT_MAX},
        from_status="skipped",
    )
    db.commit()

    if requeue_no_parser:
        execute(
            db,
            """UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
               WHERE job_id=:jid AND parse_status IN ('no_parser', 'skipped')""",
            {"jid": job_id},
        )
        db.commit()
    rounds_cap = max_rounds
    if rounds_cap is None:
        rounds_cap = int(getattr(settings, "parse_drain_max_rounds", 0) or 0)

    parsed_total = 0
    skipped_total = 0
    rounds = 0
    while True:
        remaining = count_pending_parse(db, job_id, forensic_only=forensic_only)
        if remaining <= 0:
            break
        if rounds_cap and rounds >= rounds_cap:
            break
        if not rounds_cap and rounds > 10_000:
            log.warning("Parse drain safety stop after %s rounds job=%s", rounds, job_id)
            break

        if update_job_status:
            from app.services.dual_rag_index import _count_indexable_without_chunks

            rag_remaining = _count_indexable_without_chunks(db, job_id)
            chunks_row = fetchone(
                db,
                "SELECT count(*) c FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence'",
                {"jid": job_id},
            )
            chunk_n = int(chunks_row["c"]) if chunks_row else 0
            from app.services.pipeline_orchestrator import record_pipeline_milestone

            if rag_remaining <= 0:
                # Q&A-ready, but parse is still draining: keep orchestration and
                # let the sync compute an honest (<100) overall.
                record_pipeline_milestone(
                    db,
                    job_id,
                    status="indexed",
                    writer="parse",
                    progress={
                        "phase": "parse",
                        "completed": parsed_total,
                        "total": parsed_total + remaining,
                        "label": f"background parse ({remaining:,} pending) — Q&A ready",
                    },
                )
            else:
                record_pipeline_milestone(
                    db,
                    job_id,
                    status="indexing",
                    writer="rag",
                    progress={
                        "phase": "rag",
                        "completed": chunk_n,
                        "total": max(chunk_n + rag_remaining, 1),
                        "label": f"GPU RAG in progress — background parse ({remaining:,} pending)",
                    },
                )
            db.commit()

        pr = parse_job_artifacts_for_paths(
            db,
            job_id,
            paths=None,
            index_map=index_map,
            update_status=False,
            forensic_only=forensic_only,
            batch_limit=int(getattr(settings, "parse_drain_batch_limit", 200) or 200),
            parse_bucket=parse_bucket,
            parse_buckets=parse_buckets,
        )
        batch = int(pr.get("parsed", 0)) + int(pr.get("skipped", 0))
        parsed_total += int(pr.get("parsed", 0))
        skipped_total += int(pr.get("skipped", 0))
        rounds += 1
        if rounds == 1 or rounds % 5 == 0 or batch == 0:
            bucket_label = ""
            if parse_bucket is not None and parse_buckets:
                bucket_label = f" bucket {parse_bucket}/{parse_buckets}"
            write_disk_log(
                db,
                job_id,
                f"Parse drain{bucket_label} round {rounds}: +{pr.get('parsed', 0):,} parsed, "
                f"+{pr.get('skipped', 0):,} skipped ({remaining:,} were pending)",
                stage="parse",
            )
            db.commit()
        if interleave_rag and int(pr.get("parsed", 0)) > 0 and schema_name:
            try:
                from app.tasks import rag_append_task

                rag_append_task.delay(schema_name, job_id)
            except Exception as exc:
                log.warning("Interleaved RAG queue failed: %s", exc)
        if batch == 0:
            break

    return {
        "status": "ok",
        "parsed": parsed_total,
        "skipped": skipped_total,
        "rounds": rounds,
    }
