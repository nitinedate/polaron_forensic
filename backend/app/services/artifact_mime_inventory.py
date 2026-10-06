"""Background MIME/type normalization for every materialized forensic file.

The scanner is deliberately metadata-first for known formats and byte-sniffs
ambiguous/generic files.  This avoids random-reading tens of gigabytes merely to
reconfirm obvious ``.jpg``/``.pdf`` files, while still ensuring every artifact
receives a deterministic MIME classification status.

Unknown bytes remain ``application/x-forensic-data``.  We never rename or alter
original evidence; only derived type metadata is persisted.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.artifact_type_resolver import FORENSIC_DATA_MIME, TYPE_SNIFF_BYTES, resolve_artifact_type

log = logging.getLogger("artifact_mime_inventory")

MIME_SCAN_VERSION = "v36.1"
MIME_SCAN_BATCH = 750


def mime_inventory_progress(db, job_id: str) -> dict[str, Any]:
    row = fetchone(
        db,
        """SELECT
             count(*)::bigint AS total,
             count(*) FILTER (WHERE metadata->>'mime_scan_version'=:ver)::bigint AS completed,
             count(*) FILTER (
               WHERE metadata->>'mime_scan_version'=:ver
                 AND coalesce(metadata->>'resolved_content_type','')='application/x-forensic-data'
             )::bigint AS unknown
           FROM job_artifacts WHERE job_id=:jid""",
        {"jid": job_id, "ver": MIME_SCAN_VERSION},
    ) or {}
    total = int(row.get("total") or 0)
    completed = int(row.get("completed") or 0)
    unknown = int(row.get("unknown") or 0)
    return {
        "version": MIME_SCAN_VERSION,
        "total": total,
        "completed": completed,
        "unknown": unknown,
        "resolved": max(completed - unknown, 0),
        "done": completed >= total if total > 0 else True,
    }


def _read_head(db, job_id: str, row: dict[str, Any]) -> bytes:
    from app.services.artifact_preview import iter_artifact_content

    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in iter_artifact_content(db, job_id, row, max_bytes=TYPE_SNIFF_BYTES):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= TYPE_SNIFF_BYTES:
                break
    except Exception:
        return b""
    return b"".join(chunks)[:TYPE_SNIFF_BYTES]


def _needs_byte_sniff(resolved) -> bool:
    # Strong path/parser metadata and ordinary well-known extensions are enough
    # for initial inventory. Generic/fallback/placeholder formats must inspect
    # evidence bytes so Chrome cache objects and extensionless files are typed.
    if resolved.content_type == FORENSIC_DATA_MIME:
        return True
    if resolved.source == "fallback":
        return True
    ext = (resolved.extension or "").lower()
    if ext in {".dat", ".bin", ".tmp", ".cache", ".blob", ".file", ".unknown"}:
        return True
    return False


def scan_artifact_mime_batch(db, job_id: str, *, limit: int = MIME_SCAN_BATCH) -> dict[str, Any]:
    limit = max(min(int(limit or MIME_SCAN_BATCH), 2000), 1)
    rows = fetchall(
        db,
        """SELECT id, job_id, file_name, file_path, extension, size_bytes, minio_uri,
                  metadata, encyclopedia_artifact_id, created_at
           FROM job_artifacts
           WHERE job_id=:jid
             AND coalesce(metadata->>'mime_scan_version','') <> :ver
           ORDER BY
             CASE WHEN lower(coalesce(extension,'')) IN ('', '.dat', '.bin', '.tmp', '.cache', '.blob') THEN 0 ELSE 1 END,
             id
           LIMIT :lim""",
        {"jid": job_id, "ver": MIME_SCAN_VERSION, "lim": limit},
    )
    scanned = 0
    byte_sniffed = 0
    recognized = 0
    unknown = 0
    errors = 0

    for raw in rows:
        row = dict(raw)
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        base = resolve_artifact_type({**row, "metadata": meta})
        head = b""
        if _needs_byte_sniff(base):
            head = _read_head(db, job_id, row)
            byte_sniffed += 1
        resolved = resolve_artifact_type({**row, "metadata": meta}, data=head or None)
        status = "unrecognized" if resolved.content_type == FORENSIC_DATA_MIME else "resolved"
        if status == "resolved":
            recognized += 1
        else:
            unknown += 1
        patch = {
            "mime_scan_version": MIME_SCAN_VERSION,
            "mime_scan_status": status,
            "resolved_content_type": resolved.content_type,
            "content_type": resolved.content_type,
            "content_type_label": resolved.label,
            "type_label": resolved.label,
            "detected_extension": resolved.extension,
            "detected_kind": resolved.kind,
            "type_source": resolved.source,
            "type_confidence": resolved.confidence,
            "normalized_filename": resolved.normalized_filename,
            "mime_byte_sniffed": bool(head),
        }
        try:
            execute(
                db,
                """UPDATE job_artifacts
                   SET metadata=coalesce(metadata, '{}'::jsonb) || CAST(:patch AS jsonb)
                   WHERE id=:id AND job_id=:jid""",
                {"patch": json.dumps(patch), "id": str(row["id"]), "jid": job_id},
            )
            scanned += 1
        except Exception as exc:
            errors += 1
            log.debug("MIME metadata update failed artifact=%s: %s", row.get("id"), exc)

    db.commit()
    progress = mime_inventory_progress(db, job_id)
    return {
        **progress,
        "batch_rows": len(rows),
        "scanned": scanned,
        "byte_sniffed": byte_sniffed,
        "recognized_batch": recognized,
        "unknown_batch": unknown,
        "errors": errors,
    }


def ensure_artifact_mime_inventory(db, job_id: str, *, schema_name: str) -> dict[str, Any]:
    progress = mime_inventory_progress(db, job_id)
    if progress["done"] or progress["total"] <= 0:
        return progress
    try:
        from app.services.job_locks import job_lock_held

        if job_lock_held("mime_inventory", job_id):
            return {**progress, "queued": True}
    except Exception:
        pass
    try:
        from app.forensic_common.pipeline_routing import followup_queue
        from app.tasks import artifact_mime_inventory_task

        artifact_mime_inventory_task.apply_async(
            args=(schema_name, job_id),
            queue=followup_queue(),
            countdown=1,
        )
        return {**progress, "queued": True}
    except Exception as exc:
        log.warning("Could not queue MIME inventory job=%s: %s", job_id, exc)
        return {**progress, "queued": False, "queue_error": str(exc)[:300]}
