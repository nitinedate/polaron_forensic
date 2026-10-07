"""Materialize job_artifacts from extracted disk index + encyclopedia path matching."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import PurePosixPath

from sqlalchemy import text

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.deleted_evidence import detect_deleted_path_hint
from app.services.disk_build_log import write_disk_log
from app.services.encyclopedia_match import (
    ensure_extended_encyclopedia,
    load_encyclopedia_cache,
    match_encyclopedia_id,
)

_BATCH_SIZE = 2000
_PROGRESS_EVERY = 20000
log = logging.getLogger("artifact_materialize")


def _publish_materialize_progress(db, job_id, *, completed, total, label, activity, status_sql):
    """Record visible registration progress and extend the stage deadline.

    The UI counter lives on the job progress document. progressAgent only treats
    pipeline_stage_runs.progress_at as useful work, and it cancels a running
    stage once operation_deadline passes. Updating both keeps a long
    registration from being killed and started over.
    """
    from app.services.forensic_serial_stages import report_progress
    from app.services.pipeline_progress import write_merged_pipeline_progress

    write_merged_pipeline_progress(
        db,
        job_id,
        {
            "phase": "materialize",
            "completed": completed,
            "total": total,
            "label": label,
            "materialize_activity": activity,
        },
        writer="materialize",
        status_sql=status_sql,
    )
    report_progress(db, job_id, "materialize", total=total, completed=completed, label=label)


def _load_index(manifest: dict) -> list[dict]:
    from app.services.disk_manifest import load_index_entries

    shard_indexes = manifest.get("shard_indexes") or {}
    if shard_indexes:
        return load_index_entries({"shard_indexes": shard_indexes})
    return load_index_entries(manifest)


def _load_encyclopedia_cache(db) -> list[dict]:
    ensure_extended_encyclopedia(db)
    return load_encyclopedia_cache(db)


def _match_encyclopedia_id(path: str, enc_cache: list[dict]) -> str | None:
    return match_encyclopedia_id(path, enc_cache)


def materialize_index_entries(
    db,
    job_id: str,
    entries: list[dict],
    *,
    update_status: bool = True,
    phase1_filter: bool | None = None,
) -> dict:
    if not entries:
        return {"status": "ok", "artifacts_total": 0, "encyclopedia_matched": 0}

    from app.config import get_settings
    from app.services.phase1_artifact_scope import should_materialize_path

    if phase1_filter is None:
        phase1_filter = bool(get_settings().phase1_artifact_filter)

    total_entries = len(entries)
    inspected = 0
    last_progress = 0
    if update_status:
        _publish_materialize_progress(
            db,
            job_id,
            completed=0,
            total=total_entries,
            label=f"Registering artifacts from extracted evidence — 0 / {total_entries:,}",
            activity={
                "entries_inspected": 0,
                "entries_total": total_entries,
                "artifacts_registered": 0,
                "skipped_noise": 0,
            },
            status_sql="status='indexing'",
        )

    enc_cache = _load_encyclopedia_cache(db)
    created = 0
    matched = 0
    skipped_noise = 0
    batch: list[dict] = []

    insert_sql = text(
        """INSERT INTO job_artifacts (job_id, file_path, file_name, extension, size_bytes, sha256,
           encyclopedia_artifact_id, parse_status, metadata)
           VALUES (:job_id, :path, :name, :ext, :size, :sha, :enc, 'pending', CAST(:meta AS jsonb))
           ON CONFLICT (job_id, file_path) DO UPDATE SET
             encyclopedia_artifact_id=EXCLUDED.encyclopedia_artifact_id,
             metadata = CASE
               WHEN EXCLUDED.metadata IS NOT NULL AND EXCLUDED.metadata <> '{}'::jsonb
                 THEN coalesce(job_artifacts.metadata, '{}'::jsonb) || EXCLUDED.metadata
               ELSE job_artifacts.metadata
             END,
             updated_at=NOW()"""
    )
    deleted_tagged = 0

    for e in entries:
        inspected += 1
        path = e.get("path", "")
        if not path:
            continue
        include, skip_reason = should_materialize_path(path, enabled=phase1_filter)
        if not include:
            skipped_noise += 1
            if update_status and inspected - last_progress >= _PROGRESS_EVERY:
                _publish_materialize_progress(
                    db,
                    job_id,
                    completed=inspected,
                    total=total_entries,
                    label=(
                        f"Registering artifacts from extracted evidence — "
                        f"{inspected:,} / {total_entries:,} index records inspected"
                    ),
                    activity={
                        "entries_inspected": inspected,
                        "entries_total": total_entries,
                        "artifacts_registered": created,
                        "skipped_noise": skipped_noise,
                    },
                    status_sql="status='indexing'",
                )
                last_progress = inspected
            continue
        ext = PurePosixPath(path.replace("\\", "/")).suffix.lower()
        enc_id = _match_encyclopedia_id(path, enc_cache)
        if enc_id:
            matched += 1
        del_meta = detect_deleted_path_hint(path)
        # Preserve deleted flags from disk walk when present.
        if e.get("is_deleted") or e.get("unallocated"):
            del_meta = {
                **(del_meta or {}),
                "is_deleted": True,
                "recovery_state": (del_meta or {}).get("recovery_state")
                or ("unallocated" if e.get("unallocated") else "mft_deleted"),
            }
            if e.get("deleted_at"):
                del_meta["deleted_at"] = e.get("deleted_at")
        if del_meta:
            deleted_tagged += 1
        batch.append({
            "job_id": job_id,
            "path": path,
            "name": PurePosixPath(path.replace("\\", "/")).name,
            "ext": ext,
            "size": int(e.get("size_bytes") or 0),
            "sha": e.get("sha256") or "",
            "enc": enc_id,
            "meta": json.dumps(del_meta or {}),
        })
        created += 1
        if len(batch) >= _BATCH_SIZE:
            db.execute(insert_sql, batch)
            db.flush()
            batch.clear()

        if update_status and (inspected - last_progress >= _PROGRESS_EVERY or inspected >= total_entries):
            _publish_materialize_progress(
                db,
                job_id,
                completed=inspected,
                total=total_entries,
                label=(
                    f"Registering artifacts from extracted evidence — "
                    f"{inspected:,} / {total_entries:,} index records inspected"
                ),
                activity={
                    "entries_inspected": inspected,
                    "entries_total": total_entries,
                    "artifacts_registered": created,
                    "skipped_noise": skipped_noise,
                },
                status_sql="status='indexing'",
            )
            last_progress = inspected

    if batch:
        db.execute(insert_sql, batch)
        db.flush()

    if update_status:
        _publish_materialize_progress(
            db,
            job_id,
            completed=total_entries,
            total=total_entries,
            label=f"Artifact registration complete — {created:,} forensic artifacts registered",
            activity={
                "entries_inspected": total_entries,
                "entries_total": total_entries,
                "artifacts_registered": created,
                "skipped_noise": skipped_noise,
            },
            status_sql="status='artifacts_registered'",
        )
        noise_note = f", filtered {skipped_noise:,} non-evidence paths" if skipped_noise else ""
        deleted_note = f", tagged {deleted_tagged:,} deleted/trash paths" if deleted_tagged else ""
        write_disk_log(
            db,
            job_id,
            f"Materialized {created:,} job artifacts ({matched:,} matched to encyclopedia){noise_note}{deleted_note}",
            stage="materialize",
            metadata={
                "total": created,
                "matched": matched,
                "skipped_noise": skipped_noise,
                "deleted_tagged": deleted_tagged,
                "phase1_filter": phase1_filter,
            },
        )
        db.commit()
    result = {
        "status": "ok",
        "artifacts_total": created,
        "encyclopedia_matched": matched,
        "skipped_noise": skipped_noise,
        "phase1_filter": phase1_filter,
    }
    try:
        from app.services.evidence_browse_indexes import ensure_evidence_browse_indexes

        ensure_evidence_browse_indexes(db)
    except Exception:
        log.exception("browse index ensure failed job=%s", job_id)
    return result


def _entries_from_manifest(manifest: dict) -> list[dict]:
    from app.services.critical_forensic_paths import filter_critical_entries, is_critical_forensic_path

    entries = _load_index(manifest)
    if not entries:
        return []
    by_path: dict[str, dict] = {}
    for e in entries:
        path = (e.get("path") or "").replace("\\", "/")
        if not path:
            continue
        prev = by_path.get(path)
        if prev is None or (e.get("sha256") and not prev.get("sha256")):
            by_path[path] = e
    entries = list(by_path.values())

    parts_map = manifest.get("parts_map") or {}
    if parts_map:
        valid_parts = {int(k) for k in parts_map.keys()}
        entries = [e for e in entries if int(e.get("part_id", -1)) in valid_parts]

    critical = filter_critical_entries(entries)
    hashed = [e for e in entries if e.get("sha256")]
    if hashed:
        hashed_paths = {(e.get("path") or "").replace("\\", "/") for e in hashed}
        for c in critical:
            cp = (c.get("path") or "").replace("\\", "/")
            if cp and cp not in hashed_paths:
                hashed.append(c)
        return hashed

    # Never truncate the manifest — critical hives must survive materialize.
    return entries


def materialize_missing_critical_from_disk(db, job_id: str) -> dict:
    """Legacy repair fallback for critical files absent from the extracted manifest.

    Under the extract-then-process contract a finalized extracted image is the
    only evidence source for all downstream agents. Reopening the E01/raw image
    here would be a second extraction pass and makes both timing and provenance
    ambiguous, so the fallback is disabled after the extraction barrier.
    """
    from app.config import get_settings
    from app.services.forensic_serial_policy import serial_enabled
    from app.services.critical_forensic_paths import CRITICAL_CONFIG_HIVE_PATHS
    from app.services.disk_manifest import build_index_map
    from app.services.storage import put_bytes
    from app.services.virtual_disk import open_virtual_disk, read_full_file_from_disk

    row = fetchone(
        db,
        "SELECT disk_source, extracted_disk_uri FROM jobs WHERE id=:id",
        {"id": job_id},
    )
    if not row or not row.get("disk_source"):
        return {"status": "failed", "error": "No disk manifest", "fetched": 0}
    if (serial_enabled() or bool(getattr(get_settings(), "extract_then_process", True))) and row.get("extracted_disk_uri"):
        log.warning(
            "Post-extract source reread blocked job=%s; critical-file repair must use extracted evidence",
            job_id,
        )
        return {
            "status": "ok",
            "fetched": 0,
            "skipped": True,
            "reason": "extract_then_process: source image reread disabled after extraction",
        }

    manifest = row["disk_source"]
    if isinstance(manifest, str):
        manifest = json.loads(manifest)

    index_map = build_index_map(manifest or {})
    enc_cache = _load_encyclopedia_cache(db)
    fetched: list[dict] = []
    errors: list[dict] = []

    try:
        vd = open_virtual_disk(db, job_id)
    except Exception as exc:
        return {"status": "failed", "error": f"Cannot open virtual disk: {exc}", "fetched": 0}

    insert_sql = text(
        """INSERT INTO job_artifacts (job_id, file_path, file_name, extension, size_bytes, sha256,
           encyclopedia_artifact_id, parse_status, minio_uri)
           VALUES (:job_id, :path, :name, :ext, :size, :sha, :enc, 'pending', :minio)
           ON CONFLICT (job_id, file_path) DO UPDATE SET
             size_bytes=EXCLUDED.size_bytes,
             sha256=EXCLUDED.sha256,
             minio_uri=COALESCE(EXCLUDED.minio_uri, job_artifacts.minio_uri),
             parse_status='pending',
             updated_at=NOW()"""
    )

    for path in CRITICAL_CONFIG_HIVE_PATHS:
        norm = path.replace("\\", "/")
        if index_map.get(norm):
            continue

        existing = fetchone(
            db,
            """SELECT id, minio_uri FROM job_artifacts
               WHERE job_id=:jid AND lower(replace(file_path, '\\', '/')) = lower(:p)
               LIMIT 1""",
            {"jid": job_id, "p": norm},
        )
        if existing and existing.get("minio_uri"):
            continue

        try:
            data = read_full_file_from_disk(vd, norm)
        except Exception as exc:
            errors.append({"path": norm, "error": str(exc)})
            log.warning("Critical hive read failed job=%s path=%s: %s", job_id, norm, exc)
            continue
        if not data:
            errors.append({"path": norm, "error": "empty file"})
            continue

        sha = hashlib.sha256(data).hexdigest()
        hive_name = PurePosixPath(norm).name
        key = f"jobs/{job_id}/critical-hives/{hive_name}"
        minio_uri = put_bytes(key, data, content_type="application/octet-stream")
        ext = PurePosixPath(norm).suffix.lower()
        enc_id = _match_encyclopedia_id(norm, enc_cache)
        db.execute(
            insert_sql,
            {
                "job_id": job_id,
                "path": norm,
                "name": hive_name,
                "ext": ext,
                "size": len(data),
                "sha": sha,
                "enc": enc_id,
                "minio": minio_uri,
            },
        )
        fetched.append({"path": norm, "size_bytes": len(data), "minio_uri": minio_uri})
        log.info("Fetched critical hive from disk job=%s path=%s bytes=%s", job_id, norm, len(data))

    if fetched:
        critical_hives = dict(manifest.get("critical_hives") or {})
        for item in fetched:
            critical_hives[item["path"]] = item["minio_uri"]
        manifest["critical_hives"] = critical_hives
        execute(
            db,
            "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:id",
            {"id": job_id, "ds": json.dumps(manifest)},
        )
        write_disk_log(
            db,
            job_id,
            f"Fetched {len(fetched)} critical hive(s) from disk (not in tar index): "
            + ", ".join(item["path"] for item in fetched),
            stage="materialize",
            metadata={"fetched": fetched},
        )

    db.flush()
    return {
        "status": "ok",
        "fetched": len(fetched),
        "paths": [item["path"] for item in fetched],
        "errors": errors,
    }


def materialize_critical_forensic_paths(db, job_id: str) -> dict:
    """Upsert critical registry hives, profile hives, and key EVTX from the disk index."""
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    if not row or not row.get("disk_source"):
        return {"status": "failed", "error": "No disk manifest"}
    manifest = row["disk_source"]
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    entries = _entries_from_manifest(manifest)
    from app.services.critical_forensic_paths import filter_critical_entries

    critical = filter_critical_entries(entries)
    if not critical:
        return {"status": "ok", "artifacts_total": 0, "added": 0, "critical_total": 0}
    before = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:id", {"id": job_id})
    result = materialize_index_entries(db, job_id, critical, update_status=False)
    after = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:id", {"id": job_id})
    result["before"] = int(before["c"]) if before else 0
    result["after"] = int(after["c"]) if after else 0
    result["added"] = max(0, result["after"] - result["before"])
    result["critical_total"] = len(critical)
    result["critical_paths"] = sorted({(e.get("path") or "") for e in critical})
    return result


def rematerialize_critical_account_paths(db, job_id: str) -> dict:
    """Backward-compatible alias — upsert SAM/SOFTWARE/SYSTEM/SECURITY/NTUSER/EVTX."""
    return materialize_critical_forensic_paths(db, job_id)


def rematerialize_missing_from_index(db, job_id: str, *, update_status: bool = False) -> dict:
    """Upsert any index paths not yet in job_artifacts (fixes streamed-pipeline gaps)."""
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    if not row or not row.get("disk_source"):
        return {"status": "failed", "error": "No disk manifest"}
    manifest = row["disk_source"]
    if isinstance(manifest, str):
        manifest = json.loads(manifest)
    entries = _entries_from_manifest(manifest)
    if not entries:
        return {"status": "failed", "error": "Empty disk index"}
    before = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:id", {"id": job_id})
    result = materialize_index_entries(db, job_id, entries, update_status=update_status)
    after = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:id", {"id": job_id})
    result["before"] = int(before["c"]) if before else 0
    result["after"] = int(after["c"]) if after else 0
    result["added"] = max(0, result["after"] - result["before"])
    return result


def materialize_job_artifacts(db, job_id: str, *, schema_name: str) -> dict:
    existing = fetchone(db, "SELECT count(*) c FROM job_artifacts WHERE job_id=:id", {"id": job_id})
    # Always upsert from full index so streamed Phase 3 gaps (SAM/NTUSER/evtx) get filled.
    if existing and int(existing["c"]) > 0:
        filled = rematerialize_missing_from_index(db, job_id, update_status=True)
        total = int(filled.get("after") or existing["c"])
        return {
            "status": "ok",
            "artifacts_total": total,
            "encyclopedia_matched": int(filled.get("encyclopedia_matched") or 0),
            "skipped": filled.get("added", 0) == 0,
            "rematerialized_added": int(filled.get("added") or 0),
        }

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    if not row or not row.get("disk_source"):
        return {"status": "failed", "error": "No disk manifest"}
    manifest = row["disk_source"]
    if isinstance(manifest, str):
        manifest = json.loads(manifest)

    entries = _entries_from_manifest(manifest)
    if not entries:
        return {"status": "failed", "error": "Empty disk index"}

    return materialize_index_entries(db, job_id, entries, update_status=True)
