"""Cooperative stop/resume and extraction checkpoint helpers."""

from __future__ import annotations

import json
from typing import Any

from app.db.sql_helpers import execute, fetchone


class JobStopRequested(Exception):
    """Raised when a worker observes stop_requested on the job."""


class PipelineStopRequested(JobStopRequested):
    """Raised when pipeline stop is requested during indexing/RAG."""


class ThermalAbortRequested(PipelineStopRequested):
    """Raised when GPU temperature exceeds safe abort threshold."""


def pipeline_should_stop(db, job_id: str) -> bool:
    if is_stop_requested(db, job_id):
        return True
    row = fetchone(db, "SELECT status FROM jobs WHERE id=:id", {"id": job_id})
    return bool(row and row.get("status") == "paused")


def is_stop_requested(db, job_id: str) -> bool:
    """Read stop_requested on a short-lived autocommit connection.

    Using the caller's session here left an AccessShareLock on ``jobs`` while
    extract did minutes of file I/O. ALTER/ensure-schema then queued behind
    that lock, and every dashboard / progress SELECT piled up behind the ALTER.
    """
    schema = None
    try:
        schema = (getattr(db, "info", None) or {}).get("firm_schema")
    except Exception:
        schema = None
    if schema:
        from app.db.session import firm_session_readonly

        try:
            with firm_session_readonly(schema) as ro:
                row = fetchone(ro, "SELECT stop_requested FROM jobs WHERE id=:id", {"id": job_id})
            return bool(row and row.get("stop_requested"))
        except Exception:
            pass
    row = fetchone(db, "SELECT stop_requested FROM jobs WHERE id=:id", {"id": job_id})
    return bool(row and row.get("stop_requested"))


def request_job_stop(db, job_id: str) -> dict:
    row = fetchone(
        db,
        "SELECT status, stop_requested, celery_task_id FROM jobs WHERE id=:id",
        {"id": job_id},
    )
    if not row:
        return {"ok": False, "message": "Job not found"}
    status = row["status"]
    stoppable = (
        "processing",
        "building_disk",
        "indexing",
        "extracted",
        "extracting",
        "disk_ready",
        "parsed",
        "artifacts_registered",
        "report_generating",
        "ready",
        "indexed",
        "report_ready",
    )
    if status not in stoppable:
        return {"ok": False, "message": f"Job is not running (status={status})"}
    if row.get("stop_requested"):
        return {"ok": True, "message": "Stop already requested — worker will halt at next checkpoint"}
    if status in ("indexing", "extracted", "extracting", "disk_ready", "parsed", "artifacts_registered", "report_generating"):
        mark_job_paused(
            db,
            job_id,
            message="Pipeline stopped by user — resume when ready",
        )
        _revoke_celery_task(row.get("celery_task_id"))
        return {"ok": True, "message": "Pipeline stopped — work halted at last checkpoint (resumable)"}
    execute(
        db,
        "UPDATE jobs SET stop_requested=TRUE, updated_at=NOW() WHERE id=:id",
        {"id": job_id},
    )
    return {"ok": True, "message": "Stop requested — extraction will halt after the current file"}


def _revoke_celery_task(task_id: str | None) -> None:
    if not task_id:
        return
    try:
        from app.celery_app import celery

        celery.control.revoke(task_id, terminate=True, signal="SIGTERM")
    except Exception:
        pass


def pipeline_is_stale(row: dict | None, *, threshold_sec: float = 180.0) -> bool:
    """True when an indexing/enrichment job has not updated recently."""
    if not row:
        return False
    if row.get("status") not in ("indexing", "indexed", "extracted", "parsed", "artifacts_registered"):
        return False
    updated = row.get("updated_at")
    if not updated:
        return True
    from datetime import datetime, timezone

    if getattr(updated, "tzinfo", None) is None:
        updated = updated.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    return age > threshold_sec


def clear_stop_request(db, job_id: str) -> None:
    execute(
        db,
        "UPDATE jobs SET stop_requested=FALSE, updated_at=NOW() WHERE id=:id",
        {"id": job_id},
    )


def load_extraction_checkpoint(db, job_id: str) -> dict | None:
    row = fetchone(db, "SELECT extraction_checkpoint FROM jobs WHERE id=:id", {"id": job_id})
    cp = row.get("extraction_checkpoint") if row else None
    if isinstance(cp, str):
        cp = json.loads(cp)
    return cp if isinstance(cp, dict) else None


def save_extraction_checkpoint(db, job_id: str, checkpoint: dict) -> None:
    """Persist extract progress. Retries on a fresh firm session if the pooled
    connection was killed (idle-in-transaction / server restart)."""
    params = {
        "cp": json.dumps(checkpoint),
        "fe": checkpoint.get("files_extracted", 0),
        "be": checkpoint.get("bytes_extracted", 0),
        "ft": checkpoint.get("nodes_total", 0),
        "pct": checkpoint.get("progress_pct", 0),
        "id": job_id,
    }
    sql = """UPDATE jobs SET extraction_checkpoint=CAST(:cp AS jsonb),
           files_extracted=:fe, bytes_extracted=:be, files_total=:ft,
           progress_pct=:pct, updated_at=NOW()
           WHERE id=:id"""
    try:
        execute(db, sql, params)
        return
    except Exception:
        schema = None
        try:
            schema = (getattr(db, "info", None) or {}).get("firm_schema")
        except Exception:
            schema = None
        try:
            db.rollback()
        except Exception:
            pass
        if not schema:
            raise
        from app.db.session import apply_firm_search_path, firm_session

        with firm_session(schema) as fresh:
            execute(fresh, sql, params)
            fresh.commit()
        try:
            apply_firm_search_path(db, schema)
        except Exception:
            pass


def mark_job_paused(db, job_id: str, *, message: str | None = None) -> None:
    execute(
        db,
        """UPDATE jobs SET status='paused', stop_requested=FALSE,
           error=:err, updated_at=NOW() WHERE id=:id""",
        {"err": message, "id": job_id},
    )


def extraction_is_stale(row: dict | None, *, threshold_sec: float = 240.0) -> bool:
    """True when a building_disk job has not updated recently (worker likely died).

    Threshold is 4 minutes — E01 enumerate/filter can be quiet for a while; heartbeats
    refresh updated_at so healthy jobs should not trip this.
    """
    if not row:
        return False
    if row.get("status") not in ("building_disk", "processing"):
        return False
    updated = row.get("updated_at")
    if not updated:
        return True
    from datetime import datetime, timezone

    if getattr(updated, "tzinfo", None) is None:
        updated = updated.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    if age <= threshold_sec:
        return False
    # V45.5: jobs.updated_at is a weak signal (only some steps write it). Before
    # declaring the worker dead, consult its Redis lease heartbeat, which the
    # worker refreshes from inside the process regardless of which step runs.
    try:
        from app.services.job_locks import cpu_heavy_lease_for_job

        lease = cpu_heavy_lease_for_job(str(row.get("id") or ""))
        if lease and float(lease.get("heartbeat_age_sec") or 0) <= 180.0:
            return False
    except Exception:
        pass
    return True


def extract_worker_liveness(row: dict | None) -> dict | None:
    """V45.5: {alive, heartbeat_age_sec, pid, since} for the UI/API, or None when no worker holds this job."""
    if not row or row.get("status") not in ("building_disk", "processing"):
        return None
    try:
        from app.services.job_locks import cpu_heavy_lease_for_job

        lease = cpu_heavy_lease_for_job(str(row.get("id") or ""))
    except Exception:
        return None
    if not lease:
        return {"alive": False}
    return {
        "alive": float(lease.get("heartbeat_age_sec") or 0) <= 180.0,
        "heartbeat_age_sec": lease.get("heartbeat_age_sec"),
        "pid": lease.get("pid"),
        "reason": lease.get("reason"),
    }


def set_celery_task_id(db, job_id: str, task_id: str | None) -> None:
    execute(
        db,
        "UPDATE jobs SET celery_task_id=:tid, updated_at=NOW() WHERE id=:id",
        {"tid": task_id, "id": job_id},
    )


def completed_shard_ids(checkpoint: dict | None) -> set[int]:
    if not checkpoint:
        return set()
    return {int(s["shard_id"]) for s in checkpoint.get("completed_shards", []) if "shard_id" in s}


def merge_checkpoint_shard(checkpoint: dict, shard_result: dict, *, strip_index: bool = True) -> dict:
    """Append a finished shard to the checkpoint."""
    shards = list(checkpoint.get("completed_shards") or [])
    shard_id = int(shard_result["shard_id"])
    shards = [s for s in shards if int(s.get("shard_id", -1)) != shard_id]
    entry = {
        "shard_id": shard_id,
        "part_key": shard_result.get("part_key"),
        "part_uri": shard_result.get("part_uri"),
        "files_extracted": shard_result.get("files_extracted", 0),
        "bytes_extracted": shard_result.get("bytes_extracted", 0),
        "files_skipped": shard_result.get("files_skipped", 0),
    }
    index_uri = shard_result.get("index_uri")
    if index_uri:
        entry["index_uri"] = index_uri
        shard_indexes = dict(checkpoint.get("shard_indexes") or {})
        shard_indexes[str(shard_id)] = index_uri
        checkpoint["shard_indexes"] = shard_indexes
    elif not strip_index:
        entry["index_entries"] = shard_result.get("index_entries") or []
    shards.append(entry)
    if shard_result.get("part_uri"):
        parts_map = dict(checkpoint.get("parts_map") or {})
        parts_map[str(shard_id)] = shard_result["part_uri"]
        checkpoint["parts_map"] = parts_map
    checkpoint["completed_shards"] = sorted(shards, key=lambda s: int(s["shard_id"]))
    checkpoint["files_extracted"] = sum(int(s.get("files_extracted") or 0) for s in shards)
    checkpoint["bytes_extracted"] = sum(int(s.get("bytes_extracted") or 0) for s in shards)
    checkpoint["files_skipped"] = int(checkpoint.get("files_skipped") or 0) + int(shard_result.get("files_skipped") or 0)
    return checkpoint


def checkpoint_index_and_parts(checkpoint: dict | None) -> tuple[list[dict], list[str]]:
    if not checkpoint:
        return [], []
    index: list[dict] = []
    parts: list[str] = []
    parts_map = checkpoint.get("parts_map") or {}
    worker_count = int(checkpoint.get("worker_count") or 0)
    if parts_map and worker_count:
        parts = [parts_map.get(str(i)) or parts_map.get(i) for i in range(worker_count)]
        parts = [p for p in parts if p]
    for shard in checkpoint.get("completed_shards") or []:
        if shard.get("index_entries"):
            index.extend(shard.get("index_entries") or [])
        elif shard.get("index_uri"):
            from app.services.disk_manifest import load_index_entries

            index.extend(load_index_entries({"shard_indexes": {str(shard["shard_id"]): shard["index_uri"]}}))
        uri = shard.get("part_uri")
        if uri and not parts_map:
            parts.append(uri)
    if checkpoint.get("shard_indexes") and not index:
        from app.services.disk_manifest import load_index_entries

        index = load_index_entries({"shard_indexes": checkpoint["shard_indexes"]})
    return index, parts


def empty_checkpoint(
    *,
    worker_count: int,
    mode: str,
    filter_stats: dict,
    nodes_total: int,
    files_skipped: int = 0,
    shard_strategy: str = "path_range",
) -> dict[str, Any]:
    return {
        "version": 1,
        "phase": "extract",
        "worker_count": worker_count,
        "shard_strategy": shard_strategy,
        "extract_mode": mode,
        "filter_stats": filter_stats,
        "nodes_total": nodes_total,
        "completed_shards": [],
        "files_extracted": 0,
        "bytes_extracted": 0,
        "files_skipped": files_skipped,
        "progress_pct": 5,
    }
