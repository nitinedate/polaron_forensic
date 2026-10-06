"""Repair critical hives (SOFTWARE/SYSTEM/SAM) → parse → RAG synthetic OS/user chunks."""

from __future__ import annotations

import logging
from typing import Any

from app.db.sql_helpers import fetchall, fetchone
from app.services.artifact_materialize import (
    materialize_critical_forensic_paths,
    materialize_missing_critical_from_disk,
)
from app.services.critical_forensic_paths import CRITICAL_PATH_SQL, missing_critical_hive_names

log = logging.getLogger("critical_forensic_pipeline")


def _software_os_parsed(db, job_id: str) -> bool:
    row = fetchone(
        db,
        """SELECT 1 AS ok FROM artifact_parse_results apr
           JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
           WHERE ja.job_id=:jid
             AND ja.file_path ILIKE '%/config/SOFTWARE'
             AND EXISTS (
               SELECT 1 FROM jsonb_array_elements(
                 CASE WHEN jsonb_typeof(apr.normalized) = 'array' THEN apr.normalized ELSE '[]'::jsonb END
               ) e
               WHERE e->>'record_type' = 'windows_os'
             )
           LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)


def ensure_critical_forensic_pipeline(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    refresh_hives: bool = True,
) -> dict[str, Any]:
    """Materialize missing hives from disk index, parse, and refresh synthetic RAG chunks."""
    from app.services.artifact_materialize import _entries_from_manifest
    from app.services.artifact_parse import parse_job_artifacts_for_paths
    from app.services.disk_manifest import build_index_map
    from app.services.forensic_profile_index import ensure_os_fact_chunks, ensure_profile_fact_chunks

    result: dict[str, Any] = {"materialize": {}, "parse": {}, "os_chunks": 0, "profile_chunks": 0}

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
    manifest = row.get("disk_source") if row else {}
    if isinstance(manifest, str):
        import json
        try:
            manifest = json.loads(manifest)
        except Exception:
            manifest = {}

    entries = _entries_from_manifest(manifest or {})
    missing = missing_critical_hive_names(entries)
    result["missing_in_index"] = missing

    result["materialize"] = materialize_critical_forensic_paths(db, job_id)
    result["disk_fetch"] = materialize_missing_critical_from_disk(db, job_id)

    if refresh_hives or missing or not _software_os_parsed(db, job_id):
        row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:id", {"id": job_id})
        manifest = row.get("disk_source") if row else {}
        if isinstance(manifest, str):
            import json
            try:
                manifest = json.loads(manifest)
            except Exception:
                manifest = {}
        paths = [
            r["file_path"]
            for r in fetchall(
                db,
                f"""SELECT file_path FROM job_artifacts
                    WHERE job_id=:jid AND ({CRITICAL_PATH_SQL})""",
                {"jid": job_id},
            )
        ]
        if paths:
            index_map = build_index_map(manifest or {})
            from app.db.sql_helpers import execute

            execute(
                db,
                f"""UPDATE job_artifacts SET parse_status='pending', updated_at=NOW()
                    WHERE job_id=:jid AND ({CRITICAL_PATH_SQL})""",
                {"jid": job_id},
            )
            execute(
                db,
                f"""DELETE FROM artifact_parse_results
                    WHERE job_artifact_id IN (
                      SELECT id FROM job_artifacts WHERE job_id=:jid AND ({CRITICAL_PATH_SQL})
                    )""",
                {"jid": job_id},
            )
            db.flush()
            result["parse"] = parse_job_artifacts_for_paths(
                db, job_id, paths=paths, index_map=index_map, update_status=False,
            )

    try:
        result["profile_chunks"] = ensure_profile_fact_chunks(db, job_id, refresh_critical=False)
        result["os_chunks"] = ensure_os_fact_chunks(db, job_id, refresh_hives=False)
        db.flush()
    except Exception as exc:
        log.warning("Synthetic chunk refresh failed job=%s: %s", job_id, exc)
        result["chunk_error"] = str(exc)

    result["software_os_parsed"] = _software_os_parsed(db, job_id)
    return result
