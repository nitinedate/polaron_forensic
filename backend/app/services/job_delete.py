"""Hard-delete a forensic job and every related file / object / row."""

from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import text

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("job_delete")

# Child tables that can block DELETE FROM jobs when CASCADE is missing.
# Order matters: dependents first. Missing tables are ignored.
_KNOWN_CHILD_DELETES = (
    """DELETE FROM agent_tool_calls tc
       USING agent_runs r
       WHERE tc.run_id = r.id AND r.job_id = CAST(:id AS uuid)""",
    "DELETE FROM agent_runs WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM agent_threads WHERE job_id = CAST(:id AS uuid)",
    """DELETE FROM report_exports e
       USING report_runs rr
       WHERE e.report_run_id = rr.id AND rr.job_id = CAST(:id AS uuid)""",
    "DELETE FROM rag_retrieval_log WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM parser_runs WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM disk_build_logs WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM pipeline_heal_events WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM rag_chunks WHERE job_id = CAST(:id AS uuid)",
    """DELETE FROM artifact_parse_results apr
       USING job_artifacts ja
       WHERE apr.job_artifact_id = ja.id AND ja.job_id = CAST(:id AS uuid)""",
    """DELETE FROM ocr_results ocr
       USING job_artifacts ja
       WHERE ocr.job_artifact_id = ja.id AND ja.job_id = CAST(:id AS uuid)""",
    "DELETE FROM job_artifacts WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM evidence_files WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM graph_sync_state WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM artifact_scope WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM selected_job_artifacts WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM selected_job_objectives_procedure WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM case_intake WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM timeline_events WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM report_sections WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM report_runs WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM job_axiom_artifact_results WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM job_objective_observations WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM job_count_reconciliation WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM job_artifact_groups WHERE job_id = CAST(:id AS uuid)",
    "DELETE FROM objective_procedure_scope WHERE job_id = CAST(:id AS uuid)",
    "UPDATE cases SET job_id = NULL WHERE job_id = CAST(:id AS uuid)",
)


def _try_execute(db, sql: str, params: dict[str, Any]) -> int:
    trans = db.begin_nested()
    try:
        result = execute(db, sql, params)
        trans.commit()
        return int(getattr(result, "rowcount", 0) or 0)
    except Exception:
        trans.rollback()
        return 0


def _child_tables_with_job_id(db) -> list[str]:
    rows = fetchall(
        db,
        """
        SELECT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema AND t.table_name = c.table_name
        WHERE c.table_schema = current_schema()
          AND c.column_name = 'job_id'
          AND t.table_type = 'BASE TABLE'
          AND c.table_name <> 'jobs'
        ORDER BY c.table_name
        """,
        {},
    )
    return [str(r["table_name"]) for r in rows]


def _purge_local_path(path: Path) -> bool:
    try:
        if path.is_file() or path.is_symlink():
            path.unlink(missing_ok=True)
            return True
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            return True
    except Exception as exc:
        log.warning("could not delete %s: %s", path, exc)
    return False


def _uri_to_local_path(uri: str | None) -> Path | None:
    text = (uri or "").strip()
    if not text:
        return None
    if text.startswith("file:"):
        parsed = urlparse(text)
        raw = parsed.path
        if parsed.netloc and parsed.netloc != "localhost":
            raw = f"//{parsed.netloc}{parsed.path}"
        return Path(raw)
    if text.startswith("/") or (len(text) > 2 and text[1] == ":"):
        return Path(text)
    return None


def _normalize_path_key(path: Path | str) -> str:
    try:
        resolved = Path(path).resolve()
    except Exception:
        resolved = Path(str(path))
    return str(resolved).replace("/", "\\").lower().rstrip("\\")


def _path_aliases(path: Path) -> list[Path]:
    """Windows host paths and Docker /host mounts that refer to the same folder."""
    raw = str(path).strip()
    aliases = [Path(raw)]
    win = re.match(r"^([A-Za-z]):[\\/]+(.*)$", raw)
    if win:
        letter = win.group(1).lower()
        rest = win.group(2).replace("\\", "/").strip("/")
        aliases.append(Path(f"/host/{letter}/{rest}"))
        aliases.append(Path(f"/mnt/host/{letter}/{rest}"))
    dock = re.match(r"^/(?:host|mnt/host)/([A-Za-z])/(.*)$", raw.replace("\\", "/"))
    if dock:
        letter = dock.group(1).upper()
        rest = dock.group(2).replace("/", "\\").strip("\\")
        aliases.append(Path(f"{letter}:\\{rest}"))
    return aliases


def _is_protected_evidence_path(path: Path, protected: set[str]) -> bool:
    """True when ``path`` is (or lives under) an examiner source folder.

    Job delete must remove pipeline staging / MinIO copies, never the original
    mobile/disk image folder the examiner selected on the host.
    """
    if not protected:
        return False
    for alias in _path_aliases(path):
        key = _normalize_path_key(alias)
        if not key:
            continue
        for src in protected:
            if not src:
                continue
            if key == src or key.startswith(src + "\\") or src.startswith(key + "\\"):
                return True
    return False


def _collect_protected_evidence_paths(row: dict[str, Any] | None) -> set[str]:
    protected: set[str] = set()
    if not row:
        return protected
    disk_source = row.get("disk_source")
    if not isinstance(disk_source, dict):
        return protected
    for key in (
        "evidence_folder",
        "last_host_path",
        "host_path",
        "path",
        "source_path",
        "source_folder",
        "image_folder",
        "selected_folder",
    ):
        local = _uri_to_local_path(str(disk_source.get(key) or ""))
        if local is None:
            continue
        for alias in _path_aliases(local):
            protected.add(_normalize_path_key(alias))
    return protected


def _purge_job_files(job_id: str, row: dict[str, Any] | None) -> dict[str, Any]:
    settings = get_settings()
    root = Path(settings.data_root)
    removed: list[str] = []
    skipped_protected: list[str] = []
    protected = _collect_protected_evidence_paths(row)
    candidates = [
        root / "uploads" / job_id,
        root / "jobs" / job_id,
        root / "extracted" / job_id,
        root / "artifacts" / job_id,
    ]
    if row:
        for key in ("extracted_disk_uri",):
            local = _uri_to_local_path(str(row.get(key) or ""))
            if local:
                candidates.append(local)
        disk_source = row.get("disk_source")
        if isinstance(disk_source, dict):
            # Staging/work copies only — never evidence_folder / host image roots.
            for key in ("extracted_path", "work_dir", "output_dir", "local_path", "staging_container_path"):
                local = _uri_to_local_path(str(disk_source.get(key) or ""))
                if local:
                    candidates.append(local)
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if _is_protected_evidence_path(path, protected):
            skipped_protected.append(key)
            log.info("job delete preserving examiner evidence source: %s", key)
            continue
        if _purge_local_path(path):
            removed.append(key)

    object_count = 0
    try:
        from app.services.storage import delete_prefix

        # Job-scoped pipeline objects only. Host-selected mobile/disk images are
        # never stored under these prefixes as the sole original.
        for prefix in (f"jobs/{job_id}/", f"client-uploads/{job_id}/"):
            object_count += int(delete_prefix(prefix) or 0)
    except Exception as exc:
        log.warning("object storage cleanup failed for job %s: %s", job_id, exc)

    return {
        "local_paths": removed,
        "objects": object_count,
        "preserved_evidence_sources": skipped_protected,
    }


def _purge_celery_for_job(job_id: str, celery_task_id: str | None = None) -> int:
    """Revoke the stored task and any in-flight/queued tasks that mention this job."""
    from app.celery_app import celery
    from app.services.job_control import _revoke_celery_task

    _revoke_celery_task(celery_task_id)
    revoked = 1 if celery_task_id else 0
    try:
        inspector = celery.control.inspect(timeout=3)
        buckets = []
        for getter in (inspector.active, inspector.reserved, inspector.scheduled):
            try:
                found = getter() or {}
            except Exception:
                found = {}
            buckets.append(found)
        seen: set[str] = set()
        for bucket in buckets:
            for _worker, tasks in (bucket or {}).items():
                for task in tasks or []:
                    info = task.get("request") if isinstance(task.get("request"), dict) else task
                    tid = str(info.get("id") or task.get("id") or "")
                    blob = " ".join(
                        str(info.get(key) or task.get(key) or "")
                        for key in ("args", "kwargs", "name", "delivery_info")
                    )
                    if job_id not in blob and job_id not in tid:
                        continue
                    if not tid or tid in seen:
                        continue
                    seen.add(tid)
                    celery.control.revoke(tid, terminate=True, signal="SIGTERM")
                    revoked += 1
    except Exception as exc:
        log.warning("celery inspect/revoke failed for job %s: %s", job_id, exc)
    return revoked


def _purge_job_locks(job_id: str) -> None:
    for kind in ("parse", "ocr", "inventory", "rag", "extract", "phase3", "rag_enrich"):
        try:
            from app.services.job_locks import force_release_job_lock

            force_release_job_lock(kind, job_id)
        except Exception:
            pass


def _purge_neo4j_job(job_id: str) -> int:
    try:
        from app.services.neo4j_sync import _get_driver

        driver = _get_driver()
        if driver is None:
            return 0
        with driver.session() as session:
            result = session.run(
                """
                MATCH (n) WHERE n.job_id = $jid OR n.id = $jid
                WITH n DETACH DELETE n
                RETURN count(*) AS c
                """,
                jid=job_id,
            )
            rec = result.single()
            return int(rec["c"]) if rec and rec.get("c") is not None else 0
    except Exception as exc:
        log.warning("Neo4j cleanup failed for job %s: %s", job_id, exc)
        return 0


def hard_delete_job(db, job_id: str) -> dict[str, Any]:
    """Stop workers, erase files, then drop every row for this job id."""
    jid = (job_id or "").strip()
    if not jid:
        raise ValueError("job_id is required")
    row = fetchone(db, "SELECT * FROM jobs WHERE id = CAST(:id AS uuid)", {"id": jid})
    if not row:
        raise KeyError(jid)

    try:
        from app.services.job_control import request_job_stop

        request_job_stop(db, jid)
        db.commit()
    except Exception as exc:
        log.warning("stop before delete failed for job %s: %s", jid, exc)
        try:
            db.rollback()
        except Exception:
            pass

    revoked = 0
    try:
        revoked = _purge_celery_for_job(jid, row.get("celery_task_id"))
    except Exception as exc:
        log.warning("celery revoke failed for job %s: %s", jid, exc)
    _purge_job_locks(jid)
    graph_nodes = _purge_neo4j_job(jid)

    files = _purge_job_files(jid, dict(row))

    params = {"id": jid}
    tables = 0
    for sql in _KNOWN_CHILD_DELETES:
        if _try_execute(db, sql, params):
            tables += 1
    for name in _child_tables_with_job_id(db):
        if _try_execute(db, f'DELETE FROM "{name}" WHERE job_id = CAST(:id AS uuid)', params):
            tables += 1

    deleted = db.execute(text("DELETE FROM jobs WHERE id = CAST(:id AS uuid)"), params)
    if int(getattr(deleted, "rowcount", 0) or 0) < 1:
        raise KeyError(jid)
    db.commit()
    return {
        "ok": True,
        "deleted": True,
        "job_id": jid,
        "hard": True,
        "files": files,
        "child_cleanup": tables,
        "celery_revoked": revoked,
        "graph_nodes": graph_nodes,
    }
