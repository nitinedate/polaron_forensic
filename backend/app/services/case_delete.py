"""Delete cases and scan jobs even when scans are still queued or running."""

from __future__ import annotations

from typing import Any

from app.db.sql_helpers import execute, fetchall, fetchone

DEFAULT_WORKSPACE_ID = "00000000-0000-4000-8000-000000000001"
DELETABLE_SCAN_JOB_STATUSES = frozenset(
    {"queued", "pending", "running", "processing", "syncing"}
)


def table_exists(db, name: str) -> bool:
    row = fetchone(db, "SELECT to_regclass(:n) AS rel", {"n": name})
    return bool(row and row.get("rel"))


def _try_execute(db, sql: str, params: dict[str, Any]) -> None:
    """Run a cleanup statement; ignore missing tables/columns in older firm schemas."""
    trans = db.begin_nested()
    try:
        execute(db, sql, params)
        trans.commit()
    except Exception:
        trans.rollback()


def terminate_scan_job_runtime(job: dict[str, Any] | None) -> dict[str, Any]:
    """Stop OpenVAS and Celery work for this job so nothing keeps running on the server."""
    from app.services.scan_orchestrator import terminate_scan_job_processes

    return terminate_scan_job_processes(job or {})


def delete_scan_job_cascade(db, job_id: str) -> None:
    """Remove a scan job and its child rows so a running/queued job can be dropped."""
    params = {"id": job_id}
    for sql in (
        """DELETE FROM vuln_finding_correlations
           WHERE finding_id IN (SELECT id FROM vuln_findings WHERE scan_job_id = CAST(:id AS uuid))""",
        "DELETE FROM vuln_findings WHERE scan_job_id = CAST(:id AS uuid)",
        "DELETE FROM vuln_scan_engine_runs WHERE scan_job_id = CAST(:id AS uuid)",
        "DELETE FROM vuln_scan_results WHERE scan_job_id = CAST(:id AS uuid)",
        "DELETE FROM vuln_scan_targets WHERE scan_job_id = CAST(:id AS uuid)",
    ):
        _try_execute(db, sql, params)
    execute(db, "DELETE FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)", params)


def _delete_case_children(db, case_id: str) -> int:
    jobs = []
    if table_exists(db, "vuln_scan_jobs"):
        jobs = fetchall(
            db,
            "SELECT id FROM vuln_scan_jobs WHERE case_id = CAST(:cid AS uuid)",
            {"cid": case_id},
        )
    for job in jobs:
        delete_scan_job_cascade(db, str(job["id"]))

    cid = {"cid": case_id}
    for sql in (
        "DELETE FROM vuln_finding_correlations WHERE case_id = CAST(:cid AS uuid)",
        "DELETE FROM vuln_remediation_tasks WHERE case_id = CAST(:cid AS uuid)",
        "DELETE FROM vuln_exceptions WHERE case_id = CAST(:cid AS uuid)",
        "DELETE FROM vuln_timeline_events WHERE case_id = CAST(:cid AS uuid)",
        "DELETE FROM vuln_pentest_jobs WHERE case_id = CAST(:cid AS uuid)",
        """DELETE FROM vuln_asset_identifiers
           WHERE asset_id IN (SELECT id FROM vuln_assets WHERE case_id = CAST(:cid AS uuid))""",
        "DELETE FROM vuln_findings WHERE case_id = CAST(:cid AS uuid)",
        "DELETE FROM vuln_assets WHERE case_id = CAST(:cid AS uuid)",
        "DELETE FROM vuln_scan_policies WHERE case_id = CAST(:cid AS uuid)",
        "UPDATE jobs SET case_id = NULL WHERE case_id = CAST(:cid AS uuid)",
    ):
        _try_execute(db, sql, cid)
    return len(jobs)


def delete_case_cascade(db, case_id: str) -> dict[str, Any]:
    if case_id == DEFAULT_WORKSPACE_ID:
        raise ValueError("default_workspace")
    row = fetchone(db, "SELECT id, title FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    if not row:
        raise LookupError("not_found")
    job_count = _delete_case_children(db, case_id)
    execute(db, "DELETE FROM cases WHERE id = CAST(:id AS uuid)", {"id": case_id})
    return {"id": case_id, "title": row.get("title"), "deleted_scan_jobs": job_count}
