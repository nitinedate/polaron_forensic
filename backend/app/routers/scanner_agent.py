"""HTTPS API for on-site scanner agents (poll jobs, upload OpenVAS results)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import SessionLocal, apply_firm_search_path, bind_firm_schema
from app.db.sql_helpers import fetchone
from app.services.scanner_agent_auth import EdgeAgentContext, get_edge_agent
from app.services.scanner_agent_jobs import (
    claim_next_job,
    ingest_agent_logs,
    ingest_agent_results,
    touch_scanner_heartbeat,
    update_job_progress,
)

router = APIRouter(prefix="/api/scanner-agent", tags=["scanner-agent"])


def _require_vuln() -> None:
    if not get_settings().vuln_module_enabled:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "vuln_disabled", "message": "Vulnerability module is disabled"}},
        )


def _agent_db(agent: EdgeAgentContext) -> Session:
    db = SessionLocal()
    bind_firm_schema(db, agent.schema_name)
    apply_firm_search_path(db, agent.schema_name)
    return db


class HeartbeatIn(BaseModel):
    version: str | None = None
    openvas_ready: bool | None = None
    detail: str | None = None


class JobProgressIn(BaseModel):
    status: str | None = None
    progress_pct: float | None = None
    message: str | None = None
    external_scan_id: str | None = None
    error: str | None = None
    chunk_tasks: list[dict[str, Any]] | None = None
    target_progress: dict[str, dict[str, Any]] | None = None
    policy_snapshots: dict[str, dict[str, Any]] | None = None


class JobResultsIn(BaseModel):
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    status: str = "completed"
    external_scan_id: str | None = None
    partial: bool = False
    partial_reason: str | None = None
    error: str | None = None

    # Durable scan-assessment evidence from the on-site Greenbone task/report.
    # A zero-finding upload is only a verified clean result when these fields
    # prove that the intended targets were actually assessed.
    report_id: str | None = None
    task_status: str | None = None
    hosts_attempted: int | None = Field(default=None, ge=0)
    hosts_assessed: int | None = Field(default=None, ge=0)
    assessed_hosts: list[str] = Field(default_factory=list)
    skipped_hosts: list[Any] = Field(default_factory=list)
    report_result_count: int | None = Field(default=None, ge=0)
    plugin_error_count: int | None = Field(default=None, ge=0)
    plugin_error_details: list[dict[str, Any]] = Field(default_factory=list)
    scan_start: str | None = None
    scan_end: str | None = None
    assessment_complete: bool | None = None
    assessment_verdict: str | None = None
    alive_test: str | None = None
    report_read_error: str | None = None
    # V45.4: per-host coverage verdict from the agent (port scanner killed => degraded).
    host_coverage: dict[str, Any] = Field(default_factory=dict)
    degraded_hosts: list[str] = Field(default_factory=list)
    service_coverage: dict[str, Any] = Field(default_factory=dict)
    policy_snapshots: dict[str, dict[str, Any]] = Field(default_factory=dict)


class AgentLogEntryIn(BaseModel):
    ts: str | None = None
    level: str = "info"
    logger: str | None = None
    message: str
    job_id: str | None = None
    stage: str | None = None


class AgentLogsIn(BaseModel):
    entries: list[AgentLogEntryIn] = Field(default_factory=list, max_length=200)


@router.post("/heartbeat")
def agent_heartbeat(body: HeartbeatIn, agent: EdgeAgentContext = Depends(get_edge_agent)):
    _require_vuln()
    db = _agent_db(agent)
    try:
        touch_scanner_heartbeat(db, agent.scanner_id, version=body.version,
                                openvas_ready=body.openvas_ready, detail=body.detail)
        db.commit()
        from app.services.scanner_credentials import infer_scanner_role

        scanner = fetchone(
            db,
            "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)",
            {"id": agent.scanner_id},
        )
        return {
            "ok": True,
            "scanner_id": agent.scanner_id,
            "scanner_name": agent.scanner_name,
            "scanner_role": infer_scanner_role(scanner or agent.scanner),
            "tenant": agent.firm_slug,
        }
    finally:
        db.close()


@router.post("/logs")
def agent_logs(body: AgentLogsIn, agent: EdgeAgentContext = Depends(get_edge_agent)):
    _require_vuln()
    db = _agent_db(agent)
    try:
        stored = ingest_agent_logs(
            db,
            scanner_id=agent.scanner_id,
            entries=[e.model_dump() for e in body.entries],
        )
        db.commit()
        return {"ok": True, "stored": stored}
    finally:
        db.close()


@router.get("/jobs/next")
def agent_next_job(
    active_job_ids: str | None = None,
    agent_instance_id: str | None = None,
    x_aetheris_agent_instance: str | None = Header(default=None, alias="X-Aetheris-Agent-Instance"),
    agent: EdgeAgentContext = Depends(get_edge_agent),
):
    _require_vuln()
    if agent.scanner.get("openvas_ready") is False:
        return {"job": None}
    db = _agent_db(agent)
    try:
        touch_scanner_heartbeat(db, agent.scanner_id)
        active = [x.strip() for x in (active_job_ids or "").split(",") if x.strip()][:16]
        # v1.2.24 transport fallback: header remains primary, but accept the
        # same non-secret fencing id as a query parameter when a reverse proxy
        # strips unknown custom headers.
        ownership_instance = x_aetheris_agent_instance or agent_instance_id
        job = claim_next_job(
            db,
            agent.scanner_id,
            active_job_ids=active,
            agent_instance_id=ownership_instance,
        )
        db.commit()
        if not job:
            return {"job": None}
        return {"job": job}
    finally:
        db.close()


@router.patch("/jobs/{job_id}")
def agent_job_progress(
    job_id: str,
    body: JobProgressIn,
    agent_instance_id: str | None = None,
    x_aetheris_agent_instance: str | None = Header(default=None, alias="X-Aetheris-Agent-Instance"),
    agent: EdgeAgentContext = Depends(get_edge_agent),
):
    _require_vuln()
    db = _agent_db(agent)
    try:
        touch_scanner_heartbeat(db, agent.scanner_id)
        updated = update_job_progress(
            db,
            scanner_id=agent.scanner_id,
            job_id=job_id,
            status=body.status,
            progress_pct=body.progress_pct,
            message=body.message,
            external_scan_id=body.external_scan_id,
            error=body.error,
            chunk_tasks=body.chunk_tasks,
            target_progress=body.target_progress,
            policy_snapshots=body.policy_snapshots,
            agent_instance_id=(x_aetheris_agent_instance or agent_instance_id),
        )
        if not updated:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "not_found", "message": "Job not found for this scanner"}},
            )
        if updated.get("owner_mismatch"):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "code": "edge_job_owned_elsewhere",
                        "message": "This scan job is owned by another live scanner-agent process",
                    }
                },
            )
        db.commit()
        return updated
    finally:
        db.close()


@router.post("/jobs/{job_id}/results")
def agent_job_results(
    job_id: str,
    body: JobResultsIn,
    agent_instance_id: str | None = None,
    x_aetheris_agent_instance: str | None = Header(default=None, alias="X-Aetheris-Agent-Instance"),
    agent: EdgeAgentContext = Depends(get_edge_agent),
):
    _require_vuln()
    db = _agent_db(agent)
    try:
        touch_scanner_heartbeat(db, agent.scanner_id)
        result = ingest_agent_results(
            db,
            scanner_id=agent.scanner_id,
            job_id=job_id,
            vulnerabilities=body.vulnerabilities,
            status=body.status,
            external_scan_id=body.external_scan_id,
            partial=body.partial,
            partial_reason=body.partial_reason,
            error=body.error,
            report_id=body.report_id,
            task_status=body.task_status,
            hosts_attempted=body.hosts_attempted,
            hosts_assessed=body.hosts_assessed,
            assessed_hosts=body.assessed_hosts,
            skipped_hosts=body.skipped_hosts,
            report_result_count=body.report_result_count,
            plugin_error_count=body.plugin_error_count,
            plugin_error_details=body.plugin_error_details,
            scan_start=body.scan_start,
            scan_end=body.scan_end,
            assessment_complete=body.assessment_complete,
            assessment_verdict=body.assessment_verdict,
            alive_test=body.alive_test,
            report_read_error=body.report_read_error,
            agent_instance_id=(x_aetheris_agent_instance or agent_instance_id),
            host_coverage=body.host_coverage,
            service_coverage=body.service_coverage,
            policy_snapshots=body.policy_snapshots,
        )
        if result.get("status") == "missing":
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "not_found", "message": "Job not found for this scanner"}},
            )
        if result.get("status") == "not_edge_job":
            raise HTTPException(
                status_code=400,
                detail={"error": {"code": "not_edge_job", "message": "Job is not an edge-agent job"}},
            )
        if result.get("status") == "owner_mismatch":
            raise HTTPException(
                status_code=409,
                detail={
                    "error": {
                        "code": "edge_job_owned_elsewhere",
                        "message": "This scan job is owned by another live scanner-agent process",
                    }
                },
            )
        db.commit()
        return result
    finally:
        db.close()
