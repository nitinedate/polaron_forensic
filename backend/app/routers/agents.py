"""Forensic Agentic AI API.

Extends the previous stub while keeping GET /api/agents/jobs/{job_id}/runs.
Nessus agents remain under /api/vuln/agents (untouched).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agent.orchestrator import list_runs_for_job, run_investigator, run_specialized_agent
from app.agent.registry import list_agent_definitions
from app.agent.tools import list_tools
from app.config import get_settings
from app.deps import CurrentUser, firm_db, require_firm_permission

router = APIRouter(prefix="/api/agents", tags=["agents"])


def _require_agent_module() -> None:
    if not get_settings().agent_module_enabled:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "agent_disabled", "message": "Agentic AI module is disabled"}},
        )


class ChatRequest(BaseModel):
    query: str = Field(min_length=1)
    thread_id: str | None = None
    async_run: bool = False


@router.get("")
def list_agents(
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Agent registry for frontend listAgents()."""
    _require_agent_module()
    return {"items": list_agent_definitions()}


@router.get("/tools")
def get_tools(
    current: CurrentUser = Depends(require_firm_permission("forensic_agent:read")),
):
    _require_agent_module()
    return {"items": list_tools()}


@router.get("/jobs/{job_id}/runs")
def job_agent_runs(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Pipeline / agent run history (was stub returning [])."""
    if not get_settings().agent_module_enabled:
        return {"job_id": job_id, "items": []}
    try:
        items = list_runs_for_job(db, job_id)
    except Exception:
        # Tables may not exist yet on old firms — fail soft for pipeline banner
        items = []
    return {"job_id": job_id, "items": items}


@router.post("/jobs/{job_id}/intake-validate")
def intake_validate(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _require_agent_module()
    return run_specialized_agent(
        db, job_id=job_id, agent_id="intake_validator", user_id=current.user_id
    )


@router.post("/jobs/{job_id}/scope-advise")
def scope_advise(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _require_agent_module()
    return run_specialized_agent(
        db, job_id=job_id, agent_id="scope_advisor", user_id=current.user_id
    )


@router.post("/jobs/{job_id}/report-qa")
def report_qa(
    job_id: str,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    _require_agent_module()
    return run_specialized_agent(
        db, job_id=job_id, agent_id="report_qa", user_id=current.user_id
    )


@router.post("/jobs/{job_id}/chat")
def agent_chat(
    job_id: str,
    body: ChatRequest,
    db: Session = Depends(firm_db),
    current: CurrentUser = Depends(require_firm_permission("forensic_agent:run")),
):
    """Multi-step investigator agent (tool loop)."""
    _require_agent_module()
    if body.async_run:
        from app.tasks import forensic_agent_chat_task

        schema = current.schema_name
        if not schema:
            raise HTTPException(400, detail={"error": {"code": "no_schema", "message": "Missing firm schema"}})
        async_result = forensic_agent_chat_task.delay(
            schema, job_id, body.query, current.user_id, body.thread_id
        )
        return {
            "agent_id": "investigator",
            "run_id": None,
            "status": "queued",
            "message": "Agent run queued",
            "output": {"celery_task_id": async_result.id},
        }
    return run_investigator(
        db,
        job_id=job_id,
        query=body.query,
        user_id=current.user_id,
        thread_id=body.thread_id,
    )
