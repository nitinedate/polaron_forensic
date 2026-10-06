"""Acceptance checks for Forensic Agentic AI module.

Isolated from extract/RAG mutation logic. Source-level checks avoid needing
Postgres/DLL at unit-test time (same pattern as test_vuln_module).
"""

from __future__ import annotations

from pathlib import Path

from app.agent.registry import get_agent_definition, list_agent_definitions
from app.agent.tools import TOOL_REGISTRY, list_tools
from app.services.permissions_catalog import FIRM_PERMISSIONS


def test_agent_definitions_present():
    ids = {a["id"] for a in list_agent_definitions()}
    assert {"investigator", "intake_validator", "scope_advisor", "report_qa"} <= ids
    assert get_agent_definition("investigator") is not None


def test_tools_are_read_only_wrappers():
    names = {t["name"] for t in list_tools()}
    assert "retrieve_evidence" in names
    assert "answer_question" in names
    assert "intake_validate" in names
    # Must not expose mutating extract/process tools
    for forbidden in ("start_extract", "process_job", "delete_job", "launch_scan"):
        assert forbidden not in TOOL_REGISTRY


def test_forensic_agent_permissions_distinct_from_nessus():
    codes = {c for c, *_ in FIRM_PERMISSIONS}
    assert "forensic_agent:read" in codes
    assert "forensic_agent:run" in codes
    assert "agent:read" in codes  # Nessus agents remain
    assert "agent:manage" in codes
    assert "credential:manage" in codes


def test_agents_router_has_chat_and_specialized():
    src = Path(__file__).resolve().parents[1] / "app" / "routers" / "agents.py"
    text = src.read_text(encoding="utf-8")
    assert 'prefix="/api/agents"' in text
    assert "/jobs/{job_id}/runs" in text
    assert "/jobs/{job_id}/chat" in text
    assert "intake-validate" in text
    assert "scope-advise" in text
    assert "report-qa" in text
    assert "agent-orchestration" in text or "forensic_agent_chat_task" in text


def test_celery_routes_agent_queue_isolated():
    src = Path(__file__).resolve().parents[1] / "app" / "celery_app.py"
    text = src.read_text(encoding="utf-8")
    assert "forensic_agent_chat_task" in text
    assert "agent-orchestration" in text
    assert '"queue": "disk-build"' in text or "'queue': 'disk-build'" in text
    # Agent task must not share disk-build / rag-index
    assert 'forensic_agent_chat_task": {"queue": "agent-orchestration"}' in text.replace("'", '"')


def test_migration_014_agentic_tables():
    mig = Path(__file__).resolve().parents[2] / "migrations" / "014_firm_agentic_ai.sql"
    text = mig.read_text(encoding="utf-8")
    for table in ("agent_threads", "agent_messages", "agent_runs", "agent_tool_calls"):
        assert table in text
    assert "apply_firm_agentic_ai" in text
    assert "CREATE TABLE IF NOT EXISTS %I.vuln_agents" not in text


def test_compose_has_worker_agent():
    compose = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    text = compose.read_text(encoding="utf-8")
    assert "worker-agent:" in text
    assert "agent-orchestration" in text
    assert "AGENT_MODULE_ENABLED" in text
    assert "worker-mobile:" in text
    assert "mobile-build" in text
