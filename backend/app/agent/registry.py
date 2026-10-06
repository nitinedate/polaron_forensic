"""Forensic AI agent registry — definitions for UI and orchestrator."""

from __future__ import annotations

from app.services.pipeline_supervisor import PIPELINE_STAGE_AGENTS

AGENT_DEFINITIONS = [{**agent,"kind":"pipeline","sort_order":100+index}
                     for index,agent in enumerate(PIPELINE_STAGE_AGENTS.values())]


def list_agent_definitions() -> list[dict]:
    return sorted(AGENT_DEFINITIONS, key=lambda a: int(a.get("sort_order") or 0))


def get_agent_definition(agent_id: str) -> dict | None:
    for a in AGENT_DEFINITIONS:
        if a["id"] == agent_id:
            return a
    return None
