"""Required process stages and the single progressAgent coordinator."""
from __future__ import annotations
from typing import Any

def list_action_agents() -> list[dict[str, Any]]:
    from app.services.forensic_serial_pipeline import STAGES,queue_for_stage
    stages=[{'id':aid,'name':name,'stage':stage,'role':'action','lane':'process',
        'queue':queue_for_stage(stage),'action':name,'consults':['progressAgent'],
        'dispatch_agent':aid,'dispatch_action':stage} for stage,name,aid in STAGES]
    return stages+[{'id':'report_generator_agent','name':'Report generation','stage':'report',
        'role':'action','lane':'process','action':'Build the evidence report','consults':['progressAgent']}]

def list_council_agents() -> list[dict[str, Any]]:
    from app.services.progress_agent import PROGRESS_AGENT,progress_queue
    return [{**PROGRESS_AGENT,'queue':progress_queue()}]

def list_all_process_agents() -> list[dict[str, Any]]:
    return list_council_agents() + list_action_agents()
