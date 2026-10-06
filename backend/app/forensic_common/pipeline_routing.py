"""Route extract/parse/inventory work to disk vs mobile queues and agents."""

from __future__ import annotations

from typing import Any

from app.forensic_common.job_types import is_mobile_job

# Generic stage -> (disk_agent, mobile_agent)
_DOMAIN_STAGE_AGENTS: dict[str, tuple[str, str]] = {
    "extract_agent": ("extract_agent_disk", "extract_agent_mobile"),
    "parse_agent": ("parse_agent_disk", "parse_agent_mobile"),
    "inventory_agent": ("inventory_agent_disk", "inventory_agent_mobile"),
}

_PLATFORM_STAGE_AGENTS: dict[str, dict[str, str]] = {
    "android": {
        "extract_agent": "extract_agent_android",
        "parse_agent": "parse_agent_android",
        "inventory_agent": "inventory_agent_android",
    },
    "ios": {
        "extract_agent": "extract_agent_ios",
        "parse_agent": "parse_agent_ios",
        "inventory_agent": "inventory_agent_ios",
    },
}

_MOBILE_ALIAS = {
    "extract_agent_mobile": "extract_agent",
    "parse_agent_mobile": "parse_agent",
    "inventory_agent_mobile": "inventory_agent",
    "extract_agent_android": "extract_agent",
    "parse_agent_android": "parse_agent",
    "inventory_agent_android": "inventory_agent",
    "extract_agent_ios": "extract_agent",
    "parse_agent_ios": "parse_agent",
    "inventory_agent_ios": "inventory_agent",
}
_DISK_ALIAS = {
    "extract_agent_disk": "extract_agent",
    "parse_agent_disk": "parse_agent",
    "inventory_agent_disk": "inventory_agent",
}


_PLATFORM_OWNER_ALIAS = {
    "iosagent": "extract_agent",
    "androidagent": "extract_agent",
    "ios_os_agent": "extract_agent",
    "android_os_agent": "extract_agent",
}


def resolve_platform_owner_id(db, job_id: str) -> str | None:
    """iOS Agent or Android Agent that owns extract + RAG for this phone job."""
    if not is_mobile_job(db, job_id):
        return None
    try:
        from app.services.mobile_platform_agents import owner_agent_for_job

        return owner_agent_for_job(db, job_id)
    except Exception:
        return None


def resolve_domain_agent_id(db, job_id: str, agent_id: str) -> str:
    """Map a generic or domain agent id to the correct domain-specific id for this job."""
    if agent_id in {"iosagent", "androidagent"}:
        owner = resolve_platform_owner_id(db, job_id)
        if owner and owner != agent_id:
            return owner
        return agent_id
    generic = (
        _MOBILE_ALIAS.get(agent_id)
        or _DISK_ALIAS.get(agent_id)
        or _PLATFORM_OWNER_ALIAS.get(agent_id)
        or agent_id
    )
    pair = _DOMAIN_STAGE_AGENTS.get(generic)
    if not pair:
        return agent_id
    disk_id, mobile_id = pair
    if is_mobile_job(db, job_id):
        try:
            from app.forensic_common.job_types import mobile_os_family

            family = mobile_os_family(db, job_id)
        except Exception:
            family = None
        platform_id = (_PLATFORM_STAGE_AGENTS.get(str(family)) or {}).get(generic)
        return platform_id or mobile_id
    return disk_id


def normalize_stage_agent_id(agent_id: str) -> str:
    """Collapse domain agent ids to the generic stage key used in recommendation logic."""
    return (
        _MOBILE_ALIAS.get(agent_id)
        or _DISK_ALIAS.get(agent_id)
        or _PLATFORM_OWNER_ALIAS.get(agent_id)
        or agent_id
    )


def stage_key_for_recommendation(agent_id: str, action: str) -> str:
    """Route by action first so iosagent inventory/parse never hit extract."""
    if action == "artifact_inventory":
        return "inventory_agent"
    if action == "parse_drain":
        return "parse_agent"
    if action == "resume_extraction":
        return "extract_agent"
    if action == "start_phase3":
        return "materialize_agent"
    return normalize_stage_agent_id(agent_id)


def extract_queue_for_job(db, job_id: str) -> str:
    if not is_mobile_job(db, job_id):
        return "disk-build"
    try:
        from app.forensic_common.job_types import mobile_os_family

        family = mobile_os_family(db, job_id)
    except Exception:
        family = None
    if family == "android":
        return "android-build"
    if family == "ios":
        return "ios-build"
    from app.service_identity import mobile_queue_prefix

    return f"{mobile_queue_prefix()}-build"


def should_continue_after_extract(
    *,
    phase3_auto: bool = False,
    rag_auto: bool = False,
    service: str | None = None,
) -> bool:
    """Mobile extract is useless without materialize/parse — always continue.

    Forensic still honors PHASE3_AUTO_AFTER_DISK / RAG_AUTO_AFTER_DISK so GPU
    work can stay gated on the disk stack.
    """
    from app.service_identity import current_service, is_mobile_service

    if is_mobile_service(service or current_service()):
        return True
    return bool(phase3_auto or rag_auto)


def phase3_queue(service: str | None = None) -> str:
    from app.service_identity import current_service, is_mobile_service, mobile_queue_prefix

    svc = service or current_service()
    return f"{mobile_queue_prefix(svc)}-build" if is_mobile_service(svc) else "disk-build"


def parse_queue(service: str | None = None) -> str:
    """Product-local post-processing queue, isolated from extraction admission."""
    from app.service_identity import (
        MOBILE_EXTRACT,
        current_service,
        is_mobile_service,
        mobile_queue_prefix,
    )

    svc = service or current_service()
    # Legacy mobile-extract has no dedicated *-parse Celery worker — parse/enrich
    # share mobile-build (see MOBILE_ROUTES). Routing to mobile-parse parks tasks
    # forever and freezes Entity / Annotation / Ontology at 1%.
    if svc == MOBILE_EXTRACT:
        return "mobile-build"
    return f"{mobile_queue_prefix(svc)}-parse" if is_mobile_service(svc) else "disk-parse"


def followup_queue(service: str | None = None) -> str:
    """CPU enrichment stays off the extraction queue to prevent queue starvation."""
    return parse_queue(service)


def domain_pipeline_agents() -> dict[str, dict[str, Any]]:
    """Agent registry entries for disk- and mobile-specific stage agents."""
    return {
        "extract_agent_disk": {
            "name": "Extract Agent (Disk)",
            "stage": "extract",
            "description": "Virtual disk build and MinIO extraction from E01/EWF segments.",
            "queue": "disk-build",
            "task": "app.tasks.build_extracted_disk_task",
            "domain": "disk",
        },
        "parse_agent_disk": {
            "name": "Parse Agent (Disk)",
            "stage": "parse",
            "description": "Windows forensic parsers (EVTX, registry, prefetch, SQLite) on disk artifacts.",
            "queue": "disk-parse",
            "task": "app.tasks.parse_drain_task",
            "domain": "disk",
        },
        "inventory_agent_disk": {
            "name": "Artifact Inventory Agent (Disk)",
            "stage": "artifact_inventory",
            "description": "Disk/EWF catalog artifact counts (extension census + Windows collectors).",
            "queue": "disk-inventory",
            "task": "app.tasks.axiom_artifact_inventory_task",
            "domain": "disk",
        },
        "extract_agent_mobile": {
            "name": "Extract Agent (Mobile)",
            "stage": "extract",
            "description": "Mobile folder/UFED/iOS-backup package extract into MinIO working image.",
            "queue": "mobile-build",
            "task": "app.tasks.build_extracted_mobile_task",
            "domain": "mobile",
        },
        "parse_agent_mobile": {
            "name": "Parse Agent (Mobile)",
            "stage": "parse",
            "description": "Mobile SQLite/path parsers on extracted mobile artifacts.",
            "queue": "mobile-parse",
            "task": "app.tasks.parse_drain_mobile_task",
            "domain": "mobile",
        },
        "inventory_agent_mobile": {
            "name": "Artifact Inventory Agent (Mobile)",
            "stage": "artifact_inventory",
            "description": "Mobile AXIOM-style SQLite/path inventory (no disk census).",
            "queue": "mobile-build",
            "task": "app.tasks.axiom_artifact_inventory_mobile_task",
            "domain": "mobile",
        },
        "extract_agent_android": {
            "name": "Extract Agent (Android)",
            "stage": "extract",
            "description": "Android-only acquisition package extraction and materialization.",
            "queue": "android-build",
            "task": "app.tasks.build_extracted_mobile_task",
            "domain": "mobile",
            "os_family": "android",
        },
        "parse_agent_android": {
            "name": "Parse Agent (Android)",
            "stage": "parse",
            "description": "Android SQLite/app/media parsers only.",
            "queue": "android-parse",
            "task": "app.tasks.parse_drain_mobile_task",
            "domain": "mobile",
            "os_family": "android",
        },
        "inventory_agent_android": {
            "name": "Artifact Inventory Agent (Android)",
            "stage": "artifact_inventory",
            "description": "Android-only artifact inventory.",
            "queue": "android-build",
            "task": "app.tasks.axiom_artifact_inventory_mobile_task",
            "domain": "mobile",
            "os_family": "android",
        },
        "extract_agent_ios": {
            "name": "Extract Agent (iOS)",
            "stage": "extract",
            "description": "iOS-only backup/image extraction and materialization.",
            "queue": "ios-build",
            "task": "app.tasks.build_extracted_mobile_task",
            "domain": "mobile",
            "os_family": "ios",
        },
        "parse_agent_ios": {
            "name": "Parse Agent (iOS)",
            "stage": "parse",
            "description": "iOS plist/SQLite/app/media parsers only.",
            "queue": "ios-parse",
            "task": "app.tasks.parse_drain_mobile_task",
            "domain": "mobile",
            "os_family": "ios",
        },
        "inventory_agent_ios": {
            "name": "Artifact Inventory Agent (iOS)",
            "stage": "artifact_inventory",
            "description": "iOS-only artifact inventory.",
            "queue": "ios-build",
            "task": "app.tasks.axiom_artifact_inventory_mobile_task",
            "domain": "mobile",
            "os_family": "ios",
        },
        "iosagent": {
            "name": "iOS Agent",
            "stage": "extract",
            "description": (
                "Owns iPhone/iPad USB collection, backup extract, parse, and RAG. "
                "Never processes Android phones."
            ),
            "queue": "ios-build",
            "task": "app.tasks.build_extracted_mobile_task",
            "domain": "mobile",
            "os_family": "ios",
        },
        "androidagent": {
            "name": "Android Agent",
            "stage": "extract",
            "description": (
                "Owns Android USB/MTP/ADB collection, extract, parse, and RAG. "
                "Never processes iPhones."
            ),
            "queue": "android-build",
            "task": "app.tasks.build_extracted_mobile_task",
            "domain": "mobile",
            "os_family": "android",
        },
    }
