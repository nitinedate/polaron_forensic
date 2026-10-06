"""iOS Agent — exclusive owner of iPhone/iPad extract and RAG."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.services.disk_build_log import write_disk_log
from app.services.mobile_platform_agents import (
    IOSAGENT_ID,
    IOSAGENT_LABEL,
    PlatformMismatchError,
    assert_agent_owns_job,
    detect_mobile_platform,
    owner_progress_from_stage_states,
)

AGENT_ID = IOSAGENT_ID
AGENT_LABEL = IOSAGENT_LABEL
PLATFORM = "ios"


def detects(hint: Any) -> bool:
    return detect_mobile_platform(hint) == PLATFORM


def owns_job(db: Session, job_id: str) -> bool:
    try:
        return assert_agent_owns_job(db, job_id, AGENT_ID) == AGENT_ID
    except PlatformMismatchError:
        return False


def refuse_if_wrong_platform(db: Session, job_id: str) -> str:
    return assert_agent_owns_job(db, job_id, AGENT_ID)


def log_owner(db: Session, job_id: str, message: str, *, stage: str = "extract") -> None:
    write_disk_log(
        db,
        job_id,
        f"[{AGENT_LABEL}] {message}",
        stage=stage,
        metadata={"agent_id": AGENT_ID, "platform": PLATFORM, "owns": "extract_and_rag"},
    )


def card_from_states(states: dict[str, dict[str, Any]]) -> dict[str, Any]:
    state, pct, detail = owner_progress_from_stage_states(states)
    return {"state": state, "pct": pct, "label": AGENT_LABEL, "detail": detail}
