"""Retired huddle compatibility and console noise rules; no monitoring worker."""

import re

HUDDLE_NOISE_PATTERN = r"^[[:space:]]*\[Agent[[:space:]]+huddle\][[:space:]]*(Observe|Performance|Repair)([[:space:]:—-]|$)"
_NOISE = re.compile(
    r"^\s*\[Agent\s+huddle\]\s*(Observe|Performance|Repair)(?:\s|[:—-]|$)",
    re.IGNORECASE,
)


# Narrowly match legacy supervisor chatter, never arbitrary evidence text.
IDLE_AGENT_WAIT_PATTERN = r"^[[:space:]]*\[[a-z0-9_]+\][[:space:]]*wait[[:space:]]*[—–-][[:space:]]*blocked:[[:space:]]*Waiting[[:space:]]+for([[:space:]]|$)"
_IDLE_WAIT = re.compile(
    r"^\s*\[[a-z0-9_]+\]\s*wait\s*[—–-]\s*blocked:\s*Waiting\s+for(?:\s|$)",
    re.IGNORECASE,
)


def is_idle_agent_wait_message(message: str, level: str = "info") -> bool:
    return level.strip().lower() in {"info", "debug"} and bool(_IDLE_WAIT.search(message))


def is_silent_pipeline_message(message: str, level: str = "info") -> bool:
    return is_retired_huddle_message(message) or is_idle_agent_wait_message(message, level)


def is_retired_huddle_message(message: str) -> bool:
    return bool(_NOISE.search(message))


def visible_pipeline_logs_sql(column: str = "message") -> str:
    if column not in {"message", "l.message"}:
        raise ValueError("Unsupported log column")
    level_column = "l.level" if column == "l.message" else "level"
    return (
        f"(COALESCE({column},'') !~* '{HUDDLE_NOISE_PATTERN}' AND "
        f"(COALESCE(LOWER({level_column}),'info') NOT IN ('info','debug') OR "
        f"COALESCE({column},'') !~* '{IDLE_AGENT_WAIT_PATTERN}'))"
    )


def retired_huddle_result(job_id: str | None = None) -> dict:
    return {
        "status": "retired",
        "coordinator": "progressAgent",
        "job_id": job_id,
        "reason": "Scheduled progressAgent owns monitoring; retired huddle delivery performed no work",
    }
