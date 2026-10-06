"""Retired huddle compatibility and console noise rules; no monitoring worker."""

import re

HUDDLE_NOISE_PATTERN = r"^[[:space:]]*\[Agent[[:space:]]+huddle\][[:space:]]*(Observe|Performance|Repair)([[:space:]:—-]|$)"
_NOISE = re.compile(
    r"^\s*\[Agent\s+huddle\]\s*(Observe|Performance|Repair)(?:\s|[:—-]|$)",
    re.IGNORECASE,
)


def is_retired_huddle_message(message: str) -> bool:
    return bool(_NOISE.search(message))


def visible_pipeline_logs_sql(column: str = "message") -> str:
    if column not in {"message", "l.message"}:
        raise ValueError("Unsupported log column")
    return f"COALESCE({column},'') !~* '{HUDDLE_NOISE_PATTERN}'"


def retired_huddle_result(job_id: str | None = None) -> dict:
    return {
        "status": "retired",
        "coordinator": "progressAgent",
        "job_id": job_id,
        "reason": "Scheduled progressAgent owns monitoring; retired huddle delivery performed no work",
    }
