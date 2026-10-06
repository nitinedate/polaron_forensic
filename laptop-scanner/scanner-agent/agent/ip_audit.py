"""Per-IP durable audit logging for the LaptopScanner.

Each IP gets its own JSONL file on the laptop and the same structured event is
also emitted through ``scanner_agent.ip`` so the existing central log shipper
captures it.  Logging is best-effort and can never fail a scan.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("scanner_agent.ip")
_lock = threading.Lock()


def _safe(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "").strip())
    return text[:160] or "unknown"


def _root() -> Path:
    return Path(os.environ.get("IP_SCAN_LOG_DIR") or "/app/logs/ip")


def emit_ip_event(job_id: str, host: str, event: str, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "job_id": str(job_id or ""),
        "ip": str(host or ""),
        "event": str(event or "event"),
    }
    for key, value in fields.items():
        if value is not None:
            payload[str(key)] = value
    line = json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))

    try:
        folder = _root() / _safe(job_id)
        path = folder / f"{_safe(host)}.jsonl"
        summary = folder / "all-ips.jsonl"
        with _lock:
            folder.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            with summary.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        log.debug("Unable to persist per-IP audit file", exc_info=True)

    level = logging.WARNING if event in {"start_error", "poll_error", "scan_failed", "unreachable", "skipped"} else logging.INFO
    log.log(level, "IP_EVENT %s", line, extra={"job_id": str(job_id or "")})
