"""Ship scanner-agent log records to central over the existing HTTPS API."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("scanner_agent.log_shipper")

_job_id = threading.local()


def set_current_job_id(job_id: str | None) -> None:
    _job_id.value = (job_id or "").strip() or None


def current_job_id() -> str | None:
    return getattr(_job_id, "value", None)


class CentralLogHandler(logging.Handler):
    """Buffer scanner_agent.* records and POST them in batches."""

    def __init__(self, api: Any, *, max_buffer: int = 400) -> None:
        super().__init__(level=logging.INFO)
        self._api = api
        self._max_buffer = max(50, int(max_buffer))
        self._buf: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = 0.0
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        name = str(record.name or "")
        if name.startswith("scanner_agent.log_shipper") or name.startswith("scanner_agent.auth_recovery"):
            return
        try:
            msg = self.format(record).strip()
        except Exception:
            msg = str(record.getMessage())
        if not msg:
            return
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": "warning" if (record.levelname or "").lower() in {"warn", "warning"} else (record.levelname or "INFO").lower(),
            "logger": name,
            "message": msg[:2000],
            "job_id": (getattr(record, "job_id", None) or current_job_id()),
            "stage": name.rsplit(".", 1)[-1] if "." in name else "agent",
        }
        with self._lock:
            self._buf.append(entry)
            if len(self._buf) > self._max_buffer:
                self._buf = self._buf[-self._max_buffer :]

    def drain(self, *, max_entries: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            batch = self._buf[:max_entries]
            self._buf = self._buf[len(batch) :]
            return batch

    def maybe_flush(self, *, min_interval_sec: float = 8.0, force: bool = False) -> None:
        now = time.monotonic()
        with self._lock:
            pending = len(self._buf)
        if pending <= 0:
            return
        if not force and pending < 12 and (now - self._last_flush) < min_interval_sec:
            return
        batch = self.drain()
        if not batch:
            return
        try:
            self._api.post_logs(batch)
            self._last_flush = time.monotonic()
        except Exception as exc:
            with self._lock:
                self._buf = batch + self._buf
                if len(self._buf) > self._max_buffer:
                    self._buf = self._buf[-self._max_buffer :]
            log.debug("log ship skipped (%s)", exc.__class__.__name__)


def install_log_shipper(api: Any) -> CentralLogHandler:
    handler = CentralLogHandler(api)
    logging.getLogger("scanner_agent").addHandler(handler)
    return handler
