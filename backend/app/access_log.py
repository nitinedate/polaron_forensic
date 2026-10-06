"""Keep uvicorn access logs useful while OpenVAS CGI probes flood 404s."""

from __future__ import annotations

import logging
import re

# uvicorn: '172.18.0.1:56862 - "GET /crm/ HTTP/1.1" 404 Not Found'
_ACCESS_RE = re.compile(
    r'"[A-Z]+ ([^ ]+) HTTP/[0-9.]+"\s+(\d{3})',
)

_KEEP_404_PREFIXES = (
    "/api/",
    "/health",
    "/internal/",
    "/docs",
    "/openapi",
    "/redoc",
)


def keep_access_log(path: str, status: int) -> bool:
    if status != 404:
        return True
    p = (path or "").split("?", 1)[0]
    return any(p == prefix.rstrip("/") or p.startswith(prefix) for prefix in _KEEP_404_PREFIXES)


class SkipScanner404Filter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 5:
            method_or_path = args[2] if len(args) > 2 else ""
            status = args[4]
            if isinstance(status, int) and isinstance(method_or_path, str):
                # Formats vary: (client, method, path, httpver, status) or similar.
                path = method_or_path if str(method_or_path).startswith("/") else ""
                if path:
                    return keep_access_log(path, status)
        try:
            msg = record.getMessage()
        except Exception:
            return True
        match = _ACCESS_RE.search(msg)
        if not match:
            return True
        return keep_access_log(match.group(1), int(match.group(2)))


def install_access_log_filter() -> None:
    logging.getLogger("uvicorn.access").addFilter(SkipScanner404Filter())
