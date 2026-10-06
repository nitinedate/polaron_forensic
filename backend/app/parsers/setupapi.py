"""Parse Windows setupapi.dev.log for USB connect / device-install events."""

from __future__ import annotations

import re
from typing import Any

_SECTION_START = re.compile(
    r">>>?\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
    re.I,
)
_DEVICE_INSTALL = re.compile(
    r">>>?\s+\[Device Install(?:\s*\([^)]*\))?\s*-\s*([^\]]+)\]",
    re.I,
)
_USBISH = re.compile(
    r"USBSTOR|WPDBUSENUM|USB\\VID_|USB\\PID_|\\\\USB\\\\|\\USB\\|USB\s*Composite|USB\s*Mass\s*Storage",
    re.I,
)


def _normalize_ts(raw: str) -> str:
    # 2023/05/24 15:48:28.387 → ISO-ish
    parts = raw.strip().split()
    if len(parts) >= 2:
        return f"{parts[0].replace('/', '-')}T{parts[1]}Z"
    return raw.strip()


def parse_setupapi_log(data: bytes, path: str = "") -> list[dict[str, Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-16-le", errors="replace")
    # Cap very large rotated logs for structured extract (full text still truncated for preview)
    work = text[:2_000_000]
    records: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    lines = work.splitlines()
    pending_device: str | None = None
    pending_line: int | None = None
    for i, line in enumerate(lines):
        m_dev = _DEVICE_INSTALL.search(line)
        if m_dev:
            device = m_dev.group(1).strip().rstrip("]")
            if _USBISH.search(device) or _USBISH.search(line):
                pending_device = device
                pending_line = i
            else:
                pending_device = None
                pending_line = None
            continue
        m_start = _SECTION_START.search(line)
        if m_start and pending_device:
            ts = _normalize_ts(m_start.group(1))
            events.append({
                "record_type": "usb_usage_event",
                "event_kind": "device_install",
                "event_time": ts,
                "device_id": pending_device,
                "source": path or "setupapi.dev.log",
                "text": f"USB usage/connect event at {ts}: {pending_device}",
            })
            pending_device = None
            pending_line = None
            continue
        # Also catch USBSTOR mentions with nearby section starts (fallback)
        if "USBSTOR" in line.upper() and "Section start" not in line:
            # look ahead/back a few lines for section start
            window = "\n".join(lines[max(0, i - 5) : i + 6])
            m2 = _SECTION_START.search(window)
            if m2:
                ts = _normalize_ts(m2.group(1))
                events.append({
                    "record_type": "usb_usage_event",
                    "event_kind": "usbstor_activity",
                    "event_time": ts,
                    "device_id": line.strip()[:240],
                    "source": path or "setupapi.dev.log",
                    "text": f"USBSTOR activity at {ts}: {line.strip()[:180]}",
                })

    # Deduplicate by time+device
    seen: set[str] = set()
    for ev in events:
        key = f"{ev.get('event_time')}|{ev.get('device_id')}"
        if key in seen:
            continue
        seen.add(key)
        records.append(ev)

    if records:
        records.insert(0, {
            "record_type": "usb_usage_summary",
            "usage_event_count": len(records),
            "source": path or "setupapi.dev.log",
            "text": (
                f"USB usage/connect events found in SetupAPI: {len(records)} "
                f"(hardware-initiated USB/USBSTOR/WPDBUSENUM installs)"
            ),
        })

    # Keep a short text preview for RAG
    preview_lines = [ln for ln in text.splitlines() if ln.strip()][:30]
    records.append({
        "record_type": "setupapi_preview",
        "line_count": text.count("\n") + 1,
        "text": text[:20_000],
        "preview": "\n".join(preview_lines),
        "source": path,
    })
    return records
