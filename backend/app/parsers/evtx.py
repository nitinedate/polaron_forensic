"""Windows EVTX event log parser — logon / password-change focused extraction."""

from __future__ import annotations

import re
from typing import Any

EVTX_MAGIC = b"ElfFile\x00"

# Security log events we care about for account timeline answers
_ACCOUNT_EVENT_IDS = frozenset({
    "4624",  # successful logon
    "4625",  # failed logon
    "4634",  # logoff
    "4647",  # user initiated logoff
    "4723",  # password change attempt
    "4724",  # password reset
    "4738",  # user account changed
})


def _account_record_limit() -> int:
    from app.config import get_settings

    return max(int(getattr(get_settings(), "parse_evtx_account_limit", 5000) or 5000), 100)


def _xml_field(xml: str, *names: str) -> str | None:
    for name in names:
        m = re.search(
            rf"<(?:Data\s+Name=\"{name}\"|{name})[^>]*>([^<]*)</(?:Data|{name})>",
            xml,
            re.I,
        )
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def _xml_time(xml: str) -> str | None:
    m = re.search(r"SystemTime=\"([^\"]+)\"", xml)
    if m:
        raw = m.group(1).strip()
        raw = raw.replace("+00:00", "Z")
        if not raw.endswith("Z") and "T" in raw:
            raw += "Z"
        return raw
    m = re.search(r"<TimeCreated[^>]*>([^<]+)</TimeCreated>", xml, re.I)
    if not m:
        return None
    raw = m.group(1).strip().replace(" ", "T").replace("+00:00", "Z")
    if not raw.endswith("Z") and "T" in raw:
        raw += "Z"
    return raw


def _account_record(event_id: str, xml: str, *, source: str, record_id: int | None = None) -> dict[str, Any] | None:
    if event_id not in _ACCOUNT_EVENT_IDS:
        return None
    user = (
        _xml_field(xml, "TargetUserName", "SubjectUserName", "AccountName")
        or _xml_field(xml, "TargetUserSid")
    )
    domain = _xml_field(xml, "TargetDomainName", "SubjectDomainName", "AccountDomain")
    logon_type = _xml_field(xml, "LogonType")
    when = _xml_time(xml)
    if not user and not when:
        return None
    # Skip computer accounts / noisy SYSTEM
    if user and user.endswith("$"):
        return None
    if user and user.upper() in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}:
        return None

    kind = {
        "4624": "logon_success",
        "4625": "logon_failed",
        "4634": "logoff",
        "4647": "logoff",
        "4723": "password_change",
        "4724": "password_reset",
        "4738": "account_changed",
    }.get(event_id, "account_event")

    rec: dict[str, Any] = {
        "record_type": "security_event",
        "event_id": event_id,
        "event_kind": kind,
        "username": user,
        "domain": domain,
        "logon_type": logon_type,
        "event_time": when,
        "source": source,
    }
    if record_id is not None:
        rec["record_id"] = record_id

    label = {
        "logon_success": "successful logon",
        "logon_failed": "failed logon",
        "logoff": "logoff",
        "password_change": "password changed",
        "password_reset": "password reset by admin",
        "account_changed": "account changed",
    }.get(kind, f"event {event_id}")
    parts = [f"Security.evtx {label}"]
    if user:
        parts.append(f"user: {user}")
    if domain:
        parts.append(f"domain: {domain}")
    if when:
        parts.append(f"at: {when}")
    if logon_type:
        parts.append(f"logon type: {logon_type}")
    rec["text"] = "; ".join(parts)
    return rec


def _parse_with_python_evtx(data: bytes) -> list[dict[str, Any]] | None:
    try:
        import Evtx.Evtx as evtx_mod  # type: ignore
        import os
        import tempfile
    except ImportError:
        return None

    records: list[dict[str, Any]] = []
    event_id_counts: dict[str, int] = {}
    errors = 0
    tmp_path = None
    try:
        # python-evtx expects a filesystem path (BytesIO is not supported).
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        with evtx_mod.Evtx(tmp_path) as log:
            for rec in log.records():
                try:
                    xml = rec.xml()
                    m = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
                    if not m:
                        continue
                    eid = m.group(1)
                    event_id_counts[eid] = event_id_counts.get(eid, 0) + 1
                    acct = _account_record(eid, xml, source="evtx_lib", record_id=rec.record_num())
                    if acct:
                        records.append(acct)
                    elif len(records) < 50 and eid in _ACCOUNT_EVENT_IDS:
                        records.append({
                            "event_id": eid,
                            "record_id": rec.record_num(),
                            "source": "evtx_lib",
                        })
                except Exception:
                    errors += 1
                    continue
                if len(records) >= _account_record_limit():
                    break
    except Exception:
        return None
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if event_id_counts:
        top = sorted(event_id_counts.items(), key=lambda x: -x[1])[:30]
        records.insert(0, {
            "format": "evtx",
            "size_bytes": len(data),
            "event_id_counts": dict(top),
            "parser": "python-evtx",
            "decode_errors": errors,
            "text": "EVTX event ID summary: " + ", ".join(f"{k}×{v}" for k, v in top),
        })
    return records


def _scan_fallback(data: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    event_ids: list[str] = []
    # Chunked UTF-16 scan — never decode a 100MB+ EVTX as one giant string (OOM risk).
    window = 4 * 1024 * 1024
    limit = _account_record_limit()
    for start in range(0, len(data), window):
        chunk_bytes = data[start : start + window + 64_000]  # overlap for split Event tags
        text = chunk_bytes.decode("utf-16-le", errors="ignore")
        chunks = re.split(r"</Event>", text)
        for chunk in chunks:
            if "<EventID" not in chunk and "EventID>" not in chunk:
                continue
            m = re.search(r"<EventID[^>]*>(\d+)</EventID>", chunk)
            if not m:
                continue
            eid = m.group(1)
            if eid not in event_ids:
                event_ids.append(eid)
            acct = _account_record(eid, chunk + "</Event>", source="evtx_scan")
            if acct:
                records.append(acct)
            if len(records) >= limit:
                break
        if len(records) >= limit:
            break

    if event_ids:
        records.insert(0, {
            "format": "evtx",
            "size_bytes": len(data),
            "event_ids_sample": event_ids[:40],
            "parser": "evtx_scan",
            "text": "EVTX contains event IDs: " + ", ".join(event_ids[:40]),
        })
    if not records:
        records.append({
            "format": "evtx",
            "size_bytes": len(data),
            "note": "binary EVTX — no events decoded",
        })
    return records


def _is_critical_evtx_path(path: str) -> bool:
    low = (path or "").replace("\\", "/").lower()
    return low.endswith(("security.evtx", "system.evtx", "application.evtx"))


def parse_evtx(data: bytes, path: str = "") -> list[dict[str, Any]]:
    if len(data) < 4096 or not data.startswith(EVTX_MAGIC):
        return []

    limit = _account_record_limit()
    # python-evtx walks every record — large Security/System logs can exceed timeouts.
    # Fast chunked UTF-16 scan extracts account events for large logs without OOM.
    critical = _is_critical_evtx_path(path)
    if not critical:
        return _scan_fallback(data)[:limit]
    if len(data) > 8_000_000:
        return _scan_fallback(data)[:limit]

    parsed = _parse_with_python_evtx(data)
    if parsed:
        return parsed[:limit]
    return _scan_fallback(data)[:limit]