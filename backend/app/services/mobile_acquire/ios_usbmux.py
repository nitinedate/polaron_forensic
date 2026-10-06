"""List paired iOS devices via Apple usbmux (Windows Apple Mobile Device Support).

libimobiledevice binaries are optional. pymobiledevice3 talks to the same
Apple Mobile Device Service that already sees the handset over USB.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from typing import Any

_last_error: str | None = None
_CANONICAL_UDID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}$|^[0-9A-Fa-f]{40}$")
_HEX = re.compile(r"[0-9A-Fa-f]+")


def normalize_ios_udid(value: str | None) -> str:
    """Turn a Windows USB instance id or raw serial into a lockdown UDID.

    WPD/Apple driver ids look like ``USB#VID_05AC&PID_12A8#000081500002659C0CBB401C``.
    pymobiledevice3 only accepts ``00008150-0002659C0CBB401C`` (or a 40-hex UDID).
    """
    raw = str(value or "").strip()
    if not raw:
        return ""
    if _CANONICAL_UDID.match(raw):
        return raw
    tail = raw.replace("\\", "#").split("#")[-1]
    tail = tail.split("&")[0].split("?")[0].strip()
    hex_only = "".join(_HEX.findall(tail))
    if len(hex_only) == 24:
        return f"{hex_only[:8]}-{hex_only[8:]}"
    if len(hex_only) == 40:
        return hex_only
    hex_all = "".join(_HEX.findall(raw))
    if len(hex_all) >= 40:
        return hex_all[-40:]
    if len(hex_all) >= 24:
        chunk = hex_all[-24:]
        return f"{chunk[:8]}-{chunk[8:]}"
    return ""


def _udid_key(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").lower()


def resolve_ios_udid(value: str | None, *, live: list[str] | None = None) -> str:
    """Prefer a connected usbmux serial that matches the examiner's device id."""
    wanted = normalize_ios_udid(value)
    connected = list(live) if live is not None else list_ios_udids()
    if wanted:
        want_key = _udid_key(wanted)
        for uid in connected:
            key = _udid_key(uid)
            if key == want_key or key.endswith(want_key) or want_key.endswith(key):
                return uid
        return wanted
    if len(connected) == 1:
        return connected[0]
    return ""


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    new_loop = asyncio.new_event_loop()
    try:
        return new_loop.run_until_complete(coro)
    finally:
        new_loop.close()


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


def last_error() -> str | None:
    return _last_error


def call_maybe_async(fn, *args, **kwargs):
    """Run a pymobiledevice3 callable that may be sync (5.x) or async (4.x)."""
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        return _run(result)
    return result


def get_lockdown(serial: str):
    """Return a lockdown client. pymobiledevice3 4.x is async; 5.x is sync."""
    from pymobiledevice3.lockdown import create_using_usbmux

    resolved = resolve_ios_udid(serial)
    if not resolved:
        raise ValueError(f"No iOS UDID could be resolved from {serial!r}")
    return call_maybe_async(create_using_usbmux, serial=resolved)


async def _list_async() -> list[dict[str, Any]]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.usbmux import list_devices

    devices = await _maybe_await(list_devices())
    out: list[dict[str, Any]] = []
    for dev in devices:
        serial = normalize_ios_udid(str(getattr(dev, "serial", "") or "").strip()) or str(
            getattr(dev, "serial", "") or ""
        ).strip()
        item: dict[str, Any] = {
            "udid": serial,
            "connection": str(getattr(dev, "connection_type", "") or "USB"),
            "name": "",
            "product": "",
            "version": "",
        }
        if not serial:
            continue
        try:
            lockdown = await _maybe_await(create_using_usbmux(serial=serial))
            item["name"] = str(getattr(lockdown, "display_name", "") or "")
            item["product"] = str(getattr(lockdown, "product_type", "") or "")
            item["version"] = str(getattr(lockdown, "product_version", "") or "")
        except Exception as exc:
            item["error"] = str(exc)
        out.append(item)
    return out


def list_ios_devices() -> list[dict[str, Any]]:
    """Return connected iOS devices (empty list if usbmux/pymobiledevice3 unavailable)."""
    global _last_error
    _last_error = None
    try:
        return _run(_list_async())
    except Exception as exc:
        _last_error = f"{type(exc).__name__}: {exc}"
        return []


def list_ios_udids() -> list[str]:
    return [d["udid"] for d in list_ios_devices() if d.get("udid")]


def as_json() -> str:
    devices = list_ios_devices()
    payload: dict[str, Any] = {"ok": True, "devices": devices, "count": len(devices)}
    if _last_error:
        payload["ok"] = False
        payload["error"] = _last_error
    return json.dumps(payload)
