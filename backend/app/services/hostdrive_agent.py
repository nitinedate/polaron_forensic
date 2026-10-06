"""HostDrive agent — status/proxy for examiner host drive helper (port 9876)."""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("hostdrive_agent")

DEFAULT_HELPER_URLS = (
    os.environ.get("HOST_DRIVE_HELPER_URL") or "",
    "http://host.docker.internal:9876",
    "http://127.0.0.1:9876",
)


def _helper_bases() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in DEFAULT_HELPER_URLS:
        base = (raw or "").strip().rstrip("/")
        if not base or base in seen:
            continue
        seen.add(base)
        out.append(base)
    return out


def _http_json(url: str, *, method: str = "GET", timeout: float = 3.0, body: bytes | None = None) -> dict[str, Any]:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    token = os.environ.get("HOST_DRIVE_HELPER_TOKEN") or ""
    if token:
        req.add_header("X-Host-Helper-Token", token)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        import json

        raw = resp.read().decode("utf-8") or "{}"
        return json.loads(raw)


def probe_helper() -> dict[str, Any]:
    """Return HostDrive agent / helper status from the examiner host."""
    errors: list[str] = []
    for base in _helper_bases():
        try:
            health = _http_json(f"{base}/health", timeout=2.5)
            if not health.get("ok"):
                errors.append(f"{base}: health not ok")
                continue
            drives: dict[str, Any] = {}
            try:
                drives = _http_json(f"{base}/drives", timeout=4.0)
            except Exception as exc:
                drives = {"ok": False, "error": str(exc)[:200]}
            letters = drives.get("drives") if isinstance(drives, dict) else None
            mobiles = drives.get("mobile_devices") if isinstance(drives, dict) else None
            return {
                "ok": True,
                "agent": "hostdrive_agent",
                "helper_url": base,
                "busy": bool(health.get("busy")),
                "drives": letters or [],
                "drive_count": len(letters or []),
                "volumes": drives.get("volumes") if isinstance(drives, dict) else [],
                "mobile_devices": mobiles or [],
                "mobile_count": len(mobiles or []),
                "message": f"HostDrive agent online — {len(letters or [])} drive letter(s)",
                "start_hint": (
                    "powershell -ExecutionPolicy Bypass -File scripts\\ensure-host-drive-helper.ps1"
                ),
            }
        except Exception as exc:
            errors.append(f"{base}: {exc}")
            log.debug("hostdrive probe failed %s: %s", base, exc)
    return {
        "ok": False,
        "agent": "hostdrive_agent",
        "helper_url": None,
        "drives": [],
        "drive_count": 0,
        "message": "HostDrive agent / helper offline on the examiner PC",
        "errors": errors[:5],
        "start_hint": (
            "powershell -ExecutionPolicy Bypass -File scripts\\ensure-host-drive-helper.ps1"
        ),
    }


def lookup_exact_path(path: str) -> dict[str, Any] | None:
    """Ask the host helper whether this exact path exists. Does not scan drives."""
    raw = (path or "").strip()
    if not raw:
        return None
    import json

    body = json.dumps({"path": raw}).encode("utf-8")
    for base in _helper_bases():
        try:
            data = _http_json(f"{base}/list-dir", method="POST", timeout=4.0, body=body)
            if data.get("ok") and data.get("path"):
                return data
        except Exception as exc:
            log.debug("helper list-dir %s: %s", base, exc)
    return None


def stage_exact_path(path: str, job_id: str) -> str | None:
    """Copy the host folder at *path* into DATA_ROOT/uploads/{job_id}/from-path."""
    raw = (path or "").strip()
    jid = (job_id or "").strip()
    if not raw or not jid:
        return None
    import json

    body = json.dumps({"path": raw, "job_id": jid}).encode("utf-8")
    for base in _helper_bases():
        try:
            data = _http_json(f"{base}/stage-folder", method="POST", timeout=600.0, body=body)
            dest = data.get("dest") or data.get("container_path")
            if not data.get("ok"):
                continue
            from app.services.client_intake import upload_root

            staged = upload_root() / jid / "from-path"
            if staged.exists():
                return str(staged)
            if dest:
                return str(dest)
        except Exception as exc:
            log.debug("helper stage-folder %s: %s", base, exc)
    return None


def proxy_refresh_mounts(required_path: str | None = None) -> dict[str, Any]:
    """Ask the host helper to regenerate mounts and optionally verify one Windows path.

    ``required_path`` is used for the folder the examiner just selected (for example
    ``G:\\Case01``). The Windows helper verifies the path exists before restarting
    containers and the refresh job verifies that the same path is visible under
    ``/host/<letter>`` afterwards.
    """
    status = probe_helper()
    if not status.get("ok"):
        return {
            "ok": False,
            "started": False,
            "error": status.get("message"),
            "start_hint": status.get("start_hint"),
            "protocol": status.get("protocol"),
        }
    base = status["helper_url"]
    try:
        import json

        payload: dict[str, Any] = {}
        if required_path:
            payload["required_path"] = required_path
        data = _http_json(
            f"{base}/refresh-drive-mounts",
            method="POST",
            timeout=30.0,
            body=json.dumps(payload).encode("utf-8"),
        )
        return {
            "ok": bool(data.get("ok", True)),
            "started": bool(data.get("started") or data.get("status") == "running"),
            "message": data.get("message"),
            "drives": data.get("drives") or status.get("drives") or [],
            "helper_url": base,
            "agent": "hostdrive_agent",
        }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        # The logon HostDrive watcher may have started a refresh milliseconds
        # before the UI. HTTP 409 means "join the existing refresh", not that
        # the helper is broken. Expose that distinction to the React client.
        if exc.code == 409:
            try:
                current = _http_json(f"{base}/refresh-drive-mounts", timeout=5.0)
                if current.get("status") == "running" or current.get("busy"):
                    return {
                        "ok": True,
                        "started": True,
                        "joined_existing": True,
                        "message": current.get("message") or "Drive mount refresh already running",
                        "drives": current.get("drives") or status.get("drives") or [],
                        "helper_url": base,
                        "agent": "hostdrive_agent",
                    }
            except Exception:
                pass
        return {"ok": False, "error": body or str(exc), "helper_url": base}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:500], "helper_url": base}


def refresh_status() -> dict[str, Any]:
    """Latest helper remount job status (running / done / error)."""
    errors: list[str] = []
    for base in _helper_bases():
        try:
            data = _http_json(f"{base}/refresh-drive-mounts", timeout=5.0)
            data["helper_url"] = base
            return data
        except Exception as exc:
            errors.append(f"{base}: {exc}")
    return {"ok": False, "status": "offline", "errors": errors[:5]}


def wait_for_refresh(*, timeout_sec: float = 150.0) -> dict[str, Any]:
    """Block until the Windows helper remount job finishes or times out."""
    import time

    deadline = time.time() + max(float(timeout_sec), 8.0)
    last: dict[str, Any] = {}
    while time.time() < deadline:
        last = refresh_status()
        status = str(last.get("status") or "").lower()
        busy = bool(last.get("busy"))
        if status in ("done", "error"):
            return last
        if status in ("idle", "offline") and not busy:
            return last
        time.sleep(2.0)
    last["timed_out"] = True
    return last


def proxy_drives() -> dict[str, Any]:
    """Office-host drive letters for remote browse, plus Docker mount flags."""
    from app.services.drive_mount_agent import inspect_host_letters, mounted_letters

    helper = probe_helper()
    docker_mounted = {letter.upper() for letter in mounted_letters()}
    volumes: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add_volume(raw: dict[str, Any] | str, *, drive_type: str = "fixed") -> None:
        if isinstance(raw, str):
            letter = raw.strip().upper()[:1]
            vol: dict[str, Any] = {"letter": letter, "drive_type": drive_type}
        else:
            letter = str(raw.get("letter") or "").strip().upper()[:1]
            vol = dict(raw)
            vol["letter"] = letter
        if not letter.isalpha() or letter in seen:
            return
        seen.add(letter)
        vol["mounted"] = letter in docker_mounted
        volumes.append(vol)

    if helper.get("ok"):
        for vol in helper.get("volumes") or []:
            if isinstance(vol, dict):
                _add_volume(vol)
        for raw in helper.get("drives") or []:
            _add_volume(str(raw))
    if not volumes:
        for row in inspect_host_letters():
            if row.get("mounted"):
                _add_volume(str(row.get("letter") or "").upper())

    drives = [str(v.get("letter") or "").upper() for v in volumes if v.get("letter")]
    mobile_devices = [
        {**dict(row), "attach_host": "office_server"}
        for row in (helper.get("mobile_devices") or [])
        if isinstance(row, dict)
    ]
    return {
        "ok": bool(drives or mobile_devices),
        "source": "office_host" if helper.get("ok") else "docker",
        "helper_online": bool(helper.get("ok")),
        "helper_url": helper.get("helper_url"),
        "drives": drives,
        "volumes": volumes,
        "mobile_devices": mobile_devices,
        "mobile_count": len(mobile_devices),
        "mounted": sorted(docker_mounted),
        "count": len(volumes),
        "message": helper.get("message")
        or ("Office HostDrive online" if helper.get("ok") else "Listing Docker-mounted office letters"),
        "start_hint": helper.get("start_hint"),
    }


def _tag_office_mobile(row: dict[str, Any]) -> dict[str, Any]:
    tagged = dict(row)
    tagged["attach_host"] = "office_server"
    return tagged


def proxy_mobile_devices() -> dict[str, Any]:
    """Phones attached to the office forensic host — same helper path as disks."""
    helper = probe_helper()
    devices: list[dict[str, Any]] = []
    ios_backup_roots: list[str] = []
    if helper.get("ok") and helper.get("helper_url"):
        try:
            data = _http_json(f"{helper['helper_url']}/mobile-devices", timeout=8.0)
            raw = data.get("mobile_devices") if isinstance(data, dict) else None
            devices = [_tag_office_mobile(row) for row in (raw or []) if isinstance(row, dict)]
            ios_backup_roots = [str(p) for p in (data.get("ios_backup_roots") or [])] if isinstance(data, dict) else []
        except Exception as exc:
            log.debug("proxy mobile-devices failed: %s", exc)
            devices = [
                _tag_office_mobile(row)
                for row in (helper.get("mobile_devices") or [])
                if isinstance(row, dict)
            ]
    return {
        "ok": True,
        "source": "office_host" if helper.get("ok") else "offline",
        "helper_online": bool(helper.get("ok")),
        "helper_url": helper.get("helper_url"),
        "mobile_devices": devices,
        "count": len(devices),
        "ios_backup_roots": ios_backup_roots,
        "attach_host": "office_server",
        "message": (
            f"{len(devices)} phone(s) on the office forensic host"
            if helper.get("ok")
            else "Office HostDrive helper is offline"
        ),
        "start_hint": helper.get("start_hint"),
    }


def proxy_acquisition_devices() -> dict[str, Any]:
    """UFED-style adapter scan on the office host (ADB / MTP / iOS usbmux)."""
    helper = probe_helper()
    if not helper.get("ok") or not helper.get("helper_url"):
        return {
            "ok": False,
            "source": "offline",
            "helper_online": False,
            "devices": [],
            "warnings": [
                "Office HostDrive helper is offline. Plug the phone into this PC "
                "(no extra adapter) or start the helper on the forensic server."
            ],
            "count": 0,
            "start_hint": helper.get("start_hint"),
        }
    try:
        data = _http_json(f"{helper['helper_url']}/acquisition/devices", timeout=45.0)
    except Exception as exc:
        log.debug("proxy acquisition/devices failed: %s", exc)
        return {
            "ok": False,
            "source": "office_host",
            "helper_online": True,
            "devices": [],
            "warnings": [f"Office host device scan failed: {exc}"],
            "count": 0,
        }
    devices = [
        {**dict(row), "attach_host": "office_server"}
        for row in (data.get("devices") or [])
        if isinstance(row, dict)
    ]
    return {
        "ok": True,
        "source": "office_host",
        "helper_online": True,
        "helper_url": helper.get("helper_url"),
        "devices": devices,
        "warnings": list(data.get("warnings") or []),
        "count": len(devices),
        "attach_host": "office_server",
    }


def _list_windows_path_in_docker(win_path: str) -> dict[str, Any] | None:
    from app.services.drive_mount_agent import docker_path_for_windows, path_is_readable
    from app.services.host_evidence import container_to_workstation_path

    if not path_is_readable(win_path):
        return None
    p = docker_path_for_windows(win_path)
    if p is None:
        return None
    try:
        target = p.parent if p.is_file() else p
        entries: list[dict[str, Any]] = []
        for entry in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            try:
                is_dir = entry.is_dir()
                size = None if is_dir else int(entry.stat().st_size)
            except OSError:
                is_dir = False
                size = None
            entries.append(
                {
                    "name": entry.name,
                    "kind": "dir" if is_dir else "file",
                    "size_bytes": size,
                }
            )
        display = container_to_workstation_path(target)
        return {
            "ok": True,
            "path": display,
            "count": len(entries),
            "entries": entries,
            "source": "docker",
        }
    except OSError:
        return None


def proxy_list_dir(path: str) -> dict[str, Any]:
    """List an office-host folder from Docker, remounting the letter if needed."""
    raw = (path or "").strip()
    if not raw:
        return {"ok": False, "error": "No path specified", "path": path}

    listed = _list_windows_path_in_docker(raw)
    if listed:
        return listed

    from app.services.drive_mount_agent import ensure_path_mounted

    heal = ensure_path_mounted(raw, wait_sec=90.0)
    listed = _list_windows_path_in_docker(raw)
    if listed:
        listed["healed"] = True
        listed["mount"] = {
            "ok": heal.get("ok"),
            "mounted": heal.get("mounted"),
            "message": heal.get("message"),
            "path_ready": heal.get("path_ready"),
        }
        return listed

    info = lookup_exact_path(raw)
    if info and info.get("ok"):
        info = dict(info)
        info["source"] = "helper"
        info["mount"] = {
            "ok": heal.get("ok"),
            "mounted": heal.get("mounted"),
            "message": heal.get("message"),
            "path_ready": heal.get("path_ready"),
        }
        return info

    return {
        "ok": False,
        "path": raw,
        "error": heal.get("message")
        or f"Could not list {raw} on the office forensic server",
        "mount": heal,
        "source": "office_host",
    }
