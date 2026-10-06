"""HostDrive agent API — examiner host helper status and mount refresh proxy."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import CurrentUser, require_firm_permission
from app.services import hostdrive_agent as hda
from app.service_identity import mobile_service_platform
from app.services.mobile_platform_agents import detect_mobile_platform

router = APIRouter(prefix="/api/hostdrive", tags=["hostdrive"])


def _platform_filter_mobile_rows(payload: dict, *, key: str) -> dict:
    """Hide sibling-platform devices from dedicated Android/iOS services."""
    required = mobile_service_platform()
    if not required:
        return payload
    out = dict(payload or {})
    rows = []
    for row in out.get(key) or []:
        if not isinstance(row, dict):
            continue
        if detect_mobile_platform(row) == required:
            rows.append(row)
    out[key] = rows
    out["count"] = len(rows)
    out["mobile_platform"] = required
    if key == "mobile_devices":
        out["mobile_count"] = len(rows)
        if required != "ios":
            out["ios_backup_roots"] = []
    return out


class HostDriveRefreshRequest(BaseModel):
    required_path: str | None = None
    sync_attached: bool = False


class HostDriveEnsurePathRequest(BaseModel):
    required_path: str
    wait_sec: float | None = None


class HostDriveListDirRequest(BaseModel):
    path: str


@router.get("/status")
def hostdrive_status(
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Probe HostDrive agent / helper on the examiner PC (via host.docker.internal)."""
    return hda.probe_helper()


@router.post("/refresh")
def hostdrive_refresh(
    body: HostDriveRefreshRequest | None = None,
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Refresh dynamic Docker drive mounts and optionally verify a selected path."""
    required_path = body.required_path if body else None
    return hda.proxy_refresh_mounts(required_path=required_path)


@router.post("/ensure-all")
def hostdrive_ensure_all(
    body: HostDriveRefreshRequest | None = None,
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Drive Mount Agent: discover every letter, remount, verify /host/<letter>.

    When ``required_path`` is set, remount that evidence letter even if other
    letters are already healthy. ``sync_attached`` remounts newly attached
    Windows letters even when C: is already mounted (Create job / picker).
    """
    from app.services.drive_mount_agent import ensure_all_drives_mounted

    required_path = body.required_path if body else None
    sync_attached = bool(body.sync_attached) if body else False
    return ensure_all_drives_mounted(
        wait_sec=90.0,
        required_path=required_path,
        sync_attached=sync_attached,
    )


@router.post("/ensure-path")
def hostdrive_ensure_path(
    body: HostDriveEnsurePathRequest,
    current: CurrentUser = Depends(require_firm_permission("job:run")),
):
    """Remount the selected office-host letter until Docker can list that folder."""
    from app.services.drive_mount_agent import ensure_path_mounted

    wait_sec = body.wait_sec if body.wait_sec is not None else 90.0
    return ensure_path_mounted(body.required_path, wait_sec=wait_sec)


@router.get("/drives")
def hostdrive_drives(
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Office-host drive letters for Choose folder — not the examiner laptop."""
    return _platform_filter_mobile_rows(hda.proxy_drives(), key="mobile_devices")


@router.get("/mobile-devices")
def hostdrive_mobile_devices(
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Phones attached to the office forensic host (WPD/MTP/usbmux) — same as disks."""
    return _platform_filter_mobile_rows(hda.proxy_mobile_devices(), key="mobile_devices")


@router.get("/acquisition/devices")
def hostdrive_acquisition_devices(
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """Office-host ADB / MTP / iOS scan for remote browsers."""
    return _platform_filter_mobile_rows(hda.proxy_acquisition_devices(), key="devices")


@router.post("/list-dir")
def hostdrive_list_dir(
    body: HostDriveListDirRequest,
    current: CurrentUser = Depends(require_firm_permission("job:read")),
):
    """List a folder on the office forensic host (Docker, remounting if stale)."""
    return hda.proxy_list_dir(body.path)
