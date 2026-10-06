"""Android (and other MTP phones) over Windows portable-device / file-transfer.

Old and new Android handsets often appear as MTP/WPD without USB debugging.
This adapter identifies those phones and, on the examiner Windows host, copies
shared storage via the Shell 'This PC' portable device. App-private databases
are not reachable — that limitation is recorded, not hidden.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Callable

from app.services.mobile_acquire.adapters.base import (
    AcquisitionOutcome,
    ProgressFn,
    ToolUnavailable,
    long_job_timeout,
)
from app.services.mobile_acquire.device_profile import ConnectionMode, DeviceProfile
from app.services.mobile_acquire.methods import CollectionMethod


def _repo_root() -> Path:
    # backend/app/services/mobile_acquire/adapters/android_mtp.py → repo
    return Path(__file__).resolve().parents[5]


class AndroidMtpAdapter:
    name = "android_mtp"
    os_family = "android"

    def tool_available(self) -> bool:
        """MTP copy uses Windows Shell.Application; Docker has no USB/MTP."""
        return sys.platform == "win32"

    def detect(self) -> list[str]:
        """Host helper enumerates WPD/MTP; local detect stays empty."""
        return []

    def identify(self, device_id: str) -> DeviceProfile:
        profile = DeviceProfile(os_family="android", serial=device_id)
        profile.connection_mode = ConnectionMode.MTP
        profile.usb_debugging_authorized = False
        profile.required_cable = "Approved USB data cable (file transfer / MTP)"
        name = device_id
        if name.lower().startswith("shell:"):
            name = name[6:]
        if "VID_" in name.upper() or name.startswith("USB\\"):
            profile.observations.append(f"Windows portable device id: {device_id}")
        profile.model = name[:80]
        profile.observations.append(
            "Phone is visible as MTP / file transfer (no authorised ADB). "
            "Shared storage (DCIM, Download, WhatsApp media folders) can be copied. "
            "App-private chat databases are not on this path — enable USB debugging "
            "and accept the RSA prompt for a fuller Android logical, or use a vendor tool."
        )
        profile.observations.append(
            "Unlock the phone, choose File transfer / MTP (not Charge only), "
            "and keep the cable seated."
        )
        return profile

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]:
        return [
            CollectionMethod.LOGICAL,
            CollectionMethod.ADVANCED_LOGICAL,
            CollectionMethod.BACKUP,
            CollectionMethod.FILE_SYSTEM,
            CollectionMethod.FULL_FILE_SYSTEM,
        ]

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        problems: list[str] = []
        if method not in self.supported_methods(profile):
            problems.append("MTP/ADB host collection does not implement this method.")
        if not self.tool_available():
            problems.append(
                "MTP copy runs on the examiner Windows host. Start the host drive helper."
            )
        return problems

    def acquire(
        self,
        *,
        profile: DeviceProfile,
        method: CollectionMethod,
        destination: Path,
        progress: ProgressFn | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> AcquisitionOutcome:
        outcome = AcquisitionOutcome(ok=False, adapter=self.name, method=method)
        if not self.tool_available():
            raise ToolUnavailable(
                "MTP acquisition requires the Windows examiner host (host drive helper)."
            )
        destination.mkdir(parents=True, exist_ok=True)
        media = destination / "mtp_shared"
        media.mkdir(parents=True, exist_ok=True)
        log_path = destination / "mtp_copy.log"
        script = _repo_root() / "scripts" / "mtp_logical_copy.ps1"
        if not script.is_file():
            outcome.errors.append(f"Missing {script}")
            return outcome
        if progress:
            progress("mtp_shared", outcome.bytes_written, None)
        device_id = profile.serial or ""
        args = [
            "powershell",
            "-STA",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-InstanceId",
            device_id,
            "-DeviceName",
            (profile.model or ""),
            "-DestDir",
            str(media),
            "-LogPath",
            str(log_path),
            "-OsHint",
            "android",
        ]
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=long_job_timeout(),
                check=False,
            )
        except Exception as exc:
            outcome.errors.append(f"MTP copy failed to start: {exc}")
            return outcome
        payload: dict = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
        copied = int(payload.get("files_copied") or 0)
        for path in media.rglob("*"):
            if path.is_file():
                outcome.files_written.append(str(path))
                try:
                    outcome.bytes_written += path.stat().st_size
                except OSError:
                    pass
                copied = max(copied, len(outcome.files_written))
        if progress:
            progress("mtp_shared", outcome.bytes_written, None, copied)
        outcome.coverage_gaps.append(
            "MTP shared-storage copy does not include app-private databases "
            "(WhatsApp msgstore, SMS provider, etc.). Enable USB debugging for ADB "
            "logical/backup, or import a UFED/iTunes-style image."
        )
        if copied > 0 or payload.get("ok"):
            outcome.ok = True
            return outcome
        err = payload.get("error") or (proc.stderr or "").strip() or "mtp_no_files_copied"
        outcome.errors.append(
            f"MTP copy produced no files ({err}). Unlock the phone, set USB mode to "
            "File transfer, and confirm the handset appears under This PC."
        )
        return outcome
