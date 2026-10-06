"""iOS acquisition over lockdownd / AFC — Architecture §5, §6, §7.

Uses the documented Apple device services exposed by libimobiledevice:
`ideviceinfo`, `idevicebackup2`, `afcclient`/`ifuse`, `idevicecrashreport`,
`idevicediagnostics`, `idevicesyslog`. No jailbreak, no exploit, no lock bypass —
those need vendor entitlement and are out of scope.

The single most consequential decision this adapter enforces is the ENCRYPTED
backup. An unencrypted iTunes backup silently omits the keychain, Health data,
Safari history and call history. Examiners who take an unencrypted backup and
then report "no Health data" are reporting a tool limitation as a finding.
"""

from __future__ import annotations

import inspect
import plistlib
import re
from pathlib import Path
from typing import Callable

from app.services.mobile_acquire.adapters.base import (
    AcquisitionOutcome,
    ProgressFn,
    ToolUnavailable,
    long_job_timeout,
    run_tool,
    which,
)
from app.services.mobile_acquire.device_profile import (
    ConnectionMode,
    DeviceProfile,
    LockState,
)
from app.services.mobile_acquire.methods import CollectionMethod

def _ios_backup_manifest(backup_dir: Path) -> Path | None:
    """A usable iTunes backup has Manifest.db (iOS 10+) or a non-empty Manifest.plist."""
    if not backup_dir.is_dir():
        return None
    db = next(backup_dir.rglob("Manifest.db"), None)
    if db and db.is_file() and db.stat().st_size > 0:
        return db
    plist = next(backup_dir.rglob("Manifest.plist"), None)
    if plist and plist.is_file() and plist.stat().st_size > 64:
        hashed = any(
            p.is_file() and p.name not in {"Manifest.plist", "Manifest.db", "Info.plist", "Status.plist"}
            for p in plist.parent.iterdir()
        )
        if hashed:
            return plist
    return None


# AFC-reachable media paths (no pairing escalation required beyond trust).
AFC_TARGETS: tuple[str, ...] = (
    "/DCIM",
    "/PhotoData",
    "/PhotoData/CPLAssets",
    "/PhotoData/Thumbnails",
    "/Downloads",
    "/Books",
    "/Recordings",
    "/Purchases",
    "/iTunes_Control",
    "/MediaAnalysis",
    "/Podcasts",
    "/Photos",
    "/Videos",
)

# iOS-only. Do not import these bundles from Android adapters.
IOS_HOUSE_ARREST_BUNDLES: tuple[str, ...] = (
    "net.whatsapp.WhatsApp",
    "net.whatsapp.WhatsAppSMB",
)


class IosLockdownAdapter:
    name = "ios_lockdown"
    os_family = "ios"

    def tool_available(self) -> bool:
        if which("ideviceinfo") is not None:
            return True
        from app.services.mobile_acquire.ios_usbmux import list_ios_udids

        return bool(list_ios_udids())

    # ---------------- discovery ----------------

    def detect(self) -> list[str]:
        if which("idevice_id") is not None:
            out = run_tool(["idevice_id", "-l"], timeout=30)
            ids = [line.strip() for line in out.stdout.splitlines() if line.strip()]
            if ids:
                return ids
        from app.services.mobile_acquire.ios_usbmux import list_ios_udids

        ids = list_ios_udids()
        if ids:
            return ids
        raise ToolUnavailable(
            "No iOS device on usbmux. Unlock the phone, tap Trust This Computer, "
            "and ensure Apple Mobile Device Service is running. "
            "Optional: install idevice_id under tools\\libimobiledevice."
        )

    # ---------------- identify ----------------

    def identify(self, device_id: str) -> DeviceProfile:
        profile = DeviceProfile(os_family="ios", udid=device_id)
        profile.required_cable = "Approved Lightning or USB-C cable"

        if which("ideviceinfo") is None:
            return self._identify_via_usbmux(profile, device_id)

        try:
            out = run_tool(["ideviceinfo", "-u", device_id, "-x"], timeout=60)
        except Exception as exc:
            profile.observations.append(f"ideviceinfo failed: {exc}")
            profile.connection_mode = ConnectionMode.UNKNOWN
            profile.pairing_trusted = False
            return profile

        if out.returncode != 0:
            stderr = (out.stderr or "").lower()
            profile.pairing_trusted = False
            profile.connection_mode = ConnectionMode.UNKNOWN
            if "pair" in stderr or "trust" in stderr:
                profile.observations.append(
                    "Device is connected but not trusted. Unlock the device with the lawful "
                    "passcode and accept 'Trust This Computer', or supply a pairing record."
                )
                profile.lock_state = LockState.LOCKED_UNKNOWN_STATE
            else:
                profile.observations.append(f"ideviceinfo error: {(out.stderr or '')[:200]}")
            return profile

        try:
            info = plistlib.loads((out.stdout or "").encode())
        except Exception:
            info = {}

        self._apply_ios_identity(profile, info)

        # Backup encryption state determines what a backup will actually contain.
        try:
            enc = run_tool(
                ["ideviceinfo", "-u", device_id, "-q",
                 "com.apple.mobile.backup", "-k", "WillEncrypt"],
                timeout=30,
            ).stdout.strip().lower()
            profile.observations.append(f"Backup encryption enabled: {enc or 'unknown'}")
        except Exception:
            profile.observations.append("Backup encryption state could not be read.")

        return profile

    def _identify_via_usbmux(self, profile: DeviceProfile, device_id: str) -> DeviceProfile:
        """Identify a paired iPhone when ideviceinfo.exe is not on PATH."""
        from app.services.mobile_acquire.ios_usbmux import get_lockdown

        try:
            lockdown = get_lockdown(device_id)
        except Exception as exc:
            profile.observations.append(f"usbmux lockdown failed: {exc}")
            profile.connection_mode = ConnectionMode.UNKNOWN
            profile.pairing_trusted = False
            return profile

        info = self._lockdown_values(lockdown)
        marketing = str(getattr(lockdown, "display_name", "") or "")
        generic_names = {"iphone os", "ipad os", "ios", "iphone", "ipad", ""}
        existing = str(info.get("ProductName") or "").strip().lower()
        if marketing and existing in generic_names:
            info["ProductName"] = marketing
        self._apply_ios_identity(profile, info)
        profile.observations.append(
            "Identified via Apple usbmux (pymobiledevice3); ideviceinfo not installed."
        )
        return profile

    @staticmethod
    def _lockdown_values(lockdown) -> dict:
        """Read the same identity keys ideviceinfo -x would return."""
        vals: dict = {}
        raw = getattr(lockdown, "all_values", None)
        if isinstance(raw, dict):
            vals.update(raw)
        getter = getattr(lockdown, "get_value", None)
        if not vals and callable(getter):
            try:
                got = getter()
                if isinstance(got, dict):
                    vals.update(got)
            except Exception:
                pass
        if callable(getter):
            from app.services.mobile_acquire.ios_usbmux import call_maybe_async

            for domain, key, dest in (
                ("com.apple.mobile.backup", "WillEncrypt", "_WillEncrypt"),
                (None, "BatteryCurrentCapacity", "BatteryCurrentCapacity"),
            ):
                try:
                    got = (
                        call_maybe_async(getter, domain=domain, key=key)
                        if domain
                        else call_maybe_async(getter, key=key)
                    )
                    if inspect.isawaitable(got):
                        from app.services.mobile_acquire.ios_usbmux import _run

                        got = _run(got)
                    if got is not None:
                        vals[dest] = got
                except TypeError:
                    try:
                        got = call_maybe_async(getter, key) if domain is None else call_maybe_async(getter)
                        if got is not None and dest == "BatteryCurrentCapacity":
                            vals[dest] = got
                    except Exception:
                        pass
                except Exception:
                    pass
        return vals

    @staticmethod
    def _apply_ios_identity(profile: DeviceProfile, info: dict) -> None:
        """Map lockdownd / ideviceinfo keys onto the device profile."""
        profile.pairing_trusted = True
        profile.connection_mode = ConnectionMode.LOCKDOWN
        profile.manufacturer = "Apple"
        product = str(info.get("ProductType") or info.get("HardwareModel") or "")
        marketing = str(
            info.get("ProductName")
            or info.get("MarketingName")
            or ""
        )
        device_name = str(info.get("DeviceName") or "")
        if marketing:
            profile.model = marketing
            if product and product not in marketing:
                profile.observations.append(f"ProductType {product}.")
        else:
            profile.model = product
        if device_name:
            profile.observations.append(f"Device name reported as '{device_name}'.")

        profile.os_version = str(info.get("ProductVersion") or profile.os_version or "")
        profile.build_id = str(info.get("BuildVersion") or "")
        # iOS has no Android-style monthly security-patch date; the build is the identifier.
        if profile.build_id:
            profile.security_patch_level = profile.build_id
        profile.serial = str(info.get("SerialNumber") or "")
        profile.imei = str(
            info.get("InternationalMobileEquipmentIdentity")
            or info.get("InternationalMobileEquipmentIdentity2")
            or ""
        )
        profile.chipset = str(
            info.get("HardwarePlatform")
            or info.get("HardwareModel")
            or ""
        )
        profile.iccid = str(info.get("IntegratedCircuitCardIdentity") or "")
        profile.imsi = str(info.get("InternationalMobileSubscriberIdentity") or "")
        profile.sim_present = bool(profile.iccid) if profile.iccid else None
        # All modern iOS volumes use Data Protection; record that instead of "unknown".
        profile.encryption_state = "data_protection"

        password_protected = info.get("PasswordProtected")
        if password_protected is True or str(password_protected).lower() == "true":
            # PasswordProtected means a passcode is *configured*, not that the
            # screen is locked now. A trusted lockdown session is AFU; backup
            # is attempted. Error 208 is the only reliable "screen locked" signal.
            profile.lock_state = LockState.LOCKED_AFU
            profile.observations.append(
                "PasswordProtected=true: a device passcode is configured. That is "
                "normal and does not mean the screen is locked; backup will be attempted."
            )
        elif password_protected is False or str(password_protected).lower() == "false":
            profile.lock_state = LockState.UNLOCKED
        elif profile.lock_state == LockState.UNKNOWN:
            # Trusted lockdown session implies the device has been unlocked at least once.
            profile.lock_state = LockState.LOCKED_AFU
            profile.observations.append(
                "Lock screen flag was not in the lockdown dump; pairing is trusted so "
                "the device is treated as after-first-unlock (AFU)."
            )

        batt = info.get("BatteryCurrentCapacity")
        if batt is not None:
            try:
                profile.battery_percent = int(batt)
            except (TypeError, ValueError):
                pass

        will_enc = info.get("_WillEncrypt")
        if will_enc is None:
            will_enc = info.get("WillEncrypt")
        if will_enc is not None:
            profile.observations.append(
                f"Backup encryption enabled: {str(will_enc).lower()}"
            )

    # ---------------- capability ----------------

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]:
        if not profile.pairing_trusted:
            return []
        methods = [CollectionMethod.LOGICAL, CollectionMethod.BACKUP,
                   CollectionMethod.ADVANCED_LOGICAL]
        if profile.rooted_or_jailbroken:
            methods.append(CollectionMethod.FULL_FILE_SYSTEM)
        return methods

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        problems: list[str] = []
        if not self.tool_available():
            problems.append(
                "No iOS USB access: Apple Mobile Device Service / usbmux did not see the phone, "
                "and ideviceinfo is not installed."
            )
        if not profile.pairing_trusted:
            problems.append(
                "No trusted pairing with the device. Unlock and accept the trust prompt."
            )
        if method in (CollectionMethod.BACKUP, CollectionMethod.ADVANCED_LOGICAL) \
                and which("idevicebackup2") is None:
            try:
                from app.services.mobile_acquire.ios_usbmux import list_ios_udids

                usbmux_ok = bool(list_ios_udids())
            except Exception:
                usbmux_ok = False
            if not usbmux_ok:
                problems.append(
                    "No iOS backup tool: install tools\\libimobiledevice\\idevicebackup2.exe "
                    "or use the examiner kit (tools\\host-python + pymobiledevice3 on the host helper)."
                )
        return problems

    # ---------------- acquire ----------------

    def acquire(
        self,
        *,
        profile: DeviceProfile,
        method: CollectionMethod,
        destination: Path,
        progress: ProgressFn | None = None,
        cancel: Callable[[], bool] | None = None,
        backup_password: str | None = None,
    ) -> AcquisitionOutcome:
        device_id = profile.udid
        outcome = AcquisitionOutcome(ok=True, adapter=self.name, method=method)
        destination.mkdir(parents=True, exist_ok=True)

        self._collect_device_info(device_id, destination / "device_state", outcome, progress)
        self._collect_crash_and_diagnostics(device_id, destination, outcome, progress)

        if cancel and cancel():
            outcome.interrupted = True
            outcome.errors.append("Cancelled by examiner after device-state capture.")
            return outcome

        if method in (CollectionMethod.BACKUP, CollectionMethod.ADVANCED_LOGICAL,
                      CollectionMethod.FULL_FILE_SYSTEM):
            # AFC media first while the device may still be AFU; backup then asks for
            # an on-device passcode and fails hard if the screen stays locked.
            if method in (CollectionMethod.ADVANCED_LOGICAL, CollectionMethod.FULL_FILE_SYSTEM):
                self._collect_afc_media(device_id, destination, outcome, progress, cancel)
                self._collect_house_arrest(device_id, destination, outcome, progress, cancel)
            self._collect_backup(
                device_id, destination, outcome, progress, backup_password, cancel=cancel,
            )
        elif method == CollectionMethod.LOGICAL:
            self._collect_afc_media(device_id, destination, outcome, progress, cancel)

        if method == CollectionMethod.LOGICAL:
            outcome.coverage_gaps.append(
                "AFC media collection covers the camera roll and shared media only. "
                "Application containers, messages and system databases were NOT collected. "
                "Use a backup or full-filesystem method for those."
            )

        outcome.device_metadata = profile.as_dict()
        if outcome.errors:
            outcome.ok = False
        return outcome

    # ---------------- internals ----------------

    def _collect_device_info(self, device_id, dest: Path, outcome, progress) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        domains = (
            None,
            "com.apple.disk_usage",
            "com.apple.mobile.battery",
            "com.apple.mobile.iTunes",
            "com.apple.mobile.backup",
            "com.apple.mobile.data_sync",
            "com.apple.mobile.wireless_lockdown",
            "com.apple.international",
            "com.apple.fairplay",
            "com.apple.mobile.debug",
        )
        for domain in domains:
            args = ["ideviceinfo", "-u", device_id, "-x"]
            if domain:
                args += ["-q", domain]
            filename = f"ideviceinfo_{(domain or 'root').replace('.', '_')}.plist"
            try:
                result = run_tool(args, timeout=60)
                if result.returncode != 0 or not result.stdout.strip():
                    outcome.warnings.append(
                        f"Domain '{domain or 'root'}' not readable "
                        f"({(result.stderr or '').strip()[:120]})"
                    )
                    continue
                target = dest / filename
                target.write_text(result.stdout, encoding="utf-8")
                outcome.files_written.append(str(target))
                outcome.bytes_written += target.stat().st_size
                if progress:
                    progress(f"device_state/{filename}", outcome.bytes_written, None)
            except Exception as exc:
                outcome.warnings.append(f"ideviceinfo domain '{domain}' failed: {exc}")

    def _collect_crash_and_diagnostics(self, device_id, dest: Path, outcome, progress) -> None:
        if which("idevicecrashreport"):
            crash_dir = dest / "crash_reports"
            crash_dir.mkdir(parents=True, exist_ok=True)
            try:
                run_tool(["idevicecrashreport", "-u", device_id, "-e", str(crash_dir)],
                         timeout=900)
                for path in crash_dir.rglob("*"):
                    if path.is_file():
                        outcome.files_written.append(str(path))
                        outcome.bytes_written += path.stat().st_size
                if progress:
                    progress("crash_reports", outcome.bytes_written, None)
            except Exception as exc:
                outcome.warnings.append(f"Crash report collection failed: {exc}")
        else:
            outcome.coverage_gaps.append(
                "idevicecrashreport unavailable — crash logs (which name every process that "
                "ran, including deleted apps) were not collected."
            )

        if which("idevicediagnostics"):
            try:
                result = run_tool(
                    ["idevicediagnostics", "-u", device_id, "ioregentry"], timeout=180)
                target = dest / "device_state" / "ioregistry.txt"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(result.stdout or "", encoding="utf-8", errors="replace")
                outcome.files_written.append(str(target))
                outcome.bytes_written += target.stat().st_size
            except Exception as exc:
                outcome.warnings.append(f"idevicediagnostics failed: {exc}")

    def _collect_backup(
        self,
        device_id,
        dest: Path,
        outcome,
        progress,
        password,
        cancel: Callable[[], bool] | None = None,
    ) -> None:
        import time

        backup_dir = dest / "ios_backup"
        backup_dir.mkdir(parents=True, exist_ok=True)

        if not password:
            outcome.warnings.append(
                "No backup password supplied — an UNENCRYPTED backup will be taken."
            )
            outcome.coverage_gaps.append(
                "Unencrypted iTunes backups omit the keychain, Health data, Safari history "
                "and call history entirely. These categories will be absent from this "
                "extraction as a direct consequence of the backup type, not because the "
                "data was absent on the device. Set a backup password and re-acquire if "
                "those categories are within the authorised objective."
            )
        else:
            try:
                enc = run_tool(
                    ["idevicebackup2", "-u", device_id, "encryption", "on", password],
                    timeout=180,
                )
                if enc.returncode != 0:
                    outcome.warnings.append(
                        f"Could not enable backup encryption: {(enc.stderr or '')[:200]}"
                    )
                else:
                    outcome.warnings.append(
                        "Backup encryption was ENABLED on the device by the examiner. This "
                        "is a device state change and must be recorded as a documented "
                        "deviation, along with the password, in the case file."
                    )
            except Exception as exc:
                outcome.warnings.append(f"Enabling backup encryption failed: {exc}")

        # Do not tell the examiner to unlock up front. PasswordProtected=true is
        # normal; Error 208 is the only signal that the screen is actually locked.
        if progress:
            progress(
                "ios_backup/starting",
                outcome.bytes_written,
                None,
            )
        outcome.warnings.append(
            "Keep the iPhone awake and the USB pairing trusted during backup. "
            "A configured passcode is normal and is not a lock-screen failure."
        )

        max_attempts = 3
        last_rc = 0
        last_out = ""
        last_err = ""
        for attempt in range(1, max_attempts + 1):
            if cancel and cancel():
                outcome.interrupted = True
                outcome.errors.append("Cancelled by examiner during iOS backup.")
                return
            if progress:
                progress(f"ios_backup/attempt_{attempt}", outcome.bytes_written, None)
            try:
                proc = self._run_backup_with_live_progress(
                    device_id,
                    backup_dir,
                    outcome,
                    progress,
                    cancel,
                    attempt=attempt,
                )
            except Exception as exc:
                outcome.errors.append(f"iOS backup failed: {exc}")
                return

            last_rc = self._signed_exit_code(proc.returncode)
            last_out = (proc.stdout or "").strip()
            last_err = (proc.stderr or "").strip()
            combined = f"{last_out}\n{last_err}".strip()

            manifest = _ios_backup_manifest(backup_dir)
            if last_rc == 0 and manifest is not None:
                break

            locked = (
                last_rc == -208
                or last_rc == 208
                or "ErrorCode 208" in combined
                or "MBErrorDomain/208" in combined
                or "Device locked" in combined
            )
            if locked and attempt < max_attempts:
                outcome.warnings.append(
                    f"Backup attempt {attempt}/{max_attempts}: device locked (Error 208). "
                    "Unlock the iPhone, enter the passcode, keep the screen on — retrying…"
                )
                # Give the examiner time to unlock before the next attempt.
                for _ in range(30):
                    if cancel and cancel():
                        outcome.interrupted = True
                        outcome.errors.append("Cancelled while waiting for device unlock.")
                        return
                    time.sleep(2)
                continue

            # Permanent failure for this attempt cycle.
            break

        manifest = _ios_backup_manifest(backup_dir)
        status = next(backup_dir.rglob("Status.plist"), None)
        for path in backup_dir.rglob("*"):
            if path.is_file():
                # Avoid double-counting files already tracked during live progress.
                path_s = str(path)
                if path_s not in outcome.files_written:
                    outcome.files_written.append(path_s)
                    outcome.bytes_written += path.stat().st_size
        if progress:
            progress("ios_backup", outcome.bytes_written, None)

        if last_rc != 0 or manifest is None:
            msg = self._format_backup_failure(
                last_rc, last_out, last_err, manifest_found=manifest is not None,
            )
            outcome.errors.append(msg)
            if (dest / "afc_media").exists():
                outcome.coverage_gaps.append(
                    "Photos/videos under afc_media were still collected. WhatsApp chats, "
                    "SMS/iMessage and app databases require a successful iTunes/Finder "
                    "backup. Re-run Advanced Logical / Backup; if the tool reports "
                    "Error 208, unlock the screen and keep it on."
                )
            if status is not None and manifest is None:
                outcome.warnings.append(
                    "A partial ios_backup folder exists without Manifest.db; do not treat "
                    "hash-named files in that folder as a complete backup."
                )

    def _run_backup_with_live_progress(
        self,
        device_id: str,
        backup_dir: Path,
        outcome,
        progress: ProgressFn | None,
        cancel: Callable[[], bool] | None,
        *,
        attempt: int,
    ):
        """Run idevicebackup2 while publishing directory size as live progress."""
        import subprocess
        import threading
        import time

        idevice = which("idevicebackup2")
        if not idevice:
            return self._run_backup_usbmux(
                device_id, backup_dir, outcome, progress, cancel, attempt=attempt
            )

        args = ["idevicebackup2", "-u", device_id, "backup", "--full", str(backup_dir)]
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stop = threading.Event()
        seen_files = 0
        last_bytes = 0

        def _watch() -> None:
            nonlocal seen_files, last_bytes
            while not stop.wait(2.0):
                if cancel and cancel():
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    return
                total_bytes = 0
                file_count = 0
                try:
                    for path in backup_dir.rglob("*"):
                        if path.is_file():
                            file_count += 1
                            try:
                                total_bytes += path.stat().st_size
                            except OSError:
                                pass
                except OSError:
                    continue
                last_bytes = total_bytes
                seen_files = file_count
                if progress:
                    progress(
                        f"ios_backup/attempt_{attempt}",
                        outcome.bytes_written + total_bytes,
                        None,
                        file_count,
                    )

        watcher = threading.Thread(target=_watch, name="ios-backup-progress", daemon=True)
        watcher.start()
        try:
            stdout, stderr = proc.communicate()
        finally:
            stop.set()
            watcher.join(timeout=3.0)

        # Fold watched totals into outcome once (final pass still inventories files).
        if last_bytes and progress:
            progress(f"ios_backup/attempt_{attempt}", outcome.bytes_written + last_bytes, None)

        if _ios_backup_manifest(backup_dir) is None:
            return self._run_backup_usbmux(
                device_id, backup_dir, outcome, progress, cancel, attempt=attempt
            )

        return subprocess.CompletedProcess(
            args=args,
            returncode=proc.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
        )

    def _run_backup_usbmux(
        self,
        device_id: str,
        backup_dir: Path,
        outcome,
        progress: ProgressFn | None,
        cancel: Callable[[], bool] | None,
        *,
        attempt: int,
    ):
        """Full iTunes backup via pymobiledevice3 when idevicebackup2 is not installed."""
        import subprocess

        from app.services.mobile_acquire.ios_usbmux import get_lockdown

        try:
            from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
        except Exception as exc:
            raise ToolUnavailable(
                "Neither idevicebackup2 nor pymobiledevice3 is available for iOS backup."
            ) from exc

        def _cb(pct) -> None:
            if cancel and cancel():
                raise RuntimeError("Cancelled by examiner during iOS backup.")
            if progress:
                progress(f"ios_backup/attempt_{attempt}", outcome.bytes_written, None)

        try:
            from app.services.mobile_acquire.ios_usbmux import call_maybe_async

            lockdown = get_lockdown(device_id)
            svc = Mobilebackup2Service(lockdown)
            call_maybe_async(
                svc.backup,
                full=True,
                backup_directory=str(backup_dir),
                progress_callback=_cb,
            )
            manifest = _ios_backup_manifest(Path(backup_dir))
            if manifest is None:
                return subprocess.CompletedProcess(
                    args=["pymobiledevice3", "backup2"],
                    returncode=1,
                    stdout="",
                    stderr=(
                        "pymobiledevice3 backup finished but wrote no Manifest.db / "
                        "Manifest.plist. Check USB pairing and retry Advanced Logical."
                    ),
                )
            return subprocess.CompletedProcess(
                args=["pymobiledevice3", "backup2"],
                returncode=0,
                stdout=f"manifest={manifest}",
                stderr="",
            )
        except Exception as exc:
            return subprocess.CompletedProcess(
                args=["pymobiledevice3", "backup2"],
                returncode=1,
                stdout="",
                stderr=str(exc),
            )

    @staticmethod
    def _signed_exit_code(code: int | None) -> int:
        if code is None:
            return -1
        if code > 0x7FFFFFFF:
            return int(code) - 0x100000000
        return int(code)

    @staticmethod
    def _format_backup_failure(
        rc: int, stdout: str, stderr: str, *, manifest_found: bool
    ) -> str:
        text = f"{stdout}\n{stderr}".strip()
        if rc in (-208, 208) or "ErrorCode 208" in text or "Device locked" in text:
            return (
                "iOS backup failed: device locked (ErrorCode 208). Unlock the iPhone, "
                "enter the passcode when prompted, keep the screen on, then start "
                "Advanced Logical / Backup again. AFC media already collected remains usable."
            )
        if "ErrorCode 207" in text or rc in (-207, 207):
            return (
                "iOS backup failed: backup encryption password required or incorrect "
                f"(ErrorCode 207). Supply the device backup password and retry. Detail: {text[:240]}"
            )
        if "DeviceNotFoundError" in text or "ios_udid_unresolved" in text:
            return (
                "iOS backup failed: the handset was not visible to Apple usbmux. "
                "Unlock the phone, tap Trust This Computer, keep USB connected, "
                "then retry Advanced Logical. A Windows USB instance id is not a UDID."
            )
        detail = text[:300] if text else "backup produced no output"
        if not manifest_found:
            return (
                f"iOS backup failed (exit {rc}): {detail}. "
                "Neither Manifest.db nor Manifest.plist was produced — WhatsApp/SMS "
                "cannot be mapped. Retry Advanced Logical; only unlock the screen if "
                "the tool reports Error 208."
            )
        return f"iOS backup failed (exit {rc}): {detail}"

    def _collect_afc_media(self, device_id, dest: Path, outcome, progress, cancel) -> None:
        media_dir = dest / "afc_media"
        media_dir.mkdir(parents=True, exist_ok=True)

        if which("afcclient") is not None:
            self._collect_afc_via_afcclient(device_id, media_dir, outcome, progress, cancel)
            return
        if which("ifuse") is not None:
            outcome.warnings.append(
                "ifuse is present but interactive mount is not used in unattended acquire; "
                "falling back to pymobiledevice3 AFC if available."
            )
        if self._collect_afc_via_pymobiledevice3(device_id, media_dir, outcome, progress, cancel):
            return

        outcome.coverage_gaps.append(
            "Neither afcclient nor pymobiledevice3 AFC is available — the media partition "
            "(DCIM, PhotoData, Downloads) was not collected over AFC. An iTunes/Finder "
            "backup still includes Camera Roll and many app domains; use backup / "
            "advanced_logical for WhatsApp and photos."
        )

    def _collect_afc_via_afcclient(self, device_id, media_dir, outcome, progress, cancel) -> None:
        for remote in AFC_TARGETS:
            if cancel and cancel():
                outcome.interrupted = True
                outcome.errors.append(f"Cancelled by examiner before AFC pull of {remote}.")
                return
            local = media_dir / remote.strip("/")
            local.mkdir(parents=True, exist_ok=True)
            try:
                proc = run_tool(
                    ["afcclient", "-u", device_id, "get", remote, str(local)],
                    timeout=long_job_timeout(),
                )
                if proc.returncode != 0:
                    outcome.warnings.append(
                        f"AFC pull of {remote} returned {proc.returncode}: "
                        f"{(proc.stderr or '')[:200]}"
                    )
                    continue
                for path in local.rglob("*"):
                    if path.is_file():
                        outcome.files_written.append(str(path))
                        outcome.bytes_written += path.stat().st_size
                if progress:
                    progress(f"afc{remote}", outcome.bytes_written, None)
            except Exception as exc:
                outcome.warnings.append(f"AFC pull of {remote} failed: {exc}")

    def _collect_afc_via_pymobiledevice3(
        self, device_id, media_dir: Path, outcome, progress, cancel
    ) -> bool:
        """Pull AFC trees via pymobiledevice3 when afcclient is not on PATH."""
        try:
            from pymobiledevice3.lockdown import create_using_usbmux
            from pymobiledevice3.services.afc import AfcService
        except Exception:
            return False

        from app.services.mobile_acquire.ios_usbmux import call_maybe_async

        def _safe_name(name: str) -> str:
            return re.sub(r'[<>:"|?*]', "_", name).rstrip(" .")

        try:
            lockdown = call_maybe_async(create_using_usbmux, serial=device_id)
            afc = AfcService(lockdown)
            pulled_any = False
            for remote in AFC_TARGETS:
                if cancel and cancel():
                    outcome.interrupted = True
                    outcome.errors.append(
                        f"Cancelled by examiner before AFC pull of {remote}."
                    )
                    return True
                local = media_dir.joinpath(*remote.strip("/").split("/"))
                local.mkdir(parents=True, exist_ok=True)
                try:
                    exists = call_maybe_async(afc.exists, remote)
                    if not exists:
                        outcome.warnings.append(f"AFC path not present on device: {remote}")
                        continue
                    try:
                        call_maybe_async(afc.pull, remote, str(local))
                    except OSError as exc:
                        outcome.warnings.append(
                            f"pymobiledevice3 AFC pull of {remote} skipped illegal name: {exc}"
                        )
                    for path in list(local.rglob("*")):
                        if path.is_file():
                            if any(c in path.name for c in '<>:"|?*'):
                                safe = path.with_name(_safe_name(path.name))
                                try:
                                    path.rename(safe)
                                    path = safe
                                except OSError:
                                    pass
                            outcome.files_written.append(str(path))
                            outcome.bytes_written += path.stat().st_size
                            pulled_any = True
                    if progress:
                        progress(f"afc{remote}", outcome.bytes_written, None)
                except Exception as exc:
                    outcome.warnings.append(
                        f"pymobiledevice3 AFC pull of {remote} failed: {exc}"
                    )
            closer = getattr(afc, "close", None)
            if callable(closer):
                try:
                    call_maybe_async(closer)
                except Exception:
                    pass
        except Exception as exc:
            outcome.warnings.append(f"pymobiledevice3 AFC collection failed: {exc}")
            return False

        if pulled_any:
            outcome.warnings.append(
                "AFC media collected via pymobiledevice3 (afcclient not installed)."
            )
        return True

    def _collect_house_arrest(self, device_id, dest: Path, outcome, progress, cancel) -> None:
        """Pull WhatsApp app containers. iOS-only; Android adapters must not call this."""
        try:
            from pymobiledevice3.exceptions import AppNotInstalledError
            from pymobiledevice3.lockdown import create_using_usbmux
            from pymobiledevice3.services.house_arrest import HouseArrestService
        except Exception as exc:
            outcome.warnings.append(f"house_arrest unavailable: {exc}")
            return

        from app.services.mobile_acquire.ios_usbmux import call_maybe_async

        house_dir = dest / "house_arrest"
        house_dir.mkdir(parents=True, exist_ok=True)
        for bundle in IOS_HOUSE_ARREST_BUNDLES:
            if cancel and cancel():
                outcome.interrupted = True
                outcome.errors.append(f"Cancelled by examiner before house_arrest of {bundle}.")
                return
            local = house_dir / bundle
            local.mkdir(parents=True, exist_ok=True)
            if progress:
                progress(f"house_arrest/{bundle}", outcome.bytes_written, None)
            try:
                lockdown = call_maybe_async(create_using_usbmux, serial=device_id)
                svc = HouseArrestService(lockdown, bundle_id=bundle, documents_only=False)
                try:
                    call_maybe_async(svc.pull, "/", str(local))
                except Exception as exc:
                    outcome.warnings.append(f"house_arrest {bundle} container: {exc}")
                    try:
                        call_maybe_async(svc.pull, "/Documents", str(local / "Documents"))
                    except Exception as exc2:
                        outcome.warnings.append(f"house_arrest {bundle} Documents: {exc2}")
                for path in local.rglob("*"):
                    if path.is_file():
                        outcome.files_written.append(str(path))
                        try:
                            outcome.bytes_written += path.stat().st_size
                        except OSError:
                            pass
                closer = getattr(svc, "close", None)
                if callable(closer):
                    try:
                        call_maybe_async(closer)
                    except Exception:
                        pass
            except AppNotInstalledError:
                outcome.warnings.append(f"house_arrest: {bundle} is not installed")
            except Exception as exc:
                outcome.warnings.append(f"house_arrest {bundle}: {exc}")