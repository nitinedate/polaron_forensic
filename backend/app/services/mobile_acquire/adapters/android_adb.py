"""Android acquisition over ADB — Architecture §5, §6, §7.

Uses only documented Android interfaces: adb shell/pull/exec-out and the
`bu`/`backup` agent. There is deliberately no lock-bypass, bootloader-exploit or
chipset-recovery path here — those require vendor entitlement and are out of
scope for this module. Where a method is unavailable the adapter says so and the
orchestrator records a capability gap (§20) instead of an empty result.

Collection targets are driven by the Android artifact scope pack, so acquisition
and later extraction filtering agree on what "everything relevant" means.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from app.services.mobile_acquire.adapters.base import (
    AcquisitionOutcome,
    ProgressFn,
    ToolUnavailable,
    long_job_timeout,
    run_tool,
    stream_tool,
    which,
)
from app.services.mobile_acquire.device_profile import (
    ConnectionMode,
    DeviceProfile,
    LockState,
)
from app.services.mobile_acquire.integrity import HashingWriter
from app.services.mobile_acquire.methods import CollectionMethod

from app.services.mobile_acquire.app_catalog import ANDROID_SHARED_EXTRA

# Shared-storage trees reachable without root. Ordered most- to least-valuable so
# an interrupted run still captures the highest-value data first.
SHARED_STORAGE_TARGETS: tuple[str, ...] = (
    "/sdcard/Android/media/com.whatsapp",
    "/sdcard/Android/media/com.whatsapp.w4b",
    "/sdcard/Android/media/org.telegram.messenger",
    "/sdcard/Android/media/com.instagram.android",
    "/sdcard/Android/data/com.whatsapp",
    "/sdcard/Android/data/com.whatsapp.w4b",
    "/sdcard/Android/data/org.telegram.messenger",
) + ANDROID_SHARED_EXTRA + (
    "/sdcard/Android/media",
    "/sdcard/Android/data",
    "/sdcard/WhatsApp",
    "/sdcard/WhatsApp Business",
    "/sdcard/Telegram",
    "/sdcard/DCIM",
    "/sdcard/Pictures",
    "/sdcard/Movies",
    "/sdcard/Video",
    "/sdcard/Videos",
    "/sdcard/Download",
    "/sdcard/Downloads",
    "/sdcard/Documents",
    "/sdcard/Music",
    "/sdcard/Audio",
    "/sdcard/Recordings",
    "/sdcard/Sounds",
    "/sdcard/Ringtones",
    "/sdcard/Notifications",
    "/sdcard/Podcasts",
    "/sdcard/Backups",
    "/sdcard/bluetooth",
    "/sdcard/MIUI/sound_recorder",
    "/sdcard/Record/Sound",
)

# Privileged trees — only reachable when the device reports root.
PRIVILEGED_TARGETS: tuple[str, ...] = (
    "/data/data",
    "/data/user",
    "/data/user_de",
    "/data/system",
    "/data/system_ce",
    "/data/system_de",
    "/data/misc",
    "/data/misc_ce",
    "/data/misc_de",
    "/data/media",
    "/data/app",
    "/data/tombstones",
    "/data/anr",
    "/data/log",
    "/data/adb",
    "/mnt/expand",
)

# Live-state commands captured as text evidence. These are volatile: they cannot
# be recovered later from an image, which is why they are collected first.
STATE_COMMANDS: dict[str, list[str]] = {
    "getprop.txt": ["shell", "getprop"],
    "packages_all.txt": ["shell", "pm", "list", "packages", "-f", "-u"],
    "packages_installed.txt": ["shell", "pm", "list", "packages", "-f"],
    "packages_disabled.txt": ["shell", "pm", "list", "packages", "-d"],
    "users.txt": ["shell", "pm", "list", "users"],
    "accounts.txt": ["shell", "dumpsys", "account"],
    "wifi.txt": ["shell", "dumpsys", "wifi"],
    "bluetooth.txt": ["shell", "dumpsys", "bluetooth_manager"],
    "usagestats.txt": ["shell", "dumpsys", "usagestats"],
    "batterystats.txt": ["shell", "dumpsys", "batterystats"],
    "netstats.txt": ["shell", "dumpsys", "netstats", "detail"],
    "notifications.txt": ["shell", "dumpsys", "notification", "--noredact"],
    "activities.txt": ["shell", "dumpsys", "activity", "activities"],
    "device_policy.txt": ["shell", "dumpsys", "device_policy"],
    "telephony.txt": ["shell", "dumpsys", "telephony.registry"],
    "location.txt": ["shell", "dumpsys", "location"],
    "mounts.txt": ["shell", "cat", "/proc/mounts"],
    "processes.txt": ["shell", "ps", "-A"],
    "logcat_main.txt": ["logcat", "-d", "-b", "all", "-v", "threadtime"],
}


class AndroidAdbAdapter:
    name = "android_adb"
    os_family = "android"

    def __init__(self, adb: str = "adb") -> None:
        self.adb = adb

    # ---------------- discovery ----------------

    def tool_available(self) -> bool:
        return which(self.adb) is not None

    def _adb(self, device_id: str | None, args: list[str], **kw):
        prefix = [self.adb] + (["-s", device_id] if device_id else [])
        return run_tool(prefix + args, **kw)

    def detect(self) -> list[str]:
        """Return connected serials. 'unauthorized' devices are reported too —
        an examiner needs to know a phone is attached but not yet trusted."""
        if not self.tool_available():
            raise ToolUnavailable(
                "adb not found. Install platform-tools on the acquisition workstation."
            )
        out = run_tool([self.adb, "devices", "-l"], timeout=30)
        devices: list[str] = []
        for line in out.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                devices.append(parts[0])
        return devices

    # ---------------- identify ----------------

    def _getprop(self, device_id: str) -> dict[str, str]:
        try:
            out = self._adb(device_id, ["shell", "getprop"], timeout=60)
        except Exception:
            return {}
        props: dict[str, str] = {}
        for match in re.finditer(r"^\[([^\]]+)\]: \[([^\]]*)\]$", out.stdout, re.M):
            props[match.group(1)] = match.group(2)
        return props

    def identify(self, device_id: str) -> DeviceProfile:
        profile = DeviceProfile(os_family="android", serial=device_id)

        state = ""
        try:
            state = self._adb(device_id, ["get-state"], timeout=20).stdout.strip()
        except Exception as exc:
            profile.observations.append(f"adb get-state failed: {exc}")

        if state != "device":
            profile.connection_mode = ConnectionMode.UNKNOWN
            profile.usb_debugging_authorized = False
            if state == "unauthorized":
                profile.observations.append(
                    "USB debugging is connected but not authorised. Unlock the phone and "
                    "tap Allow on the RSA fingerprint prompt. Shared storage may still be "
                    "available via MTP / file transfer (android_mtp) without ADB."
                )
            elif state == "offline":
                profile.observations.append(
                    "adb reports the device offline. Unplug/replug, disable Charge only, "
                    "and set USB mode to File transfer."
                )
            else:
                profile.observations.append(
                    f"Device is not in an authorised adb state (reported '{state or 'none'}'). "
                    "Accept the USB debugging prompt, or use MTP file transfer for shared storage."
                )
            return profile

        profile.connection_mode = ConnectionMode.ADB
        profile.usb_debugging_authorized = True

        props = self._getprop(device_id)
        profile.manufacturer = props.get("ro.product.manufacturer", "")
        profile.model = props.get("ro.product.model", "")
        profile.chipset = (props.get("ro.board.platform")
                           or props.get("ro.hardware") or "")
        profile.os_version = props.get("ro.build.version.release", "")
        profile.security_patch_level = props.get("ro.build.version.security_patch", "")
        profile.build_id = props.get("ro.build.fingerprint", "")
        profile.developer_mode = props.get("ro.debuggable", "0") == "1"

        crypto = props.get("ro.crypto.state", "")
        crypto_type = props.get("ro.crypto.type", "")
        if crypto == "encrypted":
            profile.encryption_state = "fbe" if crypto_type == "file" else "fde"
        elif crypto == "unencrypted":
            profile.encryption_state = "none"

        # Lock state: if adb shell can read a credential-encrypted path the device
        # is at least AFU. This is an observation, not an assumption.
        try:
            probe = self._adb(
                device_id,
                ["shell", "ls", "/data/user/0/", "2>/dev/null", "||", "echo", "DENIED"],
                timeout=30,
            ).stdout
            profile.lock_state = (
                LockState.LOCKED_AFU if "DENIED" not in probe and probe.strip()
                else LockState.LOCKED_UNKNOWN_STATE
            )
        except Exception:
            profile.lock_state = LockState.UNKNOWN

        try:
            su = self._adb(device_id, ["shell", "which", "su"], timeout=20).stdout.strip()
            root_probe = self._adb(
                device_id, ["shell", "su", "-c", "id"], timeout=20).stdout
            profile.rooted_or_jailbroken = bool(su) and "uid=0" in root_probe
        except Exception:
            profile.rooted_or_jailbroken = False

        for prop, attr in (("ro.serialno", "serial"),):
            if props.get(prop):
                setattr(profile, attr, props[prop])

        # IMEI requires a privileged call on modern Android; absence is recorded.
        try:
            imei = self._adb(
                device_id,
                ["shell", "service", "call", "iphonesubinfo", "1"],
                timeout=20,
            ).stdout
            digits = "".join(re.findall(r"'([^']*)'", imei)).replace(".", "").strip()
            profile.imei = re.sub(r"\D", "", digits)[:15]
        except Exception:
            pass
        if not profile.imei:
            profile.observations.append(
                "IMEI not readable over unprivileged adb — record it from the device "
                "label, packaging or *#06# and enter it manually."
            )

        try:
            batt = self._adb(device_id, ["shell", "dumpsys", "battery"], timeout=30).stdout
            match = re.search(r"level:\s*(\d+)", batt)
            if match:
                profile.battery_percent = int(match.group(1))
        except Exception:
            pass

        try:
            sd = self._adb(device_id, ["shell", "ls", "/mnt/expand"], timeout=20).stdout
            profile.sd_card_present = bool(sd.strip())
            if profile.sd_card_present:
                profile.observations.append(
                    "Adopted storage detected at /mnt/expand — this is a second encrypted "
                    "data volume and must be collected."
                )
        except Exception:
            pass

        profile.required_cable = "USB-A/USB-C validated data cable"
        return profile

    # ---------------- capability ----------------

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]:
        if profile.connection_mode != ConnectionMode.ADB:
            return []
        methods = [
            CollectionMethod.LOGICAL,
            CollectionMethod.BACKUP,
            CollectionMethod.ADVANCED_LOGICAL,
            CollectionMethod.FILE_SYSTEM,
            CollectionMethod.FULL_FILE_SYSTEM,
        ]
        if profile.rooted_or_jailbroken:
            methods.append(CollectionMethod.PHYSICAL)
        return methods

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        problems: list[str] = []
        if not self.tool_available():
            problems.append("adb is not installed on this workstation.")
        if profile.connection_mode != ConnectionMode.ADB:
            problems.append("Device is not connected in an authorised adb state.")
        if method == CollectionMethod.PHYSICAL and not profile.rooted_or_jailbroken:
            problems.append(
                "Physical imaging requires an already-rooted device (su + dd). "
                "No lock-bypass or bootloader exploit is used."
            )
        if profile.battery_percent is not None and profile.battery_percent < 15:
            problems.append(
                f"Battery at {profile.battery_percent}% — connect power before starting."
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
    ) -> AcquisitionOutcome:
        device_id = profile.serial
        outcome = AcquisitionOutcome(ok=True, adapter=self.name, method=method)
        destination.mkdir(parents=True, exist_ok=True)

        # 1. Volatile state first — it cannot be recovered later.
        self._collect_state(device_id, destination / "device_state", outcome, progress)

        if cancel and cancel():
            outcome.interrupted = True
            outcome.errors.append("Cancelled by examiner after device-state capture.")
            return outcome

        # 2. Method-specific payload.
        if method in (CollectionMethod.BACKUP, CollectionMethod.LOGICAL, CollectionMethod.ADVANCED_LOGICAL):
            from app.services.mobile_acquire.privileged_app_pull import pull_whatsapp_key_evidence
            keys = pull_whatsapp_key_evidence(adb=self.adb, serial=device_id,
                                             out=destination / "private_keys", cancel=cancel)
            outcome.bytes_written += int(keys.get("bytes") or 0)
            outcome.files_written.extend(record["case_file"] for record in keys.get("whatsapp_key_files", []))
            outcome.coverage_gaps.extend(keys.get("limitations") or [])
            outcome.errors.extend(keys.get("errors") or [])
            if keys.get("interrupted"):
                outcome.interrupted = True
                return outcome
        if method == CollectionMethod.BACKUP:
            # Shared media first — adb backup often omits large media and apps that
            # set allowBackup=false (WhatsApp typically). Pull what is reachable without root.
            self._pull_targets(device_id, SHARED_STORAGE_TARGETS,
                               destination / "shared_storage", outcome, progress, cancel)
            self._collect_backup(device_id, destination, outcome, progress)
            outcome.coverage_gaps.append(
                "Android backup + shared-storage pull. WhatsApp chat databases in "
                "/data/data are NOT collected without root. Shared WhatsApp media under "
                "/sdcard is collected when present. Deleted files in unallocated space "
                "require a physical/filesystem image."
            )
        elif method in (CollectionMethod.LOGICAL, CollectionMethod.ADVANCED_LOGICAL):
            self._pull_targets(device_id, SHARED_STORAGE_TARGETS,
                               destination / "shared_storage", outcome, progress, cancel)
            outcome.coverage_gaps.append(
                "Shared-storage collection covers DCIM, Downloads, Music, WhatsApp/Telegram "
                "media folders and Android/media where readable without root. Application "
                "private databases (/data/data), including WhatsApp msgstore.db, were NOT "
                "collected unless a deeper rooted method is used."
            )
            if method == CollectionMethod.ADVANCED_LOGICAL:
                self._collect_backup(device_id, destination, outcome, progress)
        elif method in (CollectionMethod.FILE_SYSTEM, CollectionMethod.FULL_FILE_SYSTEM):
            # ADB pull runs as shell on production phones even when su is
            # available. Read priority private apps with the already-provided
            # privilege before collecting the broad filesystem/shared trees.
            from app.services.mobile_acquire.privileged_app_pull import pull_debuggable_evidence, pull_private_evidence
            private = pull_private_evidence(adb=self.adb,serial=device_id,out=destination / "private_apps",cancel=cancel)
            if private.get("root_mode") == "unavailable":
                accessible = pull_debuggable_evidence(adb=self.adb,serial=device_id,out=destination / "private_apps",cancel=cancel)
                private["files"] = int(accessible.get("files") or 0)
                private["bytes"] = int(accessible.get("bytes") or 0)
                private["limitations"].extend(accessible.get("limitations") or [])
                private["errors"].extend(accessible.get("errors") or [])
            outcome.bytes_written += int(private.get("bytes") or 0)
            outcome.files_written.extend(str(path) for path in (destination / "private_apps").rglob("*") if path.is_file())
            outcome.coverage_gaps.extend(private.get("limitations") or [])
            outcome.errors.extend(private.get("errors") or [])
            if private.get("interrupted"):
                outcome.interrupted = True
                return outcome
            self._pull_targets(device_id, SHARED_STORAGE_TARGETS,
                               destination / "shared_storage", outcome, progress, cancel)
            self._pull_targets(device_id, PRIVILEGED_TARGETS,
                               destination / "data", outcome, progress, cancel)
        elif method == CollectionMethod.PHYSICAL:
            self._collect_physical(profile, destination, outcome, progress, cancel)
        else:
            outcome.ok = False
            outcome.errors.append(f"Method {method.value} is not implemented by this adapter.")
            return outcome

        outcome.device_metadata = profile.as_dict()
        if outcome.errors:
            outcome.ok = False
        return outcome

    def _resolve_userdata_partition(self, device_id: str | None) -> str | None:
        """Locate a userdata block device via /dev/block/by-name (rooted)."""
        try:
            result = self._adb(device_id, ["shell", "su", "-c", "ls /dev/block/by-name"], timeout=60)
        except Exception:
            return None
        names = (result.stdout or "").split()
        preferred = ("userdata", "userdata_a", "data", "userdata_b")
        for name in preferred:
            if name in names:
                return f"/dev/block/by-name/{name}"
        return None

    def _collect_physical(
        self,
        profile: DeviceProfile,
        destination: Path,
        outcome: AcquisitionOutcome,
        progress: ProgressFn | None,
        cancel: Callable[[], bool] | None,
    ) -> None:
        """Root-only physical: userdata .raw + shared storage sidecar (not vendor unlock)."""
        images = destination / "physical_images"
        images.mkdir(parents=True, exist_ok=True)
        partition = self._resolve_userdata_partition(profile.serial)
        if not partition:
            outcome.errors.append(
                "Could not resolve userdata partition under /dev/block/by-name. "
                "Physical imaging aborted — record as a capability gap (§20)."
            )
            outcome.coverage_gaps.append(
                "Physical acquisition requires a readable userdata block device. "
                "This is not Cellebrite-class unlock; locked unrooted devices remain unsupported."
            )
            return

        part_out = self.acquire_partition_image(
            profile=profile,
            partition=partition,
            destination=images,
            progress=progress,
        )
        outcome.files_written.extend(part_out.files_written)
        outcome.bytes_written += part_out.bytes_written
        outcome.warnings.extend(part_out.warnings)
        outcome.errors.extend(part_out.errors)
        if part_out.ok:
            outcome.ok = True
            outcome.coverage_gaps.append(
                "Physical image is a root dd of the userdata partition only. Bootloader, "
                "modem, and vendor unlock workflows are not performed (§10)."
            )
        else:
            outcome.ok = False

        if cancel and cancel():
            outcome.interrupted = True
            return
        # Sidecar shared storage for examiner convenience (not a substitute for the .raw).
        self._pull_targets(
            profile.serial,
            SHARED_STORAGE_TARGETS,
            destination / "shared_storage",
            outcome,
            progress,
            cancel,
        )

    # ---------------- internals ----------------

    def _collect_state(self, device_id, dest: Path, outcome, progress) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for filename, args in STATE_COMMANDS.items():
            try:
                result = self._adb(device_id, args, timeout=180)
                target = dest / filename
                target.write_text(result.stdout or "", encoding="utf-8", errors="replace")
                outcome.files_written.append(str(target))
                outcome.bytes_written += target.stat().st_size
                if progress:
                    progress(f"device_state/{filename}", outcome.bytes_written, None)
                if result.returncode != 0:
                    outcome.warnings.append(
                        f"{filename}: adb returned {result.returncode} "
                        f"({(result.stderr or '').strip()[:120]})"
                    )
            except Exception as exc:
                outcome.warnings.append(f"Device-state command '{filename}' failed: {exc}")

    def _collect_backup(self, device_id, dest: Path, outcome, progress) -> None:
        """`adb backup` via the bu agent. Deprecated by Google and honoured only
        by apps that have not set allowBackup=false — the gap is recorded."""
        target = dest / "android_backup" / "backup.ab"
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            args = [self.adb] + (["-s", device_id] if device_id else []) + [
                "backup", "-all", "-apk", "-obb", "-shared", "-system", "-f", str(target),
            ]
            proc = run_tool(args, timeout=long_job_timeout())
            if target.exists() and target.stat().st_size > 0:
                outcome.files_written.append(str(target))
                outcome.bytes_written += target.stat().st_size
                if progress:
                    progress("android_backup/backup.ab", outcome.bytes_written, None)
            else:
                outcome.warnings.append(
                    "adb backup produced no data. The device may require the on-screen "
                    "'Back up my data' confirmation, or the backup agent may be disabled."
                )
            if proc.returncode != 0:
                outcome.warnings.append(
                    f"adb backup returned {proc.returncode}: {(proc.stderr or '')[:200]}"
                )
        except Exception as exc:
            outcome.warnings.append(f"adb backup failed: {exc}")

        # Targeted social / mail app backups (many set allowBackup=false, but try).
        from app.services.mobile_acquire.app_catalog import ANDROID_SOCIAL_PACKAGES

        for pkg in ANDROID_SOCIAL_PACKAGES:
            label = pkg.replace(".", "_") + ".ab"
            self._collect_app_backup(device_id, dest, outcome, progress, pkg, label)

        outcome.coverage_gaps.append(
            "adb backup only includes applications that permit backup "
            "(android:allowBackup=true). WhatsApp, Signal and most banking apps opt out, "
            "so their absence from the .ab file is a tool limitation, not evidence of "
            "absence on the device. Shared social media under /sdcard is still collected "
            "via shared_storage when present. True /data/data chat DBs need root."
        )

    def _collect_app_backup(
        self,
        device_id,
        dest: Path,
        outcome,
        progress,
        package: str,
        filename: str,
    ) -> None:
        target = dest / "android_backup" / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            args = [self.adb] + (["-s", device_id] if device_id else []) + [
                "backup", "-f", str(target), "-apk", package,
            ]
            if progress:
                progress(f"android_backup/{filename}", outcome.bytes_written, None)
            proc = run_tool(args, timeout=long_job_timeout())
            if target.exists() and target.stat().st_size > 64:
                outcome.files_written.append(str(target))
                outcome.bytes_written += target.stat().st_size
                if progress:
                    progress(f"android_backup/{filename}", outcome.bytes_written, None)
            else:
                if target.exists() and target.stat().st_size <= 64:
                    try:
                        target.unlink()
                    except OSError:
                        pass
                outcome.warnings.append(
                    f"Targeted adb backup of {package} produced no usable data "
                    f"(allowBackup likely false, or on-screen confirm was declined). "
                    f"exit={proc.returncode}"
                )
        except Exception as exc:
            outcome.warnings.append(f"Targeted backup of {package} failed: {exc}")

    def _pull_targets(self, device_id, targets, dest: Path, outcome, progress, cancel) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for remote in targets:
            if cancel and cancel():
                outcome.interrupted = True
                outcome.errors.append(f"Cancelled by examiner before pulling {remote}.")
                return
            local = dest / remote.strip("/").replace("/", "_")
            try:
                proc = self._adb(device_id, ["pull", "-a", remote, str(local)], timeout=long_job_timeout())
                if proc.returncode != 0:
                    outcome.warnings.append(
                        f"Could not pull {remote}: {(proc.stderr or proc.stdout or '')[:200]}"
                    )
                    continue
                pulled = 0
                for path in local.rglob("*"):
                    if path.is_file():
                        outcome.files_written.append(str(path))
                        pulled += path.stat().st_size
                outcome.bytes_written += pulled
                if progress:
                    progress(remote, outcome.bytes_written, None)
            except Exception as exc:
                outcome.warnings.append(f"Pull of {remote} failed: {exc}")

    def acquire_partition_image(
        self,
        *,
        profile: DeviceProfile,
        partition: str,
        destination: Path,
        progress: ProgressFn | None = None,
    ) -> AcquisitionOutcome:
        """Root-only block-level read of a named partition, hashed inline.

        Requires an already-rooted device; this performs no privilege escalation.
        """
        outcome = AcquisitionOutcome(
            ok=False, adapter=self.name, method=CollectionMethod.PHYSICAL)
        if not profile.rooted_or_jailbroken:
            outcome.errors.append(
                "Block-level acquisition requires root. Not available on this device — "
                "record the capability gap rather than reporting an empty image."
            )
            return outcome

        target = destination / f"{Path(partition).name}.raw"
        args = [self.adb] + (["-s", profile.serial] if profile.serial else []) + [
            "exec-out", "su", "-c", f"dd if={partition} bs=1M",
        ]
        try:
            with HashingWriter(target, progress=lambda n: progress and progress(
                    str(target.name), n, None)) as writer:
                for chunk in stream_tool(args):
                    writer.write(chunk)
            outcome.ok = True
            outcome.files_written.append(str(target))
            outcome.bytes_written = writer.bytes_written
            outcome.device_metadata = {
                "partition": partition,
                "digests": writer.digests,
                "bytes": writer.bytes_written,
            }
        except Exception as exc:
            outcome.errors.append(f"Partition image of {partition} failed: {exc}")
        return outcome
