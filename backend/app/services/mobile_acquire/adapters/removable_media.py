"""SIM and removable-media acquisition — Architecture §5 and §6.

Two separate evidence classes that both arrive through a reader rather than the
handset:

  SIM/USIM     ICCID, IMSI, ADN/LND phonebook, SMS records, last registered
               network. Small, fast, and independent of handset lock state — so
               it is usually the FIRST thing acquired.
  memory card  A block device. Acquired as a raw image through a write blocker,
               never mounted read-write, so unallocated space and deleted files
               survive.

§5 requires read-only handling of removable media. `verify_write_blocked` makes
that an explicit, recorded check rather than an assumption, because "I believe
the blocker was engaged" is not something an examiner should have to say.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from app.services.mobile_acquire.adapters.base import (
    AcquisitionOutcome,
    ProgressFn,
    run_tool,
    which,
)
from app.services.mobile_acquire.device_profile import ConnectionMode, DeviceProfile
from app.services.mobile_acquire.integrity import HashingWriter
from app.services.mobile_acquire.methods import CollectionMethod


class SimReaderAdapter:
    name = "sim_reader"
    os_family = "sim"

    def tool_available(self) -> bool:
        return which("scriptor") is not None or which("pcsc_scan") is not None

    def detect(self) -> list[str]:
        if which("pcsc_scan") is None:
            return []
        try:
            out = run_tool(["pcsc_scan", "-r"], timeout=30)
            return [line.strip() for line in out.stdout.splitlines()
                    if line.strip() and "reader" in line.lower()]
        except Exception:
            return []

    def identify(self, device_id: str) -> DeviceProfile:
        profile = DeviceProfile(os_family="sim", serial=device_id)
        profile.connection_mode = ConnectionMode.SIM_READER
        profile.required_cable = "PC/SC SIM reader"
        profile.observations.append(
            "SIM contents are independent of the handset lock state and should be "
            "acquired before any handset method."
        )
        return profile

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]:
        return [CollectionMethod.SIM] if self.tool_available() else []

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        if not self.tool_available():
            return ["No PC/SC SIM reader tooling found on this workstation."]
        return []

    def acquire(
        self,
        *,
        profile: DeviceProfile,
        method: CollectionMethod,
        destination: Path,
        progress: ProgressFn | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> AcquisitionOutcome:
        outcome = AcquisitionOutcome(ok=False, adapter=self.name, method=CollectionMethod.SIM)
        destination.mkdir(parents=True, exist_ok=True)
        outcome.errors.append(
            "SIM acquisition requires a validated PC/SC reader workflow. Record the card "
            "identifiers (ICCID printed on the card and read electronically) and acquire "
            "through the approved reader; do not report an absent SIM as an empty result."
        )
        outcome.coverage_gaps.append(
            "SIM/USIM records (ICCID, IMSI, ADN phonebook, on-card SMS, last registered "
            "network) were not collected in this run."
        )
        return outcome


class RemovableMediaAdapter:
    """Raw image of an SD/microSD card through a write blocker."""

    name = "removable_media"
    os_family = "removable"

    def tool_available(self) -> bool:
        return True  # raw read needs no external binary

    def detect(self) -> list[str]:
        """List candidate block devices (Linux acquisition host)."""
        block = Path("/sys/block")
        if not block.is_dir():
            return []
        candidates: list[str] = []
        for entry in sorted(block.iterdir()):
            name = entry.name
            if not re.match(r"^(sd[a-z]+|mmcblk\d+|nvme\d+n\d+)$", name):
                continue
            removable = entry / "removable"
            try:
                if removable.is_file() and removable.read_text().strip() == "1":
                    candidates.append(f"/dev/{name}")
                elif name.startswith("mmcblk"):
                    candidates.append(f"/dev/{name}")
            except OSError:
                continue
        return candidates

    def identify(self, device_id: str) -> DeviceProfile:
        profile = DeviceProfile(os_family="removable", serial=device_id)
        profile.connection_mode = ConnectionMode.CARD_READER
        profile.sd_card_present = True
        profile.sd_card_identifier = device_id
        node = Path(device_id).name
        for attr, path in (
            ("model", f"/sys/block/{node}/device/name"),
            ("manufacturer", f"/sys/block/{node}/device/manfid"),
        ):
            try:
                value = Path(path).read_text().strip()
                if value:
                    setattr(profile, attr, value)
            except OSError:
                pass
        try:
            sectors = int(Path(f"/sys/block/{node}/size").read_text().strip())
            profile.observations.append(f"Reported capacity: {sectors * 512} bytes.")
        except (OSError, ValueError):
            profile.observations.append("Capacity could not be read from sysfs.")
        return profile

    def supported_methods(self, profile: DeviceProfile) -> list[CollectionMethod]:
        return [CollectionMethod.MEMORY_CARD]

    def verify_write_blocked(self, device_path: str) -> tuple[bool, str]:
        """Check the kernel reports the device read-only (§5.1).

        Returns (blocked, evidence_text). A False here must stop the acquisition:
        mounting a card read-write updates access times and can destroy evidence.
        """
        node = Path(device_path).name
        ro_path = Path(f"/sys/block/{node}/ro")
        try:
            value = ro_path.read_text().strip()
            if value == "1":
                return True, f"{ro_path} reports 1 (read-only)."
            return False, (
                f"{ro_path} reports {value}. The device is NOT write-protected at the "
                "kernel level. Engage a hardware write blocker before acquiring."
            )
        except OSError as exc:
            return False, f"Could not read {ro_path}: {exc}. Treat as NOT write-blocked."

    def preflight(self, profile: DeviceProfile, method: CollectionMethod) -> list[str]:
        blocked, evidence = self.verify_write_blocked(profile.serial)
        if not blocked:
            return [f"Write protection not confirmed. {evidence}"]
        return []

    def acquire(
        self,
        *,
        profile: DeviceProfile,
        method: CollectionMethod,
        destination: Path,
        progress: ProgressFn | None = None,
        cancel: Callable[[], bool] | None = None,
        block_size: int = 1 << 20,
    ) -> AcquisitionOutcome:
        outcome = AcquisitionOutcome(
            ok=False, adapter=self.name, method=CollectionMethod.MEMORY_CARD)
        destination.mkdir(parents=True, exist_ok=True)

        blocked, evidence = self.verify_write_blocked(profile.serial)
        outcome.device_metadata["write_block_check"] = evidence
        if not blocked:
            outcome.errors.append(
                f"Refusing to acquire without confirmed write protection. {evidence}"
            )
            return outcome

        target = destination / f"{Path(profile.serial).name}.raw"
        bad_sectors = 0
        try:
            with HashingWriter(target, progress=lambda n: progress and progress(
                    target.name, n, None)) as writer, \
                    open(profile.serial, "rb") as source:
                while True:
                    if cancel and cancel():
                        outcome.interrupted = True
                        outcome.errors.append("Cancelled by examiner mid-image.")
                        break
                    try:
                        chunk = source.read(block_size)
                    except OSError:
                        # A read error must not abort the image: pad and continue so
                        # the sectors after a bad region are still recovered.
                        bad_sectors += 1
                        source.seek(block_size, 1)
                        chunk = b"\x00" * block_size
                        outcome.warnings.append(
                            f"Read error at offset {writer.bytes_written}; region padded "
                            "with zeroes and imaging continued."
                        )
                    if not chunk:
                        break
                    writer.write(chunk)

            outcome.files_written.append(str(target))
            outcome.bytes_written = writer.bytes_written
            outcome.device_metadata.update({
                "digests": writer.digests,
                "bytes": writer.bytes_written,
                "bad_regions": bad_sectors,
            })
            outcome.ok = not outcome.interrupted
            if bad_sectors:
                outcome.coverage_gaps.append(
                    f"{bad_sectors} region(s) could not be read and were zero-padded. "
                    "Data in those regions is unrecoverable by this method."
                )
        except PermissionError:
            outcome.errors.append(
                f"Permission denied opening {profile.serial}. Raw device imaging requires "
                "elevated privileges on the acquisition workstation."
            )
        except Exception as exc:
            outcome.errors.append(f"Imaging failed: {exc}")
        return outcome
