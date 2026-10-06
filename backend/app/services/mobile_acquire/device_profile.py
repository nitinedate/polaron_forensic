"""Device profile and capability resolution — Architecture §3.2 and §3.3.

Capability decision model (§3.3):

    device identity + OS/security version + chipset + lock/encryption state
    + tool version + licence entitlement  ->  supported collection flow

The important discipline here is that `DeviceProfile` records what was OBSERVED,
and `resolve_capability` turns observations into a supported-method list. Nothing
is inferred from the marketing model name: an unread field stays unknown and
surfaces as a warning, because "we could not determine the lock state" and "the
device was unlocked" have very different evidential weight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.mobile_acquire.methods import CollectionMethod


class LockState(str):
    UNKNOWN = "unknown"
    UNLOCKED = "unlocked"                   # user-authenticated, screen accessible
    LOCKED_AFU = "locked_after_first_unlock"  # booted and unlocked at least once
    LOCKED_BFU = "locked_before_first_unlock"  # cold boot, keys not derived
    LOCKED_UNKNOWN_STATE = "locked_state_unknown"


class ConnectionMode(str):
    UNKNOWN = "unknown"
    ADB = "adb"                     # Android Debug Bridge, USB debugging authorised
    MTP = "mtp"                     # media transfer, user storage only
    AFC = "afc"                     # Apple File Conduit over lockdownd
    LOCKDOWN = "lockdown"           # trusted pairing established
    RECOVERY = "recovery"
    FASTBOOT = "fastboot"
    SIM_READER = "sim_reader"
    CARD_READER = "card_reader"


@dataclass
class DeviceProfile:
    """§3.2 device profile and capability layer — observations only."""

    # Identity
    manufacturer: str = ""
    model: str = ""
    chipset: str = ""
    serial: str = ""
    imei: str = ""
    udid: str = ""

    # Operating system
    os_family: str = ""             # android | ios
    os_version: str = ""
    security_patch_level: str = ""
    build_id: str = ""

    # State
    lock_state: str = LockState.UNKNOWN
    encryption_state: str = "unknown"       # fbe | fde | none | unknown
    connection_mode: str = ConnectionMode.UNKNOWN
    usb_debugging_authorized: bool = False
    pairing_trusted: bool = False
    developer_mode: bool = False
    rooted_or_jailbroken: bool | None = None
    battery_percent: int | None = None
    network_isolated: bool | None = None

    # Removable media
    sim_present: bool | None = None
    iccid: str = ""
    imsi: str = ""
    sd_card_present: bool | None = None
    sd_card_identifier: str = ""

    # Environment
    tool_version: str = ""
    license_entitlements: tuple[str, ...] = ()
    required_cable: str = ""

    observations: list[str] = field(default_factory=list)

    @property
    def device_label(self) -> str:
        parts = [p for p in (self.manufacturer, self.model) if p]
        return " ".join(parts) or (self.serial or self.udid or "UNKNOWN-DEVICE")

    def unknown_fields(self) -> list[str]:
        """Fields that could not be determined — each is a reportable limitation."""
        unknown: list[str] = []
        if not self.manufacturer or not self.model:
            unknown.append("device_identity")
        if not self.os_version:
            unknown.append("os_version")
        if not self.security_patch_level:
            if not ((self.os_family or "").lower() == "ios" and self.build_id):
                unknown.append("security_patch_level")
        if self.lock_state == LockState.UNKNOWN:
            unknown.append("lock_state")
        if self.encryption_state == "unknown":
            unknown.append("encryption_state")
        if self.serial == "" and self.imei == "" and self.udid == "":
            unknown.append("unique_identifier")
        return unknown

    def as_dict(self) -> dict[str, Any]:
        return {
            "manufacturer": self.manufacturer,
            "model": self.model,
            "device_label": self.device_label,
            "chipset": self.chipset,
            "serial": self.serial,
            "imei": self.imei,
            "udid": self.udid,
            "os_family": self.os_family,
            "os_version": self.os_version,
            "security_patch_level": self.security_patch_level,
            "build_id": self.build_id,
            "lock_state": self.lock_state,
            "encryption_state": self.encryption_state,
            "connection_mode": self.connection_mode,
            "usb_debugging_authorized": self.usb_debugging_authorized,
            "pairing_trusted": self.pairing_trusted,
            "developer_mode": self.developer_mode,
            "rooted_or_jailbroken": self.rooted_or_jailbroken,
            "battery_percent": self.battery_percent,
            "network_isolated": self.network_isolated,
            "sim_present": self.sim_present,
            "iccid": self.iccid,
            "imsi": self.imsi,
            "sd_card_present": self.sd_card_present,
            "sd_card_identifier": self.sd_card_identifier,
            "tool_version": self.tool_version,
            "license_entitlements": list(self.license_entitlements),
            "required_cable": self.required_cable,
            "unknown_fields": self.unknown_fields(),
            "observations": self.observations,
        }


@dataclass
class Capability:
    """Resolved outcome of the §3.3 capability decision model."""

    supported_methods: list[CollectionMethod] = field(default_factory=list)
    blocked_methods: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    preparation_steps: list[str] = field(default_factory=list)
    label: str = "VALIDATION_PENDING"

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_label": self.label,
            "supported_methods": [m.value for m in self.supported_methods],
            "blocked_methods": self.blocked_methods,
            "warnings": self.warnings,
            "preparation_steps": self.preparation_steps,
        }


def resolve_capability(profile: DeviceProfile) -> Capability:
    """Turn observed device state into a supported-method list.

    Deliberately conservative: a method is only listed as supported when the
    observed state is sufficient for it. Where state is unknown the method is
    blocked with the reason, not offered optimistically.
    """
    cap = Capability()
    fam = (profile.os_family or "").strip().lower()

    # --- removable media are independent of handset state ---------------------
    if profile.sim_present:
        cap.supported_methods.append(CollectionMethod.SIM)
    elif profile.sim_present is None:
        cap.blocked_methods[CollectionMethod.SIM.value] = "SIM presence not determined."
    if profile.sd_card_present:
        cap.supported_methods.append(CollectionMethod.MEMORY_CARD)
        cap.preparation_steps.append(
            "Remove the card and acquire through a write-blocked reader rather than "
            "through the handset (§5)."
        )

    # --- lock state gates everything on the handset ---------------------------
    if profile.lock_state == LockState.LOCKED_BFU:
        for m in (CollectionMethod.LOGICAL, CollectionMethod.ADVANCED_LOGICAL,
                  CollectionMethod.FILE_SYSTEM, CollectionMethod.FULL_FILE_SYSTEM,
                  CollectionMethod.BACKUP):
            cap.blocked_methods[m.value] = (
                "Device is locked before first unlock; file keys are not derived and "
                "user data is not readable."
            )
        cap.label = "DEVICE_UNLOCK_REQUIRED"
        cap.warnings.append(
            "BFU state. Do NOT power-cycle the device — a device already in AFU must not "
            "be rebooted, as that discards derived keys."
        )
        return cap

    if profile.lock_state == LockState.UNKNOWN:
        cap.warnings.append(
            "Lock state was not determined. Document this as a limitation; do not record "
            "the device as unlocked."
        )

    # --- Android --------------------------------------------------------------
    if fam == "android":
        if profile.connection_mode == ConnectionMode.ADB and profile.usb_debugging_authorized:
            cap.supported_methods.extend([
                CollectionMethod.LOGICAL,
                CollectionMethod.BACKUP,
                CollectionMethod.ADVANCED_LOGICAL,
                CollectionMethod.FILE_SYSTEM,
                CollectionMethod.FULL_FILE_SYSTEM,
            ])
            if profile.rooted_or_jailbroken:
                cap.supported_methods.append(CollectionMethod.PHYSICAL)
                cap.warnings.append(
                    "Device reports root. Root changes the integrity assumptions for every "
                    "artifact recovered and must be stated in the report."
                )
                cap.blocked_methods.pop(CollectionMethod.PHYSICAL.value, None)
            else:
                cap.warnings.append(
                    "Full /data/data requires an already-rooted handset or adb root "
                    "(userdebug). Production builds still expose the accessible filesystem "
                    "(/sdcard, Android/media including WhatsApp media and crypt14 backups)."
                )
                cap.blocked_methods[CollectionMethod.PHYSICAL.value] = (
                    "Physical .raw imaging requires an already-rooted device (su + dd). "
                    "Vendor unlock / bootloader exploit paths are not implemented (§10)."
                )
            cap.label = "SUPPORTED_DIRECT_LOGICAL"
        elif profile.connection_mode == ConnectionMode.MTP:
            cap.supported_methods.extend([
                CollectionMethod.LOGICAL,
                CollectionMethod.ADVANCED_LOGICAL,
                CollectionMethod.BACKUP,
                CollectionMethod.FILE_SYSTEM,
                CollectionMethod.FULL_FILE_SYSTEM,
            ])
            cap.warnings.append(
                "Host USB collection uses ADB when debugging is authorised, otherwise MTP. "
                "Select File System / Full File System to stream shared storage (WhatsApp media) "
                "and attempt /data/data only if the phone is already rooted. No lock bypass."
            )
            cap.label = "SUPPORTED_DIRECT_LOGICAL"
        else:
            cap.blocked_methods["*"] = (
                "No authorised data connection. Enable USB debugging and accept the RSA "
                "prompt on the device, or use MTP for shared storage only."
            )
            cap.preparation_steps.append(
                "Connect the validated data cable, set USB mode to file transfer, and "
                "authorise the workstation RSA fingerprint on the device screen (§5)."
            )
            cap.label = "DEVICE_UNLOCK_REQUIRED"

        if CollectionMethod.PHYSICAL.value not in cap.blocked_methods \
                and CollectionMethod.PHYSICAL not in cap.supported_methods:
            cap.blocked_methods.setdefault(
                CollectionMethod.PHYSICAL.value,
                "Physical acquisition depends on chipset, bootloader state, encryption and "
                "root. Not assumed available (§6.1).",
            )

    # --- iOS ------------------------------------------------------------------
    elif fam == "ios":
        if profile.pairing_trusted and profile.connection_mode in (
            ConnectionMode.LOCKDOWN, ConnectionMode.AFC,
        ):
            cap.supported_methods.extend([
                CollectionMethod.LOGICAL,
                CollectionMethod.BACKUP,
                CollectionMethod.ADVANCED_LOGICAL,
            ])
            cap.label = "SUPPORTED_BACKUP"
            cap.preparation_steps.append(
                "Set a known backup password before acquisition: an ENCRYPTED iTunes "
                "backup includes keychain, Health and Safari history that an unencrypted "
                "backup omits entirely. Record the password in the case file."
            )
            if profile.rooted_or_jailbroken:
                cap.supported_methods.append(CollectionMethod.FULL_FILE_SYSTEM)
        else:
            cap.blocked_methods["*"] = (
                "No trusted pairing. The device must be unlocked and 'Trust This Computer' "
                "accepted, or a valid pairing/escrow record supplied from a associated host."
            )
            cap.preparation_steps.append(
                "Unlock the device with the lawful passcode and accept the trust prompt; "
                "alternatively recover the lockdown pairing record from a seized computer "
                "(/var/db/lockdown on macOS)."
            )
            cap.label = "DEVICE_UNLOCK_REQUIRED"

        cap.blocked_methods.setdefault(
            CollectionMethod.PHYSICAL.value,
            "Physical acquisition of modern iOS devices is not available through documented "
            "interfaces. Do not offer it (§6.1).",
        )

    else:
        cap.blocked_methods["*"] = (
            f"Unrecognised device family '{profile.os_family or 'unknown'}'. Resolve the "
            "device profile before selecting a method."
        )
        cap.label = "VALIDATION_PENDING"

    # De-duplicate while preserving order.
    cap.supported_methods = list(dict.fromkeys(cap.supported_methods))

    if profile.battery_percent is not None and profile.battery_percent < 20:
        cap.warnings.append(
            f"Battery at {profile.battery_percent}%. Connect external power before starting: "
            "an interruption mid-acquisition invalidates the run."
        )
    if profile.network_isolated is False:
        cap.warnings.append(
            "Device is NOT network isolated. Remote wipe and message sync remain possible — "
            "isolate before collection (§13.2)."
        )
    for unknown in profile.unknown_fields():
        cap.warnings.append(f"Device profile field not determined: {unknown}.")

    if not cap.supported_methods and cap.label not in ("DEVICE_UNLOCK_REQUIRED",):
        cap.label = "UNSUPPORTED_DIRECT_ACQUISITION"
    return cap
