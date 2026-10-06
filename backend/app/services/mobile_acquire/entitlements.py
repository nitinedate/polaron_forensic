"""Licence and entitlement layer — Architecture §3.3.

The capability decision model is:

    device identity + OS/security version + chipset + lock/encryption state
    + tool version + LICENCE ENTITLEMENT  ->  supported collection flow

Everything except the last term is already modelled in `device_profile`. This
module supplies entitlement, and it exists to make one distinction impossible to
blur:

    "we are not licensed for this"   is NOT   "this device does not support it"

Both produce an unavailable method, but only the first is fixable by procurement
and neither may be reported as an absence of evidence. `explain` returns text
that names which of the two applies, so the limitation written into the report is
accurate about why the data was not obtained.

Entitlements are declared, not discovered. There is no licence-server call here:
the lab states what it holds, that statement goes under change control with the
installer, and the capability model consumes it. A lab that has not declared
anything gets the documented open-interface baseline, which is what the shipped
adapters actually implement.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.mobile_acquire.methods import CollectionMethod


class Entitlement(str):
    """Named capabilities a lab may hold a licence for."""

    LOGICAL = "logical_collection"
    ADVANCED_LOGICAL = "advanced_logical_collection"
    FILE_SYSTEM = "filesystem_collection"
    FULL_FILE_SYSTEM = "full_filesystem_collection"
    PHYSICAL = "physical_collection"
    SIM = "sim_collection"
    REMOVABLE_MEDIA = "removable_media_collection"
    ADVANCED_ACCESS = "advanced_access"       # separately licensed unlock workflows
    CLOUD_ACQUISITION = "cloud_acquisition"


# Methods the shipped adapters implement using documented interfaces only. These
# require no vendor licence, so they are the default entitlement set.
OPEN_INTERFACE_ENTITLEMENTS: frozenset[str] = frozenset({
    Entitlement.LOGICAL,
    Entitlement.ADVANCED_LOGICAL,
    Entitlement.FILE_SYSTEM,
    Entitlement.FULL_FILE_SYSTEM,
    Entitlement.PHYSICAL,  # Android root dd → .raw only; not vendor unlock
    Entitlement.SIM,
    Entitlement.REMOVABLE_MEDIA,
})

METHOD_ENTITLEMENT: dict[CollectionMethod, str] = {
    CollectionMethod.LOGICAL: Entitlement.LOGICAL,
    CollectionMethod.BACKUP: Entitlement.LOGICAL,
    CollectionMethod.ADVANCED_LOGICAL: Entitlement.ADVANCED_LOGICAL,
    CollectionMethod.FILE_SYSTEM: Entitlement.FILE_SYSTEM,
    CollectionMethod.FULL_FILE_SYSTEM: Entitlement.FULL_FILE_SYSTEM,
    CollectionMethod.PHYSICAL: Entitlement.PHYSICAL,
    CollectionMethod.SIM: Entitlement.SIM,
    CollectionMethod.MEMORY_CARD: Entitlement.REMOVABLE_MEDIA,
}

# Capabilities the shipped code does not implement at all. Holding a licence does
# not make these work here — the licence would have to be exercised through the
# vendor's own tooling. Keeping the two facts separate prevents a lab from
# believing a purchase enabled something in this platform that it did not.
NOT_IMPLEMENTED_HERE: frozenset[str] = frozenset({
    Entitlement.ADVANCED_ACCESS,  # Cellebrite-class unlock / checkm8 / PA services
    Entitlement.CLOUD_ACQUISITION,
})


@dataclass
class LicenceProfile:
    """What this endpoint is licensed and equipped to do."""

    endpoint_id: str = ""
    licensee: str = ""
    entitlements: frozenset[str] = field(default=OPEN_INTERFACE_ENTITLEMENTS)
    expires_utc: str | None = None
    notes: str = ""

    # ---------- state ----------

    @property
    def expired(self) -> bool:
        if not self.expires_utc:
            return False
        try:
            when = datetime.fromisoformat(self.expires_utc)
        except ValueError:
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when < datetime.now(timezone.utc)

    @property
    def days_remaining(self) -> int | None:
        if not self.expires_utc:
            return None
        try:
            when = datetime.fromisoformat(self.expires_utc)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return int((when - datetime.now(timezone.utc)).total_seconds() // 86400)

    # ---------- decisions ----------

    def permits(self, method: CollectionMethod) -> bool:
        if self.expired:
            return False
        return METHOD_ENTITLEMENT.get(method, "") in self.entitlements

    def implemented(self, method: CollectionMethod) -> bool:
        return METHOD_ENTITLEMENT.get(method, "") not in NOT_IMPLEMENTED_HERE

    def explain(self, method: CollectionMethod) -> str:
        """Why this method is or is not available — precise about which reason."""
        entitlement = METHOD_ENTITLEMENT.get(method, "")
        if not self.implemented(method):
            return (
                f"{method.value} is not implemented by this platform. It requires vendor "
                "advanced-access tooling exercised outside this system. This is a "
                "capability gap, not evidence that the data does not exist on the device."
            )
        if self.expired:
            return (
                f"The licence for endpoint '{self.endpoint_id or 'unspecified'}' expired on "
                f"{self.expires_utc}. No method may be used until it is renewed."
            )
        if entitlement not in self.entitlements:
            return (
                f"{method.value} requires the '{entitlement}' entitlement, which this "
                "endpoint does not hold. This is a licensing gap that procurement can "
                "resolve — it is NOT a statement that the device lacks the data."
            )
        return f"{method.value} is licensed and implemented on this endpoint."

    def filter_methods(
        self, methods: list[CollectionMethod]
    ) -> tuple[list[CollectionMethod], dict[str, str]]:
        """Split a supported-method list into permitted and blocked-with-reason."""
        permitted: list[CollectionMethod] = []
        blocked: dict[str, str] = {}
        for method in methods:
            if self.permits(method) and self.implemented(method):
                permitted.append(method)
            else:
                blocked[method.value] = self.explain(method)
        return permitted, blocked

    def warnings(self) -> list[str]:
        out: list[str] = []
        if self.expired:
            out.append(
                f"Licence expired {self.expires_utc}. Acquisitions performed under an "
                "expired licence must be recorded as such."
            )
        else:
            remaining = self.days_remaining
            if remaining is not None and remaining <= 30:
                out.append(
                    f"Licence expires in {remaining} day(s) ({self.expires_utc}). Renew "
                    "before it lapses mid-case."
                )
        if not self.entitlements:
            out.append("No entitlements are declared for this endpoint.")
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "licensee": self.licensee,
            "entitlements": sorted(self.entitlements),
            "expires_utc": self.expires_utc,
            "expired": self.expired,
            "days_remaining": self.days_remaining,
            "notes": self.notes,
            "not_implemented_here": sorted(NOT_IMPLEMENTED_HERE),
            "warnings": self.warnings(),
        }


DEFAULT_PROFILE = LicenceProfile(
    endpoint_id="",
    licensee="",
    entitlements=OPEN_INTERFACE_ENTITLEMENTS,
    notes=(
        "Default open-interface profile. Covers the documented device interfaces the "
        "shipped adapters implement (ADB, lockdownd/AFC, PC/SC, block-device imaging). "
        "No vendor licence is required for these, and none is claimed."
    ),
)


def load_profile(path: str | os.PathLike[str] | None = None) -> LicenceProfile:
    """Load the declared licence profile, or fall back to the open-interface default.

    A malformed or missing declaration degrades to the default rather than
    failing: an examiner must never be blocked from a lawful, documented-interface
    collection because a configuration file was mistyped.
    """
    target = path or os.environ.get("FORENSIC_LICENCE_PROFILE")
    if not target:
        return DEFAULT_PROFILE
    file = Path(target)
    if not file.is_file():
        return DEFAULT_PROFILE
    try:
        data = json.loads(file.read_text())
    except Exception:
        return DEFAULT_PROFILE
    declared = data.get("entitlements")
    return LicenceProfile(
        endpoint_id=data.get("endpoint_id", ""),
        licensee=data.get("licensee", ""),
        entitlements=frozenset(declared) if declared else OPEN_INTERFACE_ENTITLEMENTS,
        expires_utc=data.get("expires_utc"),
        notes=data.get("notes", ""),
    )
