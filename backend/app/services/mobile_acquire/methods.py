"""Collection methods and method selection — Architecture §6 and §6.1.

§6.1 states the rule this module encodes:

    "Select the least intrusive method that is sufficient for the authorized
     objective, while preserving the option to perform a deeper method when
     legally authorized and technically necessary. Never assume that a
     particular device supports physical or full-file-system acquisition."

Two consequences that are easy to get wrong and are enforced here:

  * intrusiveness ordering is a *total* order, so "least intrusive sufficient"
    is deterministic and reproducible by a second examiner;
  * a method is only offered if an adapter has actually reported it as
    supported for THIS device. Nothing is assumed from the model name.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CollectionMethod(str, Enum):
    """§6 method architecture."""

    LOGICAL = "logical"
    ADVANCED_LOGICAL = "advanced_logical"
    FILE_SYSTEM = "file_system"
    FULL_FILE_SYSTEM = "full_file_system"
    PHYSICAL = "physical"
    SIM = "sim"
    MEMORY_CARD = "memory_card"
    BACKUP = "backup"


# Lower value = less intrusive. SIM/memory-card sit outside the device-data
# ladder: they touch removable media, not the handset's protected storage.
INTRUSIVENESS: dict[CollectionMethod, int] = {
    CollectionMethod.SIM: 5,
    CollectionMethod.MEMORY_CARD: 6,
    CollectionMethod.LOGICAL: 10,
    CollectionMethod.BACKUP: 15,
    CollectionMethod.ADVANCED_LOGICAL: 20,
    CollectionMethod.FILE_SYSTEM: 30,
    CollectionMethod.FULL_FILE_SYSTEM: 40,
    CollectionMethod.PHYSICAL: 50,
}


@dataclass(frozen=True)
class MethodProfile:
    method: CollectionMethod
    meaning: str
    coverage: str
    limitations: str
    deleted_data: str


# §6 table, kept as data so the examiner-facing UI and the report both read the
# same text and cannot drift apart.
METHOD_PROFILES: dict[CollectionMethod, MethodProfile] = {
    CollectionMethod.LOGICAL: MethodProfile(
        CollectionMethod.LOGICAL,
        "Uses supported OS, backup, synchronisation or API interfaces to collect "
        "user-accessible data.",
        "Contacts, calls, messages, media, some app data.",
        "Fast and minimally intrusive, but deleted and protected data coverage may be limited.",
        "Generally not recovered, except records still present in application databases.",
    ),
    CollectionMethod.ADVANCED_LOGICAL: MethodProfile(
        CollectionMethod.ADVANCED_LOGICAL,
        "Combines logical mechanisms or extended interfaces for broader coverage.",
        "Logical set plus additional app domains and some system data.",
        "Availability varies by OS version and device state.",
        "Partially, where retained in app databases and their WAL journals.",
    ),
    CollectionMethod.FILE_SYSTEM: MethodProfile(
        CollectionMethod.FILE_SYSTEM,
        "Enumerates accessible directories, files, metadata, application databases, "
        "logs, configurations and media.",
        "Accessible filesystem with timestamps and structure.",
        "Bounded by the access rights the method obtains.",
        "Recoverable from journals, WAL files and unreferenced records.",
    ),
    CollectionMethod.FULL_FILE_SYSTEM: MethodProfile(
        CollectionMethod.FULL_FILE_SYSTEM,
        "Obtains a broader view of supported system and application domains exposed "
        "by the applicable method.",
        "System and app domains including keychain/keystore material where supported.",
        "Requires supported device, OS version and entitlement.",
        "Substantially, including deleted records within retained databases.",
    ),
    CollectionMethod.PHYSICAL: MethodProfile(
        CollectionMethod.PHYSICAL,
        "Obtains supported low-level storage data or a binary representation.",
        "Bit-level image of the supported storage region.",
        "Availability depends on hardware, chipset, encryption, OS version, patch "
        "level, device state, tool release and licence. Never assume it is available.",
        "Best available, subject to encryption and wear-levelling.",
    ),
    CollectionMethod.SIM: MethodProfile(
        CollectionMethod.SIM,
        "Acquires subscriber records from the SIM/USIM.",
        "ICCID, IMSI, contacts, SMS where stored on card, last-registered network.",
        "Only data physically resident on the card.",
        "Deleted SMS on card may be recoverable where the record remains allocated.",
    ),
    CollectionMethod.MEMORY_CARD: MethodProfile(
        CollectionMethod.MEMORY_CARD,
        "Acquires removable media content.",
        "Media, documents, app external storage, filesystem structure.",
        "Prefer write-blocked or read-only handling.",
        "Yes — unallocated space and deleted files are recoverable.",
    ),
    CollectionMethod.BACKUP: MethodProfile(
        CollectionMethod.BACKUP,
        "Uses the vendor backup interface (iTunes/Finder backup, Android backup).",
        "Whatever the backup agent chooses to include.",
        "Vendor decides scope; encrypted backups need the backup password. Apps may "
        "opt out of backup entirely, so absence here is not absence on the device.",
        "No — backups contain current state only.",
    ),
}


@dataclass(frozen=True)
class MethodDecision:
    selected: CollectionMethod | None
    considered: tuple[CollectionMethod, ...]
    rejected: dict[str, str]
    rationale: str
    deeper_available: tuple[CollectionMethod, ...] = ()

    def as_dict(self) -> dict:
        return {
            "selected": self.selected.value if self.selected else None,
            "considered": [m.value for m in self.considered],
            "rejected": self.rejected,
            "rationale": self.rationale,
            "deeper_available": [m.value for m in self.deeper_available],
        }


def select_method(
    *,
    supported: list[CollectionMethod],
    objective_requires: list[CollectionMethod] | None = None,
    authorized: list[CollectionMethod] | None = None,
    examiner_override: CollectionMethod | None = None,
) -> MethodDecision:
    """Apply §6.1: least intrusive method that is sufficient AND authorised.

    `objective_requires` is the set of methods that would satisfy the authorised
    objective (e.g. deleted-message recovery needs at least FILE_SYSTEM). If it
    is empty every supported method is considered sufficient.
    """
    supported_set = list(dict.fromkeys(supported))
    rejected: dict[str, str] = {}

    if not supported_set:
        return MethodDecision(
            selected=None,
            considered=(),
            rejected={"*": "No collection method reported as supported for this device."},
            rationale=(
                "No supported method. Record the capability gap; do not report a "
                "zero result as an absence of evidence (§20)."
            ),
        )

    auth = set(authorized) if authorized else set(supported_set)
    sufficient = set(objective_requires) if objective_requires else set(supported_set)

    candidates: list[CollectionMethod] = []
    for method in supported_set:
        if method not in auth:
            rejected[method.value] = "Not covered by the legal authority on file."
            continue
        if method not in sufficient:
            rejected[method.value] = "Insufficient coverage for the authorised objective."
            continue
        candidates.append(method)

    if examiner_override is not None:
        if examiner_override not in supported_set:
            return MethodDecision(
                selected=None,
                considered=tuple(candidates),
                rejected={**rejected,
                          examiner_override.value: "Examiner override is not supported by the device."},
                rationale="Examiner override rejected: method not supported for this device.",
            )
        deeper = tuple(sorted(
            (m for m in supported_set if INTRUSIVENESS[m] > INTRUSIVENESS[examiner_override]),
            key=lambda m: INTRUSIVENESS[m],
        ))
        return MethodDecision(
            selected=examiner_override,
            considered=tuple(candidates),
            rejected=rejected,
            rationale=(
                f"Examiner explicitly selected {examiner_override.value}. Recorded as a "
                "documented deviation from automatic least-intrusive selection (§20)."
            ),
            deeper_available=deeper,
        )

    if not candidates:
        return MethodDecision(
            selected=None,
            considered=(),
            rejected=rejected,
            rationale=(
                "Every supported method was either outside the legal authority or "
                "insufficient for the objective. Escalate for authority or record the gap."
            ),
        )

    candidates.sort(key=lambda m: INTRUSIVENESS[m])
    chosen = candidates[0]
    deeper = tuple(sorted(
        (m for m in supported_set if INTRUSIVENESS[m] > INTRUSIVENESS[chosen]),
        key=lambda m: INTRUSIVENESS[m],
    ))
    profile = METHOD_PROFILES[chosen]
    return MethodDecision(
        selected=chosen,
        considered=tuple(candidates),
        rejected=rejected,
        rationale=(
            f"{chosen.value} is the least intrusive supported method sufficient for the "
            f"authorised objective. Coverage: {profile.coverage} "
            f"Deleted data: {profile.deleted_data}"
        ),
        deeper_available=deeper,
    )


def coverage_statement(method: CollectionMethod) -> dict[str, str]:
    """§20.1 — the limitation text that MUST accompany every reported result."""
    profile = METHOD_PROFILES[method]
    return {
        "method": method.value,
        "meaning": profile.meaning,
        "coverage": profile.coverage,
        "limitations": profile.limitations,
        "deleted_data": profile.deleted_data,
        "mandatory_caveat": (
            "Extraction methods differ in evidence coverage. Absence of an artifact in "
            "this extraction does not establish that it never existed on the device."
        ),
    }
