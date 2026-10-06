"""Aetheris runtime product identity and hard job-domain boundaries.

Disk, Android mobile, iOS mobile and vulnerability operations are independent
runtime products.  Android/iOS may share source-code utilities, but they must
not share job databases, Celery queues or evidence namespaces in deployment.
"""

from __future__ import annotations

import os
from typing import Final, Literal

ServiceName = Literal[
    "forensic",
    "mobile-android",
    "mobile-ios",
    "mobile-extract",
    "vuln",
]

FORENSIC: Final = "forensic"
MOBILE_ANDROID: Final = "mobile-android"
MOBILE_IOS: Final = "mobile-ios"
# Legacy compatibility identity.  New deployments should use the two platform
# services above; keeping this avoids breaking old recovery/upgrade scripts.
MOBILE_EXTRACT: Final = "mobile-extract"
VULN: Final = "vuln"

MOBILE_SERVICES: Final[frozenset[str]] = frozenset(
    {MOBILE_ANDROID, MOBILE_IOS, MOBILE_EXTRACT}
)
VALID_SERVICES: Final[frozenset[str]] = frozenset(
    {FORENSIC, MOBILE_ANDROID, MOBILE_IOS, MOBILE_EXTRACT, VULN}
)

HEALTH_ROLES: Final[dict[str, str]] = {
    FORENSIC: "forensic-api",
    MOBILE_ANDROID: "mobile-android-api",
    MOBILE_IOS: "mobile-ios-api",
    MOBILE_EXTRACT: "mobile-extract-api",
    VULN: "vuln-api",
}

ANDROID_JOB_TYPES: Final[frozenset[str]] = frozenset(
    {"android_mobile", "android_backup"}
)
IOS_JOB_TYPES: Final[frozenset[str]] = frozenset({"ios_mobile", "ios_backup"})
LEGACY_MOBILE_JOB_TYPES: Final[frozenset[str]] = frozenset({"mobile_extraction"})
MOBILE_JOB_TYPES: Final[frozenset[str]] = frozenset(
    set(ANDROID_JOB_TYPES) | set(IOS_JOB_TYPES) | set(LEGACY_MOBILE_JOB_TYPES)
)
DISK_JOB_TYPES: Final[frozenset[str]] = frozenset({"host_disk", "forensic", "disk"})

# Legacy laptop-scanner fingerprint from the pre-split monolith.
LEGACY_HEALTH_ROLE: Final = "central-api"


def current_service() -> ServiceName:
    raw = (
        os.environ.get("AETHERIS_SERVICE")
        or os.environ.get("AETHERIS_ROLE")
        or FORENSIC
    ).strip().lower()
    aliases = {
        "mobile_android": MOBILE_ANDROID,
        "android-mobile": MOBILE_ANDROID,
        "android": MOBILE_ANDROID,
        "mobile_ios": MOBILE_IOS,
        "ios-mobile": MOBILE_IOS,
        "ios": MOBILE_IOS,
        "mobile_extract": MOBILE_EXTRACT,
        "mobile": MOBILE_EXTRACT,
        "extract": MOBILE_EXTRACT,
        "vulnerabilities": VULN,
        "vulnerability": VULN,
        "volnureties": VULN,
        "scanner": VULN,
    }
    normalized = aliases.get(raw, raw)
    if normalized in VALID_SERVICES:
        return normalized  # type: ignore[return-value]
    return FORENSIC


def is_mobile_service(service: str | None = None) -> bool:
    return (service or current_service()) in MOBILE_SERVICES


def mobile_service_platform(service: str | None = None) -> str | None:
    svc = service or current_service()
    if svc == MOBILE_ANDROID:
        return "android"
    if svc == MOBILE_IOS:
        return "ios"
    return None


def mobile_queue_prefix(service: str | None = None) -> str:
    """Celery queue namespace for the current mobile backend."""
    svc = service or current_service()
    if svc == MOBILE_ANDROID:
        return "android"
    if svc == MOBILE_IOS:
        return "ios"
    return "mobile"


def health_role(service: str | None = None) -> str:
    return HEALTH_ROLES.get(service or current_service(), HEALTH_ROLES[FORENSIC])


def health_payload(service: str | None = None) -> dict[str, str]:
    svc = service or current_service()
    out = {"status": "ok", "service": "aetheris", "role": health_role(svc), "product": svc}
    platform = mobile_service_platform(svc)
    if platform:
        out["mobile_platform"] = platform
    return out


def is_aetheris_health_role(role: str) -> bool:
    value = (role or "").strip().lower()
    return value == LEGACY_HEALTH_ROLE or value in HEALTH_ROLES.values() or value.endswith("-api")


def job_type_platform(job_type: str, source_type: str = "", mobile_os: str = "") -> str | None:
    jt = (job_type or "").strip().lower()
    src = (source_type or "").strip().lower()
    os_hint = (mobile_os or "").strip().lower()
    if jt in ANDROID_JOB_TYPES or src == "android_backup" or os_hint == "android":
        return "android"
    if jt in IOS_JOB_TYPES or src == "ios_backup" or os_hint == "ios":
        return "ios"
    return None


def job_type_is_mobile(job_type: str, source_type: str = "") -> bool:
    if (job_type or "").strip().lower() in MOBILE_JOB_TYPES:
        return True
    return (source_type or "").strip().lower() in {
        "mobile",
        "android_backup",
        "ios_backup",
    }


def service_allows_job_type(
    job_type: str,
    source_type: str = "",
    service: str | None = None,
    *,
    mobile_os: str = "",
) -> bool:
    """Hard runtime admission check.

    Platform mobile services only accept their own canonical job types.  The
    legacy mobile-extract service keeps old jobs readable during upgrades.
    """
    svc = service or current_service()
    jt = (job_type or "").strip().lower()
    mobile = job_type_is_mobile(jt, source_type)
    platform = job_type_platform(jt, source_type, mobile_os)

    if svc == MOBILE_ANDROID:
        if jt == "mobile_extraction":
            return platform in {None, "android"}
        return jt in ANDROID_JOB_TYPES or (mobile and platform == "android")
    if svc == MOBILE_IOS:
        if jt == "mobile_extraction":
            return platform in {None, "ios"}
        return jt in IOS_JOB_TYPES or (mobile and platform == "ios")
    if svc == MOBILE_EXTRACT:
        return mobile
    if svc == FORENSIC:
        return not mobile
    return False


def canonical_mobile_job_type(service: str | None = None) -> str | None:
    svc = service or current_service()
    if svc == MOBILE_ANDROID:
        return "android_mobile"
    if svc == MOBILE_IOS:
        return "ios_mobile"
    if svc == MOBILE_EXTRACT:
        return "mobile_extraction"
    return None


def list_jobs_type_sql(service: str | None = None) -> tuple[str, dict]:
    """Extra WHERE fragment so each product only lists its own jobs."""
    svc = service or current_service()
    if svc == MOBILE_ANDROID:
        return "type IN :svc_job_types", {"svc_job_types": tuple(sorted(ANDROID_JOB_TYPES))}
    if svc == MOBILE_IOS:
        return "type IN :svc_job_types", {"svc_job_types": tuple(sorted(IOS_JOB_TYPES))}
    if svc == MOBILE_EXTRACT:
        return "type IN :svc_job_types", {"svc_job_types": tuple(sorted(MOBILE_JOB_TYPES))}
    if svc == FORENSIC:
        return "type NOT IN :svc_job_types", {"svc_job_types": tuple(sorted(MOBILE_JOB_TYPES))}
    return "1=0", {}
