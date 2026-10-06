"""Normalize examiner-selected mobile OS and map to AXIOM platforms."""

from __future__ import annotations

from typing import Any

MOBILE_OS_ANDROID = "android"
MOBILE_OS_IOS = "ios"
MOBILE_OS_OTHER = "other"

VALID_MOBILE_OS = frozenset({MOBILE_OS_ANDROID, MOBILE_OS_IOS, MOBILE_OS_OTHER})

# Keys preserved across disk_source rewrites during mount/extract.
MOBILE_DISK_SOURCE_KEYS = (
    "source_type",
    "mobile_os",
    "axiom_platform",
    "evidence_platform",
    "capability_label",
    "capability_reasons",
    "permitted_actions",
    "acquisition_mode",
    "os_selection_source",
    "import_adapter",
    "collection_summary",
    "os_mismatch_warning",
    "legal_authority_acknowledged",
    "owner_agent",
    "owner_agent_label",
    "adapter",
    "os_family",
)


def normalize_mobile_os(value: str | None) -> str | None:
    raw = (value or "").strip().lower()
    if not raw:
        return None
    aliases = {
        "android": MOBILE_OS_ANDROID,
        "ios": MOBILE_OS_IOS,
        "iphone": MOBILE_OS_IOS,
        "ipad": MOBILE_OS_IOS,
        "apple": MOBILE_OS_IOS,
        "other": MOBILE_OS_OTHER,
        "unknown": MOBILE_OS_OTHER,
        "other / unknown": MOBILE_OS_OTHER,
    }
    return aliases.get(raw)


def mobile_os_to_axiom_platform(mobile_os: str | None) -> str | None:
    os_id = normalize_mobile_os(mobile_os)
    if os_id == MOBILE_OS_ANDROID:
        return "Android"
    if os_id == MOBILE_OS_IOS:
        return "iOS"
    return None


def extract_mobile_meta(disk_source: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(disk_source, dict):
        return {}
    return {k: disk_source[k] for k in MOBILE_DISK_SOURCE_KEYS if k in disk_source and disk_source[k] is not None}


def merge_mobile_meta_into_disk_source(
    disk_source: dict[str, Any] | None,
    mobile_meta: dict[str, Any] | None,
) -> dict[str, Any]:
    out = dict(disk_source or {})
    for key, value in (mobile_meta or {}).items():
        if value is None:
            continue
        # Examiner OS selection must not be overwritten by inference.
        if key in ("mobile_os", "os_selection_source") and out.get("os_selection_source") == "examiner":
            if key == "mobile_os" and out.get("mobile_os"):
                continue
            if key == "os_selection_source":
                continue
        if key in ("axiom_platform", "evidence_platform") and out.get("os_selection_source") == "examiner":
            examiner_platform = mobile_os_to_axiom_platform(str(out.get("mobile_os") or ""))
            if examiner_platform:
                out[key] = examiner_platform
                continue
        out[key] = value
    return out


def load_job_disk_source(row: dict[str, Any] | None) -> dict[str, Any]:
    import json

    if not row:
        return {}
    ds = row.get("disk_source")
    if isinstance(ds, str):
        try:
            ds = json.loads(ds)
        except json.JSONDecodeError:
            return {}
    return dict(ds) if isinstance(ds, dict) else {}


def build_mobile_disk_source_seed(
    *,
    mobile_os: str,
    acquisition_mode: str = "import",
    source_type: str = "mobile",
    legal_authority_acknowledged: bool = False,
    capability: dict[str, Any] | None = None,
) -> dict[str, Any]:
    os_id = normalize_mobile_os(mobile_os) or MOBILE_OS_OTHER
    platform = mobile_os_to_axiom_platform(os_id)
    cap = capability or {}
    seed: dict[str, Any] = {
        "source_type": source_type or "mobile",
        "mobile_os": os_id,
        "acquisition_mode": acquisition_mode or "import",
        "os_selection_source": "examiner",
        "legal_authority_acknowledged": bool(legal_authority_acknowledged),
        "capability_label": cap.get("capability_label") or "SUPPORTED_IMPORT",
        "capability_reasons": cap.get("reasons") or [],
        "permitted_actions": cap.get("permitted_actions") or ["import"],
    }
    if platform:
        seed["axiom_platform"] = platform
        seed["evidence_platform"] = platform
    from app.services.mobile_platform_agents import persist_owner_on_disk_source

    return persist_owner_on_disk_source(seed, os_id)
