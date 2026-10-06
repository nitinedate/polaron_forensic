"""iOS Agent and Android Agent — exclusive owners of phone extract + RAG.

Each agent auto-detects its platform from the adapter, OS family, job seed,
or evidence path. An iOS job never runs Android extract/parse/inventory/RAG,
and the reverse is also refused.
"""

from __future__ import annotations

from typing import Any, Literal

from app.services.mobile_os import normalize_mobile_os

MobilePlatform = Literal["ios", "android"]

IOSAGENT_ID = "iosagent"
ANDROIDAGENT_ID = "androidagent"
PLATFORM_AGENT_IDS = frozenset({IOSAGENT_ID, ANDROIDAGENT_ID})

IOSAGENT_LABEL = "iOS Agent"
ANDROIDAGENT_LABEL = "Android Agent"

OWNED_STAGES = (
    "extract",
    "materialize",
    "ocr",
    "parse",
    "rag_index",
    "rag_enrich",
    "graph_sync",
    "artifact_inventory",
)

_IOS_ADAPTERS = frozenset({"ios_lockdown", "ios", "ios_backup"})
_ANDROID_ADAPTERS = frozenset({"android_adb", "android_mtp", "android", "android_backup"})

_IOS_NAME_HINTS = (
    "iphone",
    "ipad",
    "ipod",
    "ios",
    "apple",
    "manifest.db",
    "manifest.plist",
    "ios_backup",
    "chatstorage.sqlite",
    "sms.db",
    "addressbook.sqlitedb",
    "vid_05ac",
)
_ANDROID_NAME_HINTS = (
    "android",
    "samsung",
    "galaxy",
    "pixel",
    "xiaomi",
    "huawei",
    "honor",
    "oneplus",
    "oppo",
    "vivo",
    "mtp_shared",
    "adb_logical",
    "com.whatsapp",
    "com.android",
    "/data/data/",
    "data/data/",
)


class PlatformMismatchError(ValueError):
    """Raised when an agent is asked to work a phone it does not own."""


def owner_agent_id(platform: str | None) -> str | None:
    family = normalize_mobile_os(platform)
    if family == "ios":
        return IOSAGENT_ID
    if family == "android":
        return ANDROIDAGENT_ID
    return None


def owner_agent_label(platform: str | None) -> str | None:
    aid = owner_agent_id(platform)
    if aid == IOSAGENT_ID:
        return IOSAGENT_LABEL
    if aid == ANDROIDAGENT_ID:
        return ANDROIDAGENT_LABEL
    return None


def platform_for_agent(agent_id: str | None) -> MobilePlatform | None:
    aid = (agent_id or "").strip().lower().replace("_", "")
    if aid in {"iosagent", "iososagent"}:
        return "ios"
    if aid in {"androidagent", "androidosagent"}:
        return "android"
    return None


def detect_mobile_platform(*hints: Any) -> MobilePlatform | None:
    """Classify a device / job / path as ios or android. None if unknown."""
    seen_ios = False
    seen_android = False
    for hint in hints:
        family = _classify_one(hint)
        if family == "ios":
            seen_ios = True
        elif family == "android":
            seen_android = True
    if seen_ios and seen_android:
        return None
    if seen_ios:
        return "ios"
    if seen_android:
        return "android"
    return None


def _classify_one(hint: Any) -> MobilePlatform | None:
    if hint is None:
        return None
    if isinstance(hint, dict):
        for key in (
            "owner_agent",
            "adapter",
            "os_family",
            "mobile_os",
            "axiom_platform",
            "evidence_platform",
            "platform",
            "os_hint",
            "device_label",
            "model",
            "name",
            "type",
            "source_type",
        ):
            family = _classify_one(hint.get(key))
            if family:
                return family
        detected = hint.get("detected_os")
        if isinstance(detected, dict):
            family = _classify_one(detected.get("family") or detected.get("os_family"))
            if family:
                return family
        for key in ("device_id", "udid", "serial", "path", "host_path", "evidence_folder", "working"):
            family = _classify_text(str(hint.get(key) or ""))
            if family:
                return family
        return None
    if isinstance(hint, (list, tuple)):
        for item in hint:
            family = _classify_one(item)
            if family:
                return family
        return None
    return _classify_text(str(hint))


def _classify_text(raw: str) -> MobilePlatform | None:
    text = (raw or "").strip().lower().replace("\\", "/")
    if not text:
        return None
    compact = text.replace("_", "").replace("-", "")
    if compact in {"iosagent", "iososagent"}:
        return "ios"
    if compact in {"androidagent", "androidosagent"}:
        return "android"
    adapter = text.split("/")[-1]
    if adapter in _IOS_ADAPTERS or text in _IOS_ADAPTERS:
        return "ios"
    if adapter in _ANDROID_ADAPTERS or text in _ANDROID_ADAPTERS:
        return "android"
    norm = normalize_mobile_os(text)
    if norm in {"ios", "android"}:
        return norm  # type: ignore[return-value]
    if any(token in text for token in _IOS_NAME_HINTS):
        return "ios"
    if any(token in text for token in _ANDROID_NAME_HINTS):
        return "android"
    return None


def mobile_os_family_from_job_row(row: dict[str, Any] | None) -> MobilePlatform | None:
    from app.forensic_common.job_types import _as_dict

    if not row:
        return None
    ds = _as_dict(row.get("disk_source"))
    family = detect_mobile_platform(
        ds.get("owner_agent"),
        ds.get("mobile_os"),
        ds.get("axiom_platform"),
        ds.get("evidence_platform"),
        ds.get("adapter"),
        ds.get("os_family"),
        ds,
        row.get("type"),
    )
    if family:
        return family
    jtype = str(row.get("type") or "")
    if jtype in {"ios_backup", "ios_mobile"}:
        return "ios"
    if jtype in {"android_backup", "android_mobile"}:
        return "android"
    return None


def owner_agent_for_job(db, job_id: str) -> str | None:
    from app.db.sql_helpers import fetchone

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    return owner_agent_id(mobile_os_family_from_job_row(row))


def current_service_owns_job(db, job_id: str) -> bool:
    """True when this process is the product that should run the job.

    Disk, Android, and iOS share one firm database, so each product's supervisor
    can see the others' jobs. Only the owning product may dispatch work.
    """
    from app.db.sql_helpers import fetchone
    from app.service_identity import (
        FORENSIC,
        MOBILE_ANDROID,
        MOBILE_EXTRACT,
        MOBILE_IOS,
        current_service,
    )

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    family = mobile_os_family_from_job_row(row)
    svc = current_service()
    if svc == MOBILE_ANDROID:
        return family == "android"
    if svc == MOBILE_IOS:
        return family == "ios"
    if svc == MOBILE_EXTRACT:
        return family in {"android", "ios"}
    if svc == FORENSIC:
        return family is None
    return family is None


def assert_agent_owns_job(db, job_id: str, agent_id: str) -> str:
    """Return the owner id, or raise if this agent is the wrong platform."""
    wanted = platform_for_agent(agent_id)
    if not wanted:
        owner = owner_agent_for_job(db, job_id)
        return owner or agent_id
    from app.db.sql_helpers import fetchone

    row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:jid", {"jid": job_id})
    family = mobile_os_family_from_job_row(row)
    if family and family != wanted:
        raise PlatformMismatchError(
            f"{owner_agent_label(wanted)} cannot process a {family} phone — "
            f"{owner_agent_label(family)} owns this job"
        )
    return owner_agent_id(wanted) or agent_id


def persist_owner_on_disk_source(disk_source: dict[str, Any] | None, platform: str | None) -> dict[str, Any]:
    out = dict(disk_source or {})
    family = normalize_mobile_os(platform) or detect_mobile_platform(out)
    if family not in {"ios", "android"}:
        return out
    out["mobile_os"] = family
    out["owner_agent"] = owner_agent_id(family)
    out["owner_agent_label"] = owner_agent_label(family)
    if family == "ios":
        out["axiom_platform"] = out.get("axiom_platform") or "iOS"
        out["evidence_platform"] = out.get("evidence_platform") or "iOS"
    else:
        out["axiom_platform"] = out.get("axiom_platform") or "Android"
        out["evidence_platform"] = out.get("evidence_platform") or "Android"
    return out


def owner_progress_from_stage_states(states: dict[str, dict[str, Any]]) -> tuple[str, int, str]:
    """Composite extract→RAG progress for the owning platform agent."""
    owned = (
        "extraction_agent",
        "materialize_agent",
        "ocr_agent",
        "parse_agent",
        "chunk_agent",
        "embed_agent",
        "entity_agent",
        "neo4j_agent",
        "annotation_agent",
        "ontology_agent",
        "artifacts_agent",
    )
    running: list[tuple[str, int, str]] = []
    pending = 0
    done = 0
    failed_detail = ""
    for aid in owned:
        entry = states.get(aid) if isinstance(states.get(aid), dict) else {}
        state = str(entry.get("state") or "pending")
        pct = int(entry.get("pct") or 0)
        label = str(entry.get("label") or aid)
        detail = str(entry.get("detail") or "")
        if state == "failed":
            failed_detail = detail or f"{label} failed"
        elif state == "running":
            running.append((label, pct, detail))
        elif state == "done":
            done += 1
        else:
            pending += 1
    if failed_detail:
        return "failed", min(99, max(1, int(100 * done / max(len(owned), 1)))), failed_detail
    if running:
        label, pct, detail = running[0]
        return "running", min(99, max(1, pct or 1)), detail or f"{label} in progress"
    if pending == 0 and done > 0:
        return "done", 100, "Phone extract and RAG complete"
    if done == 0 and pending == len(owned):
        return "pending", 0, "Waiting to start phone extract"
    overall = int(100 * done / max(len(owned), 1))
    return "running", min(99, max(1, overall)), f"{done}/{len(owned)} owned stages complete"
