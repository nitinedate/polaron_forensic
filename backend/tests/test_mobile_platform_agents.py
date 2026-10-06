"""iOS Agent / Android Agent own extract + RAG and never mix platforms."""

from __future__ import annotations

from app.forensic_common.job_types import _as_dict
from app.forensic_common.pipeline_routing import domain_pipeline_agents, resolve_domain_agent_id
from app.services.action_agents import ACTION_AGENTS
from app.services.mobile_platform_agents import (
    ANDROIDAGENT_ID,
    IOSAGENT_ID,
    detect_mobile_platform,
    owner_agent_id,
    persist_owner_on_disk_source,
    platform_for_agent,
)
from app.services.pipeline_orchestrator import PIPELINE_AGENTS
from app.services.pipeline_supervisor import PIPELINE_STAGE_AGENTS


def mobile_os_family_from_row(row):
    from app.services.mobile_platform_agents import mobile_os_family_from_job_row

    return mobile_os_family_from_job_row(row)


def mobile_platform_label(row):
    family = mobile_os_family_from_row(row)
    if family == "android":
        return "Android"
    if family == "ios":
        return "iOS"
    return "Mobile"


def test_detect_ios_from_adapter_and_windows_usb():
    assert detect_mobile_platform("ios_lockdown") == "ios"
    assert detect_mobile_platform({"adapter": "ios_lockdown", "os_family": "ios"}) == "ios"
    assert detect_mobile_platform("USB#VID_05AC&PID_12A8#000081500002659C0CBB401C") == "ios"
    assert detect_mobile_platform("Apple iPhone") == "ios"
    assert detect_mobile_platform("ios_backup") == "ios"
    assert owner_agent_id("ios") == IOSAGENT_ID


def test_detect_android_from_adapter_and_paths():
    assert detect_mobile_platform("android_mtp") == "android"
    assert detect_mobile_platform("android_adb") == "android"
    assert detect_mobile_platform({"os_family": "android", "label": "Galaxy S21"}) == "android"
    assert detect_mobile_platform("mtp_shared/DCIM") == "android"
    assert detect_mobile_platform("data/data/com.whatsapp") == "android"
    assert owner_agent_id("android") == ANDROIDAGENT_ID


def test_detect_does_not_default_mobile_extraction_to_android():
    assert detect_mobile_platform("mobile_extraction") is None
    assert detect_mobile_platform({"type": "mobile_extraction"}) is None
    assert mobile_os_family_from_row({"type": "mobile_extraction", "disk_source": {}}) is None
    assert mobile_platform_label({"type": "mobile_extraction"}) == "Mobile"


def test_mixed_hints_stay_unknown():
    assert detect_mobile_platform("ios_lockdown", "android_mtp") is None


def test_owner_persisted_on_disk_source():
    seeded = persist_owner_on_disk_source({"source_type": "mobile"}, "ios")
    assert seeded["owner_agent"] == IOSAGENT_ID
    assert seeded["mobile_os"] == "ios"
    assert seeded["axiom_platform"] == "iOS"


def test_platform_for_agent_aliases():
    assert platform_for_agent("iosagent") == "ios"
    assert platform_for_agent("ios_agent") == "ios"
    assert platform_for_agent("androidagent") == "android"
    assert platform_for_agent("android_os_agent") == "android"


def test_agents_registered():
    agents = domain_pipeline_agents()
    assert agents["iosagent"]["os_family"] == "ios"
    assert agents["androidagent"]["os_family"] == "android"
    assert "iosagent" in PIPELINE_STAGE_AGENTS
    assert "androidagent" in PIPELINE_STAGE_AGENTS
    ids = {a["id"] for a in ACTION_AGENTS}
    assert IOSAGENT_ID in ids
    assert ANDROIDAGENT_ID in ids
    orch_ids = {a["id"] for a in PIPELINE_AGENTS}
    assert IOSAGENT_ID in orch_ids
    assert ANDROIDAGENT_ID in orch_ids


def test_resolve_domain_falls_back_without_db(monkeypatch):
    from app.forensic_common import pipeline_routing as pr

    monkeypatch.setattr(pr, "is_mobile_job", lambda db, job_id: job_id == "mobile-job")
    assert resolve_domain_agent_id(None, "mobile-job", "extract_agent") == "extract_agent_mobile"
    assert resolve_domain_agent_id(None, "disk-job", "extract_agent") == "extract_agent_disk"


def test_as_dict_helper_still_works():
    assert _as_dict('{"mobile_os":"ios"}')["mobile_os"] == "ios"


def test_iosagent_stands_down_on_android_job():
    from app.services.action_agents import collect_action_votes

    snap = {
        "row": {"status": "created", "disk_source": {"mobile_os": "android", "owner_agent": "androidagent"}},
        "status": "created",
        "is_mobile": True,
        "mobile_platform": "android",
        "owner_agent": "androidagent",
        "extract_health": {"should_run": False, "live": False, "complete": False, "should_stand_down": False},
        "inventory": {"total": 0, "completed": 0, "done": True},
        "list_folder_done": True,
    }
    votes = {v["id"]: v for v in collect_action_votes(snap)}
    assert votes["iosagent"]["want"] == "done"
    assert "Android" in votes["iosagent"]["reason"]
    assert votes["androidagent"]["want"] in {"run", "idle"}
    assert votes["drive_mount_agent"]["want"] == "done"


def test_androidagent_stands_down_on_ios_job():
    from app.services.action_agents import collect_action_votes

    snap = {
        "row": {"status": "created", "disk_source": {"mobile_os": "ios", "owner_agent": "iosagent"}},
        "status": "created",
        "is_mobile": True,
        "mobile_platform": "ios",
        "owner_agent": "iosagent",
        "extract_health": {"should_run": False, "live": False, "complete": False, "should_stand_down": False},
        "inventory": {"total": 0, "completed": 0, "done": True},
        "list_folder_done": True,
    }
    votes = {v["id"]: v for v in collect_action_votes(snap)}
    assert votes["androidagent"]["want"] == "done"
    assert "iPhone" in votes["androidagent"]["reason"] or "iOS" in votes["androidagent"]["reason"]
    assert votes["iosagent"]["want"] in {"run", "idle"}


def test_iosagent_starts_extract_not_inventory_when_zero_files():
    from app.services.action_agents import collect_action_votes

    snap = {
        "row": {
            "status": "awaiting_segments",
            "disk_source": {"mobile_os": "ios", "owner_agent": "iosagent"},
            "files_extracted": 0,
        },
        "status": "awaiting_segments",
        "is_mobile": True,
        "mobile_platform": "ios",
        "owner_agent": "iosagent",
        "files_total": 0,
        "files_done": 0,
        "extract_live": False,
        "extract_health": {"should_run": True, "live": False, "complete": False, "should_stand_down": False},
        "inventory": {"total": 31, "completed": 0, "done": False},
        "list_folder_done": True,
        "parse_pending": 0,
        "rag_remaining": 0,
    }
    votes = {v["id"]: v for v in collect_action_votes(snap)}
    assert votes["iosagent"]["want"] == "run"
    assert votes["iosagent"]["dispatch_action"] == "resume_extraction"
    assert votes["iosagent"]["dispatch_agent"] == "extract_agent"


def test_only_the_owning_product_runs_the_job():
    from unittest.mock import patch

    from app.services.mobile_platform_agents import current_service_owns_job

    android = {"type": "android_mobile", "disk_source": {"mobile_os": "android"}}
    disk = {"type": "disk_image", "disk_source": {}}
    with patch("app.db.sql_helpers.fetchone", return_value=android), patch(
        "app.service_identity.current_service", return_value="forensic"
    ):
        assert current_service_owns_job(object(), "job-1") is False
    with patch("app.db.sql_helpers.fetchone", return_value=android), patch(
        "app.service_identity.current_service", return_value="mobile-ios"
    ):
        assert current_service_owns_job(object(), "job-1") is False
    with patch("app.db.sql_helpers.fetchone", return_value=android), patch(
        "app.service_identity.current_service", return_value="mobile-android"
    ):
        assert current_service_owns_job(object(), "job-1") is True
    with patch("app.db.sql_helpers.fetchone", return_value=disk), patch(
        "app.service_identity.current_service", return_value="forensic"
    ):
        assert current_service_owns_job(object(), "job-1") is True
    with patch("app.db.sql_helpers.fetchone", return_value=disk), patch(
        "app.service_identity.current_service", return_value="mobile-android"
    ):
        assert current_service_owns_job(object(), "job-1") is False
