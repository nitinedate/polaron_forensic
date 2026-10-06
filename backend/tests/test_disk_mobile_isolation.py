"""Disk vs mobile isolation + evidence contract validation."""

from __future__ import annotations

from pathlib import Path

from app.disk_forensic.segments import DISK_IMAGE_EXT_RE, is_disk_image_filename
from app.forensic_common.pipeline_routing import (
    domain_pipeline_agents,
    followup_queue,
    normalize_stage_agent_id,
    phase3_queue,
    resolve_domain_agent_id,
    should_continue_after_extract,
    stage_key_for_recommendation,
)
from app.services.evidence_contract import (
    baseline_mobile_evidence_contract,
    validate_evidence_contract,
)
from app.services.evidence_contract_planner import plan_evidence_contract
from app.services.extract_filters import matches_forensic_include
from app.services.host_evidence import DISK_EXT_RE
from app.services.mobile_segments import is_mobile_segment_filename
from app.services.pipeline_supervisor import PIPELINE_STAGE_AGENTS


def test_disk_ext_excludes_mobile_packages():
    assert DISK_EXT_RE.search("case.E01")
    assert DISK_IMAGE_EXT_RE.search("image.dd")
    assert not DISK_EXT_RE.search("export.pas")
    assert not DISK_EXT_RE.search("case.ufd")
    assert not DISK_EXT_RE.search("backup.zip")
    assert is_disk_image_filename("disk.E01")
    assert not is_disk_image_filename("phone.pas001")
    assert is_mobile_segment_filename("phone.pas001")
    assert is_mobile_segment_filename("export.ufdx")


def test_extract_filters_no_mobile_bleed_on_windows():
    # Mobile-only path (no handbook extension) must not match Windows/disk include rules.
    mobile_only = "data/data/com.whatsapp/cache/random_blob_without_ext"
    assert matches_forensic_include(mobile_only, None, os_family="android")
    assert not matches_forensic_include(mobile_only, None, os_family="windows")
    # .db still matches disk via handbook extensions (expected) — isolation is path-prefix bleed.


def test_domain_stage_agents_registered():
    agents = domain_pipeline_agents()
    assert "extract_agent_disk" in agents
    assert "extract_agent_mobile" in agents
    assert agents["extract_agent_mobile"]["queue"] == "mobile-build"
    assert agents["inventory_agent_disk"]["queue"] == "disk-build"
    for aid in (
        "extract_agent_disk",
        "parse_agent_disk",
        "inventory_agent_disk",
        "extract_agent_mobile",
        "parse_agent_mobile",
        "inventory_agent_mobile",
    ):
        assert aid in PIPELINE_STAGE_AGENTS


def test_celery_routes_isolate_mobile_queue():
    src = Path(__file__).resolve().parents[1] / "app" / "celery_factory.py"
    text = src.read_text(encoding="utf-8")
    assert '"app.tasks.build_extracted_disk_task": {"queue": "disk-build"}' in text
    assert '"app.tasks.build_extracted_mobile_task": {"queue": "mobile-build"}' in text
    assert '"app.tasks.parse_drain_mobile_task": {"queue": "mobile-build"}' in text
    assert '"app.tasks.axiom_artifact_inventory_mobile_task": {"queue": "mobile-build"}' in text
    assert '"app.tasks.mobile_analysis_task": {"queue": "mobile-build"}' in text
    assert '"app.tasks.phase3_pipeline_task": {"queue": "mobile-build"}' in text
    assert '"app.tasks.pipeline_supervisor_task": {"queue": "mobile-build"}' in text
    assert '"app.tasks.ocr_drain_task": {"queue": "ocr"}' in text
    assert '"app.tasks.rag_index_task": {"queue": "rag-index"}' in text
    assert "FORENSIC_ROUTES" in text
    assert "MOBILE_ROUTES" in text
    assert "VULN_ROUTES" in text


def test_mobile_always_continues_after_extract():
    assert should_continue_after_extract(
        phase3_auto=False, rag_auto=False, service="mobile-extract"
    ) is True
    assert should_continue_after_extract(
        phase3_auto=False, rag_auto=False, service="forensic"
    ) is False
    assert should_continue_after_extract(
        phase3_auto=True, rag_auto=False, service="forensic"
    ) is True
    assert phase3_queue("mobile-extract") == "mobile-build"
    assert phase3_queue("forensic") == "disk-build"
    assert followup_queue("mobile-extract") == "mobile-build"
    assert followup_queue("forensic") == "disk-parse"
    assert followup_queue("mobile-android") == "android-parse"
    assert followup_queue("mobile-ios") == "ios-parse"


def test_rag_enrich_never_hardcodes_disk_queue_on_mobile():
    supervisor = Path(__file__).resolve().parents[1] / "app" / "services" / "pipeline_supervisor.py"
    tasks = Path(__file__).resolve().parents[1] / "app" / "tasks.py"
    celery = Path(__file__).resolve().parents[1] / "app" / "celery_factory.py"
    assert "queue=followup_queue()" in supervisor.read_text(encoding="utf-8")
    assert 'rag_enrich_task.apply_async(args=(schema_name, job_id), queue="disk-build")' not in tasks.read_text(
        encoding="utf-8"
    )
    assert '"app.tasks.rag_enrich_task": {"queue": "mobile-build"}' in celery.read_text(encoding="utf-8")
    assert '"app.tasks.ocr_drain_task": {"queue": "ocr"}' in celery.read_text(encoding="utf-8")


def test_normalize_stage_agent_id():
    assert normalize_stage_agent_id("extract_agent_mobile") == "extract_agent"
    assert normalize_stage_agent_id("inventory_agent_disk") == "inventory_agent"
    assert normalize_stage_agent_id("rag_agent") == "rag_agent"
    assert normalize_stage_agent_id("iosagent") == "extract_agent"
    assert normalize_stage_agent_id("androidagent") == "extract_agent"


def test_mobile_evidence_contract_baseline_and_validation():
    contract = baseline_mobile_evidence_contract("Mobile Chat & Messaging Applications")
    assert contract["domain"] == "mobile"
    assert contract["source"] == "axiom_forensic_kb"
    assert "Chat Messages" in (contract.get("artifact_names") or [])
    assert "MESSAGE" in (contract.get("count_domains") or [])
    assert "INSTANT_MESSAGING" in (contract.get("report_ids") or [])

    # Reject invented artifact names when a current canonical family is supplied.
    dirty = {**contract, "artifact_names": ["Chat Messages", "Totally Fake Artifact XYZ"]}
    cleaned = validate_evidence_contract(dirty, allowed_artifact_names={"Chat Messages"})
    assert cleaned["artifact_names"] == ["Chat Messages"]


def test_plan_evidence_contract_baseline_without_llm():
    planned = plan_evidence_contract(
        title="Device Identity & SIM Attribution",
        objective_statement="Identify device and SIM",
        domain="mobile",
        intake={"organization_name": "Acme"},
        model=None,
        use_llm=False,
    )
    assert planned["source"] == "axiom_forensic_kb"
    assert planned["domain"] == "mobile"
    assert "EVIDENCE CONTRACT" not in str(planned)  # raw JSON dict


class _FakeRow(dict):
    pass


def test_resolve_domain_agent_uses_job_type(monkeypatch):
    from app.forensic_common import pipeline_routing as pr

    def fake_is_mobile(db, job_id):
        return job_id == "mobile-job"

    monkeypatch.setattr(pr, "is_mobile_job", fake_is_mobile)
    monkeypatch.setattr(pr, "resolve_platform_owner_id", lambda db, job_id: "iosagent")
    assert resolve_domain_agent_id(None, "mobile-job", "extract_agent") == "extract_agent_mobile"
    assert resolve_domain_agent_id(None, "disk-job", "extract_agent") == "extract_agent_disk"
    assert resolve_domain_agent_id(None, "mobile-job", "inventory_agent") == "inventory_agent_mobile"
    assert resolve_domain_agent_id(None, "mobile-job", "inventory_agent_disk") == "inventory_agent_mobile"
    assert resolve_domain_agent_id(None, "mobile-job", "parse_agent") == "parse_agent_mobile"
    assert normalize_stage_agent_id(
        resolve_domain_agent_id(None, "mobile-job", "inventory_agent")
    ) == "inventory_agent"


def test_stage_key_follows_action_not_iosagent_alias():
    assert stage_key_for_recommendation("iosagent", "artifact_inventory") == "inventory_agent"
    assert stage_key_for_recommendation("iosagent", "parse_drain") == "parse_agent"
    assert stage_key_for_recommendation("iosagent", "resume_extraction") == "extract_agent"
    assert stage_key_for_recommendation("inventory_agent", "artifact_inventory") == "inventory_agent"
