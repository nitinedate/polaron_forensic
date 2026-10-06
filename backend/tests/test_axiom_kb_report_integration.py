from __future__ import annotations

import inspect

from app.services.axiom_forensic_kb import (
    REPORT_AGENT_SYSTEM_RULES,
    controlled_objective_text,
    controlled_procedure_text,
    kb_summary,
    objective_knowledge_plan,
    report_definition,
    sanitize_narrative_text,
)
from app.services.axiom_forensic_report_engine import (
    _run_kb_report,
    validate_observation_against_brief,
)
from app.services.evidence_contract_planner import attach_evidence_contracts_to_objectives
from app.services.report_objective_procedures import enrich_axiom_procedure_for_title
from app.services.report_objectives_observation_service import _agent_safe_brief


def test_supplied_kb_is_loaded_with_expected_seed_counts():
    assert kb_summary() == {
        "procedures": 18,
        "reports": 58,
        "artifact_families": 56,
        "exclusions": 3,
    }


def test_external_hard_disk_objective_does_not_treat_generic_usb_total_as_direct_answer():
    plan = objective_knowledge_plan("Connection of External Hard Disks")
    assert "USB_DEVICES" in plan["report_ids"]
    assert plan["direct_report_ids"] == []
    assert plan["direct_primary_artifact_families"] == []


def test_generic_usb_objective_uses_usb_devices_as_direct_primary_report():
    plan = objective_knowledge_plan("USB and External Device Usage")
    assert "USB_DEVICES" in plan["direct_report_ids"]
    assert "USB Devices" in plan["direct_primary_artifact_families"]


def test_controlled_procedure_comes_from_supplied_kb_and_legacy_db_text_is_ignored():
    procedure = enrich_axiom_procedure_for_title(
        "USB and External Device Usage",
        "LEGACY PROCEDURE THAT MUST NOT APPEAR",
    )
    assert "LEGACY PROCEDURE" not in procedure
    assert "Network and External Devices" not in procedure  # client wording uses purpose/steps, not internal name
    assert "stable identifiers" in procedure.lower()
    assert "serial number" in procedure.lower()


def test_controlled_objective_comes_from_supplied_report_definition():
    objective = controlled_objective_text("Presence of Encrypted Files")
    assert "encrypted" in objective.lower() or "protected" in objective.lower()
    assert objective.lower().startswith("to ")


def test_max_zero_procedure_steps_returns_narrative_without_accidentally_adding_one_step():
    text = controlled_procedure_text("USB and External Device Usage", max_steps=0)
    assert "The examination used the controlled AXIOM procedure" in text
    assert "1." not in text


def test_raw_appx_blockmap_payload_is_removed_before_report_writing():
    raw = '[{"text": "<?xml version=\\"1.0\\" encoding=\\"UTF-8\\"?><BlockMap xmlns=\\"http://schemas.microsoft.com/appx/2010/blockmap\\">"}]'
    assert sanitize_narrative_text(raw) == ""


def test_semantic_usb_dedup_uses_primary_family_only_and_supporting_lnk_cannot_inflate_count():
    report = report_definition("USB_DEVICES")
    assert report is not None
    artifacts = [
        {
            "artifact_id": "usb-current",
            "family": "USB Devices",
            "occurrence_count": 2,
            "unique_count": None,
            "snapshot_records": [
                {"device_serial": "SER-001", "vid": "1234", "pid": "5678", "manufacturer": "Acme"},
                {"device_serial": "SER-001", "vid": "1234", "pid": "5678", "manufacturer": "Acme"},
            ],
            "answer": "Two raw rows describe the same device.",
        },
        {
            "artifact_id": "lnk-current",
            "family": "LNK Files",
            "occurrence_count": 99,
            "unique_count": 99,
            "snapshot_records": [],
            "answer": "Supporting shortcut records.",
        },
    ]
    result = _run_kb_report(report, artifacts)
    assert result["reported_count"] == 1
    assert result["count_basis"] == "kb_semantic_deduplication"
    assert result["primary_family_counts"]["USB Devices"] == 2
    assert result["raw_hit_count"] == 101


def test_report_writer_validator_rejects_laptop_banner_and_unapproved_rdp_zero_count():
    brief = {"allowed_counts": []}
    bad = "Laptop [1]. 0 items (Remote Desktop Protocol (RDP)) were found. This means no issue was found."
    valid, errors = validate_observation_against_brief(bad, brief)
    assert not valid
    assert any("internal evidence-source label" in e for e in errors)
    assert any("count 0" in e for e in errors)


def test_legacy_evidence_prompt_is_replaced_not_merged():
    rows = attach_evidence_contracts_to_objectives(
        None,
        "job-1",
        {},
        [{"id": "obj-1", "title": "USB and External Device Usage", "evidence_prompt": "OLD HAND-WRITTEN PROMPT"}],
        domain="disk",
        use_llm=True,
        model="ignored",
    )
    assert len(rows) == 1
    prompt = rows[0]["evidence_prompt"]
    assert "OLD HAND-WRITTEN PROMPT" not in prompt
    assert "AXIOM FORENSIC KNOWLEDGE CONTRACT" in prompt
    assert "USB_DEVICES" in prompt


def test_llm_receives_only_safe_evidence_brief_not_raw_primary_or_provenance_objects():
    safe = _agent_safe_brief(
        {
            "objective": {"title": "USB and External Device Usage"},
            "status": "CONFIRMED",
            "knowledge_plan": {"report_ids": ["USB_DEVICES"], "direct_report_ids": ["USB_DEVICES"]},
            "report_results": [
                {
                    "report_id": "USB_DEVICES",
                    "report_title": "USB Devices",
                    "reported_count": 1,
                    "count_unit": "USB_DEVICE",
                    "primary_evidence": [{"raw": "must not reach LLM"}],
                    "supporting_evidence": [{"raw": "must not reach LLM"}],
                    "provenance": {"sql": "must not reach LLM"},
                    "safe_facts": ["One device record was recovered."],
                }
            ],
            "allowed_counts": [{"report_id": "USB_DEVICES", "count": 1, "unit": "USB_DEVICE"}],
        }
    )
    serialized = repr(safe)
    assert "must not reach LLM" not in serialized
    assert "primary_evidence" not in serialized
    assert "supporting_evidence" not in serialized
    assert "sql" not in serialized


def test_report_agent_system_rules_make_llm_wording_only():
    low = REPORT_AGENT_SYSTEM_RULES.lower()
    assert "do not change counts" in low
    assert "do not add artifacts" in low
    assert "raw appx blockmap xml" in low
    assert "laptop [1]" in low


def test_runtime_observation_service_no_longer_contains_v7_generic_artifact_context_path():
    from app.services import report_objectives_observation_service as mod

    src = inspect.getsource(mod)
    assert "_scoped_artifact_context" not in src
    assert "AXIOM-SYNCED EVIDENCE PLAN" not in src
    assert "REPORT_AGENT_SYSTEM_RULES" in src
    assert "build_structured_observation" in src


def test_report_intake_catalog_objective_text_is_generated_from_kb():
    from app.services.report_catalog_sync import REPORT_OBJECTIVES

    for row in REPORT_OBJECTIVES:
        title = row["title"]
        assert row["statement"] == controlled_objective_text(title)
        assert row["procedure"] == controlled_procedure_text(title)


def test_mobile_report_semantics_are_generated_from_kb_not_a_second_manual_playbook():
    from app.services.mobile_report_catalog import (
        MOBILE_EVIDENCE_QUESTIONS,
        MOBILE_EXAMINATION_NARRATIVES,
        MOBILE_FORENSIC_OBJECTIVE_TITLES,
        MOBILE_OBJECTIVE_STATEMENTS,
    )
    from app.services.axiom_forensic_kb import evidence_questions_for_objective

    for title in MOBILE_FORENSIC_OBJECTIVE_TITLES:
        assert MOBILE_OBJECTIVE_STATEMENTS[title] == controlled_objective_text(title)
        assert MOBILE_EVIDENCE_QUESTIONS[title] == evidence_questions_for_objective(title)
        assert MOBILE_EXAMINATION_NARRATIVES[title]["kb_report_ids"] == objective_knowledge_plan(title)["report_ids"]


def test_global_appx_exclusions_are_read_from_supplied_kb_seed():
    from app.services.axiom_forensic_kb import text_contains_prohibited_payload

    assert text_contains_prohibited_payload("AppxManifest.xml")
    assert text_contains_prohibited_payload("<Package xmlns='x'>")
    assert text_contains_prohibited_payload("<BlockMap HashMethod='x'>")
    assert not text_contains_prohibited_payload("Google Drive was accessed in the current case")


def test_supplied_kb_integrity_and_fingerprint_are_traceable():
    from app.services.axiom_forensic_kb import knowledge_base_fingerprint, validate_knowledge_base_integrity

    assert validate_knowledge_base_integrity() == []
    fingerprint = knowledge_base_fingerprint()
    assert len(fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in fingerprint)
