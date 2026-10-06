from __future__ import annotations

from app.services.axiom_forensic_kb import evidence_questions_for_objective, objective_knowledge_plan
from app.services.report_objective_evidence import (
    HEADER_EVIDENCE_QUESTIONS,
    STATUS_OPENING,
    build_objective_evidence_prompt,
    build_rag_queries,
    evidence_text_is_raw_payload,
    reference_artifact_context_mode,
    reference_chunk_relevant,
    reference_inconclusive_observation,
    reference_observation_contract,
    reference_observation_contract_text,
    reference_safe_counts,
)


def test_header_questions_are_generated_from_supplied_kb():
    for title in ("User Accounts & Login Activity", "USB and External Device Usage", "Access to Cloud Storage Services"):
        assert HEADER_EVIDENCE_QUESTIONS[title] == evidence_questions_for_objective(title)
        assert HEADER_EVIDENCE_QUESTIONS[title]


def test_evidence_prompt_names_controlled_reports_and_primary_count_rule():
    prompt = build_objective_evidence_prompt(
        header_title="USB and External Device Usage",
        objective_statement="legacy statement must not choose evidence",
        procedure_text="legacy procedure must not choose evidence",
    )
    assert "SUPPLIED AXIOM KNOWLEDGE BASE" in prompt
    assert "USB_DEVICES" in prompt
    assert "PRIMARY" in prompt
    assert "semantic deduplication" in prompt.lower()


def test_rag_queries_come_from_mapped_kb_reports():
    queries = build_rag_queries({"title": "USB and External Device Usage"})
    joined = " ".join(queries).lower()
    assert "usb devices" in joined
    assert "device_serial" in joined or "serial" in joined
    assert "lnk" in joined or "jump" in joined


def test_status_opening_has_controlled_states():
    assert {"CONFIRMED", "PROBABLE", "POSSIBLE", "NOT_FOUND", "INCONCLUSIVE", "NOT_EXAMINED"} <= set(STATUS_OPENING)


def test_reference_contract_uses_direct_primary_not_neighbor_totals():
    contract = reference_observation_contract("Connection of External Hard Disks")
    assert "USB_DEVICES" in contract["report_ids"]
    # Raw USB totals include hubs/cameras/interfaces and are supporting context for this
    # more specific business question until an external-disk filter is applied.
    assert contract["primary_artifact_families"] == []
    assert "USB Devices" in contract["all_mapped_primary_artifact_families"]


def test_reference_context_modes_prevent_generic_neighbor_count_substitution():
    assert reference_artifact_context_mode("USB and External Device Usage", "USB Devices") == "direct_count"
    assert reference_artifact_context_mode("Connection of External Hard Disks", "USB Devices") == "candidate_only"
    assert reference_artifact_context_mode("File Access and Handling", "Remote Desktop Protocol (RDP)") == "drop"


def test_safe_counts_keep_only_direct_primary_families():
    rows = [
        {"label": "USB Devices", "occurrence_count": 9},
        {"label": "Web Related Files", "occurrence_count": 15592},
    ]
    direct = reference_safe_counts("USB and External Device Usage", rows)
    assert [r["label"] for r in direct] == ["USB Devices"]
    external = reference_safe_counts("Connection of External Hard Disks", rows)
    assert external == []


def test_contract_text_and_inconclusive_wording_are_fail_closed():
    text = reference_observation_contract_text("File Access and Handling")
    assert "Controlled reports" in text
    assert "Supporting/corroborating" in text
    inconclusive = reference_inconclusive_observation("File Access and Handling")
    assert "broad artifact totals were not used" in inconclusive.lower()
    assert "This means" in inconclusive


def test_chunk_relevance_filters_unrelated_rdp_and_raw_xml_for_file_access():
    assert not reference_chunk_relevant(
        "File Access and Handling",
        {"content": "0 items (Remote Desktop Protocol (RDP))", "artifact_name": "Remote Desktop Protocol (RDP)"},
    )
    assert not reference_chunk_relevant(
        "File Access and Handling",
        {"content": '<?xml version="1.0"?><BlockMap />', "artifact_name": "AppxBlockMap.xml"},
    )


def test_raw_xml_payload_is_filtered_before_observation_rag():
    assert evidence_text_is_raw_payload('<?xml version="1.0"?><BlockMap />')
    assert evidence_text_is_raw_payload("AppxManifest.xml")
    assert not evidence_text_is_raw_payload("Google Drive browser history")


def test_plan_for_cloud_uses_browser_and_cloud_reports_without_claiming_generic_browser_count_is_direct():
    plan = objective_knowledge_plan("Access to Cloud Storage Services")
    assert "BROWSER_HISTORY" in plan["report_ids"]
    assert "CLOUD_ACTIVITY" in plan["report_ids"]
    assert plan["direct_report_ids"] == []
