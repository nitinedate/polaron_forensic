from __future__ import annotations

from app.services.axiom_forensic_kb import OBJECTIVE_REPORT_MAP, controlled_procedure_text, objective_knowledge_plan
from app.services.report_catalog_sync import REPORT_OBJECTIVES
from app.services.report_objective_procedures import (
    REPORT_OBJECTIVE_PROCEDURES,
    build_pointwise_procedure,
    enrich_axiom_procedure_for_title,
    procedure_for_title,
)


def test_all_catalog_objectives_use_kb_procedures():
    for row in REPORT_OBJECTIVES:
        title = row["title"]
        assert row["procedure"] == controlled_procedure_text(title)
        assert procedure_for_title(title) == controlled_procedure_text(title)


def test_generated_compatibility_map_has_no_second_procedure_playbook():
    for title in OBJECTIVE_REPORT_MAP:
        assert REPORT_OBJECTIVE_PROCEDURES[title] == controlled_procedure_text(title)


def test_legacy_axiom_procedure_cannot_override_supplied_kb():
    out = enrich_axiom_procedure_for_title("USB and External Device Usage", "OLD DATABASE PROCEDURE")
    assert "OLD DATABASE PROCEDURE" not in out
    assert "stable identifiers" in out.lower()


def test_legacy_pointwise_signature_delegates_to_kb():
    out = build_pointwise_procedure(
        title="Presence of Encrypted Files",
        artifact_families="WRONG OLD RULE",
        observation_focus="WRONG OLD FOCUS",
    )
    assert "WRONG OLD" not in out
    assert out == controlled_procedure_text("Presence of Encrypted Files")


def test_external_disk_procedure_uses_network_external_controlled_procedure():
    plan = objective_knowledge_plan("Connection of External Hard Disks")
    assert "P08_NETWORK_EXTERNAL" in plan["procedure_ids"]
    text = procedure_for_title("Connection of External Hard Disks")
    assert "serial number" in text.lower()
    assert "count unique devices" in text.lower()


def test_company_document_objective_is_mapped_to_document_search_reports():
    plan = objective_knowledge_plan("Storage of RRP-Related Documents on Personal Laptop")
    assert "DOCUMENTS" in plan["report_ids"]
    assert "KEYWORD_SEARCH" in plan["report_ids"]
