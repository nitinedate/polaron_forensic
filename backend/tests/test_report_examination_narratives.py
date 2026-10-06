from __future__ import annotations

from app.services.axiom_forensic_kb import OBJECTIVE_REPORT_MAP, controlled_objective_text, controlled_procedure_text, objective_knowledge_plan
from app.services.report_catalog_sync import REPORT_OBJECTIVES
from app.services.report_examination_narratives import (
    CLIENT_OBJECTIVE_STATEMENTS,
    EXAMINATION_NARRATIVES,
    format_client_objective,
    format_client_procedure,
    format_examination_block,
    get_examination_narrative,
)


def test_all_report_titles_have_kb_generated_narratives():
    for row in REPORT_OBJECTIVES:
        title = row["title"]
        narrative = get_examination_narrative(title)
        assert narrative is not None
        assert narrative["kb_report_ids"] == objective_knowledge_plan(title)["report_ids"]


def test_client_objective_and_procedure_are_controlled_kb_text():
    title = "Access to Cloud Storage Services"
    assert format_client_objective(title) == controlled_objective_text(title)
    assert format_client_procedure(title) == controlled_procedure_text(title)
    assert "cloud storage" in format_client_objective(title).lower()


def test_examination_block_exposes_controlled_scope_not_example_case_values():
    block = format_examination_block("USB and External Device Usage")
    assert "Controlled examination approach" in block
    assert "USB Devices" in block
    assert "418" not in block
    assert "RRP Electronics" not in block


def test_generated_compatibility_constants_are_from_kb():
    for title in OBJECTIVE_REPORT_MAP:
        assert CLIENT_OBJECTIVE_STATEMENTS[title] == controlled_objective_text(title)
        assert EXAMINATION_NARRATIVES[title]["kb_report_ids"] == objective_knowledge_plan(title)["report_ids"]
