from __future__ import annotations

from app.services.axiom_forensic_kb import controlled_objective_text, evidence_questions_for_objective, objective_knowledge_plan
from app.services.mobile_report_catalog import (
    MOBILE_EVIDENCE_QUESTIONS,
    MOBILE_EXAMINATION_NARRATIVES,
    MOBILE_FORENSIC_ARTIFACTS,
    MOBILE_FORENSIC_OBJECTIVE_TITLES,
    MOBILE_OBJECTIVE_STATEMENTS,
    MOBILE_TITLE_AXIOM_OBJECTIVE_ID,
)
from app.services.report_catalog_sync import REPORT_OBJECTIVES
from app.services.report_template_service import _REPORT_TITLE_AXIOM_OBJECTIVE_ID, _report_template_specs


def test_mobile_titles_registered_in_report_objectives():
    titles = {x["title"] for x in REPORT_OBJECTIVES}
    assert set(MOBILE_FORENSIC_OBJECTIVE_TITLES) <= titles


def test_mobile_titles_have_catalog_ids_and_kb_generated_report_semantics():
    for title in MOBILE_FORENSIC_OBJECTIVE_TITLES:
        assert title in MOBILE_TITLE_AXIOM_OBJECTIVE_ID
        assert title in _REPORT_TITLE_AXIOM_OBJECTIVE_ID
        assert MOBILE_OBJECTIVE_STATEMENTS[title] == controlled_objective_text(title)
        assert MOBILE_EVIDENCE_QUESTIONS[title] == evidence_questions_for_objective(title)
        assert MOBILE_EXAMINATION_NARRATIVES[title]["kb_report_ids"] == objective_knowledge_plan(title)["report_ids"]


def test_mobile_forensic_template_uses_android_artifacts():
    specs = _report_template_specs()["mobile_forensic"]
    names = {name for _, name in specs["artifacts_by_platform"]["Android"]}
    expected = {name for _, name in MOBILE_FORENSIC_ARTIFACTS}
    assert expected <= names
