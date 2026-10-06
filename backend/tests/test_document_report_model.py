"""Physical reports in document_report_model train retrieval queries and observation writing."""
from __future__ import annotations

import re


def test_physical_reports_are_unpacked_and_every_pdf_trained_the_model():
    from app.services.document_report_model import document_report_files, document_report_summary, load_document_report_model

    files = document_report_files()
    assert len(files) == 7
    assert any(name.startswith("Master Report") for name in files)
    summary = document_report_summary()
    assert summary["physical_reports"] == 7
    assert summary["documents_in_model"] == 7
    assert summary["trained_objectives"] >= 20
    assert summary["observation_rules"] >= 4
    model = load_document_report_model()
    learned = {row["file"]: row["objectives_learned"] for row in model["documents"]}
    assert all(count > 0 for count in learned.values()), learned


def test_model_teaches_queries_and_observation_shape_without_exemplar_facts():
    from app.services.document_report_model import extraction_queries_for_objective, load_document_report_model, trained_objective

    usb = trained_objective("USB and External Device Usage")
    assert usb is not None
    queries = " ".join(extraction_queries_for_objective("USB and External Device Usage")).lower()
    assert "usb" in queries
    blob = " ".join(
        str(row.get("examination_method") or "") + " " + " ".join(row.get("extraction_queries") or [])
        for row in load_document_report_model()["objectives"]
    )
    assert not re.search(r"\b[\w.+-]+@[\w.-]+\.\w+\b", blob)
    assert "this means" in " ".join(load_document_report_model()["observation_writing"]["rules"]).lower()


def test_report_agent_uses_the_document_model_for_retrieval_and_writing():
    from app.services.axiom_forensic_kb import objective_knowledge_plan, rag_terms_for_objective
    from app.services.report_objective_evidence import build_rag_queries
    from app.services.report_objectives_observation_service import _observation_prompt

    plan = objective_knowledge_plan("USB and External Device Usage")
    guide = plan["document_report_model"]
    assert guide["extraction_queries"]
    assert guide["writing_moves"]
    assert "job" in " ".join(guide["query_method"]).lower()
    terms = " ".join(rag_terms_for_objective("USB and External Device Usage")).lower()
    assert "usb" in terms
    queries = " ".join(build_rag_queries({"title": "USB and External Device Usage", "objective": ""})).lower()
    assert "usb" in queries

    prompt = _observation_prompt(
        {"title": "USB and External Device Usage"},
        brief={"knowledge_plan": plan, "report_results": [], "allowed_counts": []},
        indexed_evidence=[],
        deterministic_draft="Traces of a USB connection were identified.",
        intake_context="",
    )
    assert "document_report_model" in prompt
    assert "extraction_queries" in prompt or "writing_moves" in prompt
