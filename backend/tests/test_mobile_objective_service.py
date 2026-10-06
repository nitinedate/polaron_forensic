"""Tests for mobile AXIOM objective enrichment and RAG queries."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.mobile_objective_service import (
    MOBILE_OBJECTIVE_RAG_HINTS,
    build_mobile_objective_rag_query,
    enrich_mobile_objectives,
)


def test_build_mobile_objective_rag_query_includes_platform_and_hints():
    obj = {
        "title": "Chat / Communication Apps",
        "objective": "Identify chat usage.",
        "procedure_text": "Review messaging databases.",
        "axiom_objective_id": "O043",
    }
    query = build_mobile_objective_rag_query(obj, "Android")
    assert "Android" in query
    assert "whatsapp" in query.lower()
    assert "O043" in query
    assert MOBILE_OBJECTIVE_RAG_HINTS["Chat / Communication Apps"].split()[0] in query


@patch("app.services.mobile_objective_service.mobile_platform_for_job", return_value="iOS")
@patch("app.services.report_template_service._fetch_axiom_objective_detail")
@patch("app.services.report_template_service.artifact_lookup_objective_id", return_value="O043")
@patch("app.services.report_objective_evidence.list_catalog_artifacts_for_objective", return_value=[])
@patch("app.services.report_objective_evidence.build_objective_evidence_prompt", return_value="prompt")
def test_enrich_mobile_objectives_uses_axiom_detail(
    _prompt,
    _linked,
    _lookup_id,
    fetch_detail,
    _platform,
):
    fetch_detail.return_value = {
        "objective_id": "O043",
        "title": "Chat / Communication Apps",
        "statement": "Recover chat messages from the device.",
        "procedure_text": "1. Identify chat applications\n2. Parse message stores",
        "required_observation_fields": "counts; users",
        "expected_output_fields": "messages",
        "minimum_corroboration": "two sources",
        "limitations": "encrypted chats",
    }
    db = MagicMock()
    objectives = [{
        "id": "RPT-O913",
        "title": "Chat / Communication Apps",
        "objective": "short template",
        "procedure_text": "short proc",
    }]
    out = enrich_mobile_objectives(db, "job-1", {"report_type": "mobile_forensic"}, objectives)
    assert len(out) == 1
    assert out[0]["objective"] == "Recover chat messages from the device."
    assert out[0]["procedure_text"].startswith("1.")
    assert out[0]["mobile_platform"] == "iOS"
    assert out[0]["evidence_prompt"] == "prompt"
