from __future__ import annotations

from app.services.structured_observation_service import _confidence_for_count


def test_not_found_when_zero_count() -> None:
    assert _confidence_for_count(0) == ("NOT_FOUND", "HIGH")


def test_confirmed_with_multiple_sources() -> None:
    assert _confidence_for_count(2, corroboration_count=2) == ("CONFIRMED", "HIGH")


def test_build_structured_observation_uses_kb_brief(monkeypatch) -> None:
    from app.services import structured_observation_service as mod

    brief = {
        "status": "NOT_FOUND",
        "knowledge_plan": {"report_ids": ["USB_DEVICES"]},
        "report_results": [],
        "allowed_counts": [],
        "limitations": [],
        "examiner_review_required": False,
        "objective": {"title": "USB and External Device Usage"},
    }
    monkeypatch.setattr(mod, "build_objective_evidence_brief", lambda *_a, **_k: brief)
    monkeypatch.setattr(
        mod,
        "deterministic_observation_from_brief",
        lambda _b: "No primary USB evidence met the controlled criteria. This means the available evidence did not establish the finding.",
    )
    obs = mod.build_structured_observation(
        object(),
        "job-1",
        {"id": "OBJ-1", "title": "USB and External Device Usage"},
        intake={"case_type": "data_leakage"},
        enabled_artifact_keys=set(),
    )
    assert obs["status"] == "NOT_FOUND"
    assert obs["structured_json"]["knowledge_base"] == "aetheris_axiom_kb_starter"
    assert len(obs["structured_json"]["knowledge_base_fingerprint"]) == 64
    assert "This means" in obs["observation_md"]
