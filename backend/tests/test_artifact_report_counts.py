"""Report artifact counts must match Artifacts-page inventory, not inflated collector max()."""

from app.services.artifact_report_service import (
    _inventory_count_for_artifact,
    _selected_sections,
    _with_catalog_shape,
    gather_artifact_summary_structured,
    structured_has_artifact_groups,
)


def test_selected_sections_uses_report_keys_not_scope_intersection() -> None:
    """Saved report keys must not be dropped when artifact_scope still has defaults."""
    scope = {
        "enabled_keys": ["default-a", "default-b", "saved-x"],
        "sections": [
            {
                "title": "Communication",
                "subcategories": [
                    {"key": "default-a", "label": "Default A", "count": 1},
                    {"key": "saved-x", "label": "Saved X", "count": 5},
                ],
            },
        ],
        "groups": [{"group_name": "Communication", "enabled": True}],
    }
    selected = _selected_sections(scope, report_keys={"saved-x"})
    assert len(selected) == 1
    assert [s["key"] for s in selected[0]["subcategories"]] == ["saved-x"]


def test_selected_sections_without_report_keys_uses_scope() -> None:
    scope = {
        "enabled_keys": ["a1", "a2"],
        "sections": [
            {
                "title": "Group",
                "subcategories": [
                    {"key": "a1", "label": "One", "count": 1},
                    {"key": "a2", "label": "Two", "count": 2},
                ],
            },
        ],
        "groups": [],
    }
    selected = _selected_sections(scope)
    assert len(selected) == 1
    assert len(selected[0]["subcategories"]) == 2


def test_inventory_count_prefers_persisted_inventory() -> None:
    sub = {"key": "AX-0009", "label": "Feature Usage", "count": 28}
    inventory_map = {
        "AX-0009": {"count": 28, "answer": "Feature Usage — count 28"},
    }
    assert _inventory_count_for_artifact(sub, inventory_map=inventory_map) == 28


def test_inventory_count_ignores_higher_scope_count_when_inventory_zero() -> None:
    sub = {"key": "AX-0011", "label": "Installed Programs (Non-Microsoft)", "count": 0}
    inventory_map = {"AX-0011": {"count": 0, "answer": ""}}
    assert _inventory_count_for_artifact(sub, inventory_map=inventory_map) == 0


def test_inventory_count_falls_back_to_scope_catalog() -> None:
    sub = {"key": "AX-0013", "label": "Windows Defender Logs", "count": 5}
    assert _inventory_count_for_artifact(sub, inventory_map={}) == 5


def test_catalog_shape_and_group_detection() -> None:
    empty = _with_catalog_shape({"categories": []})
    assert empty["catalog"]["sections"] == []
    assert not structured_has_artifact_groups(empty)
    filled = _with_catalog_shape({
        "categories": [{
            "title": "Web",
            "items": [{"label": "Chrome History", "count": 12, "description": "Browser visits."}],
        }],
    })
    assert filled["catalog"]["sections"][0]["title"] == "Web"
    assert filled["catalog"]["sections"][0]["subcategories"][0]["name"] == "Chrome History"
    assert structured_has_artifact_groups(filled)
    assert not structured_has_artifact_groups(None)
    assert not structured_has_artifact_groups({"categories": []})


def test_gather_fast_path_does_not_raise_on_section_title(monkeypatch) -> None:
    """Regression: report_fast loop used undefined `sec` and blanked B. ARTIFACTS."""
    from app.services import artifact_report_service as svc

    monkeypatch.setattr(svc, "artifact_scope_payload", lambda *a, **k: {
        "platform": "windows",
        "enabled_keys": ["AX-1"],
        "sections": [{
            "title": "Web Related",
            "subcategories": [{
                "key": "AX-1",
                "label": "Chrome Web History",
                "count": 12,
                "prompt_question": "Describe Chrome history.",
            }],
        }],
        "groups": [{"group_name": "Web Related", "enabled": True}],
    })
    monkeypatch.setattr(
        "app.services.report_template_service.resolve_report_artifact_keys",
        lambda *a, **k: {"AX-1"},
    )
    monkeypatch.setattr(svc, "_load_inventory_map", lambda *a, **k: {
        "AX-1": {
            "count": 12,
            "answer": "Chrome history present.",
            "prompt_question": "Describe Chrome history.",
            "observation_focus": "",
        },
    })

    out = gather_artifact_summary_structured(None, "job-1")
    assert out["categories"][0]["title"] == "Web Related"
    assert out["categories"][0]["items"][0]["label"] == "Chrome Web History"
    assert out["catalog"]["sections"][0]["subcategories"][0]["name"] == "Chrome Web History"
