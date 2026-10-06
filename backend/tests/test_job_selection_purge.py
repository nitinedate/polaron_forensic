"""Hard-replace semantics for per-job artifact and objective selections."""

from __future__ import annotations

from app.services.report_template_service import objective_ids_from_snapshot


def test_objective_ids_from_snapshot_includes_template_and_custom() -> None:
    snapshot = [
        {"id": "O022", "title": "File Access and Handling"},
        {"id": "custom-1", "title": "Custom review", "source": "custom"},
    ]
    assert objective_ids_from_snapshot(snapshot) == ["O022", "custom-1"]


def test_objective_ids_from_snapshot_skips_blank() -> None:
    snapshot = [
        {"id": "", "title": "Empty"},
        {"objective_id": "O016", "title": "Login"},
    ]
    assert objective_ids_from_snapshot(snapshot) == ["O016"]
