"""Catalog label aliases for AXIOM artifact names."""

from app.services.axiom_catalog_ingest import catalog_artifact_label


def test_installed_programs_display_label() -> None:
    assert catalog_artifact_label("AX-0011", "Installed Programs") == "Installed Programs (Non-Microsoft)"
    assert catalog_artifact_label("AX-0010", "Installed Microsoft Programs") == "Installed Microsoft Programs"
