"""Tests for case type catalog resolution and report-type mapping."""

from app.services.case_type_catalog_service import _fallback_case_types


def test_fallback_case_types_include_data_leakage() -> None:
    items = _fallback_case_types()
    ids = {i["id"] for i in items}
    assert "data_leakage" in ids
    assert "insider_threat" in ids


def test_resolve_case_type_by_label_without_db_tables(monkeypatch) -> None:
    from app.services import case_type_catalog_service as mod

    monkeypatch.setattr(mod, "_table_exists", lambda *_a, **_k: False)
    resolved = mod.resolve_case_type(object(), "Data Leakage / Exfiltration")
    assert resolved is not None
    assert resolved["case_type_id"] == "data_leakage"
    assert resolved["default_report_type_id"] == "data_exfiltration"


def test_default_report_type_for_malware_case(monkeypatch) -> None:
    from app.services import case_type_catalog_service as mod

    monkeypatch.setattr(mod, "_table_exists", lambda *_a, **_k: False)
    rt = mod.default_report_type_for_case(object(), "malware_incident")
    assert rt == "malware"
