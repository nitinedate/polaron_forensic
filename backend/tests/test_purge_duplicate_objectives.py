"""Tests for duplicate objective purge by numbered procedure."""

from __future__ import annotations

from app.services.report_template_service import (
    _pick_report_objective_keeper,
    _procedure_starts_with_one,
    purge_duplicate_objectives_without_numbered_procedure,
)


def test_procedure_starts_with_one():
    assert _procedure_starts_with_one("1. Confirm legal authority")
    assert _procedure_starts_with_one("  1. Step one")
    assert not _procedure_starts_with_one("Review user accounts")
    assert not _procedure_starts_with_one("")
    assert not _procedure_starts_with_one(None)


def test_pick_report_objective_keeper_prefers_numbered_procedure():
    short = {
        "objective_id": "RPT-O901",
        "title": "User Accounts & Login Activity",
        "procedure_text": "Review user accounts, login/logout events",
    }
    long = {
        "objective_id": "O016",
        "title": "User Accounts & Login Activity",
        "procedure_text": "1. Confirm legal/organizational authority",
    }
    keeper = _pick_report_objective_keeper([short, long])
    assert keeper["objective_id"] == "O016"


def test_purge_duplicate_objectives_without_numbered_procedure(monkeypatch):
    rows = [
        {
            "report_type_id": "general_computer_forensic",
            "objective_id": "O016",
            "title": "User Accounts & Login Activity",
            "objective": "Long statement",
            "procedure_text": "1. Confirm legal/organizational authority",
        },
        {
            "report_type_id": "general_computer_forensic",
            "objective_id": "RPT-O901",
            "title": "User Accounts & Login Activity",
            "objective": "Short statement",
            "procedure_text": "Review user accounts, login/logout events",
        },
        {
            "report_type_id": "general_computer_forensic",
            "objective_id": "O022",
            "title": "File Access and Handling",
            "objective": "Only one",
            "procedure_text": "1. Confirm legal/organizational authority",
        },
        {
            "report_type_id": "data_leakage",
            "objective_id": "O016",
            "title": "User Accounts & Login Activity",
            "objective": "Long statement",
            "procedure_text": "1. Confirm legal/organizational authority",
        },
        {
            "report_type_id": "data_leakage",
            "objective_id": "RPT-O901",
            "title": "User Accounts & Login Activity",
            "objective": "Short statement",
            "procedure_text": "Review user accounts, login/logout events",
        },
    ]
    deleted: list[tuple[str, str]] = []

    class FakeDb:
        def flush(self):
            return None

    def fake_fetchall(_db, sql, _params):
        if "WITH doomed AS" in sql:
            return [{"c": 0}]
        return rows

    def fake_execute(_db, sql, params):
        if "DELETE FROM public.reports_objective" in sql and "objective_id = :oid" in sql:
            deleted.append((params["rt"], params["oid"]))

    def fake_fetchone(_db, sql, _params):
        if "WITH doomed AS" in sql:
            return {"c": 0}
        return None

    monkeypatch.setattr("app.services.report_template_service.fetchall", fake_fetchall)
    monkeypatch.setattr("app.services.report_template_service.fetchone", fake_fetchone)
    monkeypatch.setattr("app.services.report_template_service.execute", fake_execute)

    result = purge_duplicate_objectives_without_numbered_procedure(FakeDb())
    assert result["deleted"] == 2
    assert ("general_computer_forensic", "RPT-O901") in deleted
    assert ("data_leakage", "RPT-O901") in deleted
