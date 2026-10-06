"""Tests for fast report email counts."""

from app.services.email_inventory import compute_report_email_counts


def test_compute_report_email_counts_returns_section_keys(monkeypatch) -> None:
    class _Db:
        pass

    monkeypatch.setattr(
        "app.services.email_inventory.collect_email_artifact",
        lambda _db, _jid, title, **_kw: {"count": 3 if title == "Email Attachments" else 0},
    )
    counts = compute_report_email_counts(_Db(), "job")
    assert counts["email attachments"] == 3
    assert counts["outlook emails"] == 0
    assert "eml(x) files" in counts
