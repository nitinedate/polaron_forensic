"""MBOX email count uses handbook-aligned SQL (matches browse)."""

from app.services.email_inventory import count_mbox_emails
from app.services.handbook_query_sql import MBOX_EMAIL_WHERE


class _Db:
    pass


def test_count_mbox_uses_handbook_where(monkeypatch) -> None:
    captured: dict = {}

    def fake_count(db, job_id, where):
        captured["where"] = where
        return 12

    def fake_sample(db, job_id, where, *, limit=8):
        captured["sample_where"] = where
        return ["Mail/Local Folders/inbox.mbox"]

    monkeypatch.setattr("app.services.email_inventory._count_sql", fake_count)
    monkeypatch.setattr("app.services.email_inventory._sample_sql", fake_sample)

    result = count_mbox_emails(_Db(), "job")
    assert result["count"] == 12
    assert MBOX_EMAIL_WHERE.strip() in captured["where"]
    assert MBOX_EMAIL_WHERE.strip() in captured["sample_where"]
