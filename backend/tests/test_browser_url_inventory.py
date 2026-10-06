"""Tests for browser URL inventory aggregation."""

from app.services.browser_url_inventory import _profile_key, compute_communication_url_totals
from app.services.url_category_counts import classify_url_category


def test_profile_key_groups_snapshots() -> None:
    path = "Users/pathlab/AppData/Local/Google/Chrome/User Data/Snapshots/128/Default/History"
    assert _profile_key(path) == "snapshots/128"


def test_classify_cloud_not_communication() -> None:
    assert classify_url_category("https://drive.google.com/file/d/abc/view") is None


def test_compute_communication_url_totals_empty_db(monkeypatch) -> None:
    class _Db:
        pass

    monkeypatch.setattr(
        "app.services.browser_url_inventory.collect_job_browser_url_records",
        lambda _db, _jid: [
            {"url": "https://www.youtube.com/watch?v=1", "visit_count": 3},
            {"url": "https://web.whatsapp.com/send?text=hi", "visit_count": 2},
        ],
    )
    totals = compute_communication_url_totals(_Db(), "job")
    assert totals["social media urls"] == 3
    assert totals["web chat urls"] == 2
