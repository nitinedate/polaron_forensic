"""Catalog ensure for mobile platforms (inventory unblock)."""

from __future__ import annotations

from app.services.mobile_report_catalog import MOBILE_FORENSIC_ARTIFACTS_IOS


def test_ios_catalog_pairs_nonempty():
    assert len(MOBILE_FORENSIC_ARTIFACTS_IOS) >= 10
    cats = {c for c, _ in MOBILE_FORENSIC_ARTIFACTS_IOS}
    assert "Communication" in cats
    assert "Media" in cats


def test_perf_policy_allows_inventory_when_hot(monkeypatch):
    from app.services import perf_policy

    class Snap:
        profile = "laptop"
        gpu_temp_c = 95
        cpu_temp_c = None

    class Plan:
        snapshot = Snap()
        profile = "laptop"

    monkeypatch.setattr(
        "app.services.host_capacity.get_last_plan",
        lambda: Plan(),
    )
    monkeypatch.setattr(
        "app.services.host_capacity.probe_host",
        lambda: Snap(),
    )
    monkeypatch.setattr(
        "app.services.host_capacity.cpu_thermal_pace",
        lambda: 1.0,
    )

    class Stats:
        available = True
        temperature_c = 95

    monkeypatch.setattr(
        "app.services.gpu_thermal.get_gpu_stats",
        lambda: Stats(),
    )

    # Fake baseline chunks without DB
    class FakeRow(dict):
        pass

    def fake_fetchone(db, sql, params=None):
        return {"c": 694}

    monkeypatch.setattr("app.db.sql_helpers.fetchone", fake_fetchone)

    plan = perf_policy.build_live_plan(db=object(), job_id="j1")
    assert plan["too_hot"] is True
    assert plan["allow_parallel"] is True
    assert "inventory_agent" in plan["safe_parallel_agents"]
    assert "rag_enrich_agent" not in plan["safe_parallel_agents"]
