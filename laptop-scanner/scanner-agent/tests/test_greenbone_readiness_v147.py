from __future__ import annotations

from agent import gmp_local
from agent.api_client import CentralApi


def test_ospd_feed_state_fails_closed_when_inventory_unavailable(monkeypatch):
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {"syncing": False, "versions": [], "nvt_count": None},
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is False
    assert state["reason"] == "nvt_inventory_unavailable"


def test_ospd_feed_state_requires_minimum_nvt_count(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {"syncing": False, "versions": ["20261002"], "nvt_count": 9999},
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is False
    assert state["reason"] == "nvt_inventory_loading"


def test_ospd_feed_state_ready_with_positive_inventory(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {"syncing": False, "versions": ["20261002"], "nvt_count": 50000},
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is True
    assert state["reason"] == "ready"


def test_heartbeat_sends_readiness_detail(monkeypatch):
    seen = {}
    api = CentralApi(base_url="https://example.test", tenant="a", token="t", verify_tls=True)

    def fake_request(method, path, **kwargs):
        seen.update(kwargs.get("json") or {})
        return {"ok": True}

    monkeypatch.setattr(api, "_request", fake_request)
    api.heartbeat(version="1.4.7", openvas_ready=False, detail="OSPd feed loading")
    assert seen["version"] == "1.4.7"
    assert seen["openvas_ready"] is False
    assert seen["detail"] == "OSPd feed loading"


def test_ospd_feed_state_accepts_unknown_total_when_feed_version_exists(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {"syncing": False, "versions": ["20261002"], "nvt_count": -1},
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is True
    assert state["reason"] == "nvt_inventory_present_count_unavailable"
