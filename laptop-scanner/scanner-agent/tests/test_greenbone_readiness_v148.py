from __future__ import annotations

from lxml import etree

from agent import gmp_local


def test_feed_count_supports_info_count_schema():
    xml = etree.fromstring(
        b"<get_info_response><info_count><filtered>54321</filtered><total>54321</total></info_count></get_info_response>"
    )
    assert gmp_local._feed_count_from_xml(xml) == 54321


def test_feed_health_prefers_extended_get_nvts(monkeypatch):
    class FakeGmp:
        def __init__(self):
            self.extended = None

        def get_feeds(self):
            return etree.fromstring(b"<get_feeds_response><feed><version>20261002</version></feed></get_feeds_response>")

        def get_nvts(self, **kwargs):
            self.extended = kwargs.get("extended")
            return etree.fromstring(
                b"<get_nvts_response><nvt_count><filtered>50000</filtered><total>50000</total></nvt_count><nvt oid='1'/></get_nvts_response>"
            )

    gmp = FakeGmp()
    health = gmp_local._feed_health(gmp)
    assert gmp.extended is True
    assert health["nvt_count"] == 50000


def test_unknown_total_with_feed_version_is_positive_inventory_evidence(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {
            "syncing": False,
            "versions": ["202609290606"],
            "nvt_count": -1,
            "config_nvt_count": None,
        },
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is True
    assert state["reason"] == "nvt_inventory_present_count_unavailable"
    assert state["count_trustworthy"] is False


def test_unknown_total_without_feed_version_stays_fail_closed(monkeypatch):
    monkeypatch.setenv("GVM_MIN_NVT_COUNT", "10000")
    monkeypatch.setattr(
        gmp_local,
        "_feed_health",
        lambda gmp, config_id=None: {
            "syncing": False,
            "versions": [],
            "nvt_count": -1,
            "config_nvt_count": None,
        },
    )
    state = gmp_local._ospd_feed_state(object())
    assert state["ready"] is False
    assert state["reason"] == "nvt_count_unavailable"
