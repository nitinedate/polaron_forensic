from datetime import datetime, timedelta, timezone

from app.services.scanner_credentials import (
    connection_mode_for_role,
    infer_scanner_role,
    is_edge_agent_scanner,
    is_remote_scanner_url,
    normalize_scanner_url,
    parse_gmp_credentials,
    scanner_heartbeat_online,
)


def test_parse_gmp_credentials_user_pass():
    assert parse_gmp_credentials("admin:s3cret") == ("admin", "s3cret")


def test_parse_gmp_credentials_json():
    assert parse_gmp_credentials('{"username":"gvm","password":"x"}') == ("gvm", "x")


def test_is_remote_scanner_url():
    assert is_remote_scanner_url("tls://203.0.113.10:9390") is True
    assert is_remote_scanner_url("unix:///run/gvmd/gvmd.sock") is False
    assert is_remote_scanner_url("gmp://gvmd:9390") is False
    assert is_remote_scanner_url("tls://gvmd:9390") is False
    assert is_remote_scanner_url("agent://local") is True


def test_is_edge_agent_scanner():
    assert is_edge_agent_scanner({"connection_mode": "edge_agent", "url": "agent://local"}) is True
    assert is_edge_agent_scanner({"connection_mode": "gmp", "url": "tls://host:9390"}) is False
    assert is_edge_agent_scanner(None, url="agent://local") is True


def test_infer_scanner_role_defaults_edge_to_portable():
    assert infer_scanner_role({"connection_mode": "edge_agent", "url": "agent://local"}) == "portable"
    assert (
        infer_scanner_role({"connection_mode": "edge_agent", "url": "agent://local", "scanner_role": "persistent_edge"})
        == "persistent_edge"
    )
    assert infer_scanner_role({"connection_mode": "gmp", "url": "tls://10.0.0.8:9390"}) == "remote_vpn"
    assert infer_scanner_role({"connection_mode": "gmp", "url": "unix:///run/gvmd/gvmd.sock"}) == "central"


def test_connection_mode_for_role():
    assert connection_mode_for_role("persistent_edge") == "edge_agent"
    assert connection_mode_for_role("portable") == "edge_agent"
    assert connection_mode_for_role("remote_vpn") == "gmp"
    assert connection_mode_for_role("central") == "gmp"


def test_scanner_heartbeat_online_edge_only():
    now = datetime.now(timezone.utc)
    fresh = {
        "connection_mode": "edge_agent",
        "scanner_role": "persistent_edge",
        "last_heartbeat_at": now,
    }
    assert scanner_heartbeat_online(fresh) is True
    stale = {**fresh, "last_heartbeat_at": now - timedelta(seconds=400)}
    assert scanner_heartbeat_online(stale) is False
    assert scanner_heartbeat_online({"connection_mode": "gmp", "url": "tls://10.0.0.8:9390"}) is None
    assert scanner_heartbeat_online({"connection_mode": "edge_agent", "url": "agent://local"}) is False


def test_create_scanner_persists_scanner_role():
    from pathlib import Path

    text = Path(__file__).resolve().parents[1].joinpath("app", "routers", "vuln.py").read_text(encoding="utf-8")
    assert "scanner_role" in text
    assert "SCANNER_ROLE_REMOTE_VPN" in text
    assert "SCANNER_ROLE_CENTRAL" in text
    assert "gmp_url_required" in text
    assert "central_gmp_url_required" in text
    assert "tls://site-vpn-host:9390" in text
    assert "unix:///run/gvmd/gvmd.sock" in text


def test_normalize_scanner_url():
    assert normalize_scanner_url("203.0.113.10:9390") == "tls://203.0.113.10:9390"
    assert normalize_scanner_url("gmp://10.0.0.5:9390").startswith("tls://")


def test_remote_gmp_configured_without_local_gvm_live(monkeypatch):
    from types import SimpleNamespace

    from app.services import greenbone_client as gc
    from app.services.greenbone_client import GreenboneClient

    settings = SimpleNamespace(
        gvm_live_enabled=False,
        gvm_url="",
        gvm_socket_path="",
        gvm_host="gvmd",
        gvm_port=9390,
        gvm_username="admin",
        gvm_password="admin",
        gvm_admin_password="admin",
        gvm_verify_tls=False,
    )
    monkeypatch.setattr(gc, "get_settings", lambda: settings)
    monkeypatch.setattr(gc.greenbone_gmp, "gmp_available", lambda: True)
    client = GreenboneClient(
        base_url="tls://10.0.0.8:9390",
        gmp_username="admin",
        gmp_password="secret",
    )
    assert client.configured is True
    local = GreenboneClient(base_url="unix:///run/gvmd/gvmd.sock", gmp_username="admin", gmp_password="secret")
    assert local.configured is False
