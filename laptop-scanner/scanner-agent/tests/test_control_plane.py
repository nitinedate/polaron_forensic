from agent.port_range import exclude_tcp_ports_from_range
from agent.control_plane import _body_is_aetheris, port_range_without_control_plane


def test_strips_8080_from_fast_ports():
    src = (
        "T:21-23,25,53,80,443,8080,8443,9000"
    )
    assert "8080" not in exclude_tcp_ports_from_range(src, {8080}).split(",")
    assert "8443" in exclude_tcp_ports_from_range(src, {8080})


def test_aetheris_health_fingerprint():
    assert _body_is_aetheris('{"status":"ok","service":"aetheris","role":"central-api"}') is True
    assert _body_is_aetheris('{"status":"ok","service":"aetheris","role":"vuln-api"}') is True
    assert _body_is_aetheris('{"status":"ok","service":"aetheris","role":"forensic-api"}') is True
    assert _body_is_aetheris('{"status":"ok","service":"other"}') is False


def test_port_range_without_control_plane_uses_probe(monkeypatch):
    import agent.control_plane as cp

    monkeypatch.setattr(cp, "control_plane_ports_for_hosts", lambda hosts: {8080})
    out = port_range_without_control_plane("T:80,8080,8443", ["192.168.0.163"])
    assert out == "T:80,T:8443"
