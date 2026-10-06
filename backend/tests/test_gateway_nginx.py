from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_gateway_nginx_routes_three_backends():
    conf = (REPO / "frontend" / "nginx-gateway.conf").read_text(encoding="utf-8")
    assert "host.docker.internal:8080" in conf
    assert "host.docker.internal:8081" in conf
    assert "host.docker.internal:8082" in conf
    assert "location /api/acquisition/" in conf
    assert "location /api/vuln/" in conf
    assert "X-Aetheris-Service" in (REPO / "frontend" / "gateway-proxy.inc").read_text(encoding="utf-8")


def test_gateway_compose_is_single_ui():
    yml = (REPO / "services" / "gateway" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "VITE_AETHERIS_SERVICE: unified" in yml
    assert '"3000:80"' in yml
