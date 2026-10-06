"""Tests for ASV workflow, bounded pentest, GMP helpers, endpoint inventory."""

from __future__ import annotations

from pathlib import Path

from app.services.greenbone_gmp import (
    DEFAULT_TARGET_PORT_RANGE,
    FAST_TARGET_PORT_RANGE,
    _find_preferred_port_list_id,
    _parse_host_port,
    _severity_from_threat,
    is_local_gvmd_tcp_url,
    gmp_create_and_start_scan,
    parse_socket_path,
    tcp_port_probe,
)
from app.services.vuln_asv import ASV_DISCLAIMER
from app.services.vuln_pentest import SAFE_PLAYBOOKS, run_safe_recon


def test_gmp_parse_host_port():
    assert _parse_host_port("tls://gvmd:9390") == ("gvmd", 9390)
    assert _parse_host_port("gvmd:9390")[0] == "gvmd"


def test_gmp_local_compose_endpoint_maps_to_socket():
    assert parse_socket_path("unix:///run/gvmd/gvmd.sock") == "/run/gvmd/gvmd.sock"
    assert is_local_gvmd_tcp_url("gmp://gvmd:9390") is True
    assert is_local_gvmd_tcp_url("tls://greenbone.example:9390") is False


def test_gmp_severity_mapping():
    assert _severity_from_threat("High", 7.5) == "high"
    assert _severity_from_threat(None, 9.5) == "critical"
    # Aetheris bands ignore OpenVAS/Greenbone threat labels.
    assert _severity_from_threat("High", 9.8) == "critical"
    assert _severity_from_threat("High", 5.0) == "medium"
    assert _severity_from_threat("Log", 0.0) == "info"


def test_gmp_report_filter_defaults_to_all_qod(monkeypatch):
    from app.services import greenbone_gmp

    class Settings:
        gvm_report_min_qod = 0

    import app.config
    monkeypatch.setattr(app.config, "get_settings", lambda: Settings())
    assert greenbone_gmp._report_filter_string() == "rows=-1 min_qod=0"


class _FakeXmlNode:
    def __init__(self, entity_id: str, name: str):
        self._id = entity_id
        self._name = name

    def get(self, key: str):
        return self._id if key == "id" else None

    def findtext(self, key: str):
        return self._name if key == "name" else None


class _FakeXmlResponse:
    def __init__(self, nodes):
        self._nodes = list(nodes)

    def xpath(self, expression: str):
        return list(self._nodes) if expression == "port_list" else []


def test_gmp_prefers_feed_port_list():
    class FakeGmp:
        def get_port_lists(self):
            return _FakeXmlResponse(
                [
                    _FakeXmlNode("other", "All TCP and All UDP"),
                    _FakeXmlNode("iana-tcp-id", "All IANA assigned TCP"),
                ]
            )

    assert _find_preferred_port_list_id(FakeGmp()) == "iana-tcp-id"


def test_gmp_create_target_always_supplies_port_selection(monkeypatch):
    from contextlib import contextmanager
    from app.services import greenbone_gmp

    class Created:
        def __init__(self, entity_id: str):
            self.entity_id = entity_id

        def get(self, key: str):
            return self.entity_id if key == "id" else None

    class FakeGmp:
        def __init__(self):
            self.target_kwargs = None

        def create_target(self, **kwargs):
            self.target_kwargs = kwargs
            return Created("target-1")

        def create_task(self, **kwargs):
            return Created("task-1")

        def start_task(self, task_id):
            assert task_id == "task-1"

    fake = FakeGmp()

    @contextmanager
    def fake_session(*args, **kwargs):
        yield fake

    monkeypatch.setattr(greenbone_gmp, "_gmp_session", fake_session)
    monkeypatch.setattr(greenbone_gmp, "_find_scan_config_id", lambda *args, **kwargs: "config-1")
    monkeypatch.setattr(greenbone_gmp, "_find_openvas_scanner_id", lambda *args, **kwargs: "scanner-1")
    monkeypatch.setattr(greenbone_gmp, "_find_preferred_port_list_id", lambda *args, **kwargs: None)

    task_id = gmp_create_and_start_scan(
        host="gvmd",
        port=9390,
        username="admin",
        password="admin",
        name="unit-test",
        targets="192.0.2.10",
    )

    assert task_id == "task-1"
    assert fake.target_kwargs["hosts"] == ["192.0.2.10"]
    assert fake.target_kwargs["port_range"] == DEFAULT_TARGET_PORT_RANGE
    assert "port_list_id" not in fake.target_kwargs


def test_gmp_create_target_uses_port_list_when_available(monkeypatch):
    from contextlib import contextmanager
    from app.services import greenbone_gmp

    class Created:
        def __init__(self, entity_id: str):
            self.entity_id = entity_id

        def get(self, key: str):
            return self.entity_id if key == "id" else None

    class FakeGmp:
        def __init__(self):
            self.target_kwargs = None

        def create_target(self, **kwargs):
            self.target_kwargs = kwargs
            return Created("target-1")

        def create_task(self, **kwargs):
            return Created("task-1")

        def start_task(self, task_id):
            pass

    fake = FakeGmp()

    @contextmanager
    def fake_session(*args, **kwargs):
        yield fake

    monkeypatch.setattr(greenbone_gmp, "_gmp_session", fake_session)
    monkeypatch.setattr(greenbone_gmp, "_find_scan_config_id", lambda *args, **kwargs: "config-1")
    monkeypatch.setattr(greenbone_gmp, "_find_openvas_scanner_id", lambda *args, **kwargs: "scanner-1")
    monkeypatch.setattr(greenbone_gmp, "_resolve_port_selection", lambda *args, **kwargs: {"port_selection": "port_list", "port_list_id": "port-list-1"})

    gmp_create_and_start_scan(
        host="gvmd",
        port=9390,
        username="admin",
        password="admin",
        name="unit-test",
        targets="192.0.2.10",
    )

    assert fake.target_kwargs["port_list_id"] == "port-list-1"
    assert "port_range" not in fake.target_kwargs




def test_ingest_uses_aetheris_cvss_bands():
    from app.services.vuln_finding_ingest import normalize_raw_vuln

    assert normalize_raw_vuln({"severity": "info", "cvss": 9.8})["severity"] == "critical"
    assert normalize_raw_vuln({"severity": "medium", "cvss": 7.5})["severity"] == "high"
    assert normalize_raw_vuln({"severity": "high", "cvss": 5.0})["severity"] == "medium"
    assert normalize_raw_vuln({"severity": "critical", "cvss": 5.0})["severity"] == "medium"

def test_asv_disclaimer_requires_external_asv():
    assert "accredited" in ASV_DISCLAIMER.lower()
    assert "does not" in ASV_DISCLAIMER.lower()


def test_pentest_playbooks_safe_only():
    assert "safe_recon" in SAFE_PLAYBOOKS
    assert "destructive" not in SAFE_PLAYBOOKS
    assert "full_exploit" not in SAFE_PLAYBOOKS


def test_safe_recon_returns_probe_results():
    results = run_safe_recon("127.0.0.1")
    assert len(results) == 7
    assert all(r["step_key"] == "tcp_probe" for r in results)


def test_tcp_port_probe_localhost():
    # SSH or closed — either way must return bool
    assert isinstance(tcp_port_probe("127.0.0.1", 65530, timeout=0.5), bool)


def test_migration_017_present():
    mig = Path(__file__).resolve().parents[2] / "migrations" / "017_vuln_asv_pentest_edr.sql"
    text = mig.read_text(encoding="utf-8")
    assert "vuln_asv_attestations" in text
    assert "vuln_pentest_jobs" in text
    assert "vuln_endpoint_inventory" in text


def test_docker_compose_gvm_profile():
    compose = Path(__file__).resolve().parents[2] / "docker-compose.gvm.yml"
    if not compose.exists():
        import pytest

        pytest.skip("docker-compose.gvm.yml not mounted in container")
    text = compose.read_text(encoding="utf-8")
    assert "gvmd" in text
    assert "ospd-openvas" in text


def test_vuln_extended_router_registered():
    src = Path(__file__).resolve().parents[1] / "app" / "app_factory.py"
    text = src.read_text(encoding="utf-8")
    assert "vuln_extended" in text
    assert "app.include_router(vuln_extended.router)" in text


def test_pentest_celery_task_registered():
    src = Path(__file__).resolve().parents[1] / "app" / "tasks.py"
    assert "pentest_job_task" in src.read_text(encoding="utf-8")


def test_normalize_raw_vuln_prefers_nonzero_cvss_over_string_zero_score():
    from app.services.vuln_finding_ingest import normalize_raw_vuln

    row = normalize_raw_vuln({"score": "0.0", "cvss": "9.8", "severity": "Info"})
    assert row["cvss"] == 9.8
    assert row["severity"] == "critical"
