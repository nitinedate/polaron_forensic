"""Guards for the three independent Aetheris products."""

from app.service_identity import (
    FORENSIC,
    MOBILE_EXTRACT,
    VULN,
    current_service,
    health_payload,
    health_role,
    is_aetheris_health_role,
    service_allows_job_type,
)


def test_health_roles_are_distinct():
    assert health_role(FORENSIC) == "forensic-api"
    assert health_role(MOBILE_EXTRACT) == "mobile-extract-api"
    assert health_role(VULN) == "vuln-api"
    assert health_payload(VULN)["service"] == "aetheris"
    assert is_aetheris_health_role("central-api")
    assert is_aetheris_health_role("vuln-api")
    assert not is_aetheris_health_role("openvas")


def test_job_types_are_partitioned():
    assert service_allows_job_type("host_disk", service=FORENSIC)
    assert not service_allows_job_type("mobile_extraction", service=FORENSIC)
    assert service_allows_job_type("mobile_extraction", service=MOBILE_EXTRACT)
    assert service_allows_job_type("ios_backup", service=MOBILE_EXTRACT)
    assert not service_allows_job_type("host_disk", service=MOBILE_EXTRACT)
    assert not service_allows_job_type("host_disk", service=VULN)
    assert not service_allows_job_type("mobile_extraction", service=VULN)


def test_forensic_app_omits_vuln_and_acquisition():
    from app.main_forensic import app

    paths = {getattr(r, "path", "") for r in app.routes}
    assert "/health" in paths
    assert any("/jobs" in p for p in paths)
    assert not any("scanner-agent" in p for p in paths)
    assert not any(p.startswith("/api/acquisition") or "/acquisition" in p for p in paths)


def test_mobile_extract_app_has_acquisition_not_vuln():
    from app.main_mobile_extract import app

    paths = {getattr(r, "path", "") for r in app.routes}
    assert any("acquisition" in p for p in paths)
    assert any("/jobs" in p for p in paths)
    assert any("artifact-scope" in p for p in paths)
    assert not any("scanner-agent" in p for p in paths)
    assert not any("vuln" in p and "scanner" not in p for p in paths if "/api/vuln" in p)


def test_vuln_app_has_scanner_agent_not_jobs():
    from app.main_vuln import app

    paths = {getattr(r, "path", "") for r in app.routes}
    assert any("scanner-agent" in p for p in paths)
    assert "/api/cases" in paths
    assert "/api/jobs" not in paths
    assert not any("acquisition" in p for p in paths)
    assert health_payload(VULN)["role"] == "vuln-api"


def test_current_service_aliases(monkeypatch):
    monkeypatch.setenv("AETHERIS_SERVICE", "volnureties")
    assert current_service() == VULN
    monkeypatch.setenv("AETHERIS_SERVICE", "mobile")
    assert current_service() == MOBILE_EXTRACT
