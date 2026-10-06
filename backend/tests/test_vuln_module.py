"""Acceptance checks for Vulnerability / Nessus module (BRD + SOP).

Isolated from forensic extract/RAG tests. Avoid importing FastAPI routers
(which initialize DB engines) so unit tests run without Postgres DLLs.
"""

from __future__ import annotations

from pathlib import Path

from app.services.vuln_risk import score_finding
from app.services.permissions_catalog import FIRM_PERMISSIONS
from app.services.nessus_client import NessusClient


def test_contextual_risk_kev_raises_band():
    base = score_finding(cvss=7.5, is_kev=False, external_exposure="internal")
    kev = score_finding(cvss=7.5, is_kev=True, external_exposure="internet-facing", asset_criticality="tier0")
    assert kev["enterprise_risk_score"] > base["enterprise_risk_score"]
    assert kev["risk_band"] in {"high", "critical"}
    assert kev["risk_factors_json"]["model_version"] == "nessus-aligned-weighted-1"


def test_vuln_permissions_additive_and_present():
    codes = {c for c, *_ in FIRM_PERMISSIONS}
    assert "job:read" in codes
    assert "artifact:read" in codes
    for needed in (
        "vuln:read",
        "scan:launch",
        "scan:policy_manage",
        "exception:approve",
        "dashboard:export",
        "vuln:remediate",
        "asset:write",
    ):
        assert needed in codes


def test_nessus_client_unconfigured_stub():
    client = NessusClient(base_url="", access_key="", secret_key="")
    assert client.configured is False
    created = client.create_scan(name="t", targets="10.0.0.1")
    assert created.get("stub") is True
    details = client.scan_details("stub-1")
    assert details.get("stub") is True


def test_sop_preflight_gate_in_router_source():
    src = Path(__file__).resolve().parents[1] / "app" / "routers" / "vuln.py"
    text = src.read_text(encoding="utf-8")
    assert "preflight_required" in text
    assert "preflight_confirmed" in text
    assert "authorization_ref" in text


def test_exception_sod_in_router_source():
    src = Path(__file__).resolve().parents[1] / "app" / "routers" / "vuln.py"
    text = src.read_text(encoding="utf-8")
    assert "sod_violation" in text
    assert "approved_by <> requested_by" in Path(__file__).resolve().parents[2].joinpath(
        "migrations", "012_firm_vuln_module.sql"
    ).read_text(encoding="utf-8")


def test_celery_route_isolated_from_forensic_queues():
    src = Path(__file__).resolve().parents[1] / "app" / "celery_factory.py"
    text = src.read_text(encoding="utf-8")
    assert '"app.tasks.nessus_scan_sync_task": {"queue": "nessus-sync"}' in text
    assert '"app.tasks.vuln_brd_maintenance_task": {"queue": "nessus-sync"}' in text
    assert '"app.tasks.build_extracted_disk_task": {"queue": "disk-build"}' in text
    assert '"app.tasks.rag_index_task": {"queue": "rag-index"}' in text


def test_brd_agent_lifecycle_transitions():
    from app.services.vuln_brd import ALLOWED_AGENT_TRANSITIONS, AGENT_STATES

    assert "healthy" in AGENT_STATES
    assert "healthy" in ALLOWED_AGENT_TRANSITIONS["linked"]
    assert "retired" in ALLOWED_AGENT_TRANSITIONS["healthy"]
    assert ALLOWED_AGENT_TRANSITIONS["retired"] == set()


def test_brd_complete_migration_defines_agent_tables():
    mig = Path(__file__).resolve().parents[2] / "migrations" / "013_firm_vuln_brd_complete.sql"
    text = mig.read_text(encoding="utf-8")
    for table in (
        "vuln_agents",
        "vuln_credential_refs",
        "vuln_scan_results",
        "vuln_risk_scores",
        "vuln_dashboard_snapshots",
        "vuln_alert_thresholds",
        "vuln_notifications",
        "vuln_asset_owners",
    ):
        assert table in text


def test_forensic_agents_router_untouched():
    """Forensic /api/agents/jobs/{id}/runs must remain (non-impact)."""
    src = Path(__file__).resolve().parents[1] / "app" / "routers" / "agents.py"
    text = src.read_text(encoding="utf-8")
    assert 'prefix="/api/agents"' in text
    assert "/jobs/{job_id}/runs" in text


def test_vuln_validate_permission_present():
    codes = {c for c, *_ in FIRM_PERMISSIONS}
    assert "vuln:validate" in codes
