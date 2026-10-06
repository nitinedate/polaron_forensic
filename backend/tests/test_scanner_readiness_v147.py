from __future__ import annotations

from pathlib import Path
import sys
import types

from app.services import scanner_agent_jobs
from app.services.vuln_helpers import row_scanner


def test_heartbeat_persists_only_authenticated_scanner_readiness(monkeypatch):
    seen = []

    fake_auth = types.ModuleType("app.services.scanner_agent_auth")
    fake_auth.ensure_edge_agent_readiness_columns = lambda db: None
    monkeypatch.setitem(sys.modules, "app.services.scanner_agent_auth", fake_auth)
    monkeypatch.setattr(
        scanner_agent_jobs,
        "fetchone",
        lambda db, sql, params=None: {"version": "1.4.6"},
    )

    def fake_execute(db, sql, params=None):
        seen.append((" ".join(str(sql).split()), dict(params or {})))
        return None

    monkeypatch.setattr(scanner_agent_jobs, "execute", fake_execute)
    scanner_agent_jobs.touch_scanner_heartbeat(
        object(),
        "00000000-0000-0000-0000-000000000099",
        version="1.4.7",
        openvas_ready=False,
        detail="OSPd OpenVAS NVT inventory is still loading",
    )

    readiness = [item for item in seen if "openvas_ready" in item[0]]
    assert len(readiness) == 1
    sql, params = readiness[0]
    assert "WHERE id = CAST(:id AS uuid)" in sql
    assert params["id"] == "00000000-0000-0000-0000-000000000099"
    assert params["ready"] is False
    assert "NVT inventory" in params["detail"]


def test_scanner_api_shape_exposes_readiness():
    row = row_scanner(
        {
            "id": "00000000-0000-0000-0000-000000000099",
            "name": "Laptop-NITIN",
            "edition": "openvas",
            "url": "agent://local",
            "connection_mode": "edge_agent",
            "scanner_role": "portable",
            "status": "active",
            "openvas_ready": False,
            "agent_status_detail": "VT feed loading",
            "openvas_ready_at": None,
            "last_heartbeat_at": None,
            "plugin_feed_updated_at": None,
            "created_at": None,
        }
    )
    assert row["openvas_ready"] is False
    assert row["agent_status_detail"] == "VT feed loading"


def test_launch_and_ui_gate_unready_edge_scanner():
    root = Path(__file__).resolve().parents[1]
    router = (root / "app" / "routers" / "vuln.py").read_text(encoding="utf-8")
    ui = (root.parent / "frontend" / "src" / "pages" / "vuln" / "ScanJobsPage.tsx").read_text(encoding="utf-8")
    assert "edge_scanner_not_ready" in router
    assert "scannerIsScanReady" in ui
    assert "disabled={edgeScannerNotReady}" in ui
