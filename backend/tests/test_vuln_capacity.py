"""Premise scan parallelism stays on worker-nessus and does not throttle peer cases."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services.vuln_capacity import (
    adaptive_gvm_max_hosts_checks,
    allowed_vuln_scan_slots,
    count_running_vuln_jobs,
    vuln_max_parallel_jobs,
    vuln_scan_can_start,
)


def test_parallel_job_ceiling_is_three_to_four(monkeypatch):
    monkeypatch.setattr(
        "app.services.vuln_capacity._settings",
        lambda: SimpleNamespace(vuln_max_parallel_jobs=4),
    )
    assert vuln_max_parallel_jobs() == 4
    monkeypatch.setattr(
        "app.services.vuln_capacity._settings",
        lambda: SimpleNamespace(vuln_max_parallel_jobs=3),
    )
    assert vuln_max_parallel_jobs() == 3


def test_slots_stay_at_ceiling_under_scan_cpu(monkeypatch):
    monkeypatch.setattr(
        "app.services.vuln_capacity._settings",
        lambda: SimpleNamespace(vuln_max_parallel_jobs=4),
    )
    snap = SimpleNamespace(mem_available_mb=8192)
    monkeypatch.setattr("app.services.host_capacity.probe_host", lambda: snap)
    assert allowed_vuln_scan_slots() == 4


def test_slots_drop_only_when_ram_is_critical(monkeypatch):
    monkeypatch.setattr(
        "app.services.vuln_capacity._settings",
        lambda: SimpleNamespace(vuln_max_parallel_jobs=4),
    )
    monkeypatch.setattr(
        "app.services.host_capacity.probe_host",
        lambda: SimpleNamespace(mem_available_mb=512),
    )
    assert allowed_vuln_scan_slots() == 1


def test_openvas_prefs_do_not_shrink_when_four_jobs_run(monkeypatch):
    monkeypatch.setattr(
        "app.services.vuln_capacity._settings",
        lambda: SimpleNamespace(gvm_max_checks=20, gvm_max_hosts=4),
    )
    hosts, checks = adaptive_gvm_max_hosts_checks(running_jobs=4)
    assert hosts == 4
    assert checks == 20


def test_capacity_wait_after_four_running(monkeypatch):
    monkeypatch.setattr(
        "app.services.vuln_capacity.allowed_vuln_scan_slots",
        lambda: 4,
    )
    monkeypatch.setattr(
        "app.services.vuln_capacity.count_running_vuln_jobs",
        lambda db, exclude_job_id=None: 4,
    )
    ok, reason = vuln_scan_can_start(MagicMock(), "job-new")
    assert ok is False
    assert "slots=4" in reason

    monkeypatch.setattr(
        "app.services.vuln_capacity.count_running_vuln_jobs",
        lambda db, exclude_job_id=None: 3,
    )
    ok, reason = vuln_scan_can_start(MagicMock(), "job-new")
    assert ok is True


def test_running_count_sql_ignores_edge_agent_jobs():
    src = Path(__file__).resolve().parents[1] / "app" / "services" / "vuln_capacity.py"
    text = src.read_text(encoding="utf-8")
    assert "orchestration_json->>'edge_agent'" in text
    assert "nessus-sync" in text


def test_scanner_queue_stays_isolated_from_forensic_workers():
    src = Path(__file__).resolve().parents[1] / "app" / "celery_factory.py"
    text = src.read_text(encoding="utf-8")
    assert '"app.tasks.nessus_scan_sync_task": {"queue": "nessus-sync"}' in text
    assert '"app.tasks.build_extracted_disk_task": {"queue": "disk-build"}' in text
    assert '"queue": "mobile-build"' in text
    assert '"queue": "report-gen"' in text
