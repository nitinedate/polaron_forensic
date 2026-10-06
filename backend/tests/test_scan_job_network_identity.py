"""Network identity and in-place retry for edge scan jobs."""

from __future__ import annotations

from pathlib import Path

from app.services.scanner_agent_jobs import _clip_chunk_tasks_to_job, network_key_from_targets


def test_network_keys_do_not_mix_private_ranges():
    site_a = network_key_from_targets(["10.10.80.12", "10.10.80.99"])
    site_b = network_key_from_targets(["192.168.1.10"])
    assert site_a != site_b
    assert site_a == network_key_from_targets(["10.10.80.1"])


def test_clip_chunk_tasks_drops_foreign_hosts():
    kept = _clip_chunk_tasks_to_job(
        [
            {"task_id": "same-net", "hosts": ["10.10.80.1"]},
            {"task_id": "other-net", "hosts": ["192.168.1.10"]},
        ],
        ["10.10.80.1", "10.10.80.2"],
    )
    assert kept == [{"task_id": "same-net", "hosts": ["10.10.80.1"]}]


def test_retry_sql_does_not_rewrite_targets():
    src = (Path(__file__).resolve().parents[1] / "app/services/scanner_agent_jobs.py").read_text(
        encoding="utf-8"
    )
    fn = src.split("def retry_edge_job", 1)[1].split("def retry_failed_edge_jobs_for_case", 1)[0]
    update = fn.split("UPDATE vuln_scan_jobs", 1)[1].split("timeline(", 1)[0]
    assert "FROM vuln_scan_targets" not in update
    assert "INSERT INTO vuln_scan_targets" not in update
    assert "scanner_id =" not in update
    assert "external_scan_id =" not in update
    assert "status = 'queued'" in update
    assert "completed_at = NULL" in update


def test_retry_failed_case_walks_jobs_independently():
    src = (Path(__file__).resolve().parents[1] / "app/services/scanner_agent_jobs.py").read_text(
        encoding="utf-8"
    )
    fn = src.split("def retry_failed_edge_jobs_for_case", 1)[1].split("def _nonneg_int", 1)[0]
    assert "retry_edge_job" in fn
    assert "INSERT INTO vuln_scan_targets" not in fn
