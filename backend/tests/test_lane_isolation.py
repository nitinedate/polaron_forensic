"""GPU/CPU lanes stay independent across disk, mobile, and vuln."""

from __future__ import annotations

from app.services.action_agents import performance_arbitrate
from app.services.job_locks import inspect_process_lanes
from app.services.scan_orchestrator import merge_openvas_details, openvas_ip_chunks
from app.services.vuln_capacity import vuln_openvas_ip_workers


def test_lane_keys_are_namespaced_by_service(monkeypatch):
    from app.services import job_locks

    monkeypatch.setenv("AETHERIS_SERVICE", "mobile-extract")
    assert job_locks.gpu_heavy_lock_key() == "mobile:gpu_heavy_lock"
    assert job_locks.cpu_heavy_lock_key() == "mobile:cpu_heavy_lock"
    monkeypatch.setenv("AETHERIS_SERVICE", "forensic")
    assert job_locks.gpu_heavy_lock_key() == "forensic:gpu_heavy_lock"
    monkeypatch.setenv("AETHERIS_SERVICE", "vuln")
    assert job_locks.gpu_heavy_lock_key() == "vuln:gpu_heavy_lock"


def test_cpu_heavy_start_ignores_per_job_extract_lock(monkeypatch):
    from app.services import job_locks

    monkeypatch.setattr(job_locks, "_redis_client", lambda: (_ for _ in ()).throw(RuntimeError("no redis")))
    monkeypatch.setattr(job_locks, "_gpu_slot_keys", lambda: [])
    monkeypatch.setattr(job_locks, "_lock_held", lambda key: None)
    monkeypatch.setattr(job_locks, "cpu_heavy_slot_held", lambda: None)
    monkeypatch.setattr(job_locks, "job_lock_held", lambda kind, jid: kind == "extract")
    lanes = inspect_process_lanes("job-1")
    assert lanes["extract_lock"] is True
    assert lanes["can_start_cpu_heavy"] is True


def test_extract_and_parse_go_when_gpu_slots_are_full():
    extract = {
        "want": "run",
        "lane": "cpu",
        "id": "extract_agent",
        "dispatch_agent": "extract_agent",
    }
    parse = {
        "want": "run",
        "lane": "cpu",
        "id": "parse_agent",
        "dispatch_agent": "parse_agent",
    }
    embed = {
        "want": "run",
        "lane": "gpu",
        "id": "embed_agent",
        "dispatch_agent": "rag_agent",
    }
    performance_arbitrate(
        [extract, parse, embed],
        {
            "allow_parallel": True,
            "lanes": {
                "gpu_slots_free": 0,
                "gpu_slots_total": 1,
                "gpu_slots_used": 1,
                "can_start_cpu_heavy": True,
            },
        },
        gpu_abort=False,
    )
    assert extract["decision"] == "go"
    assert parse["decision"] == "go"
    assert embed["decision"] == "hold"


def test_openvas_chunks_one_ip_when_workers_available():
    assert openvas_ip_chunks(["10.0.0.1"], 4) == [["10.0.0.1"]]
    assert openvas_ip_chunks(["10.0.0.1", "10.0.0.2", "10.0.0.3"], 4) == [
        ["10.0.0.1"],
        ["10.0.0.2"],
        ["10.0.0.3"],
    ]
    assert openvas_ip_chunks(["10.0.0.1", "10.0.0.2"], 1) == [["10.0.0.1", "10.0.0.2"]]


def test_merge_openvas_details_keeps_every_host_finding():
    merged = merge_openvas_details(
        [
            {"stub": False, "info": {"progress": 100}, "vulnerabilities": [{"host": "10.0.0.1"}]},
            {
                "stub": False,
                "partial": True,
                "partial_reason": "timed out",
                "info": {"progress": 80},
                "vulnerabilities": [{"host": "10.0.0.2"}],
            },
        ]
    )
    assert merged["parallel_ip_tasks"] == 2
    assert len(merged["vulnerabilities"]) == 2
    assert merged["partial"] is True


def test_vuln_openvas_ip_workers_floor(monkeypatch):
    monkeypatch.setattr(
        "app.services.vuln_capacity.detect_scan_accel",
        lambda: {"gpu_present": False},
    )
    monkeypatch.setattr(
        "app.services.vuln_capacity._settings",
        lambda: type("S", (), {"vuln_openvas_ip_workers": 4})(),
    )
    assert vuln_openvas_ip_workers() == 4
