"""Throughput-aware capacity planning for the 15-18 IP/hour scanner profile."""

from unittest.mock import patch

from agent.capacity import (
    IP_WORKERS_MIN,
    chunk_targets,
    ip_workers_for_cpu,
    probe_laptop_capacity,
    projected_hosts_per_hour,
    required_workers_for_slo,
)


def test_slo_requires_six_workers_at_18_hph_and_20_minutes(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '6')
    monkeypatch.setenv('SCAN_SLO_HOSTS_PER_HOUR', '18')
    monkeypatch.setenv('SCAN_EXPECTED_HOST_MINUTES', '20')
    assert required_workers_for_slo() == 6
    assert projected_hosts_per_hour(6) == 18.0


def test_auto_workers_fit_cpu_envelope(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '6')
    monkeypatch.setenv('SCAN_SLO_HOSTS_PER_HOUR', '18')
    monkeypatch.setenv('SCAN_EXPECTED_HOST_MINUTES', '20')
    assert ip_workers_for_cpu(2, explicit='auto') == 5
    assert ip_workers_for_cpu(4, explicit='auto') == 5
    assert ip_workers_for_cpu(8, explicit='auto') == 5
    assert ip_workers_for_cpu(12, explicit='auto') == 6
    assert ip_workers_for_cpu(16, explicit='auto') == 6


def test_explicit_value_respects_safe_floor_and_ceiling(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '6')
    assert ip_workers_for_cpu(16, explicit='2') == 5
    assert ip_workers_for_cpu(16, explicit='5') == 5
    assert ip_workers_for_cpu(16, explicit='9') == 6


def test_chunks_remain_one_ip_each():
    chunks = chunk_targets(['10.0.0.1', '10.0.0.2', '10.0.0.3'], 1)
    assert chunks == [['10.0.0.1'], ['10.0.0.2'], ['10.0.0.3']]


def _probe_with(*, temp=55.0, cpu_pct=30.0, load=1.0, mem=8.0):
    with (
        patch('agent.capacity._cpu_count', return_value=12),
        patch('agent.capacity._read_cpu_temp_c', return_value=temp),
        patch('agent.capacity._cpu_percent_sample', return_value=cpu_pct),
        patch('agent.capacity._read_loadavg', return_value=load),
        patch('agent.capacity._mem_available_gb', return_value=mem),
    ):
        return probe_laptop_capacity(force=True)


def test_cool_host_targets_18_per_hour(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '6')
    monkeypatch.setenv('SCAN_SLO_HOSTS_PER_HOUR', '18')
    monkeypatch.setenv('SCAN_EXPECTED_HOST_MINUTES', '20')
    plan = _probe_with()
    assert plan['thermal_state'] == 'cool'
    assert plan['ip_workers'] == 6
    assert plan['projected_hosts_per_hour'] == 18.0
    assert plan['slo_at_risk'] is False


def test_hot_host_reduces_admission_without_killing_existing(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '6')
    plan = _probe_with(temp=86.0)
    assert plan['thermal_state'] == 'hot'
    assert plan['ip_workers'] == IP_WORKERS_MIN
    assert plan['max_concurrent_jobs'] == 1
    assert plan['admission_paused'] is False


def test_critical_host_pauses_new_admission(monkeypatch):
    monkeypatch.setenv('SCAN_IP_MAX_PARALLELISM', '6')
    plan = _probe_with(temp=94.0)
    assert plan['thermal_state'] == 'critical'
    assert plan['semaphore_limit'] == IP_WORKERS_MIN
    assert plan['max_concurrent_jobs'] == 1
    assert plan['admission_paused'] is True
