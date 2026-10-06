from unittest.mock import patch

import agent.reachability as reach


def test_reachability_worker_floor_is_five_when_targets_allow(monkeypatch):
    monkeypatch.setenv('REACHABILITY_WORKERS', '2')
    assert reach._workers(50) == 5
    assert reach._workers(3) == 3


def test_partition_omits_only_failed_ip_and_keeps_order(monkeypatch):
    monkeypatch.setenv('SKIP_UNREACHABLE_TARGETS', 'true')

    def fake_probe(host, **kwargs):
        return {'host': host, 'reachable': host != '10.0.0.2', 'open_port': 443 if host != '10.0.0.2' else None}

    with patch('agent.reachability.probe_host', side_effect=fake_probe):
        out = reach.partition_targets(['10.0.0.1', '10.0.0.2', '10.0.0.3'], job_id='j')
    assert out['reachable'] == ['10.0.0.1', '10.0.0.3']
    assert out['unreachable'] == ['10.0.0.2']
    assert out['skipped_hosts'] == [{'host': '10.0.0.2', 'reason': 'unreachable'}]
