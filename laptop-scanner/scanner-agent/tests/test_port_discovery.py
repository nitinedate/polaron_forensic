from unittest.mock import patch

import agent.port_discovery as pd


def test_parse_range_and_roundtrip():
    assert pd.parse_tcp_ports('T:22,80,443,8000-8002') == [22, 80, 443, 8000, 8001, 8002]
    assert pd.ports_to_gvm_range([443, 22, 443]) == 'T:22,T:443'


def test_discovery_narrows_to_observed_open_ports(monkeypatch):
    monkeypatch.setenv('PORT_DISCOVERY_ENABLED', 'true')
    monkeypatch.setenv('PORT_DISCOVERY_RANGE', 'T:22,80,443')
    with patch('agent.port_discovery.probe_open_tcp_ports', return_value={'10.0.0.1': [80, 443]}):
        plan = pd.discovery_plan(['10.0.0.1'])
    assert plan['fallback'] is False
    assert plan['port_range'] == 'T:80,T:443'
    assert plan['open_port_count'] == 2


def test_no_open_port_falls_back_without_dropping_coverage(monkeypatch):
    monkeypatch.setenv('PORT_DISCOVERY_ENABLED', 'true')
    monkeypatch.setenv('PORT_DISCOVERY_RANGE', 'T:22,80,443')
    with patch('agent.port_discovery.probe_open_tcp_ports', return_value={'10.0.0.1': []}):
        plan = pd.discovery_plan(['10.0.0.1'])
    assert plan['fallback'] is True
    assert plan['port_range'] == 'T:22,80,443'
    assert plan['open_port_count'] == 0


def test_discovery_can_be_disabled(monkeypatch):
    monkeypatch.setenv('PORT_DISCOVERY_ENABLED', 'false')
    monkeypatch.setenv('PORT_DISCOVERY_RANGE', 'T:22,80,443')
    plan = pd.discovery_plan(['10.0.0.1'])
    assert plan['enabled'] is False
    assert plan['port_range'] == 'T:22,80,443'
