from contextlib import contextmanager
from copy import deepcopy

import pytest
from lxml import etree

from agent import gmp_local
from agent.service_policy import (
    analyze_services, clip_policy_snapshots, effective_policy,
    evaluate_ip_forwarding, matches_service, port_numbers, service_catalog, validate_request,
)


def split_range(spec, transport):
    return set(p for token in spec.split(',') if token.startswith(transport + ':')
               for p in port_numbers(token[2:]))


def test_required_guide_scope_survives_fast_custom_and_udp_off(monkeypatch):
    for key in ('PORT_PROFILE', 'UDP_PROFILE', 'UDP_PORT_RANGE', 'SCAN_TCP_CUSTOM_PORTS', 'SCAN_UDP_CUSTOM_PORTS'):
        monkeypatch.delenv(key, raising=False)
    policy = effective_policy({'port_profile': 'fast', 'custom_tcp_ports': '2222,9443', 'udp_profile': 'priority'})
    tcp = split_range(policy['port_range'], 'T')
    assert {20, 22, 135, 445, 990, 1521, 2375, 2376, 5986, 6443, 7001, 7002, 8000, 902, 9990, 10250, 11211, 15672, 27017, 2222, 9443} <= tcp
    udp = split_range(policy['port_range'], 'U')
    assert {53, 67, 68, 69, 123, 137, 161, 162, 500, 514, 520, 623, 1434, 1900, 4500, 5353, 11211, 88, 111, 389, 902, 2049, 3389} <= udp
    assert effective_policy({'port_profile': 'full', 'udp_profile': 'full'})['port_range'] == 'T:1-65535,U:1-65535'
    assert not split_range(effective_policy({'udp_profile': 'off', 'custom_udp_ports': '4000'})['port_range'], 'U')
    assert policy['service_count'] == 52


def test_legacy_udp_override_is_additive(monkeypatch):
    monkeypatch.setenv('UDP_PORT_RANGE', 'U:9999')
    udp = split_range(gmp_local._default_scan_port_range('vuln', 'priority'), 'U')
    assert {53, 161, 9999, 2049} <= udp
    assert not split_range(gmp_local._default_scan_port_range('vuln', 'off'), 'U')


@pytest.mark.parametrize('bad', [True, 0, -1, 65536, '20-10', '22;443', '1.5', 'U:22'])
def test_invalid_ports_fail_before_task_creation(bad):
    with pytest.raises(ValueError):
        validate_request({'custom_tcp_ports': bad})


def test_policy_transport_drops_secrets_and_validates_references():
    ref = '00000000-0000-0000-0000-000000000011'
    got = validate_request({'mode': 'fast', 'password': 'never transport', 'url': 'https://private',
                            'gmp_credential_refs': {'ssh': ref}, 'ssh_credential_port': 2222})
    assert got == {'port_profile': 'fast', 'gmp_credential_refs': {'ssh': ref}, 'ssh_credential_port': 2222}
    with pytest.raises(ValueError):
        validate_request({'gmp_credential_refs': {'ssh': 'not a uuid'}})
    with pytest.raises(ValueError):
        validate_request({'ssh_credential_port': '22-23'})


def test_product_detection_routes_custom_endpoint_without_port_assumptions():
    nginx = next(s for s in service_catalog()['services'] if s['name'] == 'nginx')
    assert matches_service(nginx, {'port': 43210, 'service': 'http', 'product': 'nginx'})
    assert not matches_service(nginx, {'port': 443})
    evidence = analyze_services([{'host': '10.0.0.1', 'port': 43210, 'protocol': 'tcp',
                                  'product': 'nginx', 'plugin_name': 'nginx vendor advisory',
                                  'cvss': 7.5, 'source_result_id': 'native-1'}], host='10.0.0.1')
    row = next(s for s in evidence['services'] if s['name'] == 'nginx')
    assert row['status'] == 'finding'
    assert row['finding_result_ids'] == ['native-1']
    assert evidence['endpoints'][0]['confidence'] == 'native_engine_context'
    assert evidence['coverage_complete'] is False


def test_port_only_zero_missing_or_wrong_host_never_means_service_pass():
    evidence = analyze_services([{'host': '10.0.0.99', 'port': 443, 'protocol': 'tcp',
                                  'product': 'nginx', 'cvss': 10, 'source_result_id': 'wrong-host'}],
                                host='10.0.0.1', coverage={'open_tcp_ports': [443]})
    assert len(evidence['services']) == 52
    assert evidence['counts']['finding'] == 0
    assert evidence['counts']['observation'] == 0
    assert evidence['counts']['not-tested'] == 51
    assert evidence['counts']['unsupported'] == 1  # DHCP requires a network collector.
    assert evidence['endpoints'][0]['confidence'] == 'port_hint_only'


def test_ip_forwarding_needs_both_config_states_and_device_role():
    source = {'ipv4': 1, 'ipv6': 0, 'authenticated': True, 'source_ref': 'ssh-config-1'}
    assert evaluate_ip_forwarding(source)['status'] == 'not-tested'
    assert evaluate_ip_forwarding(source, expected_forwarding=True)['status'] == 'passed'
    assert evaluate_ip_forwarding(source, expected_forwarding=False)['status'] == 'finding'
    assert evaluate_ip_forwarding({**source, 'ipv6': None}, expected_forwarding=False)['status'] == 'not-tested'
    assert evaluate_ip_forwarding({**source, 'authenticated': False}, expected_forwarding=False)['status'] == 'not-tested'


def test_task_policy_snapshot_is_scoped_and_drops_unrelated_fields():
    data = {'task-1': {'targets': ['10.0.0.1'], 'task_id': 'forged', 'port_range': 'T:22',
                       'password': 'secret', 'preferences': {'safe_checks': 'yes', 'password': 'secret'},
                       'gmp_credential_refs': {'ssh': 'ref', 'password': 'secret'}},
            'task-2': {'targets': ['10.0.0.99'], 'port_range': 'T:443'}}
    got = clip_policy_snapshots(data, ['10.0.0.1'])
    assert list(got) == ['task-1']
    assert got['task-1']['task_id'] == 'task-1'
    assert 'secret' not in str(got)


@pytest.mark.parametrize('credential_available', [True, False])
def test_native_task_uses_policy_and_records_credential_gap(monkeypatch, credential_available):
    ref = '00000000-0000-0000-0000-000000000011'
    class Fake:
        target_args = None
        def get_credential(self, cid):
            if not credential_available:
                raise ValueError('unavailable')
            return etree.fromstring(f'<get_credentials_response><credential id="{cid}" /></get_credentials_response>')
        def create_target(self, **kwargs):
            self.target_args = deepcopy(kwargs)
            return {'id': 'target-1'}
        def create_task(self, **kwargs):
            return {'id': 'task-1'}
        def start_task(self, task):
            return etree.fromstring('<start_task_response><report_id>report-1</report_id></start_task_response>')
        def get_feeds(self):
            return etree.fromstring('<get_feeds_response><feed><type>NVT</type><version>20261006</version></feed></get_feeds_response>')
    fake = Fake()
    @contextmanager
    def session(**kwargs):
        yield fake
    monkeypatch.setattr(gmp_local, '_session', session)
    monkeypatch.setattr(gmp_local, '_ensure_portscan_config', lambda *args: 'config-1')
    monkeypatch.setattr(gmp_local, '_assert_feed_quality', lambda *args: {'nvt_count': 20000})
    monkeypatch.setattr(gmp_local, '_find_scanner_id', lambda *args: 'scanner-1')
    monkeypatch.setenv('PORT_PROFILE', 'full')
    monkeypatch.delenv('UDP_PORT_RANGE', raising=False)
    scanner = gmp_local.LocalOpenVAS()
    task = scanner.start_scan(name='scope', targets=['10.0.0.1'], scan_policy={
        'port_profile': 'fast', 'udp_profile': 'off', 'custom_tcp_ports': [2222],
        'gmp_credential_refs': {'ssh': ref}, 'ssh_credential_port': 2222})
    assert task == 'task-1'
    assert 2222 in split_range(fake.target_args['port_range'], 'T')
    assert not split_range(fake.target_args['port_range'], 'U')
    if credential_available:
        assert fake.target_args['ssh_credential_id'] == ref
        assert fake.target_args['ssh_credential_port'] == 2222
    else:
        assert 'ssh_credential_id' not in fake.target_args
    snapshot = scanner.policy_snapshots[task]
    assert snapshot['feed_versions'] == {'NVT': '20261006'}
    assert snapshot['credential_status']['ssh'].startswith('bound' if credential_available else 'not-tested')
    assert snapshot['port_range'] == fake.target_args['port_range']
    assert len(snapshot['configuration_sha256']) == 64


def test_unscored_native_result_preserves_absence_of_score():
    xml = etree.fromstring('<get_reports_response><report><results><result id="r1"><host>10.0.0.1</host><port>22/tcp</port><nvt oid="oid"><name>SSH detection</name></nvt></result></results></report></get_reports_response>')
    row = gmp_local._vulnerabilities_from_report(xml)[0]
    assert row['score_available'] is False
    assert row['service'] is None
