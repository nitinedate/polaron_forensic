import csv
import io
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.routers import vuln
from app.services import scanner_agent_jobs, vuln_report_export
from app.services.scanner_service_policy import analyze_services

SID = '00000000-0000-0000-0000-000000000002'
JID = '00000000-0000-0000-0000-000000000001'
CID = '00000000-0000-0000-0000-000000000003'
PID = '00000000-0000-0000-0000-000000000004'


@pytest.mark.parametrize('ready', [True, False, None])
def test_ready_scanner_can_launch_with_sanitized_policy_and_unready_is_blocked(monkeypatch, ready):
    from app.services import scanner_agent_auth, vuln_network_tokens
    writes = []
    reads = []
    def one(db, sql, params=None):
        reads.append(sql)
        if 'FROM vuln_scan_policies' in sql:
            return {'scanner_id': SID, 'settings_json': {'port_profile': 'fast', 'udp_profile': 'off',
                      'custom_tcp_ports': '2222,9443', 'password': 'secret'}}
        if 'FROM vuln_scanners' in sql:
            # Match the real SQL projection so the missing-readiness regression fails.
            data = {'url': 'agent://local', 'edition': 'openvas', 'status': 'active', 'connection_mode': 'edge_agent'}
            if 'openvas_ready' in sql:
                data.update(openvas_ready=ready, agent_status_detail='Feed warming')
            return data
        if 'INSERT INTO vuln_scan_jobs' in sql:
            writes.append(params)
        return {'id': JID, 'case_id': CID, 'status': 'queued'}
    monkeypatch.setattr(vuln, '_require_vuln_module', lambda: None)
    monkeypatch.setattr(vuln, 'fetchone', one)
    monkeypatch.setattr(vuln, 'execute', lambda *args: None)
    monkeypatch.setattr(vuln, 'timeline', lambda *args, **kwargs: None)
    monkeypatch.setattr(vuln, '_job_row', lambda db, row: row)
    monkeypatch.setattr(scanner_agent_auth, 'ensure_edge_agent_readiness_columns', lambda db: None)
    monkeypatch.setattr(vuln_network_tokens, 'session_for_user', lambda *args: None)
    body = vuln.ScanJobCreate(policy_id=PID, preflight_confirmed=True, authorization_ref='approved-engagement',
                              targets=[{'target': '10.0.0.1'}])
    if ready is True:
        result = vuln.create_scan_job(CID, body, db=SimpleNamespace(commit=lambda: None),
                    current=SimpleNamespace(user_id=CID, schema_name='firm_test'))
        assert result['id'] == JID
        policy = json.loads(writes[0]['orch'])['scan_policy_request']
        assert policy == {'port_profile': 'fast', 'udp_profile': 'off', 'custom_tcp_ports': [2222, 9443]}
        assert 'secret' not in writes[0]['orch']
    else:
        with pytest.raises(HTTPException) as exc:
            vuln.create_scan_job(CID, body, db=SimpleNamespace(commit=lambda: None),
                                 current=SimpleNamespace(user_id=CID))
        assert exc.value.status_code == 409
        assert not writes
    assert any('openvas_ready, agent_status_detail' in sql for sql in reads)


def test_monotonic_sequence_rejects_old_task_reopen():
    merge = scanner_agent_jobs._merge_edge_target_progress
    prior = {'host': {'task_id': 'new', 'status': 'scanning', 'progress_pct': 54, 'event_seq': 20}}
    for seq in (19, 20, None, True, float('nan')):
        assert merge(prior, {'host': {'task_id': 'old', 'status': 'scanning', 'progress_pct': 10,
                                    'event_seq': seq}}, ['host']) == prior
    got = merge(prior, {'host': {'task_id': 'new', 'status': 'scanning', 'progress_pct': 40, 'event_seq': 21}}, ['host'])
    assert got['host']['progress_pct'] == 54
    assert got['host']['event_seq'] == 21


def test_guide_evidence_and_task_policy_survive_scoped_ingest():
    job = {'id': JID, 'scanner_id': SID, 'case_id': CID, 'status': 'running',
           'orchestration_json': {'edge_agent': True, 'edge_owner_instance': 'owner'}}
    writes = []
    with patch.object(scanner_agent_jobs, 'fetchone', return_value=job), \
         patch.object(scanner_agent_jobs, 'fetchall', return_value=[{'target': '10.0.0.1'}, {'target': '10.0.0.99', 'excluded': True}]), \
         patch.object(scanner_agent_jobs, 'execute', side_effect=lambda db, sql, params=None: writes.append(params)), \
         patch.object(scanner_agent_jobs, 'ingest_engine_results', return_value=1), \
         patch.object(scanner_agent_jobs, 'timeline'), patch('app.services.vuln_brd.record_scan_result') as record:
        scanner_agent_jobs.ingest_agent_results(object(), scanner_id=SID, job_id=JID, agent_instance_id='owner',
            vulnerabilities=[{'host': '10.0.0.1', 'product': 'nginx', 'port': 43210, 'protocol': 'tcp', 'cvss': 7.5,
                              'plugin_name': 'nginx advisory', 'source_result_id': 'native-1'}],
            external_scan_id='task-1', report_id='report-1', task_status='Done', hosts_attempted=1, hosts_assessed=1,
            assessed_hosts=['10.0.0.1'], report_result_count=1, scan_start='2026-10-06T10:00:00Z',
            scan_end='2026-10-06T10:15:00Z', assessment_complete=True,
            service_coverage={'10.0.0.99': {'coverage_complete': True}},
            policy_snapshots={'task-1': {'targets': ['10.0.0.1'], 'port_range': 'T:1-65535',
                             'snapshot_status': 'captured_at_task_start', 'password': 'secret'},
                              'wrong-task': {'targets': ['10.0.0.99'], 'port_range': 'T:22'}})
    evidence = record.call_args.kwargs['result_json']
    stored = json.loads(next(p['orch'] for p in writes if p and 'orch' in p))
    for view in (evidence, stored):
        assert set(view['service_coverage']) == {'10.0.0.1'}
        assert view['service_coverage']['10.0.0.1']['counts']['finding'] == 1
        assert set(view['policy_snapshots']) == {'task-1'}
        assert 'secret' not in str(view['policy_snapshots'])


def test_coverage_export_has_every_family_and_forwarding_with_no_fake_pass(monkeypatch):
    evidence = analyze_services([], host='10.0.0.1')
    monkeypatch.setattr(vuln_report_export, 'fetchall', lambda *args: [{'id': JID, 'status': 'completed',
            'orchestration_json': {'edge_agent': True, 'service_coverage': {'10.0.0.1': evidence}}}])
    rows = list(csv.DictReader(io.StringIO(vuln_report_export.export_service_coverage_csv(object(), case_id=CID))))
    assert len(rows) == 53
    assert rows[-1]['Service ID'] == 'CFG-IP-FORWARDING'
    assert 'passed' not in {r['Evidence state'] for r in rows}
    assert len({r['Service ID'] for r in rows}) == 53


def test_gap_html_has_coverage_appendix_and_toc_with_escaped_evidence():
    from app.services.gap_assessment_report import build_gap_report_html
    evidence = analyze_services([], host='10.0.0.1')
    ctx = {'client': 'Test', 'site': {}, 'findings': [], 'intro': 'Assessment',
           'assessment': {'verified': True}, 'service_coverage_jobs': [{'job_id': '<job>', 'status': 'completed',
               'service_coverage': {'10.0.0.1': evidence}, 'policy_snapshots': {'task-1': {
                   'policy_version': 'aetheris-services-2.1', 'snapshot_status': 'captured_at_task_start',
                   'tcp_port_count': 65535, 'udp_port_count': 35, 'configuration_sha256': 'a' * 64,
                   'credential_status': {'ssh': 'not-tested'}}}}]}
    result = build_gap_report_html(ctx)
    assert '7. SERVICE COVERAGE AND LIMITATIONS' in result
    assert result.replace(chr(160), ' ').count('SERVICE COVERAGE AND LIMITATIONS') >= 2
    assert '&lt;job&gt;' in result and '<job>' not in result
    assert 'not tested: 51' in result
    assert 'TCP ports: 65535' in result
    assert 'companion Service coverage CSV' in result


def test_native_missing_score_survives_central_normalization_without_losing_context():
    from app.services.vuln_finding_ingest import normalize_raw_vuln
    missing = normalize_raw_vuln({'cvss': 0, 'score_available': False, 'product': 'nginx', 'version': 'fixture-version'})
    measured_zero = normalize_raw_vuln({'cvss': 0})
    assert missing['score_available'] is False
    assert measured_zero['score_available'] is True
    assert missing['endpoint_context'] == {'product': 'nginx', 'version': 'fixture-version'}


def test_finding_api_preserves_v2_basis_and_unscored_flag():
    row = {'id': JID, 'case_id': CID, 'status': 'open', 'cvss': 9.1, 'severity': 'high',
           'risk_factors_json': json.dumps({'severity_basis': 'cvss_v2'})}
    assert vuln._finding_row(row)['severity'] == 'high'
    assert vuln._finding_row({**row, 'cvss': 0, 'risk_factors_json': {'score_available': False}})['score_available'] is False


def test_fresh_retry_retains_sequence_floor_without_retaining_terminal_state():
    prior = {'edge_agent': True, 'progress_event_seq': 20, 'target_progress': {'10.0.0.1': {'status': 'completed', 'event_seq': 20}}}
    orch = scanner_agent_jobs._clear_stale_edge_resume_state(prior)
    assert 'target_progress' not in orch and orch['progress_event_seq'] == 20
    job = {'id': JID, 'scanner_id': SID, 'status': 'running', 'orchestration_json': orch}
    writes = []
    with patch.object(scanner_agent_jobs, 'fetchone', side_effect=lambda db, sql, params=None: {'version': '1.5.3'} if 'vuln_scanners' in sql else job), \
         patch.object(scanner_agent_jobs, 'fetchall', return_value=[{'target': '10.0.0.1'}]), \
         patch.object(scanner_agent_jobs, 'execute', side_effect=lambda db, sql, params=None: writes.append(params)):
        scanner_agent_jobs.update_job_progress(object(), scanner_id=SID, job_id=JID,
                    target_progress={'10.0.0.1': {'status': 'scanning', 'task_id': 'old', 'event_seq': 20}})
    stored = json.loads(next(p['orch'] for p in writes if p and 'orch' in p))
    assert stored['target_progress'] == {} and stored['progress_event_seq'] == 20
