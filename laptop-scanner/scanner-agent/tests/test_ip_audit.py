import json
from pathlib import Path

from agent.ip_audit import emit_ip_event


def test_per_ip_audit_file_is_jsonl(tmp_path, monkeypatch):
    monkeypatch.setenv('IP_SCAN_LOG_DIR', str(tmp_path))
    emit_ip_event('job-1', '10.0.0.8', 'started', task_id='task-x', port=443)
    emit_ip_event('job-1', '10.0.0.8', 'completed', vulnerabilities=3)
    path = tmp_path / 'job-1' / '10.0.0.8.jsonl'
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    assert [r['event'] for r in rows] == ['started', 'completed']
    assert rows[0]['task_id'] == 'task-x'
    assert rows[1]['vulnerabilities'] == 3
    assert (tmp_path / 'job-1' / 'all-ips.jsonl').is_file()
