from agent import main
from agent.target_progress import build_target_progress


def test_source_build_overrides_stale_deployment_version(monkeypatch, tmp_path):
    old = tmp_path / 'version'
    old.write_text('1.4.1')
    monkeypatch.setenv('AGENT_VERSION_FILE', str(old))
    monkeypatch.setenv('AGENT_VERSION', '1.4.1')
    assert main._read_agent_version() == '1.5.3+v45.7'


def test_resume_does_not_show_assessed_host_as_waiting():
    states = build_target_progress(['a', 'b'], chunks=[['b']], in_flight={0: 't'},
        done_details={}, assessed_hosts=['a'])
    assert states['a']['status'] == 'completed'
    assert states['b']['status'] == 'scanning'
