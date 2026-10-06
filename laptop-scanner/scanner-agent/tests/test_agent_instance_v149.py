from __future__ import annotations

from pathlib import Path

from agent import api_client
from agent.api_client import CentralApi


def test_agent_instance_is_persisted_and_header_is_sent(monkeypatch, tmp_path: Path):
    instance_file = tmp_path / "agent-instance-id"
    monkeypatch.delenv("AGENT_INSTANCE_ID", raising=False)
    monkeypatch.setattr(api_client, "_AETHERIS_AGENT_INSTANCE_FILE", instance_file)
    a = CentralApi(base_url="https://example.test", tenant="a", token="t", verify_tls=True)
    b = CentralApi(base_url="https://example.test", tenant="a", token="t", verify_tls=True)
    assert a.agent_instance_id
    assert a.agent_instance_id == b.agent_instance_id
    assert instance_file.read_text().strip() == a.agent_instance_id
    assert a.headers["X-Aetheris-Agent-Instance"] == a.agent_instance_id


def test_next_job_sends_instance_query_fallback(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("AGENT_INSTANCE_ID", raising=False)
    monkeypatch.setattr(api_client, "_AETHERIS_AGENT_INSTANCE_FILE", tmp_path / "iid")
    api = CentralApi(base_url="https://example.test", tenant="a", token="t", verify_tls=True)
    seen = {}
    def fake_request(method, path, **kwargs):
        seen.update(kwargs)
        return {"job": None}
    monkeypatch.setattr(api, "_request", fake_request)
    api.next_job(active_job_ids=["11111111-1111-1111-1111-111111111111"])
    assert seen["params"]["agent_instance_id"] == api.agent_instance_id
    assert "active_job_ids" in seen["params"]


def test_progress_and_results_send_instance_query(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("AGENT_INSTANCE_ID", raising=False)
    monkeypatch.setattr(api_client, "_AETHERIS_AGENT_INSTANCE_FILE", tmp_path / "iid")
    api = CentralApi(base_url="https://example.test", tenant="a", token="t", verify_tls=True)
    calls = []
    def fake_request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return {"ok": True}
    monkeypatch.setattr(api, "_request", fake_request)
    api.patch_job("j", {"status":"running"})
    api.upload_results("j", {"status":"completed"})
    assert calls[0][2]["params"]["agent_instance_id"] == api.agent_instance_id
    assert calls[1][2]["params"]["agent_instance_id"] == api.agent_instance_id
