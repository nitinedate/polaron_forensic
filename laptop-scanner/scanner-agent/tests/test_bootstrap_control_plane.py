from __future__ import annotations

import base64
import json

import httpx

from agent import bootstrap_control_plane as b


def test_canonical_from_health_root():
    assert b._canonical_from_health("https://example.test/api/health") == "https://example.test"


def test_canonical_from_health_prefix():
    assert b._canonical_from_health("https://example.test/platform/api/health") == "https://example.test/platform"


def test_normalize_api_suffix():
    assert b._normalize_base("https://example.test/api/") == "https://example.test"


def test_api_error_nested_message():
    data = {"detail": {"error": {"message": "bad token"}}}
    assert b._api_error(data, "") == "bad token"


def test_emit_marker_decodes(capsys):
    rc = b._emit({"ok": True, "x": 1})
    assert rc == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith(b.MARKER)
    raw = base64.urlsafe_b64decode(line[len(b.MARKER):].encode("ascii"))
    assert json.loads(raw) == {"ok": True, "x": 1}


def test_preflight_redirect_and_canonical(monkeypatch):
    def fake_request(method, url, tenant, **kwargs):
        return 200, '{"status":"ok"}', {"status": "ok"}, "https://scanner.example.test/api/health"

    monkeypatch.setattr(b, "_request_json", fake_request)
    result = b.preflight("http://10.0.0.5", "a", True)
    assert result["ok"] is True
    assert result["canonical_url"] == "https://scanner.example.test"
    assert result["transport"] == "docker-httpx-openssl"


def test_preflight_rejects_non_api_success_response(monkeypatch):
    monkeypatch.setattr(b, "_request_json", lambda *args, **kwargs:
        (200, '{"ok":true}', {"ok": True}, "https://scanner.example.test/api/health"))
    result = b.preflight("https://scanner.example.test", "a", True)
    assert result["ok"] is False
    assert "access token was not sent" in result["error"].lower()


def test_bind_full_flow(monkeypatch):
    calls = []

    monkeypatch.setattr(
        b,
        "preflight",
        lambda base, tenant, verify: {"ok": True, "canonical_url": "https://scanner.example.test"},
    )

    def fake_request(method, url, tenant, **kwargs):
        calls.append((method, url, kwargs))
        if url.endswith("/api/auth/token-login"):
            return 200, '{"access_token":"session"}', {"access_token": "session"}, url
        if url.endswith("/api/scanners/bind-client-token"):
            return 200, '{"id":"sid","agent_token":"agent"}', {"id": "sid", "agent_token": "agent"}, url
        if url.endswith("/api/scanner-agent/heartbeat"):
            return 200, '{}', {}, url
        raise AssertionError(url)

    monkeypatch.setattr(b, "_request_json", fake_request)
    result = b.bind("https://x", "a", "client", "Laptop-X", "portable", "", True)
    assert result["ok"] is True
    assert result["scanner_id"] == "sid"
    assert result["agent_token"] == "agent"
    assert len(calls) == 3
    assert calls[0][2]["body"] == {"token": "client"}
    assert calls[1][2]["bearer"] == "session"
    assert calls[2][2]["bearer"] == "agent"
