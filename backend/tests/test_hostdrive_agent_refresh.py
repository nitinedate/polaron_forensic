from __future__ import annotations

import json
from pathlib import Path

from app.services import hostdrive_agent as hda

ROOT = Path(__file__).resolve().parents[2]


def test_proxy_refresh_mounts_forwards_required_windows_path(monkeypatch):
    monkeypatch.setattr(
        hda,
        "probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
            "drives": ["C", "G"],
        },
    )

    calls: list[dict[str, object]] = []

    def fake_http_json(url: str, *, method="GET", timeout=3.0, body=None):
        calls.append({"url": url, "method": method, "timeout": timeout, "body": body})
        return {"ok": True, "started": True, "status": "running", "message": "started"}

    monkeypatch.setattr(hda, "_http_json", fake_http_json)

    selected = r"G:\\Ex.1 Darshan SSD 256"
    result = hda.proxy_refresh_mounts(selected)

    assert result["ok"] is True
    assert result["started"] is True
    assert len(calls) == 1
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "http://host.docker.internal:9876/refresh-drive-mounts"
    assert json.loads(calls[0]["body"].decode("utf-8")) == {"required_path": selected}


def test_proxy_refresh_mounts_joins_existing_refresh_on_409(monkeypatch):
    import io
    import urllib.error

    monkeypatch.setattr(
        hda,
        "probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
            "drives": ["C", "G"],
        },
    )

    calls: list[tuple[str, str]] = []

    def fake_http_json(url: str, *, method="GET", timeout=3.0, body=None):
        calls.append((method, url))
        if method == "POST":
            raise urllib.error.HTTPError(
                url,
                409,
                "Conflict",
                {},
                io.BytesIO(b'{"ok":false,"error":"Refresh already in progress"}'),
            )
        return {
            "status": "running",
            "busy": True,
            "message": "Refreshing drive mounts...",
            "drives": ["C", "G"],
        }

    monkeypatch.setattr(hda, "_http_json", fake_http_json)

    result = hda.proxy_refresh_mounts(r"G:\\Evidence")

    assert result["ok"] is True
    assert result["started"] is True
    assert result["joined_existing"] is True
    assert calls == [
        ("POST", "http://host.docker.internal:9876/refresh-drive-mounts"),
        ("GET", "http://host.docker.internal:9876/refresh-drive-mounts"),
    ]


def test_scheduled_agent_refreshes_existing_drives_on_startup():
    installer = (ROOT / "scripts" / "install-hostdrive-agent.ps1").read_text(encoding="utf-8")
    # A reboot/logon must synchronize drives that were already attached; waiting
    # for the next drive-letter change is not sufficient.
    assert '-RefreshNow -WatchSeconds 30' in installer
    assert 'Start-ScheduledTask -TaskName $taskName' in installer


def test_proxy_drives_annotates_docker_mounted_letters(monkeypatch):
    monkeypatch.setattr(
        hda,
        "probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
            "drives": ["C", "G"],
            "volumes": [
                {"letter": "C", "drive_type": "fixed", "label": "Windows"},
                {"letter": "G", "drive_type": "fixed", "label": "New Volume"},
            ],
            "message": "online",
        },
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.mounted_letters",
        lambda rows=None: ["C", "D"],
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.inspect_host_letters",
        lambda: [],
    )
    data = hda.proxy_drives()
    assert data["ok"] is True
    by_letter = {v["letter"]: v for v in data["volumes"]}
    assert by_letter["C"]["mounted"] is True
    assert by_letter["G"]["mounted"] is False
    assert data["source"] == "office_host"
    assert data["mobile_devices"] == []


def test_proxy_drives_includes_office_mobile_devices(monkeypatch):
    monkeypatch.setattr(
        hda,
        "probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
            "drives": ["C"],
            "volumes": [{"letter": "C", "drive_type": "fixed"}],
            "mobile_devices": [
                {"id": "USB\\VID_05AC", "name": "Apple iPhone", "os_hint": "ios"},
            ],
            "message": "online",
        },
    )
    monkeypatch.setattr("app.services.drive_mount_agent.mounted_letters", lambda rows=None: ["C"])
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: [])
    data = hda.proxy_drives()
    assert data["mobile_count"] == 1
    assert data["mobile_devices"][0]["os_hint"] == "ios"
    assert data["mobile_devices"][0]["attach_host"] == "office_server"


def test_proxy_mobile_devices_fetches_helper(monkeypatch):
    monkeypatch.setattr(
        hda,
        "probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
            "start_hint": "hint",
        },
    )

    def fake_http_json(url: str, *, method="GET", timeout=3.0, body=None):
        assert url.endswith("/mobile-devices")
        return {
            "ok": True,
            "mobile_devices": [
                {"id": "ANDROID1", "name": "Pixel 8", "os_hint": "android"},
            ],
            "ios_backup_roots": [],
        }

    monkeypatch.setattr(hda, "_http_json", fake_http_json)
    data = hda.proxy_mobile_devices()
    assert data["ok"] is True
    assert data["count"] == 1
    assert data["mobile_devices"][0]["os_hint"] == "android"
    assert data["mobile_devices"][0]["attach_host"] == "office_server"


def test_proxy_acquisition_devices_tags_office_host(monkeypatch):
    monkeypatch.setattr(
        hda,
        "probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
        },
    )

    def fake_http_json(url: str, *, method="GET", timeout=3.0, body=None):
        assert url.endswith("/acquisition/devices")
        return {
            "ok": True,
            "devices": [
                {"adapter": "ios_lockdown", "device_id": "UDID1", "os_family": "ios", "label": "iPhone"},
            ],
            "warnings": [],
        }

    monkeypatch.setattr(hda, "_http_json", fake_http_json)
    data = hda.proxy_acquisition_devices()
    assert data["ok"] is True
    assert data["devices"][0]["attach_host"] == "office_server"
    assert data["devices"][0]["os_family"] == "ios"
