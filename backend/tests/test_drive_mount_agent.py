from app.services.drive_mount_agent import (
    ensure_all_drives_mounted,
    ensure_path_mounted,
    missing_windows_letters,
    mounts_ready,
    windows_attached_letters,
)


def _row(letter: str, *, mounted: bool, stale: bool = False) -> dict:
    return {
        "letter": letter.lower(),
        "path": f"/host/{letter.lower()}",
        "exists": mounted or stale,
        "stale": stale,
        "mounted": mounted,
        "entries": 3 if mounted else 0,
    }


def test_windows_attached_letters_include_external_and_skip_cdrom():
    helper = {
        "ok": True,
        "drives": ["C", "D", "G"],
        "volumes": [
            {"letter": "C", "drive_type": "fixed"},
            {"letter": "G", "drive_type": "fixed", "label": "New Volume"},
            {"letter": "E", "drive_type": "cdrom"},
        ],
    }
    assert windows_attached_letters(helper) == ["C", "G", "D"]


def test_missing_windows_letters_when_g_is_stale_stub():
    helper = {"ok": True, "drives": ["C", "D", "E", "F", "G"]}
    rows = [_row(L, mounted=True) for L in "CDEF"] + [_row("G", mounted=False, stale=True)]
    assert missing_windows_letters(helper, rows) == ["G"]
    assert mounts_ready(rows, helper) is True


def test_mounts_ready_when_any_docker_letter_is_up():
    helper = {"ok": True, "drives": ["C", "G"]}
    only_c = [_row("C", mounted=True), _row("G", mounted=False)]
    both = [_row("C", mounted=True), _row("G", mounted=True)]
    none = [_row("C", mounted=False), _row("G", mounted=False)]
    assert mounts_ready(only_c, helper) is True
    assert mounts_ready(both, helper) is True
    assert mounts_ready(none, helper) is False


def test_ensure_all_remounts_only_when_nothing_is_mounted(monkeypatch):
    inspect_n = {"n": 0}

    def fake_inspect():
        inspect_n["n"] += 1
        if inspect_n["n"] < 3:
            return [_row(L, mounted=False) for L in "cdefg"]
        return [_row(L, mounted=True) for L in "cdefg"]

    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {
            "ok": True,
            "helper_url": "http://host.docker.internal:9876",
            "drives": ["C", "D", "E", "F", "G"],
            "volumes": [{"letter": "G", "drive_type": "fixed", "label": "New Volume"}],
            "start_hint": "hint",
        },
    )
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", fake_inspect)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.proxy_refresh_mounts",
        lambda required_path=None: {"ok": True, "started": True, "required_path": required_path},
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.wait_for_refresh",
        lambda timeout_sec=150: {"status": "done"},
    )
    monkeypatch.setattr("app.services.drive_mount_agent.time.sleep", lambda _s: None)

    result = ensure_all_drives_mounted(wait_sec=8)
    assert result["ok"] is True
    assert result["skipped_refresh"] is False
    assert "C" in result["mounted"]


def test_ensure_all_skips_refresh_when_partial_letters_already_mounted(monkeypatch):
    rows = [_row(L, mounted=True) for L in "CDEF"]
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: rows)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": True, "drives": ["C", "D", "E", "F", "G"]},
    )
    calls = {"n": 0}

    def boom(**_kwargs):
        calls["n"] += 1
        raise AssertionError("refresh must not run when Docker already has letters")

    monkeypatch.setattr("app.services.drive_mount_agent.proxy_refresh_mounts", boom)
    result = ensure_all_drives_mounted(wait_sec=8)
    assert result["ok"] is True
    assert result["skipped_refresh"] is True
    assert calls["n"] == 0


def test_ensure_all_sync_attached_remounts_missing_g(monkeypatch):
    stale = [_row(L, mounted=True) for L in "CDEF"] + [_row("G", mounted=False, stale=True)]
    healthy = [_row(L, mounted=True) for L in "CDEFG"]
    inspect_n = {"n": 0}

    def fake_inspect():
        inspect_n["n"] += 1
        return stale if inspect_n["n"] < 3 else healthy

    refresh_calls: list[str | None] = []
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", fake_inspect)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": True, "drives": ["C", "D", "E", "F", "G"]},
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.proxy_refresh_mounts",
        lambda required_path=None: refresh_calls.append(required_path) or {"ok": True, "started": True},
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.wait_for_refresh",
        lambda timeout_sec=150: {"status": "done"},
    )
    monkeypatch.setattr("app.services.drive_mount_agent.time.sleep", lambda _s: None)

    result = ensure_all_drives_mounted(wait_sec=8, sync_attached=True)
    assert refresh_calls == ["G:\\"]
    assert result["ok"] is True
    assert result["skipped_refresh"] is False
    assert "G" in result["mounted"]
    assert result.get("newly_attached") == ["G"]


def test_ensure_all_skips_refresh_when_already_mounted(monkeypatch):
    rows = [_row(L, mounted=True) for L in "CDEFG"]
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: rows)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": True, "drives": ["C", "D", "E", "F", "G"]},
    )
    calls = {"n": 0}

    def boom(**_kwargs):
        calls["n"] += 1
        raise AssertionError("refresh must not run when every Windows letter is mounted")

    monkeypatch.setattr("app.services.drive_mount_agent.proxy_refresh_mounts", boom)
    result = ensure_all_drives_mounted(wait_sec=8)
    assert result["ok"] is True
    assert result["skipped_refresh"] is True
    assert calls["n"] == 0


def test_ensure_all_ok_when_helper_offline_if_api_already_has_mounts(monkeypatch):
    rows = [_row(L, mounted=True) for L in "CDEFG"]
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: rows)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": False, "drives": [], "start_hint": "hint"},
    )
    result = ensure_all_drives_mounted(wait_sec=8)
    assert result["ok"] is True
    assert "G" in result["mounted"]
    assert result["skipped_refresh"] is True


def test_ensure_path_remounts_when_required_letter_is_stale(monkeypatch):
    stale = [_row(L, mounted=True) for L in "CDEF"] + [_row("G", mounted=False, stale=True)]
    healthy = [_row(L, mounted=True) for L in "CDEFG"]
    inspect_n = {"n": 0}

    def fake_inspect():
        inspect_n["n"] += 1
        return stale if inspect_n["n"] < 3 else healthy

    readable = {"n": 0}

    def fake_readable(_path: str) -> bool:
        readable["n"] += 1
        return readable["n"] >= 3

    refresh_calls: list[str | None] = []

    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", fake_inspect)
    monkeypatch.setattr("app.services.drive_mount_agent.path_is_readable", fake_readable)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {
            "ok": True,
            "drives": ["C", "D", "E", "F", "G"],
            "volumes": [{"letter": "G", "drive_type": "fixed", "label": "New Volume"}],
            "start_hint": "hint",
        },
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.proxy_refresh_mounts",
        lambda required_path=None: refresh_calls.append(required_path) or {"ok": True, "started": True},
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.wait_for_refresh",
        lambda timeout_sec=150: {"status": "done"},
    )
    monkeypatch.setattr("app.services.drive_mount_agent.time.sleep", lambda _s: None)

    selected = r"G:\DISK2\DataExtration\SegerEx-1"
    result = ensure_path_mounted(selected, wait_sec=8)
    assert refresh_calls == [selected]
    assert result["ok"] is True
    assert result["path_ready"] is True
    assert result["skipped_refresh"] is False
    assert "G" in result["mounted"]


def test_ensure_all_with_required_path_remounts_stale_g(monkeypatch):
    rows = [_row(L, mounted=True) for L in "CDEF"] + [_row("G", mounted=False, stale=True)]
    calls = {"n": 0}

    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: rows)
    monkeypatch.setattr("app.services.drive_mount_agent.path_is_readable", lambda _p: False)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": True, "drives": ["C", "D", "E", "F", "G"]},
    )

    def fake_refresh(required_path=None):
        calls["n"] += 1
        calls["path"] = required_path
        return {"ok": True, "started": True}

    monkeypatch.setattr("app.services.drive_mount_agent.proxy_refresh_mounts", fake_refresh)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.wait_for_refresh",
        lambda timeout_sec=150: {"status": "done"},
    )
    monkeypatch.setattr("app.services.drive_mount_agent.time.sleep", lambda _s: None)

    result = ensure_all_drives_mounted(wait_sec=8, required_path=r"G:\Evidence")
    assert calls["n"] == 1
    assert calls["path"] == r"G:\Evidence"
    assert result["skipped_refresh"] is False


def test_ensure_path_refreshes_when_letter_is_mounted_but_exact_path_is_unreadable(monkeypatch):
    rows = [_row(L, mounted=True) for L in "CDEFG"]
    calls = {"n": 0}
    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: rows)
    monkeypatch.setattr("app.services.drive_mount_agent.path_is_readable", lambda _p: False)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": True, "drives": ["C", "D", "E", "F", "G"]},
    )

    def refresh(required_path=None):
        calls["n"] += 1
        return {"ok": True, "started": True, "required_path": required_path}

    monkeypatch.setattr("app.services.drive_mount_agent.proxy_refresh_mounts", refresh)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.wait_for_refresh",
        lambda timeout_sec=150: {"status": "error", "ok": False, "error": "Windows path missing or stale bind"},
    )
    monkeypatch.setattr("app.services.drive_mount_agent.time.sleep", lambda _s: None)
    result = ensure_path_mounted(r"G:\does-not-exist", wait_sec=8)
    assert calls["n"] == 1
    assert result["ok"] is False
    assert result["path_ready"] is False
    assert "Windows path missing or stale bind" in result["message"]


def test_ensure_path_surfaces_refresh_job_error_without_waiting_for_ttl(monkeypatch):
    rows = [_row(L, mounted=True) for L in "CDEF"] + [_row("G", mounted=False, stale=True)]
    sleeps = {"n": 0}

    monkeypatch.setattr("app.services.drive_mount_agent.inspect_host_letters", lambda: rows)
    monkeypatch.setattr("app.services.drive_mount_agent.path_is_readable", lambda _p: False)
    monkeypatch.setattr(
        "app.services.drive_mount_agent.probe_helper",
        lambda: {"ok": True, "drives": ["C", "D", "E", "F", "G"]},
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.proxy_refresh_mounts",
        lambda required_path=None: {"ok": True, "started": True, "required_path": required_path},
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.wait_for_refresh",
        lambda timeout_sec=150: {
            "status": "error",
            "ok": False,
            "error": "exact G evidence folder could not be bound read-only",
        },
    )
    monkeypatch.setattr(
        "app.services.drive_mount_agent.time.sleep",
        lambda _s: sleeps.__setitem__("n", sleeps["n"] + 1),
    )

    result = ensure_path_mounted(r"G:\\Evidence\\Disk01.E01", wait_sec=90)
    assert result["ok"] is False
    assert result["path_ready"] is False
    assert result["refresh_error"] == "exact G evidence folder could not be bound read-only"
    assert "Mount recovery detail" in result["message"]
    assert sleeps["n"] == 0
