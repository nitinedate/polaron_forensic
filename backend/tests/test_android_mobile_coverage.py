from __future__ import annotations

from app.services.mobile_acquire.adapters.android_adb import AndroidAdbAdapter
from app.services.mobile_acquire.adapters.android_mtp import AndroidMtpAdapter
from app.services.mobile_acquire.device_profile import ConnectionMode
from app.services.mobile_acquire.methods import CollectionMethod
from app.services.mobile_acquire.orchestrator import DeviceDetector


class _AdbState:
    def __init__(self, state: str) -> None:
        self.stdout = state
        self.returncode = 0


def test_unauthorized_adb_is_not_labelled_mtp(monkeypatch):
    adapter = AndroidAdbAdapter()
    monkeypatch.setattr(adapter, "_adb", lambda *a, **k: _AdbState("unauthorized"))
    profile = adapter.identify("R58MTEST")
    assert profile.connection_mode == ConnectionMode.UNKNOWN
    assert profile.usb_debugging_authorized is False
    assert any("RSA" in o or "authoris" in o.lower() or "Allow" in o for o in profile.observations)


def test_mtp_adapter_offers_filesystem_methods():
    adapter = AndroidMtpAdapter()
    profile = adapter.identify(r"USB\VID_04E8&PID_6860\1234")
    assert profile.os_family == "android"
    assert profile.connection_mode == ConnectionMode.MTP
    methods = adapter.supported_methods(profile)
    assert CollectionMethod.LOGICAL in methods
    assert CollectionMethod.FILE_SYSTEM in methods
    assert CollectionMethod.FULL_FILE_SYSTEM in methods
    assert adapter.detect() == []


def test_device_detector_registers_android_and_ios():
    names = {a.name for a in DeviceDetector().adapters}
    assert "android_adb" in names
    assert "android_mtp" in names
    assert "ios_lockdown" in names


def test_cli_picks_mtp_for_wpd_instance_id():
    from app.services.mobile_acquire.cli import _pick_adapter

    class _Empty:
        def scan(self):
            return [], []

    picked = _pick_adapter("android", r"USB\VID_04E8&PID_6860\ABC123", _Empty())
    assert picked == ("android_mtp", r"USB\VID_04E8&PID_6860\ABC123")


def test_android_adapter_does_not_import_ios_afc_or_readable():
    import inspect

    from app.services.mobile_acquire.adapters import android_adb, android_mtp
    from app.services.mobile_acquire import android_readable

    for mod in (android_adb, android_mtp, android_readable):
        src = inspect.getsource(mod)
        assert "ios_usbmux_afc" not in src
        assert "ios_readable" not in src
        assert "HouseArrestService" not in src
        assert "AFC_TARGETS" not in src
        assert "ZMESSAGETYPE" not in src


def test_android_readable_copies_trashed_media_not_ios_trees(tmp_path):
    from app.services.mobile_acquire.android_readable import materialize_android_readable_artifacts

    ios_root = tmp_path / "ios"
    (ios_root / "ios_image").mkdir(parents=True)
    out = materialize_android_readable_artifacts(ios_root)
    assert out["ok"] is False
    assert "androidagent" in out["agent"]

    root = tmp_path / "android"
    trash = root / "adb_logical" / "filesystem" / "sdcard" / "sdcard_DCIM" / ".trashed"
    trash.mkdir(parents=True)
    (trash / "IMG_0001.jpg").write_bytes(b"\xff\xd8trashed")
    wa = root / "adb_logical" / "filesystem" / "sdcard" / "sdcard_Android_media_com.whatsapp" / "WhatsApp" / "Media"
    wa.mkdir(parents=True)
    (wa / "IMG-2026.jpg").write_bytes(b"\xff\xd8livewa")
    out = materialize_android_readable_artifacts(root)
    assert out["ok"] is True
    assert out["deleted_media"] >= 1
    assert out["whatsapp_media"] >= 1
    assert (root / "readable_artifacts" / "android_deleted").is_dir()


def test_android_readable_counts_deleted_msgstore_flags_not_ios_type14(tmp_path):
    import sqlite3

    from app.services.mobile_acquire.android_readable import materialize_android_readable_artifacts

    root = tmp_path / "android"
    dbdir = root / "adb_logical" / "filesystem" / "sdcard" / "sdcard_Android_media_com.whatsapp"
    dbdir.mkdir(parents=True)
    db = dbdir / "msgstore.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE message (_id INTEGER, is_deleted INTEGER, messagetype INTEGER)")
    con.execute("INSERT INTO message VALUES (1, 1, 14)")
    con.execute("INSERT INTO message VALUES (2, 0, 0)")
    con.commit()
    con.close()
    out = materialize_android_readable_artifacts(root)
    assert out["deleted_whatsapp_messages"] == 1
