from __future__ import annotations

import json
import os
from types import SimpleNamespace

from app.services.mobile_acquire import ios_usbmux
from app.services.mobile_acquire.ios_usbmux import normalize_ios_udid, resolve_ios_udid


def test_normalize_windows_usb_instance_to_lockdown_udid():
    raw = r"USB#VID_05AC&PID_12A8#000081500002659C0CBB401C"
    assert normalize_ios_udid(raw) == "00008150-0002659C0CBB401C"
    assert normalize_ios_udid("00008150-0002659C0CBB401C") == "00008150-0002659C0CBB401C"
    assert normalize_ios_udid("000081500002659C0CBB401C") == "00008150-0002659C0CBB401C"
    assert normalize_ios_udid("") == ""


def test_resolve_ios_udid_matches_live_usbmux_serial():
    live = ["00008150-0002659C0CBB401C"]
    assert resolve_ios_udid("USB#VID_05AC&PID_12A8#000081500002659C0CBB401C", live=live) == live[0]
    assert resolve_ios_udid("", live=live) == live[0]
    assert resolve_ios_udid("USB#VID_05AC&PID_12A8#DEAD", live=[]) == ""


class _Dev:
    def __init__(self, serial: str) -> None:
        self.serial = serial
        self.connection_type = "USB"


def test_list_ios_devices_uses_usbmux(monkeypatch):
    async def fake_list():
        return [_Dev("00008150-0002659C0CBB401C")]

    class _Lock:
        udid = "00008150-0002659C0CBB401C"
        display_name = "iPhone 17"
        product_type = "iPhone18,3"
        product_version = "26.6"

    async def fake_lockdown(**kwargs):
        assert kwargs.get("serial") == "00008150-0002659C0CBB401C"
        return _Lock()

    fake_usbmux = SimpleNamespace(list_devices=fake_list)
    fake_ld = SimpleNamespace(create_using_usbmux=fake_lockdown)
    monkeypatch.setitem(__import__("sys").modules, "pymobiledevice3.usbmux", fake_usbmux)
    monkeypatch.setitem(__import__("sys").modules, "pymobiledevice3.lockdown", fake_ld)

    devices = ios_usbmux.list_ios_devices()
    assert len(devices) == 1
    assert devices[0]["udid"] == "00008150-0002659C0CBB401C"
    assert devices[0]["name"] == "iPhone 17"
    assert ios_usbmux.list_ios_udids() == ["00008150-0002659C0CBB401C"]


def test_list_ios_devices_empty_on_import_error(monkeypatch):
    def boom():
        raise RuntimeError("no usbmux")

    monkeypatch.setattr(ios_usbmux, "_list_async", boom)
    assert ios_usbmux.list_ios_devices() == []
    payload = json.loads(ios_usbmux.as_json())
    assert payload["ok"] is False
    assert "no usbmux" in payload.get("error", "")


def test_list_ios_devices_accepts_sync_usbmux(monkeypatch):
    def fake_list():
        return [_Dev("ABCD-SYNC")]

    class _Lock:
        display_name = "iPhone"
        product_type = "iPhone15,2"
        product_version = "18.0"

    def fake_lockdown(**kwargs):
        return _Lock()

    fake_usbmux = SimpleNamespace(list_devices=fake_list)
    fake_ld = SimpleNamespace(create_using_usbmux=fake_lockdown)
    monkeypatch.setitem(__import__("sys").modules, "pymobiledevice3.usbmux", fake_usbmux)
    monkeypatch.setitem(__import__("sys").modules, "pymobiledevice3.lockdown", fake_ld)

    devices = ios_usbmux.list_ios_devices()
    assert devices[0]["udid"] == "ABCD-SYNC"
    assert devices[0]["name"] == "iPhone"


def test_apply_ios_identity_clears_unknown_fields():
    from app.services.mobile_acquire.adapters.ios_lockdown import IosLockdownAdapter
    from app.services.mobile_acquire.device_profile import DeviceProfile, LockState
    from app.services.mobile_acquire.device_profile import resolve_capability
    from app.services.mobile_acquire.methods import CollectionMethod

    profile = DeviceProfile(os_family="ios", udid="00008150-0002659C0CBB401C")
    IosLockdownAdapter._apply_ios_identity(profile, {
        "ProductType": "iPhone18,3",
        "ProductName": "iPhone 17",
        "ProductVersion": "26.6",
        "BuildVersion": "23G82",
        "SerialNumber": "F2LXXXX",
        "PasswordProtected": True,
        "HardwarePlatform": "t8150",
        "BatteryCurrentCapacity": 81,
        "DeviceName": "Examiner iPhone",
        "_WillEncrypt": True,
    })
    assert profile.model == "iPhone 17"
    assert profile.lock_state == LockState.LOCKED_AFU
    assert profile.encryption_state == "data_protection"
    assert profile.security_patch_level == "23G82"
    assert profile.build_id == "23G82"
    assert profile.battery_percent == 81
    assert profile.unknown_fields() == []
    assert any("passcode is configured" in o.lower() for o in profile.observations)
    assert not any("unlock and keep the screen" in o.lower() for o in profile.observations)
    cap = resolve_capability(profile)
    assert CollectionMethod.BACKUP in cap.supported_methods
    assert CollectionMethod.ADVANCED_LOGICAL in cap.supported_methods
    assert not any("not determined" in w.lower() for w in cap.warnings)
    assert not any("Lock state was not determined" in w for w in cap.warnings)


def test_ios_backup_manifest_requires_real_files(tmp_path):
    from app.services.mobile_acquire.adapters.ios_lockdown import _ios_backup_manifest

    empty = tmp_path / "ios_backup"
    empty.mkdir()
    assert _ios_backup_manifest(empty) is None
    udid = empty / "UDID"
    udid.mkdir()
    (udid / "Manifest.plist").write_bytes(b"tiny")
    assert _ios_backup_manifest(empty) is None
    (udid / "Manifest.db").write_bytes(b"x" * 128)
    assert _ios_backup_manifest(empty).name == "Manifest.db"


def test_format_backup_failure_does_not_assume_locked():
    from app.services.mobile_acquire.adapters.ios_lockdown import IosLockdownAdapter

    msg = IosLockdownAdapter._format_backup_failure(
        1, "", "", manifest_found=False
    )
    assert "ErrorCode 208" not in msg
    assert "device locked" not in msg.lower()
    assert "Unlock the iPhone, keep the screen on, tap Trust This Computer" not in msg
    assert "Manifest.db" in msg

    locked = IosLockdownAdapter._format_backup_failure(
        208, "", "ErrorCode 208 Device locked", manifest_found=False
    )
    assert "ErrorCode 208" in locked
    assert "Unlock" in locked


def test_inventory_gaps_do_not_blame_lock_without_208(tmp_path):
    from app.services.mobile_acquire.content_inventory import inventory_extraction

    root = tmp_path / "extract"
    (root / "afc_media" / "DCIM").mkdir(parents=True)
    (root / "afc_media" / "DCIM" / "IMG_0001.JPG").write_bytes(b"jpeg")
    (root / "ios_backup").mkdir()
    (root / "ios_backup" / "hashfile").write_bytes(b"x" * 32)

    inv = inventory_extraction(root)
    joined = " ".join(inv["gaps"]).lower()
    assert "often device locked" not in joined
    assert "unlock the phone and re-run" not in joined
    assert "manifest" in joined


def test_inventory_accepts_manifest_plist(tmp_path):
    from app.services.mobile_acquire.content_inventory import inventory_extraction

    root = tmp_path / "extract"
    backup = root / "ios_backup" / "UDID"
    backup.mkdir(parents=True)
    (backup / "Manifest.plist").write_bytes(b"x" * 128)
    inv = inventory_extraction(root)
    assert inv["ios_backup_complete"] is True
    assert not any("incomplete without Manifest" in g for g in inv["gaps"])


def test_ios_backup_detects_windows_max_path():
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "ios_usbmux_backup.py"
    spec = importlib.util.spec_from_file_location("ios_usbmux_backup", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    udid = "00008150-0002659C0CBB401C"
    long_dest = (
        r"E:\projects\aetheris_project\evidence\cases\CASE-20260920-APPLEIPHON"
        r"\02_Original_Extraction"
        r"\CASE-20260920-APPLEIPHON_E-590401_Apple_iPhone_ADVANCED_LOGICAL_20260920_073307"
        r"\ios_image"
    )
    assert mod.backup_tree_would_exceed_max_path(long_dest, udid) is True
    assert mod.backup_tree_would_exceed_max_path(r"E:\ib", udid) is False
    staged = mod.short_staging_root(udid, "20260920_081928")
    assert "0CBB401C" in str(staged)
    assert "20260920_081928" in str(staged)
    assert str(staged) != str(mod.short_staging_root(udid, "other_run"))


def test_ios_backup_empty_manifest_plist_is_not_complete(tmp_path):
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "ios_usbmux_backup.py"
    spec = importlib.util.spec_from_file_location("ios_usbmux_backup", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    udid = "00008150-0002659C0CBB401C"
    nested = tmp_path / udid
    nested.mkdir()
    (nested / "Manifest.plist").write_bytes(b"")
    (nested / "Info.plist").write_bytes(b"x" * 32)
    assert mod._manifest_complete(tmp_path, udid) is None
    (nested / "Manifest.db").write_bytes(b"x" * 128)
    assert mod._manifest_complete(tmp_path, udid) == nested


def test_ios_backup_connection_drop_is_transient():
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "ios_usbmux_backup.py"
    spec = importlib.util.spec_from_file_location("ios_usbmux_backup", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    class ConnectionTerminatedError(Exception):
        pass

    assert mod._is_transient(ConnectionTerminatedError()) is True
    assert mod._is_transient(OSError("WinError 10054")) is True
    assert mod._is_transient(ValueError("bad dest")) is False


def test_ios_backup_disk_full_is_not_transient_or_manifest_missing():
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "ios_usbmux_backup.py"
    spec = importlib.util.spec_from_file_location("ios_usbmux_backup", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    class NotEnoughDiskSpaceError(OSError):
        pass

    full = NotEnoughDiskSpaceError("NotEnoughDiskSpaceError")
    assert mod._is_disk_full(full) is True
    assert mod._is_transient(full) is False
    assert mod._is_transient(OSError("NotEnoughDiskSpaceError")) is False
    payload = mod.classify_backup_failure(full, Path("E:/ib/0CBB401C/20260920_153810"))
    assert payload["ok"] is False
    assert payload["error"] == "ios_backup_not_enough_disk_space"
    assert payload["type"] == "ios_backup_not_enough_disk_space"
    assert "manifest" not in payload["error"].lower()
    assert "unlock" not in payload["error"].lower()


def test_short_staging_skips_full_volume(monkeypatch):
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "ios_usbmux_backup.py"
    spec = importlib.util.spec_from_file_location("ios_usbmux_backup", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    def fake_free(letter: str) -> int:
        return 0 if letter.upper() == "E" else 200 * 1024**3

    monkeypatch.setattr(mod, "_drive_free_bytes", fake_free)
    staged = mod.short_staging_root("00008150-0002659C0CBB401C", "20260920_160001")
    assert str(staged)[0].upper() != "E"
    assert "0CBB401C" in str(staged)
    assert "20260920_160001" in str(staged)


def test_inventory_ios_image_sees_whatsapp_and_not_sms_manifest(tmp_path):
    import sqlite3

    from app.services.mobile_acquire.content_inventory import inventory_extraction

    root = tmp_path / "extract"
    backup = root / "ios_image" / "UDID"
    backup.mkdir(parents=True)
    con = sqlite3.connect(backup / "Manifest.db")
    con.execute(
        "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)"
    )
    con.execute(
        "INSERT INTO Files VALUES (?,?,?,1)",
        (
            "7c7fba66680ef796b916b067077cc246adacf01d",
            "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
            "ChatStorage.sqlite",
        ),
    )
    con.commit()
    con.close()
    inv = inventory_extraction(root)
    assert inv["ios_backup_complete"] is True
    assert inv["counts"]["whatsapp"] >= 1
    assert not any("msgstore.db" in g and "rooted" in g for g in inv["gaps"])
    assert "manifest.db" not in " ".join(inv["categories"]["sms_imessage"]).lower()


def test_ios_readable_finds_ios_image_chatstorage(tmp_path):
    import sqlite3

    from app.services.mobile_acquire.ios_readable import materialize_ios_readable_artifacts

    root = tmp_path / "extract"
    backup = root / "ios_image" / "UDID"
    hashed = backup / "7c" / "7c7fba66680ef796b916b067077cc246adacf01d"
    hashed.parent.mkdir(parents=True)
    hashed.write_bytes(b"chat-db" * 20)
    con = sqlite3.connect(backup / "Manifest.db")
    con.execute(
        "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)"
    )
    con.execute(
        "INSERT INTO Files VALUES (?,?,?,1)",
        (
            "7c7fba66680ef796b916b067077cc246adacf01d",
            "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
            "ChatStorage.sqlite",
        ),
    )
    con.commit()
    con.close()
    out = materialize_ios_readable_artifacts(root)
    assert out["ok"] is True
    assert out["whatsapp_domains"]
    copied = " ".join(item["dest"] for item in out["copied"]).lower()
    assert "chatstorage.sqlite" in copied
    assert (root / "readable_artifacts").exists()


def test_ios_readable_copies_deleted_whatsapp_media(tmp_path):
    import sqlite3

    from app.services.mobile_acquire.ios_readable import materialize_ios_readable_artifacts

    root = tmp_path / "extract"
    backup = root / "ios_image" / "UDID"
    chat_id = "aa" * 20
    media_id = "bb" * 20
    (backup / "aa").mkdir(parents=True)
    (backup / "bb").mkdir(parents=True)
    chat = backup / "aa" / chat_id
    media = backup / "bb" / media_id
    con = sqlite3.connect(chat)
    con.execute(
        "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER, ZMESSAGETYPE INTEGER, ZMEDIAITEM INTEGER)"
    )
    con.execute("CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER, ZMEDIALOCALPATH TEXT)")
    con.execute("INSERT INTO ZWAMESSAGE VALUES (1, 14, 7)")
    con.execute(
        "INSERT INTO ZWAMEDIAITEM VALUES (7, 'Media/1555@s.whatsapp.net/a.jpg')"
    )
    con.commit()
    con.close()
    media.write_bytes(b"\xff\xd8deleted-jpg")
    mdb = sqlite3.connect(backup / "Manifest.db")
    mdb.execute(
        "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)"
    )
    mdb.executemany(
        "INSERT INTO Files VALUES (?,?,?,1)",
        [
            (chat_id, "AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"),
            (
                media_id,
                "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
                "Message/Media/1555@s.whatsapp.net/a.jpg",
            ),
        ],
    )
    mdb.commit()
    mdb.close()

    out = materialize_ios_readable_artifacts(root)
    assert out.get("deleted_whatsapp_messages") == 1
    assert out.get("deleted_whatsapp_media") == 1
    copied = " ".join(item["dest"] for item in out["copied"]).lower()
    assert "a.jpg" in copied


def test_ios_readable_copies_live_whatsapp_and_camera_media(tmp_path):
    import sqlite3

    from app.services.mobile_acquire.ios_readable import materialize_ios_readable_artifacts

    root = tmp_path / "extract"
    backup = root / "ios_image" / "UDID"
    chat_id = "aa" * 20
    live_id = "cc" * 20
    cam_id = "dd" * 20
    (backup / "aa").mkdir(parents=True)
    (backup / "cc").mkdir(parents=True)
    (backup / "dd").mkdir(parents=True)
    chat = backup / "aa" / chat_id
    live = backup / "cc" / live_id
    cam = backup / "dd" / cam_id
    con = sqlite3.connect(chat)
    con.execute(
        "CREATE TABLE ZWAMESSAGE (Z_PK INTEGER, ZMESSAGETYPE INTEGER, ZMEDIAITEM INTEGER)"
    )
    con.execute("CREATE TABLE ZWAMEDIAITEM (Z_PK INTEGER, ZMEDIALOCALPATH TEXT)")
    con.execute("INSERT INTO ZWAMESSAGE VALUES (1, 0, 7)")
    con.execute("INSERT INTO ZWAMEDIAITEM VALUES (7, 'Media/1555@s.whatsapp.net/live.jpg')")
    con.commit()
    con.close()
    live.write_bytes(b"\xff\xd8live-jpg")
    cam.write_bytes(b"\xff\xd8camera")
    mdb = sqlite3.connect(backup / "Manifest.db")
    mdb.execute(
        "CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER)"
    )
    mdb.executemany(
        "INSERT INTO Files VALUES (?,?,?,1)",
        [
            (chat_id, "AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite"),
            (
                live_id,
                "AppDomainGroup-group.net.whatsapp.WhatsApp.shared",
                "Message/Media/1555@s.whatsapp.net/live.jpg",
            ),
            (cam_id, "CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG"),
        ],
    )
    mdb.commit()
    mdb.close()

    out = materialize_ios_readable_artifacts(root)
    assert int(out.get("whatsapp_media_live") or 0) >= 1
    assert int(out.get("camera_media") or 0) >= 1
    copied = " ".join(item["dest"] for item in out["copied"]).lower()
    assert "live.jpg" in copied
    assert "img_0001.jpg" in copied


def test_ios_and_android_jobs_stay_isolated():
    from pathlib import Path

    repo = Path(__file__).resolve().parents[2]
    ios_job = (repo / "scripts" / "native_ios_job.ps1").read_text(encoding="utf-8")
    and_job = (repo / "scripts" / "native_mtp_job.ps1").read_text(encoding="utf-8")
    afc = (repo / "scripts" / "ios_usbmux_afc.py").read_text(encoding="utf-8")
    readable = (repo / "scripts" / "ios_readable_cli.py").read_text(encoding="utf-8")
    acquire = (repo / "scripts" / "host-mobile-acquire.ps1").read_text(encoding="utf-8")

    assert "Invoke-IosAfcAcquire" in ios_job
    assert "Invoke-IosReadableArtifacts" in ios_job
    assert "Invoke-AndroidAdbAcquire" not in ios_job
    assert "Invoke-AndroidReadableArtifacts" not in ios_job
    assert "ios_usbmux_afc" not in and_job
    assert "Invoke-IosAfcAcquire" not in and_job
    assert "Invoke-IosReadableArtifacts" not in and_job
    assert "Invoke-AndroidReadableArtifacts" in and_job
    assert "androidagent" in and_job.lower() or "Android Agent" in and_job
    assert "must not" in afc.lower()
    assert "must not" in readable.lower()
    assert "/sdcard/WhatsApp" in acquire
    assert "/sdcard/DCIM/.trashed" in acquire
    assert "function Invoke-IosAfcAcquire" in acquire
    assert "function Invoke-AndroidAdbAcquire" in acquire
    assert "function Invoke-AndroidReadableArtifacts" in acquire
    assert "Invoke-IosReadableArtifacts" in acquire


def test_live_ios_collection_folder_is_a_segment(tmp_path):
    from app.services.host_evidence import _collect_segment_files, readable_segment_paths
    from app.services.mobile_segments import folder_is_live_mobile_collection

    root = tmp_path / "run"
    udid = root / "ios_image" / "00008150-0002659C0CBB401C"
    udid.mkdir(parents=True)
    (udid / "Manifest.plist").write_text("ok")
    (root / "afc_media").mkdir()
    (root / "readable_artifacts").mkdir()
    (root / "backup.out").write_text("log")
    assert folder_is_live_mobile_collection(root) is True
    segs = _collect_segment_files(root, None, "mobile")
    assert udid in segs
    assert (root / "afc_media") in segs
    assert (root / "readable_artifacts") not in segs
    readable, vanished = readable_segment_paths(segs)
    assert udid in readable
    assert vanished == []


def test_iter_tree_files_skips_junctions(tmp_path):
    from app.services.mobile_acquire.adb_tar_pull import iter_tree_files

    real = tmp_path / "real"
    real.mkdir()
    (real / "keep.txt").write_text("ok")
    linked = tmp_path / "linked"
    if os.name == "nt":
        os.system(f'mklink /J "{linked}" "{real}" >nul 2>nul')
        if not linked.exists():
            return
    else:
        linked.symlink_to(real, target_is_directory=True)
    root = tmp_path / "job"
    root.mkdir()
    (root / "note.txt").write_text("meta")
    target = root / "ios_image"
    if os.name == "nt":
        os.system(f'mklink /J "{target}" "{real}" >nul 2>nul')
    else:
        target.symlink_to(real, target_is_directory=True)
    names = [rel for _full, rel in iter_tree_files(root)]
    assert "note.txt" in names
    assert not any(rel.startswith("ios_image") for rel in names)


def test_ios_export_defaults_to_payload_zip_for_sealed_original(tmp_path):
    from app.services.mobile_acquire.export_packages import build_export_packages

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    payload = b"x" * 128
    (original / "ios_image" / "Manifest.db").write_bytes(payload)
    exports = tmp_path / "exports"
    (exports / "readable_artifacts").mkdir(parents=True)
    (exports / "readable_artifacts" / "derived.bin").write_bytes(b"y" * 1024)
    bundle = build_export_packages(
        run_name="run1",
        export_dir=exports,
        original=original,
        method="advanced_logical",
    )
    assert bundle.full_payload_in_zip is True
    zpath = exports / "run1.zip"
    assert zpath.is_file()
    import zipfile

    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
        assert "aetheris_package.json" in names
        assert "ORIGINAL_PATH.txt" in names
        assert "02_Original_Extraction/ios_image/Manifest.db" in names
        assert not any(n.startswith("readable_artifacts/") for n in names)
        index = json.loads(zf.read("file_index.json"))
        assert index["complete"] is True
        assert zf.read("02_Original_Extraction/ios_image/Manifest.db") == payload


def test_ios_export_includes_complete_sealed_backup_when_full_requested(tmp_path):
    from app.services.mobile_acquire.export_packages import build_export_packages

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    payload = b"x" * 128
    (original / "ios_image" / "Manifest.db").write_bytes(payload)
    exports = tmp_path / "exports"
    (exports / "readable_artifacts").mkdir(parents=True)
    (exports / "readable_artifacts" / "derived.bin").write_bytes(b"y" * 1024)
    bundle = build_export_packages(
        run_name="run1",
        export_dir=exports,
        original=original,
        method="advanced_logical",
        full_payload=True,
    )
    assert bundle.full_payload_in_zip is True
    zpath = exports / "run1.zip"
    assert zpath.is_file()
    import zipfile

    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
        assert "aetheris_package.json" in names
        assert "02_Original_Extraction/ios_image/Manifest.db" in names
        assert not any(n.startswith("readable_artifacts/") for n in names)
        index = json.loads(zf.read("file_index.json"))
        assert index["complete"] is True
        assert index["path"] == "file_index.jsonl"
        assert index["files"] == 1
        assert zf.read("02_Original_Extraction/ios_image/Manifest.db") == payload


def test_android_sealed_export_defaults_to_payload_zip(tmp_path):
    from app.services.mobile_acquire.export_packages import build_export_packages, is_sealed_mobile_original

    original = tmp_path / "original"
    (original / "shared_storage" / "DCIM").mkdir(parents=True)
    payload = b"z" * 2048
    (original / "shared_storage" / "DCIM" / "big.bin").write_bytes(payload)
    assert is_sealed_mobile_original(original) is True
    exports = tmp_path / "exports"
    bundle = build_export_packages(
        run_name="and1",
        export_dir=exports,
        original=original,
        method="logical",
    )
    assert bundle.full_payload_in_zip is True
    import zipfile
    with zipfile.ZipFile(exports / "and1.zip") as zf:
        assert zf.read("02_Original_Extraction/shared_storage/DCIM/big.bin") == payload


def test_android_sealed_export_includes_complete_payload_when_full_requested(tmp_path):
    from app.services.mobile_acquire.export_packages import build_export_packages, is_sealed_mobile_original

    original = tmp_path / "original"
    (original / "shared_storage" / "DCIM").mkdir(parents=True)
    payload = b"z" * 2048
    (original / "shared_storage" / "DCIM" / "big.bin").write_bytes(payload)
    assert is_sealed_mobile_original(original) is True
    exports = tmp_path / "exports"
    bundle = build_export_packages(
        run_name="and1",
        export_dir=exports,
        original=original,
        method="logical",
        full_payload=True,
    )
    assert bundle.full_payload_in_zip is True
    import zipfile
    with zipfile.ZipFile(exports / "and1.zip") as zf:
        assert zf.read("02_Original_Extraction/shared_storage/DCIM/big.bin") == payload


def test_export_payload_shards_are_zip_only_extract_source(tmp_path, monkeypatch):
    import zipfile
    import app.services.mobile_acquire.export_packages as mod
    from app.services.virtual_disk import VirtualDisk, enumerate_all_files

    monkeypatch.setattr(mod, "_payload_shard_min_bytes", lambda: 1)
    monkeypatch.setattr(mod, "_payload_shard_bytes", lambda: 60)

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    (original / "ios_image" / "a.bin").write_bytes(b"A" * 80)
    (original / "ios_image" / "b.bin").write_bytes(b"B" * 80)
    exports = tmp_path / "exports"
    # V22: shards are opt-in (AETHERIS_EXPORT_SHARDS / use_shards); the default
    # export is one full <run>.zip. Sidecar catalogs live in the side-files dir.
    bundle = mod.build_export_packages(
        run_name="shard1",
        export_dir=exports,
        original=original,
        method="advanced_logical",
        use_shards=True,
    )
    assert bundle.full_payload_in_zip is True
    assert len(bundle.payload_shards) >= 2
    side = mod.side_files_dir(exports, "shard1")
    catalog = json.loads((side / "payload_shards.json").read_text())
    assert catalog["complete"] is True
    with zipfile.ZipFile(exports / "shard1.zip") as zf:
        assert "SHARDS.json" in zf.namelist()
        assert not any(n.startswith("02_Original_Extraction/") for n in zf.namelist())

    (original / "ios_image" / "MUST_NOT_WALK.bin").write_bytes(b"live-folder-only")
    vd = VirtualDisk(
        job_id="j-shard",
        mode="folder",
        segment_paths=[str(exports / "shard1.zip")],
        format="zip",
        root_folder=str(exports),
    )
    nodes = enumerate_all_files(vd)
    paths = {n["path"].replace("\\", "/") for n in nodes}
    assert any(p.endswith("a.bin") for p in paths)
    assert any(p.endswith("b.bin") for p in paths)
    assert not any("_sealed/" in p for p in paths)
    assert not any(p.endswith("MUST_NOT_WALK.bin") for p in paths)


def test_metadata_only_export_must_be_explicit(tmp_path):
    from app.services.mobile_acquire.export_packages import build_export_packages

    original = tmp_path / "original"
    (original / "shared_storage").mkdir(parents=True)
    (original / "shared_storage" / "a.bin").write_bytes(b"a" * 100)
    exports = tmp_path / "exports"
    bundle = build_export_packages(
        run_name="meta1", export_dir=exports, original=original, full_payload=False
    )
    assert bundle.full_payload_in_zip is False
    import zipfile
    with zipfile.ZipFile(exports / "meta1.zip") as zf:
        assert not any(n.startswith("02_Original_Extraction/") for n in zf.namelist())
        index = json.loads(zf.read("file_index.json"))
        assert index["skipped"] is True


def test_export_cli_prints_slim_inventory(tmp_path, capsys):
    from app.services.mobile_acquire.export_cli import main, slim_inventory

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    (original / "ios_image" / "Manifest.db").write_bytes(b"x" * 128)
    (original / "readable_artifacts" / "keep").mkdir(parents=True)
    (original / "readable_artifacts" / "keep" / "a.txt").write_text("ok")
    exports = tmp_path / "exports"
    rc = main([
        "--original", str(original),
        "--exports", str(exports),
        "--method", "advanced_logical",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert "whatsapp_domains" not in json.dumps(payload["inventory"])
    assert slim_inventory({"ok": True, "counts": {"whatsapp": 1}, "ios_manifest": {"whatsapp_domains": ["x"]}})[
        "ios_manifest"
    ].get("whatsapp_domains") is None


def test_ios_backup_required_free_bytes_uses_device_used_space(monkeypatch):
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[2] / "scripts" / "ios_usbmux_backup.py"
    spec = importlib.util.spec_from_file_location("ios_usbmux_backup_v20", script)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    gib = 1024 ** 3

    class Lockdown:
        def get_value(self, *args, **kwargs):
            return {
                "TotalDataCapacity": 128 * gib,
                "TotalDataAvailable": 8 * gib,
            }

    required, detail = mod.required_backup_free_bytes(Lockdown())
    assert detail["source"] == "device_disk_usage"
    assert detail["used_bytes"] == 120 * gib
    assert required >= 132 * gib


def test_export_uses_deflate_when_raw_copy_does_not_fit(tmp_path, monkeypatch):
    from pathlib import Path
    import app.services.mobile_acquire.export_packages as mod

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    # Highly compressible payload so the low-space mode is deterministic.
    payload = b"A" * (2 * 1024 * 1024)
    (original / "ios_image" / "Manifest.db").write_bytes(payload)
    exports = tmp_path / "exports"

    monkeypatch.setattr(mod, "_reserve_bytes", lambda: 64 * 1024)
    monkeypatch.setattr(mod, "_sample_deflate_ratio", lambda _root: 0.20)
    real_free = mod._free_bytes

    def fake_free(path):
        p = str(path)
        if "exports" in p:
            return 1024 * 1024  # smaller than raw payload, bigger than estimated compressed
        return real_free(path)

    monkeypatch.setattr(mod, "_free_bytes", fake_free)
    monkeypatch.setattr(mod, "_candidate_export_dirs", lambda requested, run: [requested])

    bundle = mod.build_export_packages(
        run_name="tight1", export_dir=exports, original=original, method="advanced_logical",
        full_payload=True,
    )
    zpath = Path(bundle.packages["zip"])
    assert zpath.is_file()
    assert zpath.stat().st_size < len(payload)
    catalog = json.loads((mod.side_files_dir(exports, "tight1") / "export_catalog.json").read_text())
    assert catalog["zip_storage_plan"]["mode"] == "deflate"
    # 05_Exports/<run> holds exactly the four package files
    assert sorted(p.suffix for p in exports.iterdir()) == [".pas", ".ufd", ".ufdx", ".zip"]


def test_export_can_place_full_zip_on_alternate_volume(tmp_path, monkeypatch):
    from pathlib import Path
    import app.services.mobile_acquire.export_packages as mod

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    (original / "ios_image" / "Manifest.db").write_bytes(b"x" * 4096)
    requested = tmp_path / "case" / "05_Exports" / "run"
    alternate = tmp_path / "external" / "run"

    monkeypatch.setattr(mod, "_reserve_bytes", lambda: 128)
    monkeypatch.setattr(mod, "_candidate_export_dirs", lambda requested_dir, run: [requested_dir, alternate])

    def fake_free(path):
        return 1024 if str(path).startswith(str(requested)) else 1024 * 1024

    monkeypatch.setattr(mod, "_free_bytes", fake_free)
    bundle = mod.build_export_packages(
        run_name="run", export_dir=requested, original=original, method="advanced_logical",
        full_payload=True,
    )
    assert Path(bundle.packages["zip"]).parent == alternate
    assert (tmp_path / "case" / "07_Logs" / "run" / "FULL_ZIP_LOCATION.txt").is_file()
    assert not (requested / "FULL_ZIP_LOCATION.txt").exists()
    assert (requested / "run.ufd").is_file()
    assert (requested / "run.pas").is_file()
    assert (requested / "run.ufdx").is_file()


def test_export_progress_does_not_force_100_until_complete(tmp_path):
    from app.services.mobile_acquire.export_cli import _merge_progress

    p = tmp_path / "progress.json"
    _merge_progress(str(p), {"stage": "seal", "progress_pct": 94.2, "item": "payload"})
    assert json.loads(p.read_text())["progress_pct"] == 94.2
    _merge_progress(str(p), {"stage": "complete", "item": "done"})
    assert json.loads(p.read_text())["progress_pct"] == 100


def test_export_cli_space_error_is_json_not_traceback(tmp_path, capsys, monkeypatch):
    import app.services.mobile_acquire.export_cli as cli
    import app.services.mobile_acquire.export_packages as ep

    original = tmp_path / "original"
    (original / "ios_image").mkdir(parents=True)
    (original / "ios_image" / "Manifest.db").write_bytes(b"x" * 128)
    exports = tmp_path / "exports"

    def fail(**kwargs):
        raise ep.ExportSpaceError(
            payload_bytes=1000,
            estimated_zip_bytes=900,
            best_free_bytes=500,
            reserve_bytes=100,
            requested_dir=str(exports),
        )

    monkeypatch.setattr(cli, "build_export_packages", fail)
    rc = cli.main(["--original", str(original), "--exports", str(exports)])
    assert rc == 3
    out = capsys.readouterr().out
    payload = json.loads(out.strip().splitlines()[-1])
    assert payload["ok"] is False
    assert payload["error_code"] == "mobile_export_insufficient_space"
    assert "Traceback" not in out
