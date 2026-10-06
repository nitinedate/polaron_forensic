"""Native Cellebrite .ufd → FileDump.zip inventory (AXIOM/PA layout)."""

from __future__ import annotations

import sqlite3
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.services.mobile_forensic.cellebrite_ufed import (
    is_native_cellebrite_pas,
    parse_ufd_text,
    resolve_ufd_dump_zip,
    resolve_ufdx_referenced_paths,
)
from app.services.mobile_forensic.package_inventory import (
    _discover_dump_targets,
    _scan_dump_zip,
    collect_portable_package_inventory,
    is_portable_zip_archive,
)


def _msgstore_bytes() -> bytes:
    path = Path(tempfile.mkstemp(suffix=".db")[1])
    try:
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE message (id INTEGER PRIMARY KEY, text TEXT)")
        cur.executemany("INSERT INTO message(text) VALUES (?)", [("a",), ("b",)])
        cur.execute("CREATE TABLE chat (id INTEGER PRIMARY KEY, jid TEXT)")
        cur.execute("INSERT INTO chat(jid) VALUES ('x@s.whatsapp.net')")
        cur.execute("CREATE TABLE call_log (id INTEGER PRIMARY KEY)")
        cur.execute("INSERT INTO call_log DEFAULT VALUES")
        cur.execute("CREATE TABLE jid (id INTEGER PRIMARY KEY, raw_string TEXT)")
        cur.executemany("INSERT INTO jid(raw_string) VALUES (?)", [("a@s.whatsapp.net",), ("b@s.whatsapp.net",)])
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def test_parse_ufd_filedump(tmp_path: Path) -> None:
    ufd = tmp_path / "vivo_V2403.ufd"
    ufd.write_text(
        "[DeviceInfo]\r\nChipset=MT6878\r\nModel=V2403\r\nVendor=vivo\r\n"
        "[Dumps]\r\nFileDump=vivo_V2403.zip\r\nKeyStore=vivo_V2403.zip\r\n"
        "[FileDump]\r\nType=ZIPfolder\r\nZIPLogicalPath=Dump\r\n",
        encoding="utf-8",
    )
    dump = tmp_path / "vivo_V2403.zip"
    with zipfile.ZipFile(dump, "w") as zf:
        zf.writestr("Dump/data/data/com.whatsapp/databases/msgstore.db", _msgstore_bytes())
        zf.writestr("Dump/DCIM/a.jpg", b"\xff\xd8\xff\xd9")

    resolved = resolve_ufd_dump_zip(ufd)
    assert resolved is not None
    zpath, prefix = resolved
    assert zpath.name == "vivo_V2403.zip"
    assert prefix == "Dump"
    assert not is_portable_zip_archive(ufd)
    assert is_portable_zip_archive(dump)


def test_native_pas_not_zip(tmp_path: Path) -> None:
    pas = tmp_path / "case.pas"
    pas.write_bytes(b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00Logic, Version=7.61.0.12")
    assert is_native_cellebrite_pas(pas)
    assert not is_portable_zip_archive(pas)


def test_collect_inventory_from_ufed_layout(tmp_path: Path) -> None:
    ufd = tmp_path / "vivo_V2403.ufd"
    ufd.write_text(
        "[DeviceInfo]\r\nModel=V2403\r\nVendor=vivo\r\n"
        "[Dumps]\r\nFileDump=vivo_V2403.zip\r\n"
        "[FileDump]\r\nType=ZIPfolder\r\nZIPLogicalPath=Dump\r\n",
        encoding="utf-8",
    )
    apps = tmp_path / "InstalledAppsList.txt"
    apps.write_text("com.whatsapp\ncom.android.mms\n", encoding="utf-8")
    dump = tmp_path / "vivo_V2403.zip"
    with zipfile.ZipFile(dump, "w") as zf:
        zf.writestr("Dump/data/data/com.whatsapp/databases/msgstore.db", _msgstore_bytes())
        zf.writestr(
            "Dump/data/data/com.android.providers.telephony/databases/mmssms.db",
            _sms_bytes(),
        )
        zf.writestr("Dump/DCIM/Camera/x.jpg", b"\xff\xd8\xff\xd9")

    paths = [
        {"host_path": str(ufd), "original_name": ufd.name, "size_bytes": ufd.stat().st_size},
        {"host_path": str(dump), "original_name": dump.name, "size_bytes": dump.stat().st_size},
        {"host_path": str(apps), "original_name": apps.name, "size_bytes": apps.stat().st_size},
    ]
    db = MagicMock()
    with patch("app.services.mobile_forensic.package_inventory.fetchall", return_value=paths), patch(
        "app.services.mobile_forensic.package_inventory._resolve_path",
        side_effect=lambda raw: Path(raw) if Path(raw).exists() else None,
    ):
        out = collect_portable_package_inventory(db, "job-ufed")

    assert out["counts"]["whatsapp_messages"] == 2
    assert out["counts"]["whatsapp_chats"] >= 1
    assert out["counts"]["sms"] >= 1
    assert out["counts"]["pictures"] >= 1
    assert out["counts"]["installed_apps"] >= 2
    assert out["total_files"] >= 3


def _sms_bytes() -> bytes:
    path = Path(tempfile.mkstemp(suffix=".db")[1])
    try:
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()
        cur.execute("CREATE TABLE sms (_id INTEGER PRIMARY KEY, body TEXT)")
        cur.executemany("INSERT INTO sms(body) VALUES (?)", [("hi",), ("yo",), ("bye",)])
        conn.commit()
        conn.close()
        return path.read_bytes()
    finally:
        path.unlink(missing_ok=True)


def test_parse_ufd_text_device() -> None:
    desc = parse_ufd_text(
        "[DeviceInfo]\nVendor=vivo\nModel=V2403\n[Dumps]\nFileDump=x.zip\n[FileDump]\nZIPLogicalPath=Dump\n"
    )
    assert desc.device_info["Model"] == "V2403"
    assert desc.dump_zip_name == "x.zip"
    assert desc.zip_logical_path == "Dump"


def test_ufd_windows_absolute_path_resolves_portable_companion(tmp_path: Path) -> None:
    dump = tmp_path / "vivo_V2403.zip"
    with zipfile.ZipFile(dump, "w") as zf:
        zf.writestr("Dump/readme.txt", b"ok")
    ufd = tmp_path / "vivo_V2403.ufd"
    ufd.write_text(
        '[DeviceInfo]\nModel=V2403\n[Dumps]\nFileDump="D:\\Cases\\Case-1\\vivo_V2403.zip"\n'
        '[FileDump]\nZIPLogicalPath=Dump\n',
        encoding="utf-8",
    )
    resolved = resolve_ufd_dump_zip(ufd)
    assert resolved is not None
    assert resolved[0] == dump
    assert resolved[1] == "Dump"


def test_ufdx_foreign_absolute_reference_stays_inside_evidence_folder(tmp_path: Path) -> None:
    ufd = tmp_path / "case.ufd"
    ufd.write_text("[DeviceInfo]\nModel=Test\n", encoding="utf-8")
    ufdx = tmp_path / "case.ufdx"
    ufdx.write_text(
        '<?xml version="1.0"?><Project><Extraction Path="C:\\Examiner\\case.ufd"/></Project>',
        encoding="utf-8",
    )
    refs = resolve_ufdx_referenced_paths(ufdx)
    assert refs == [ufd]


def test_ufdx_only_registration_follows_ufd_to_filedump_zip(tmp_path: Path) -> None:
    dump = tmp_path / "FileDump.zip"
    with zipfile.ZipFile(dump, "w") as zf:
        zf.writestr("Dump/data/data/com.whatsapp/databases/msgstore.db", _msgstore_bytes())
    ufd = tmp_path / "case.ufd"
    ufd.write_text(
        "[DeviceInfo]\nModel=Test\n[Dumps]\nFileDump=FileDump.zip\n"
        "[FileDump]\nZIPLogicalPath=Dump\n",
        encoding="utf-8",
    )
    ufdx = tmp_path / "case.ufdx"
    ufdx.write_text(
        '<?xml version="1.0"?><Project><Extraction Path="case.ufd"/></Project>',
        encoding="utf-8",
    )
    targets = _discover_dump_targets([ufdx])
    assert targets == [(dump, "Dump")]


def test_package_inventory_decrypts_whatsapp_msgstore_with_same_evidence_key(
    tmp_path: Path, monkeypatch
) -> None:
    archive = tmp_path / "mobile.zip"
    keyfile = b"K" * 30 + bytes(range(32)) + b"X" * 96
    encrypted = b"not-a-real-crypt-container"
    plain = _msgstore_bytes()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("Dump/data/data/com.whatsapp/files/key", keyfile)
        zf.writestr("Dump/WhatsApp/Databases/msgstore.db.crypt14", encrypted)
        # A media/theme sidecar is not a chat backup.
        zf.writestr("Dump/WhatsApp/Backups/theme.webp.crypt14", b"theme")

    def fake_decrypt(data: bytes, key: bytes | str | None) -> bytes | None:
        assert data == encrypted
        assert key == bytes(range(32))
        return plain

    monkeypatch.setattr(
        "app.services.mobile_forensic.whatsapp_crypt.try_decrypt_whatsapp_crypt",
        fake_decrypt,
    )
    out = _scan_dump_zip(archive, logical_prefix="Dump")
    assert out["counts"]["whatsapp_encrypted_backups"] == 1
    assert out["counts"]["whatsapp_messages"] == 2
    assert any("#decrypted" in p for p in out["db_paths"]["whatsapp"])
    assert not any("no usable same-device" in x.lower() for x in out["limitations"])


def test_package_inventory_does_not_infer_encrypted_chat_without_key(tmp_path: Path) -> None:
    archive = tmp_path / "mobile-no-key.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("Dump/WhatsApp/Databases/msgstore.db.crypt14", b"encrypted")
    out = _scan_dump_zip(archive, logical_prefix="Dump")
    assert out["counts"]["whatsapp_encrypted_backups"] == 1
    assert out["counts"]["whatsapp_messages"] == 0
    assert any("no usable same-device whatsapp key" in x.lower() for x in out["limitations"])
