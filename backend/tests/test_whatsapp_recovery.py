"""Independent wa-crypt-tools 0.1.0 vectors and Android recovery regressions.

The vectors were generated outside the application's encoder using synthetic
SQLite data, fixed test keys/IVs, WhatsApp protobuf schemas and Java key envelopes.
No user data or real encryption secrets are included.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.services.mobile_forensic import whatsapp_crypt as wc
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser

SQLITE_SHA256 = "4fe2e23f4f3e42f4ec03ccb4b743e0650038157088247bbce2a77fc945d6db4e"
VECTORS = {
    "crypt12": (
        "AAECEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiAAECAwQFBgcICQoLDA0ODx/wTaGEqokYjfirErfPhXmS56KCL9iXahvjV/+FvNjOSXwU1q4c8E5xHQfUb0vtbNf1PbqdbEEfp/5v2SOhhnm00CAa+x9wZuZhlRLgw4F+U61dyXKO8ZIKX8XGvGLv1tcWt1CuMKF5AGEnwe1teL7NLuWn833Fxel5E8XX/MuQK1v5QnTLiMVITE3cHID6PUGqMiMip7UvQkBFt0JzzxEqdhIoLK3mfjiAklJIrQ/p2J7wOTH1SzIeXxHc9p/AK2bryChT8GRseIvW3L5NcjaKaa/cC682xELVhgcSNSETeXLSUCzXF7LvPvd2nx8bM2r7TBUEPs6rwGgPswE0gzCsJdMZqYpgIs5CjQw+4Mjo8wAJu+bbwjq1ODju4zR22mYHE3oZvlQVMK41irWAhHM8cTpxdOZuYS0tMTA=",
        "rO0ABXVyAAJbQqzzF/gGCFTgAgAAeHAAAACDAAECEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiPcMPushBf3aUPpwQ4V7qy8huVGo8sCTjaMv6iUYDsmYAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ),
    "crypt14": (
        "aQEIABJNCgIAARIBMhogEREREREREREREREREREREREREREREREREREREREREREiECIiIiIiIiIiIiIiIiIiIiIqEAABAgMEBQYHCAkKCwwNDg8iFgoIMi4yNC4wLjEaAjEwIAAoATABOAEf8E2hhKqJGI34qxK3z4V5kueigi/Yl2ob41f/hbzYzkl8FNauHPBOcR0H1G9L7WzX9T26nWxBH6f+b9kjoYZ5tNAgGvsfcGbmYZUS4MOBflOtXclyjvGSCl/Fxrxi79bXFrdQrjCheQBhJ8HtbXi+zS7lp/N9xcXpeRPF1/zLkCtb+UJ0y4jFSExN3ByA+j1BqjIjIqe1L0JARbdCc88RKnYSKCyt5n44gJJSSK0P6die8Dkx9UsyHl8R3PafwCtm68goU/BkbHiL1ty+TXI2immv3AuvNsRC1YYHEjUhE3ly0lAs1xey7z73dp8fGzNq+0wVBD7Oq8BoD7MBNIMwrCXTGamKYCLOQo0MPuDI6PMACbvm28I6tTg47uM0dtpmBxN6Gb5UFV9P1YkrN0ne8EAXO8O3QGA=",
        "rO0ABXVyAAJbQqzzF/gGCFTgAgAAeHAAAACDAAECEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiPcMPushBf3aUPpwQ4V7qy8huVGo8sCTjaMv6iUYDsmYAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ),
    "crypt15": (
        "LgEIARoSChAAAQIDBAUGBwgJCgsMDQ4PIhYKCDIuMjQuMC4xGgIxMCAAKAEwATgBQnh1/pGCukkBiDfUjBjO7qGp+rVZePbPINEYsKHSU9WVV/neynvdxy78Y77GRYtMir4yLCqBsPQ0kwO+wBfy6cq+BijAJqsmJIducnkuRU86Ord2ui0NMGnk0d63e9oo8PCpjgw78IfVMSAgrGgcbG47ZQAY2Rl1XjsbBSXAKCZzlmNNsBLFyRZ5e9ntkeHArE5x92ZMC9yKD1Ltj+5rlyyp39CmvXwKMC8pUBEFyBAILcGiH3FIlyz88zUpu06GSvGYDswslIopa7Wa11u3YrYZ70WYg3uzRtlq+CJk3lbUf6ayZysJOayKCvc2b9M9jkQ+XmMKbCIwUC4JpDGk/EJ37r4NKvvudagJhuOYpCBEa2JAffxlum5XO1THGO4tuW90evWN3dAnbJrwxVWmMNGWUHQiuzQe",
        "rO0ABXVyAAJbQqzzF/gGCFTgAgAAeHAAAAAgAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    ),
}

def vector(version):
    return tuple(base64.b64decode(value) for value in VECTORS[version])


@pytest.mark.parametrize("version", ["crypt12", "crypt14", "crypt15"])
def test_independent_formats_authenticate_and_parse_chats(version):
    data, key = vector(version)
    plain = wc.try_decrypt_whatsapp_crypt(data, key, path="msgstore.db." + version)
    assert plain and hashlib.sha256(plain).hexdigest() == SQLITE_SHA256
    diag = wc.last_decrypt_diagnostics()
    assert diag["authenticated"] is True and diag["checksum_verified"] is True
    item = InventoryItem(path="WhatsApp/Databases/msgstore.db." + version, size=len(data), sha256=hashlib.sha256(data).hexdigest())
    context = ParseContext(job_id="test", platform="Android", whatsapp_key_candidates=[wc.WhatsAppKeyCandidate(b"wrong".ljust(32, b"!"), "wrong_install/key"), wc.WhatsAppKeyCandidate(key, "right_install/key")], read_bytes=lambda *_a, **_kw: data)
    records = list(WhatsAppParser().parse(item, context))
    backups = [record for record in records if record.artifact_type == "app_backup_encrypted"]
    messages = [record for record in records if record.artifact_type == "app_message"]
    assert len(backups) == 1
    assert backups[0].data["decryption_state"] == "decrypted"
    assert backups[0].data["decrypt_diagnostics"]["key_source"] == "right_install/key"
    assert backups[0].data["decrypt_diagnostics"]["keys_tried"] == 2
    assert any(record.data.get("body") == "independent crypt fixture chat" for record in messages)
    assert all(record.forensic["source_sha256"] == item.sha256 for record in messages)
    assert all(record.forensic["state"] == "backup_historical" for record in messages)
    assert key.hex() not in str(backups[0].data)


@pytest.mark.parametrize("version", ["crypt12", "crypt14", "crypt15"])
@pytest.mark.parametrize("part", ["tag", "checksum", "ciphertext"])
def test_corrupt_evidence_is_never_accepted(version, part):
    data, key = vector(version)
    changed = bytearray(data)
    trailer = 4 if version == "crypt12" else 0
    offset = len(data) - trailer - {"checksum": 1, "tag": 17, "ciphertext": 36}[part]
    changed[offset] ^= 1
    assert wc.try_decrypt_whatsapp_crypt(bytes(changed), key, path="msgstore.db." + version) is None
    assert wc.last_decrypt_diagnostics()["authenticated"] is False


def test_serialized_hex_keys_and_error_files():
    _, device = vector("crypt14")
    _, backup = vector("crypt15")
    assert len(device) == 158 and len(backup) == 59
    assert wc.parse_key_material(device).raw32 == bytes(range(32))
    assert wc.parse_key_material(backup).raw32 == bytes(range(32))
    assert wc.parse_key_material(device[27:]).raw32 == bytes(range(32))
    assert wc.parse_key_material(b"\xef\xbb\xbf" + bytes(range(32)).hex().encode() + b"\r\n").raw32 == bytes(range(32))
    assert wc.parse_key_material(backup[:-1]) is None
    assert wc.parse_key_material(backup[:23] + (900).to_bytes(4, "big") + backup[27:]) is None
    for error in (b"run-as: package not debuggable", b"cat: permission denied", b"error: device unauthorized", b"/system/bin/sh: su: not found"):
        assert wc.parse_key_material(error.ljust(158, b" ")) is None


def test_cryptography_provider_handles_16_byte_iv():
    data, key = vector("crypt14")
    import builtins
    original = builtins.__import__

    def without_crypto(name, *args, **kwargs):
        if name == "Crypto.Cipher":
            raise ImportError("exercise supported fallback")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=without_crypto):
        plain = wc.try_decrypt_whatsapp_crypt(data, key, path="msgstore.db.crypt14")
    assert plain and hashlib.sha256(plain).hexdigest() == SQLITE_SHA256


def test_discovery_checks_every_install_and_does_not_stop_on_intake_key():
    from app.services.mobile_forensic import sqlite_counts as counts

    key_rows = [{"file_path": f"data/user/{n}/com.whatsapp/files/key", "file_name": "key", "size_bytes": 158} for n in range(10)]
    right = vector("crypt14")[1]
    wrong = b"x" * 158
    calls = []

    def read(_db, _job, path, **_kwargs):
        calls.append(path)
        return right if "/9/" in path else wrong

    with patch.object(counts, "fetchone", return_value={"disk_source": {"whatsapp_key_hex": "aa" * 32}}), patch.object(counts, "fetchall", return_value=key_rows), patch.object(counts, "_read_artifact_bytes", side_effect=read):
        candidates = counts.discover_whatsapp_keys(object(), "job")
    assert len(calls) == 10
    assert len(candidates) == 3
    assert wc.decrypt_with_candidates(vector("crypt14")[0], candidates, path="msgstore.db.crypt14")
    assert "/9/" in wc.last_decrypt_diagnostics()["key_source"]


def test_materializer_tries_all_key_formats_per_backup(tmp_path):
    from app.services.mobile_acquire.android_readable import _looks_like_whatsapp_key, _materialize_whatsapp_decrypted

    crypt = []
    keys = []
    for version in ("crypt14", "crypt15"):
        data, key = vector(version)
        source = tmp_path / ("msgstore.db." + version)
        source.write_bytes(data)
        crypt.append(source)
        key_path = tmp_path / ("key" if version == "crypt14" else "encrypted_backup.key")
        key_path.write_bytes(key)
        keys.append(key_path)
    bad = tmp_path / "badkey"
    bad.write_bytes(b"x" * 158)
    missing = tmp_path / "msgstore-bad.db.crypt14"
    missing.write_bytes(b"x" * 160)
    output = {"copied": [], "errors": [], "limitations": []}
    _materialize_whatsapp_decrypted([*crypt, missing], [bad, *keys], tmp_path / "derived", output)
    assert output["whatsapp_decryption_state"] == "partial"
    assert output["whatsapp_decrypt_failed"] == 1
    assert output["whatsapp_decrypted_backups"] == 1  # identical plaintext deduplicated
    assert len(output["whatsapp_backup_results"]) == 3
    database = Path(output["copied"][0]["dest"])
    assert database.name == "msgstore.db"
    assert database.with_suffix(".db.provenance.json").exists()
    assert wc.looks_like_sqlite(database.read_bytes())
    assert _looks_like_whatsapp_key("data/user/10/com.whatsapp.w4b/files/encrypted_backup.key", "encrypted_backup.key", 59)
    assert bytes(range(32)).hex() not in str(output)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_export_multiline_media_and_urls_are_historical(encoding):
    long_body = "message text " * 400
    text = ("01/02/2026, 9:41 AM - Messages are end-to-end encrypted\n"
            "01/02/2026, 9:42 AM - Alice: " + long_body + "\ncontinued line\n"
            "\u200e[01/02/2026, 09:43:00] Bob: IMG-1.jpg (file attached)\n"
            "caption https://example.test/evidence\n"
            "01/02/2026, 9:44 AM - Alice: This message was deleted\n")
    data = text.encode(encoding)
    item = InventoryItem(path="imports/WhatsApp Chat with Team.txt", size=len(data), sha256=hashlib.sha256(data).hexdigest())
    context = ParseContext(job_id="test", platform="Android", read_bytes=lambda *_a, **_kw: data, extra={"evidence_paths": ["imports/IMG-1.jpg"]})
    parser = WhatsAppParser()
    assert parser.supports(item, context)
    records = list(parser.parse(item, context))
    messages = [record for record in records if record.artifact_type == "app_message"]
    assert len(messages) == 4
    assert messages[0].data["system_message"] is True
    assert messages[1].data["body"] == long_body + "\ncontinued line"
    assert messages[1].data["source_line_start"] == 2 and messages[1].data["source_line_end"] == 3
    assert messages[2].data["media_path"] == "imports/IMG-1.jpg"
    assert messages[2].data["url_references"] == ["https://example.test/evidence"]
    assert all(record.forensic["state"] == "historical" for record in records)
    assert all(record.timestamp_utc is None for record in messages)
    assert all(record.data["export_complete_history"] is False for record in messages)


def test_export_missing_and_ambiguous_media_are_not_invented():
    data = b"01/02/2026, 09:42 - Alice: missing.opus (file attached)\n01/02/2026, 09:43 - Alice: same.pdf (file attached)"
    item = InventoryItem(path="imports/WhatsApp/_chat.txt", size=len(data))
    context = ParseContext(job_id="j", platform="Android", read_bytes=lambda *_a, **_kw: data, extra={"evidence_paths": ["a/same.pdf", "b/same.pdf"]})
    messages = [record for record in WhatsAppParser().parse(item, context) if record.artifact_type == "app_message"]
    assert messages[0].data["media_available"] is False
    assert messages[0].data["has_attachment"] is True
    assert messages[1].data["media_path"] is None and len(messages[1].data["media_candidates"]) == 2


def _fake_adb(tmp_path, payload, code=0):
    # The executable checks the remote shell command's quoting, then streams
    # controlled bytes. Exercises the actual subprocess/binary/atomic-write path.
    path = tmp_path / "adb"
    path.write_text("#!/usr/bin/env python3\nimport sys,shlex,base64\n"
                    "args=shlex.split(sys.argv[-1])\n"
                    "assert args[:2] == ['su','-c'] and len(args)==3, args\n"
                    "assert shlex.split(args[2])[0]=='cat'\n"
                    f"sys.stdout.buffer.write(base64.b64decode('{base64.b64encode(payload).decode()}'))\n"
                    f"sys.exit({code})\n")
    path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize("kind", ["good", "stdout_error", "failed_command"])
def test_binary_adb_keys_are_exit_checked_and_validated(tmp_path, kind):
    from app.services.mobile_acquire.privileged_app_pull import _cat_file

    payload = b"run-as: package not debuggable".ljust(158, b" ") if kind == "stdout_error" else vector("crypt14")[1]
    adb = _fake_adb(tmp_path, payload, code=1 if kind == "failed_command" else 0)
    dest = tmp_path / "evidence" / "key"
    ok, _ = _cat_file(adb, "serial", "su", "/data/user/10/com.whatsapp/files/key", dest)
    assert ok == (kind == "good")
    assert dest.exists() == ok
    if ok:
        assert dest.read_bytes() == payload
    assert not list(dest.parent.glob(".acquire-*"))


def test_existing_root_collects_other_android_users_and_business(tmp_path):
    from app.services.mobile_acquire import privileged_app_pull as pull

    captured = []

    def cat(_adb, _serial, _mode, remote, dest):
        captured.append(remote)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(vector("crypt14")[1])
        return True, ""

    with patch.object(pull, "_root_mode", return_value="su"), patch.object(pull, "_android_users", return_value=[0, 10]), patch.object(pull, "_remote_exists", side_effect=lambda _a, _s, _m, root: root.startswith('/data/user/') and ("/files/" not in root or root.endswith('/files/key'))), patch.object(pull, "_list_files", side_effect=lambda _a, _s, _m, root: [root + '/files/key']), patch.object(pull, "_cat_file", side_effect=cat):
        result = pull.pull_private_evidence(adb="adb", serial="s", out=tmp_path, packages=["com.whatsapp", "com.whatsapp.w4b"], include_system=False)
    assert result["files"] == 4
    assert any("/10/com.whatsapp/" in path for path in captured)
    assert any("/10/com.whatsapp.w4b/" in path for path in captured)
    assert result["android_users"] == [0, 10]


def test_denied_run_as_never_attempts_or_creates_key(tmp_path):
    from app.services.mobile_acquire import privileged_app_pull as pull

    with patch.object(pull, "_run", return_value=SimpleNamespace(returncode=1, stdout="run-as: package not debuggable")), patch.object(pull, "_cat_file") as reader:
        result = pull.pull_debuggable_evidence(adb="adb", serial="s", out=tmp_path)
    assert result["files"] == 0 and len(result["limitations"]) == 2
    reader.assert_not_called()
    assert not list(tmp_path.rglob("key"))


def test_unknown_text_files_are_not_claimed_as_chat_exports():
    from app.services.mobile_forensic.parsers.whatsapp_export import is_whatsapp_export_path

    assert not is_whatsapp_export_path("Documents/notes.txt")
    assert not is_whatsapp_export_path("WhatsApp/Media/a.apk")
    assert is_whatsapp_export_path("WhatsApp Chat with Alice.txt")


def test_matching_key_updates_existing_backup_status_identity():
    data, key = vector("crypt14")
    item = InventoryItem(path="WhatsApp/msgstore.db.crypt14", size=len(data), sha256=hashlib.sha256(data).hexdigest())
    missing = ParseContext(job_id="j", platform="Android", read_bytes=lambda *_a, **_kw: data)
    supplied = ParseContext(job_id="j", platform="Android", whatsapp_key_candidates=[wc.WhatsAppKeyCandidate(key, "collected/key")], read_bytes=lambda *_a, **_kw: data)
    before = next(WhatsAppParser().parse(item, missing))
    after = next(WhatsAppParser().parse(item, supplied))
    assert before.artifact_id == after.artifact_id
    assert before.data["decryption_state"] == "blocked" and after.data["decryption_state"] == "decrypted"


def test_partial_source_read_is_distinguished_from_wrong_key():
    data, key = vector("crypt14")
    assert wc.decrypt_with_candidates(data[:-40], [wc.WhatsAppKeyCandidate(key)], path="msgstore.db.crypt14", expected_size=len(data)) is None
    assert wc.last_decrypt_diagnostics()["reason"] == "source_read_incomplete"


def test_unavailable_crypto_provider_is_distinguished_from_wrong_key():
    data, key = vector("crypt14")
    with patch.object(wc, "_aes_provider_available", return_value=False):
        assert wc.try_decrypt_whatsapp_crypt(data, key, path="msgstore.db.crypt14") is None
    assert wc.last_decrypt_diagnostics()["reason"] == "aes_provider_unavailable"


def test_residuals_are_uncertain_and_no_longer_capped_at_20000():
    from app.services.mobile_forensic.parsers.whatsapp_modern import iter_freelist_residuals

    item = InventoryItem(path="WhatsApp/msgstore.db.crypt14", size=1, sha256="source")
    context = ParseContext(job_id="j", platform="Android")
    values = [{"text": f"residual evidence {number}", "offset": number, "byte_length": 30, "page_number": 2, "source_kind": "freelist_leaf", "source_component": "main"} for number in range(20001)]
    with patch("app.services.mobile_acquire.sqlite_deleted.iter_sqlite_residuals_bytes", return_value=iter(values)):
        records = list(iter_freelist_residuals(b"sqlite", item, context))
    assert len(records) == 20001
    assert all(record.forensic["state"] == "freelist_candidate" for record in records)
    assert all(record.forensic["confidence"]["label"] == "LOW" for record in records)


def _deleted_sqlite_fixture(path, *, secure_delete=False):
    import sqlite3

    with sqlite3.connect(path) as db:
        db.execute("PRAGMA page_size=512")
        db.execute("PRAGMA secure_delete=" + ("ON" if secure_delete else "OFF"))
        db.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, data TEXT)")
        db.executemany("INSERT INTO messages VALUES (?, ?, ?)", [(n, "919876543210@s.whatsapp.net", f"Retained deleted evidence number {n:04d} " + "chat content " * 14) for n in range(100)])
        db.commit()
        db.execute("DELETE FROM messages")
    return path.read_bytes()


def test_real_sqlite_leaf_pages_recover_candidates_with_exact_offsets(tmp_path):
    from app.services.mobile_acquire.sqlite_deleted import iter_sqlite_residuals_bytes, recover_sqlite_residuals
    from app.services.mobile_forensic.parsers.whatsapp_modern import iter_freelist_residuals

    path = tmp_path / "msgstore.db"
    plain = _deleted_sqlite_fixture(path)
    residuals = list(iter_sqlite_residuals_bytes(plain))
    assert len(residuals) > 50
    assert any(row["source_kind"] == "freelist_leaf" for row in residuals)
    for row in residuals:
        assert plain[row["offset"]:row["offset"] + row["byte_length"]] == row["text"].encode()
    item = InventoryItem(path="WhatsApp/Databases/msgstore.db.crypt14", size=1, sha256="ciphertext-source")
    context = ParseContext(job_id="j", platform="Android")
    records = list(iter_freelist_residuals(plain, item, context))
    assert len(records) == len(residuals)
    assert all(row.forensic["state"] == "freelist_candidate" and row.data["deleted_flag"] is None for row in records)
    assert all(row.data["decrypted_sqlite_sha256"] == hashlib.sha256(plain).hexdigest() for row in records)
    assert all(row.forensic["source_sha256"] == "ciphertext-source" for row in records)
    assert recover_sqlite_residuals(path, tmp_path / "derived")["chat_like_residuals"] > 50


def test_erased_sqlite_leaf_pages_do_not_invent_deleted_content(tmp_path):
    from app.services.mobile_acquire.sqlite_deleted import iter_sqlite_residuals_bytes

    plain = _deleted_sqlite_fixture(tmp_path / "erased.db", secure_delete=True)
    assert list(iter_sqlite_residuals_bytes(plain)) == []


def test_authenticated_backup_parser_actually_recovers_deleted_leaf_text(tmp_path):
    plain = _deleted_sqlite_fixture(tmp_path / "deleted.db")
    key = bytes(range(32))
    crypt = wc._encrypt_fixture(plain, wc.parse_key_material(key), container="crypt14", iv=bytes(range(16)))
    item = InventoryItem(path="WhatsApp/Databases/msgstore.db.crypt14", size=len(crypt), sha256=hashlib.sha256(crypt).hexdigest())
    context = ParseContext(job_id="j", platform="Android", whatsapp_key_candidates=[wc.WhatsAppKeyCandidate(key, "key")], read_bytes=lambda *_a, **_kw: crypt)
    records = list(WhatsAppParser().parse(item, context))
    assert records[0].data["decrypt_diagnostics"]["authenticated"] is True
    candidates = [row for row in records if row.forensic["state"] == "freelist_candidate"]
    assert len(candidates) > 50
    assert any("Retained deleted evidence" in row.data["body"] for row in candidates)
    for row in candidates:
        start = row.data["residual_offset"]
        assert plain[start:start + row.data["residual_byte_length"]] == row.data["body"].encode()


def test_residual_body_is_complete_and_date_is_not_deletion_time(tmp_path):
    import json
    import sqlite3
    from app.services.mobile_acquire.sqlite_deleted import recover_sqlite_residuals

    path = tmp_path / "msgstore.db"
    body = "Retained evidence on 2026-02-01 10:12:13 " + "all retained text " * 65
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA secure_delete=OFF")
        db.execute("CREATE TABLE messages (body TEXT)")
        db.executemany("INSERT INTO messages VALUES (?)", [(body,) for _ in range(30)])
        db.commit()
        db.execute("DELETE FROM messages")
    result = recover_sqlite_residuals(path, tmp_path / "derived")
    items = json.loads(Path(result["structured_output"]).read_text())["items"]
    row = next(row for row in items if body.rstrip() in row["body"])
    assert len(row["body"]) > 800
    assert row["deleted_at"] is None and row["retained_time_text"] == "2026-02-01 10:12:13"


def test_corrupt_freelist_cycle_is_bounded_and_does_not_scan_live_pages(tmp_path):
    from app.services.mobile_acquire.sqlite_deleted import iter_sqlite_residuals_bytes

    plain = bytearray(_deleted_sqlite_fixture(tmp_path / "cycle.db"))
    trunk = int.from_bytes(plain[32:36], "big")
    offset = (trunk - 1) * 512
    plain[offset:offset + 4] = trunk.to_bytes(4, "big")
    assert 50 < len(list(iter_sqlite_residuals_bytes(bytes(plain)))) < 110
    plain[offset + 4:offset + 8] = (1000).to_bytes(4, "big")
    assert list(iter_sqlite_residuals_bytes(bytes(plain))) == []


def test_export_bodies_are_complete_in_rag_text():
    from app.services.mobile_forensic.mobile_rag import artifact_to_rag_text

    body = "all retained text " * 500
    text = ("01/02/2026, 09:42 - Alice: " + body).encode()
    item = InventoryItem(path="WhatsApp Chat with Alice.txt", size=len(text))
    context = ParseContext(job_id="j", platform="Android", read_bytes=lambda *_a, **_kw: text)
    message = next(record for record in WhatsAppParser().parse(item, context) if record.artifact_type == "app_message")
    rag = artifact_to_rag_text(message.to_dict())
    assert body in rag and "owner_chat_export" in rag and item.path in rag


def test_nul_filenames_and_remote_command_quoting():
    from app.services.mobile_acquire import privileged_app_pull as pull

    root = "/data/user/10/com.whatsapp"
    name = root + "/files/evidence space\nहिन्दी.pdf"
    with patch.object(pull, "_run", return_value=SimpleNamespace(stdout=(name + "\0/outside/path\0").encode(), returncode=0)) as runner:
        assert pull._list_files("adb", "device", "su", root) == [name]
    import shlex

    args = runner.call_args.args[0]
    remote = shlex.split(args[-1])
    assert remote[0:2] == ["su", "-c"] and len(remote) == 3
    assert "-print0" in remote[-1]


def test_reprocess_endpoint_restarts_idle_serial_pipeline(monkeypatch):
    from app.routers import jobs
    from app.services import forensic_serial_pipeline as serial
    from app.services import forensic_serial_policy as policy
    import sys

    monkeypatch.setitem(sys.modules, "app.tasks", SimpleNamespace(mobile_analysis_task=SimpleNamespace(delay=lambda *_args: pytest.fail("legacy task must not be used for serial reprocessing"))))
    monkeypatch.setattr(jobs, "_ensure_job", lambda *_args: None)
    monkeypatch.setattr(policy, "serial_enabled", lambda: True)
    monkeypatch.setattr(serial, "ensure_serial_schema", lambda _db: None)
    monkeypatch.setattr(serial, "stage_rows", lambda *_args: [{"status": "done"}])
    with patch.object(serial, "start_serial_pipeline", return_value={"status": "queued"}) as start:
        result = jobs.mobile_analysis_run("j", db=object(), current=SimpleNamespace(schema_name="firm_test"))
    assert result["status"] == "queued"
    assert start.call_args.kwargs["reprocess"] is True


def test_reprocess_endpoint_protects_running_work(monkeypatch):
    from app.routers import jobs
    from app.services import forensic_serial_pipeline as serial
    from app.services import forensic_serial_policy as policy
    from fastapi import HTTPException
    import sys

    monkeypatch.setitem(sys.modules, "app.tasks", SimpleNamespace(mobile_analysis_task=SimpleNamespace(delay=lambda *_args: None)))
    monkeypatch.setattr(jobs, "_ensure_job", lambda *_args: None)
    monkeypatch.setattr(policy, "serial_enabled", lambda: True)
    monkeypatch.setattr(serial, "ensure_serial_schema", lambda _db: None)
    monkeypatch.setattr(serial, "stage_rows", lambda *_args: [{"status": "running"}])
    with patch.object(serial, "start_serial_pipeline") as start, pytest.raises(HTTPException) as error:
        jobs.mobile_analysis_run("j", db=object(), current=SimpleNamespace(schema_name="firm_test"))
    assert error.value.status_code == 409
    start.assert_not_called()


def test_invalid_intake_key_is_rejected_before_saving(monkeypatch):
    from app.routers import report
    from fastapi import HTTPException

    with patch.object(report, "execute") as execute, pytest.raises(HTTPException) as error:
        report.patch_intake("j", {"forensic_keys": {"whatsapp_key_hex": "run-as: package not debuggable"}}, db=object(), current=SimpleNamespace(schema_name="firm_test"))
    assert error.value.status_code == 400
    execute.assert_not_called()
