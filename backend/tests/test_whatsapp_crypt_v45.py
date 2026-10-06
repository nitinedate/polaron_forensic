"""V45 WhatsApp crypt tests — run with: pytest tests/test_whatsapp_crypt_v45.py -q"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from app.services.mobile_forensic import whatsapp_crypt as wc


def _sqlite_fixture() -> bytes:
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "msgstore.db")
        conn = sqlite3.connect(p)
        conn.execute("CREATE TABLE message(_id INTEGER PRIMARY KEY, chat_row_id INT, text_data TEXT, message_type INT)")
        conn.executemany(
            "INSERT INTO message(chat_row_id, text_data, message_type) VALUES (?,?,?)",
            [(1, "hello", 0), (1, None, 15), (2, "evidence line", 0)],
        )
        conn.commit()
        conn.close()
        return open(p, "rb").read()


def _keyfile158(key32: bytes, t1: bytes) -> bytes:
    kf = bytearray(os.urandom(wc.KEYFILE_LEN))
    kf[wc.KEYFILE_T1_OFFSET : wc.KEYFILE_T1_OFFSET + 32] = t1
    kf[wc.KEYFILE_KEY_OFFSET :] = key32
    return bytes(kf)


@pytest.fixture(scope="module")
def sqlite_bytes() -> bytes:
    return _sqlite_fixture()


def test_keyfile_offset_is_last_32_bytes():
    key32 = os.urandom(32)
    km = wc.parse_key_material(_keyfile158(key32, b"\x11" * 32))
    assert km is not None and km.kind == "keyfile158"
    assert km.raw32 == key32
    assert km.t1 == b"\x11" * 32


def test_hex64_and_raw32():
    key32 = os.urandom(32)
    assert wc.parse_key_material(key32.hex()).raw32 == key32
    assert wc.parse_key_material(" ".join(key32.hex()[i : i + 8] for i in range(0, 64, 8))).raw32 == key32
    assert wc.parse_key_material(key32).kind == "raw32"
    assert wc.parse_key_material(b"run-as: package not debuggable") is None
    assert wc.parse_key_material("not-hex") is None


def test_crypt15_hkdf_is_deterministic():
    km = wc.KeyMaterial("raw32", b"\x01" * 32)
    k1 = km.key_crypt15
    assert len(k1) == 32 and k1 != km.raw32
    assert k1 == wc.KeyMaterial("hex64", b"\x01" * 32).key_crypt15


@pytest.mark.parametrize("container", ["crypt12", "crypt14", "crypt15"])
def test_round_trip(sqlite_bytes: bytes, container: str):
    key32 = os.urandom(32)
    t1 = os.urandom(32)
    if container == "crypt15":
        km = wc.parse_key_material(key32.hex())      # examiner typed the 64-digit key
        key_in = key32.hex()
    else:
        km = wc.parse_key_material(_keyfile158(key32, t1))
        key_in = _keyfile158(key32, t1)
    blob = wc._encrypt_fixture(sqlite_bytes, km, container=container, iv=os.urandom(16))
    out = wc.try_decrypt_whatsapp_crypt(blob, key_in, path=f"msgstore.db.{container}")
    assert out is not None and out[:16] == wc.SQLITE_MAGIC
    assert out == sqlite_bytes
    diag = wc.last_decrypt_diagnostics()
    assert diag["container"] == container and diag["strategy"]


def test_wrong_key_fails_closed(sqlite_bytes: bytes):
    km = wc.parse_key_material(_keyfile158(os.urandom(32), os.urandom(32)))
    blob = wc._encrypt_fixture(sqlite_bytes, km, container="crypt14", iv=os.urandom(16))
    assert wc.try_decrypt_whatsapp_crypt(blob, os.urandom(32), path="msgstore.db.crypt14") is None
    diag = wc.last_decrypt_diagnostics()
    assert diag["reason"] == "key_mismatch_or_damaged_backup"
    assert diag["candidates_tried"] > 0


def test_crypt15_with_keyfile_explains_gap(sqlite_bytes: bytes):
    km = wc.parse_key_material(os.urandom(32).hex())
    blob = wc._encrypt_fixture(sqlite_bytes, km, container="crypt15", iv=os.urandom(16))
    assert wc.try_decrypt_whatsapp_crypt(blob, _keyfile158(os.urandom(32), os.urandom(32)), path="x.crypt15") is None
    assert any("encrypted_backup.key" in n for n in wc.last_decrypt_diagnostics()["notes"])


def test_plaintext_passthrough(sqlite_bytes: bytes):
    assert wc.try_decrypt_whatsapp_crypt(sqlite_bytes, None) == sqlite_bytes
