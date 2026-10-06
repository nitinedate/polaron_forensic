"""Synthetic backup fixtures encoded independently of the application decoder.

These fixed QA keys are public test data. They cannot open anyone's real backup.
Encoding uses cryptography's AES/HKDF, not whatsapp_crypt._encrypt_fixture.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import sqlite3
import tempfile
import zipfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEVICE_SECRET = bytes(range(32))
BACKUP_SECRET = bytes(range(32, 64))
LEGACY_ACCOUNT = "whatsapp-qa@example.test"
IV = bytes(range(16))
T1 = b"\x11" * 32
KEYFILE = bytes(30) + T1 + bytes(64) + DEVICE_SECRET
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aO4kAAAAASUVORK5CYII=")


def sqlite_fixture() -> bytes:
    with tempfile.TemporaryDirectory(prefix="whatsapp_qa_") as temporary:
        path = Path(temporary) / "msgstore.db"
        con = sqlite3.connect(path)
        con.execute("""CREATE TABLE messages(_id INTEGER PRIMARY KEY,key_remote_jid TEXT,
            key_from_me INTEGER,data TEXT,timestamp INTEGER,media_name TEXT,media_url TEXT,
            media_mime_type TEXT,is_deleted INTEGER)""")
        con.executemany("INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?)", [
            (1, "qa@example.test", 0, "Synthetic CRYPT14 QA message https://example.test/qa", 1760000000000, None, None, None, 0),
            (2, "qa@example.test", 1, "Synthetic attachment", 1760000001000, "fixture.png", "WhatsApp/Media/fixture.png", "image/png", 0),
            (3, "qa@example.test", 0, "Synthetic surviving deleted row", 1760000002000, None, None, None, 1),
        ])
        con.commit()
        con.close()
        return path.read_bytes()


def _field(number: int, value: bytes) -> bytes:
    assert len(value) < 128 and number < 16
    return bytes([(number << 3) | 2, len(value)]) + value


def modern_backup(payload: bytes, version: str, *, compressed=True) -> bytes:
    body = zlib.compress(payload, 9) if compressed else payload
    secret = DEVICE_SECRET
    if version in {"crypt9", "crypt10", "crypt11"}:
        body = gzip.compress(payload, mtime=0) if compressed else payload
        prefix = bytes(51) + IV
    elif version == "crypt12":
        prefix = b"\x00\x01\x02" + T1 + b"\x22" * 16 + IV
    elif version == "crypt14":
        crypto = _field(1, b"\x00\x01") + _field(2, b"3") + _field(3, T1) + _field(4, b"\x22" * 16) + _field(5, IV)
        header = b"\x08\x00" + _field(2, crypto)
        prefix = bytes([len(header)]) + b"\x01" + header
    elif version == "crypt15":
        secret = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"backup encryption").derive(BACKUP_SECRET)
        header = b"\x08\x01" + _field(3, _field(1, IV))
        prefix = bytes([len(header)]) + b"\x01" + header
    else:
        raise ValueError(version)
    enc = Cipher(algorithms.AES(secret), modes.GCM(IV)).encryptor()
    encrypted = enc.update(body) + enc.finalize()
    output = prefix + encrypted + enc.tag
    if version in {"crypt9", "crypt10", "crypt11"}:
        return output
    output += hashlib.md5(output).digest()
    return output + (b"\x00\x00\x00\x00" if version == "crypt12" else b"")


def legacy_backup(payload: bytes, version: str) -> bytes:
    body = gzip.compress(payload, mtime=0) if version == "crypt8" else payload
    padder = padding.PKCS7(128).padder()
    body = padder.update(body) + padder.finalize()
    if version == "crypt":
        key, iv, prefix = b"4j#e*F9+Ms%|g1~5.3rH!we,", None, b""
    elif version == "crypt5":
        seed = hashlib.md5(LEGACY_ACCOUNT.encode()).digest()
        base = bytes.fromhex("8d4b155cc9ff81e5cbf6fa7819366a3ec621a656416cd793")
        key = bytes(value ^ seed[index % 16] for index, value in enumerate(base))
        iv = bytes.fromhex("1e39f369e90db33aa73b442bbbb6b0b9")
        prefix = b""
    elif version in {"crypt7", "crypt8"}:
        key, iv = DEVICE_SECRET, IV
        prefix = b"\x00\x01\x02" + T1 + b"\x22" * 16 + iv
    else:
        raise ValueError(version)
    enc = Cipher(algorithms.AES(key), modes.ECB() if version == "crypt" else modes.CBC(iv)).encryptor()
    return prefix + enc.update(body) + enc.finalize()


def zip_fixture() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("messages.json", json.dumps({"messages": [
            {"type": "message", "sender": "QA", "conversation_id": "fixture", "body": "Synthetic incremental JSON message"}
        ]}))
        archive.writestr("fixture.png", PNG)
        archive.writestr("fixture.eml", "From: qa@example.test\nTo: examiner@example.test\nSubject: Synthetic test\n\nFixture email body.\n")
    return buffer.getvalue()


def build_fixtures(root: Path) -> dict:
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        raise ValueError("Fixture directory must be empty; existing files are never overwritten")
    root.mkdir(parents=True, exist_ok=True)
    files = {}
    database = sqlite_fixture()
    for version in ("crypt", "crypt5", "crypt7", "crypt8", "crypt9", "crypt10", "crypt11", "crypt12", "crypt14", "crypt15"):
        name = "WhatsApp/Databases/msgstore.db." + version
        files[name] = legacy_backup(database, version) if version in {"crypt", "crypt5", "crypt7", "crypt8"} else modern_backup(database, version)
    files.update({
        "data/data/com.whatsapp/files/key": KEYFILE,
        "data/data/com.whatsapp/files/encrypted_backup.key": BACKUP_SECRET,
        "WhatsApp/Backups/settings.json.crypt14": modern_backup(b'{"fixture":true,"label":"Synthetic settings"}', "crypt14", compressed=False),
        "WhatsApp/Backups/msgstore-increment.crypt15": modern_backup(zip_fixture(), "crypt15"),
        "WhatsApp/Backups/fixture.png.crypt15": modern_backup(PNG, "crypt15", compressed=False),
        "WhatsApp/Backups/fixture.bin.crypt12": modern_backup(b"\x00\x01Synthetic binary evidence\x00\xfe", "crypt12", compressed=False),
    })
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
    manifest = {"synthetic_test_data": True, "keys_are_public_qa_fixtures": True,
                "key_can_be_extracted_from_ciphertext": False, "legacy_account": LEGACY_ACCOUNT,
                "expected_key_offset": [126, 158], "expected_key_hex": DEVICE_SECRET.hex(),
                "expected_sqlite_sha256": hashlib.sha256(database).hexdigest(),
                "files_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    (root / "SYNTHETIC-FIXTURE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
