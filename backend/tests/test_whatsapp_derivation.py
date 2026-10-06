"""Regression coverage for the finalized-source working-copy boundary."""
from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

import pytest

from app.services.mobile_forensic.whatsapp_derivation import DERIVATION_VERSION, read_registered_derivation


@pytest.fixture
def registered(tmp_path):
    job = "qa-job"
    body = b'{"fixture":"derived evidence"}'
    path = "derived/whatsapp_decrypted/source/payload/settings.json"
    file = tmp_path / "jobs" / job / path
    file.parent.mkdir(parents=True)
    file.write_bytes(body)
    row = {"file_path": path, "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
           "minio_uri": "file://" + str(file), "metadata": {"whatsapp_derivation": DERIVATION_VERSION,
           "encrypted_source_path": "WhatsApp/settings.json.crypt14", "encrypted_source_sha256": "source-hash"}}
    original = {"sha256": "source-hash", "metadata": {"whatsapp_decryption": {"derived_paths": [path]}}}
    return tmp_path, job, body, row, original


def _read(registered, row=None, original=None, limit=768_000_000):
    root, job, body, baseline, source = registered
    def get(uri, max_bytes):
        return Path(uri[7:]).read_bytes()[:max_bytes]
    with patch("app.services.storage._local_root", return_value=root), patch("app.services.storage.get_bytes", side_effect=get), patch("app.db.sql_helpers.fetchone", return_value=original if original is not None else source):
        return read_registered_derivation(object(), job, row or baseline, max_bytes=limit)


def test_registered_payload_is_verified_before_returning_native_parser_prefix(registered):
    assert _read(registered) == registered[2]
    assert _read(registered, limit=5) == registered[2][:5]


@pytest.mark.parametrize("damage", ["foreign_namespace", "content", "hash", "missing_source_link", "source_hash"])
def test_untrusted_or_damaged_derivation_is_rejected(registered, damage):
    root, job, body, baseline, source = registered
    row = {**baseline}
    original = source
    if damage == "foreign_namespace":
        row["minio_uri"] = "file://" + str(root / "outside.json")
    elif damage == "content":
        Path(row["minio_uri"][7:]).write_bytes(b"tampered")
    elif damage == "hash":
        row["sha256"] = "wrong"
    elif damage == "missing_source_link":
        original = {"sha256": "source-hash", "metadata": {}}
    elif damage == "source_hash":
        original = {**source, "sha256": "different-source"}
    with pytest.raises(ValueError):
        _read(registered, row=row, original=original)


def test_serial_mobile_reader_accepts_verified_derivation_without_reopening_original(registered):
    from app.services.mobile_forensic.sqlite_counts import _read_artifact_bytes
    row = registered[3]
    with patch("app.services.mobile_forensic.sqlite_counts.fetchone", return_value=row), patch("app.services.mobile_forensic.whatsapp_derivation.read_registered_derivation", return_value=registered[2]) as derived, patch("app.services.virtual_disk.open_virtual_disk", side_effect=AssertionError("Original source reopened")):
        assert _read_artifact_bytes(object(), registered[1], row["file_path"]) == registered[2]
    assert derived.call_count == 1
