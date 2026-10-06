"""Independent-format fixtures, payload recovery and evidence provenance."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

from app.services.mobile_forensic import whatsapp_crypt as wc
from app.services.mobile_forensic.models import InventoryItem
from app.services.mobile_forensic.plugins import ParseContext
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
from app.services.mobile_forensic.whatsapp_derivation import iter_derived_payloads

spec = importlib.util.spec_from_file_location("independent_whatsapp_fixtures", Path(__file__).resolve().parents[2] / "scripts/whatsapp_qa_fixtures.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


@pytest.fixture(scope="module")
def database():
    return fixtures.sqlite_fixture()


@pytest.mark.parametrize("version", wc.SUPPORTED_BACKUP_FORMATS)
def test_independently_encoded_supported_versions(database, version):
    legacy = version in {"crypt", "crypt5", "crypt7", "crypt8"}
    blob = fixtures.legacy_backup(database, version) if legacy else fixtures.modern_backup(database, version)
    key = fixtures.BACKUP_SECRET if version == "crypt15" else fixtures.KEYFILE
    assert wc.try_decrypt_whatsapp_crypt(blob, key, path="msgstore.db." + version, legacy_account=fixtures.LEGACY_ACCOUNT) == database
    diag = wc.last_decrypt_diagnostics()
    assert diag["container"] == version
    assert diag["payload_kind"] == "sqlite"
    assert diag["authenticated"] is (not legacy)
    assert diag["integrity"] == ("legacy_structure_checked_no_mac" if legacy else "aes_gcm_authenticated")


def test_requested_crypt14_cannot_return_key_without_collected_key(database):
    blob = fixtures.modern_backup(database, "crypt14")
    assert wc.decrypt_with_candidates(blob, [], path="msgstore.db.crypt14", allow_payloads=True) is None
    assert wc.last_decrypt_diagnostics()["reason"] == "key_material_missing_or_invalid"
    assert wc.last_decrypt_diagnostics()["keys_tried"] == 0
    assert wc.parse_key_material(blob) is None
    assert wc.parse_key_material(fixtures.KEYFILE).raw32.hex() == fixtures.KEYFILE[126:158].hex()
    assert len(wc.parse_key_material(fixtures.KEYFILE).raw32.hex()) == 64


@pytest.mark.parametrize("version", ["crypt1", "crypt6", "crypt13", "crypt16", "crypt99"])
def test_unsupported_numbered_formats_retained_without_guessing(database, version):
    assert wc.crypt_extension("WhatsApp/msgstore.db." + version.upper()) == version
    assert wc.try_decrypt_whatsapp_payload(fixtures.modern_backup(database, "crypt14"), fixtures.KEYFILE, path="msgstore.db." + version) is None
    assert wc.last_decrypt_diagnostics()["reason"] == "unsupported_crypt_version"
    assert wc.last_decrypt_diagnostics()["candidates_tried"] == 0


def test_crypt5_requires_exact_original_account(database):
    blob = fixtures.legacy_backup(database, "crypt5")
    assert wc.try_decrypt_whatsapp_crypt(blob, None, path="msgstore.db.crypt5") is None
    assert wc.last_decrypt_diagnostics()["reason"] == "legacy_account_required"
    assert wc.try_decrypt_whatsapp_crypt(blob, None, path="msgstore.db.crypt5", legacy_account="wrong@example.test") is None
    assert wc.try_decrypt_whatsapp_crypt(blob, None, path="msgstore.db.crypt5", legacy_account=fixtures.LEGACY_ACCOUNT) == database


@pytest.mark.parametrize("version", ["crypt5", "crypt7", "crypt8"])
def test_legacy_structure_corruption_is_rejected(database, version):
    blob = bytearray(fixtures.legacy_backup(database, version))
    blob[0 if version == "crypt5" else 67] ^= 1
    assert wc.try_decrypt_whatsapp_crypt(bytes(blob), fixtures.KEYFILE, path="msgstore.db." + version, legacy_account=fixtures.LEGACY_ACCOUNT) is None
    assert wc.last_decrypt_diagnostics()["authenticated"] is False


@pytest.mark.parametrize("version", ["crypt12", "crypt14", "crypt15"])
@pytest.mark.parametrize("part", ["tag", "checksum"])
def test_modern_payload_tampering_is_rejected(version, part):
    blob = bytearray(fixtures.modern_backup(b'{"test":"evidence"}', version))
    trailer = 4 if version == "crypt12" else 0
    blob[len(blob) - trailer - (17 if part == "tag" else 1)] ^= 1
    assert wc.try_decrypt_whatsapp_payload(bytes(blob), fixtures.BACKUP_SECRET if version == "crypt15" else fixtures.KEYFILE,
                                         path="WhatsApp/settings.json." + version) is None
    assert wc.last_decrypt_diagnostics()["authenticated"] is False


@pytest.mark.parametrize("payload,kind", [
    (b'{"setting":"synthetic"}', "json"), (fixtures.zip_fixture(), "zip"),
    (fixtures.PNG, "png"), (b"\x00\xfeSynthetic binary data\x00", "binary"),
])
def test_modern_non_chat_payloads_are_authenticated_but_not_chats(payload, kind):
    blob = fixtures.modern_backup(payload, "crypt14", compressed=False)
    assert wc.try_decrypt_whatsapp_payload(blob, fixtures.KEYFILE, path="WhatsApp/Backups/item.crypt14") == payload
    assert wc.last_decrypt_diagnostics()["payload_kind"] == kind
    assert wc.last_decrypt_diagnostics()["authenticated"] is True
    assert wc.try_decrypt_whatsapp_crypt(blob, fixtures.KEYFILE, path="WhatsApp/Backups/item.crypt14") is None


def test_decompression_limit_is_fail_closed(database, monkeypatch):
    blob = fixtures.modern_backup(database, "crypt14")
    monkeypatch.setattr(wc, "MAX_PAYLOAD_BYTES", len(database) - 1)
    assert len(blob) < wc.MAX_PAYLOAD_BYTES
    assert wc.try_decrypt_whatsapp_payload(blob, fixtures.KEYFILE, path="msgstore.db.crypt14") is None
    assert wc.last_decrypt_diagnostics()["reason"] == "authenticated_payload_invalid_or_over_limit"


def test_zip_recovery_preserves_members_and_rejects_windows_and_traversal_paths():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("messages.json", '{"body":"safe"}')
        for path in ("../escape.txt", "/absolute.txt", "C:/escape.txt", "NUL.txt", "data/file:stream", "MESSAGES.json"):
            archive.writestr(path, "unsafe")
    warnings = []
    files = list(iter_derived_payloads(buffer.getvalue(), "WhatsApp/msgstore-increment.crypt15", warnings))
    assert len(files) == 2  # original ZIP and only the safe JSON member
    assert files[1][0] == "members/messages.json"
    assert len(warnings) == 6


def test_zip_limit_retains_original_archive(monkeypatch):
    import app.services.mobile_forensic.whatsapp_derivation as derivation
    monkeypatch.setattr(derivation, "MAX_ARCHIVE_MEMBERS", 1)
    warnings = []
    files = list(iter_derived_payloads(fixtures.zip_fixture(), "WhatsApp/increment.crypt15", warnings))
    assert len(files) == 1 and files[0][2]["payload_kind"] == "zip"
    assert warnings


def test_cached_encrypted_artifact_does_not_parse_chat_twice(database):
    source = "WhatsApp/msgstore.db.crypt14"
    item = InventoryItem(path=source, meta={"whatsapp_decryption": {"state": "decrypted", "derived_paths": ["derived/msgstore.db"],
                         "diagnostics": {"container": "crypt14", "authenticated": True, "payload_kind": "sqlite"}}})
    def unread(*args, **kwargs):
        raise AssertionError("Cached source must not be read/decrypted again")
    rows = list(WhatsAppParser().parse(item, ParseContext(job_id="qa", platform="Android", read_bytes=unread)))
    assert len(rows) == 1 and rows[0].artifact_type == "app_backup_encrypted"
    assert rows[0].data["derived_paths"] == ["derived/msgstore.db"]


def test_derived_database_provenance_survives_chat_parsing_and_rag(database):
    from app.services.mobile_forensic.mobile_rag import artifact_to_rag_text
    meta = {"whatsapp_derivation": "qa", "encrypted_source_path": "WhatsApp/msgstore.db.crypt14",
            "encrypted_source_sha256": "abc123", "decryption_integrity": "aes_gcm_authenticated"}
    item = InventoryItem(path="derived/whatsapp_decrypted/qa/msgstore.db", size=len(database),
                         sha256=hashlib.sha256(database).hexdigest(), meta=meta)
    rows = list(WhatsAppParser().parse(item, ParseContext(job_id="qa", platform="Android", read_bytes=lambda *args, **kw: database)))
    messages = [row for row in rows if row.artifact_type == "app_message"]
    assert len(messages) == 3
    assert all(row.forensic["encrypted_source_sha256"] == "abc123" for row in messages)
    assert any(row.forensic["state"] == "database_deleted" for row in messages)
    assert "Encrypted source SHA256: abc123" in artifact_to_rag_text(messages[0].to_dict())


def test_materializer_records_every_blocked_file_without_fabricating_keys(tmp_path, database):
    from app.services.mobile_acquire.android_readable import _materialize_whatsapp_decrypted
    paths = []
    for version in ("crypt14", "crypt15", "crypt99"):
        path = tmp_path / ("msgstore.db." + version)
        path.write_bytes(fixtures.modern_backup(database, "crypt14"))
        paths.append(path)
    out = {}
    _materialize_whatsapp_decrypted(paths, [], tmp_path / "out", out)
    assert len(out["whatsapp_backup_results"]) == 3
    assert out["copied"] == []
    assert {item["diagnostics"]["reason"] for item in out["whatsapp_backup_results"]} == {"key_material_missing_or_invalid", "unsupported_crypt_version"}
    assert fixtures.DEVICE_SECRET.hex() not in json.dumps(out)


def test_package_import_tries_business_and_e2e_backup_keys(tmp_path, database):
    from app.services.mobile_forensic.package_inventory import _scan_dump_zip
    archive = tmp_path / "mobile.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("data/data/com.whatsapp/files/key", b"x" * 158)
        package.writestr("data/user/10/com.whatsapp.w4b/files/key", fixtures.KEYFILE)
        package.writestr("data/user/10/com.whatsapp.w4b/files/encrypted_backup.key", fixtures.BACKUP_SECRET)
        package.writestr("WhatsApp Business/msgstore.db.crypt14", fixtures.modern_backup(database, "crypt14"))
        package.writestr("WhatsApp Business/msgstore-old.db.crypt15", fixtures.modern_backup(database, "crypt15"))
    result = _scan_dump_zip(archive)
    assert result["counts"]["whatsapp_messages"] == 3
    assert result["counts"]["whatsapp_encrypted_backups"] == 2
    assert len(result["db_paths"]["whatsapp"]) == 2


def test_legacy_account_is_kept_out_of_public_job_metadata():
    from app.services.mobile_forensic.integrity import forensic_key_status_from_disk_source
    from app.services.mobile_forensic.key_intake import redact_forensic_keys
    source = {"case_intake": {"whatsapp_legacy_account": fixtures.LEGACY_ACCOUNT}, "whatsapp_legacy_account": fixtures.LEGACY_ACCOUNT}
    assert forensic_key_status_from_disk_source(source)["whatsapp_legacy_account_set"]
    assert fixtures.LEGACY_ACCOUNT not in json.dumps(redact_forensic_keys(source))


def test_wrong_key_for_chat_backup_does_not_repeat_full_payload_decryption(database, monkeypatch):
    blob = fixtures.modern_backup(database, "crypt14")
    calls = []
    original = wc._aes_gcm_decrypt
    def expensive(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)
    monkeypatch.setattr(wc, "_aes_gcm_decrypt", expensive)
    assert wc.try_decrypt_whatsapp_payload(blob, b"z" * 32, path="msgstore.db.crypt14") is None
    assert len(calls) <= 2


def test_authenticated_empty_payload_is_recovered_without_chat_rows():
    blob = fixtures.modern_backup(b"", "crypt14", compressed=False)
    assert wc.try_decrypt_whatsapp_payload(blob, fixtures.KEYFILE, path="WhatsApp/empty.bin.crypt14") == b""
    assert wc.last_decrypt_diagnostics()["authenticated"]


def test_filename_hint_never_blocks_authenticated_non_sqlite_payload():
    payload = b'{"fixture":"renamed evidence"}'
    blob = fixtures.modern_backup(payload, "crypt14", compressed=False)
    assert wc.try_decrypt_whatsapp_payload(blob, fixtures.KEYFILE, path="msgstore.db.crypt14") == payload
    assert wc.last_decrypt_diagnostics()["payload_kind"] == "json"
