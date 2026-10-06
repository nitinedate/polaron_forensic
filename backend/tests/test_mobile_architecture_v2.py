"""Acceptance tests for Mobile Forensics Architecture v2 (doc Table 12 themes)."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.services.mobile_forensic.cellebrite_ufed import (
    parse_ufdx_extraction_paths,
    resolve_ufdx_referenced_paths,
)
from app.services.mobile_forensic.integrity import (
    PARSER_PLATFORM_VERSION,
    build_evidence_manifest,
    hash_evidence_paths,
    load_intake_keys_from_disk_source,
    sha256_file,
)
from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact, UI_STATE_LABELS
from app.services.mobile_forensic.plugins import ParseContext, get_plugin_registry, reset_plugin_registry_for_tests
from app.services.mobile_forensic.parsers.sms_calls import SmsCallsParser
from app.services.mobile_forensic.parsers.messaging import WhatsAppParser
from app.services.mobile_forensic.case_export import build_case_package_zip


def test_ufdx_path_follow(tmp_path: Path):
    dump = tmp_path / "FileDump.zip"
    dump.write_bytes(b"PK\x03\x04dummy")
    ufd = tmp_path / "case.ufd"
    ufd.write_text("[DeviceInfo]\nModel=Test\n", encoding="utf-8")
    ufdx = tmp_path / "case.ufdx"
    ufdx.write_text(
        """<?xml version="1.0"?>
        <Project>
          <Extraction Path="case.ufd"/>
          <Extraction Path="FileDump.zip"/>
        </Project>
        """,
        encoding="utf-8",
    )
    paths = parse_ufdx_extraction_paths(ufdx)
    assert "case.ufd" in paths
    assert "FileDump.zip" in paths
    resolved = resolve_ufdx_referenced_paths(ufdx)
    names = {p.name for p in resolved}
    assert "case.ufd" in names
    assert "FileDump.zip" in names


def test_intake_manifest_integrity(tmp_path: Path):
    src = tmp_path / "evidence.zip"
    src.write_bytes(b"hello-evidence")
    digest = sha256_file(src)
    hashed = hash_evidence_paths([src])
    assert hashed[0]["sha256"] == digest
    manifest = build_evidence_manifest(
        job_id="00000000-0000-0000-0000-000000000001",
        source_paths=[str(src)],
        hashed=hashed,
        mobile_os="Android",
        acquisition_mode="import",
        formats=[".zip"],
        adapter="ufed",
        intake_keys={"whatsapp_key_hex": "aabbcc"},
    )
    assert manifest["immutable_original"] is True
    assert manifest["parser_platform_version"] == PARSER_PLATFORM_VERSION
    assert manifest["key_material"]["whatsapp_key_present"] is True
    # Raw key must not appear in public manifest
    assert "aabbcc" not in json.dumps(manifest)


def test_intake_keys_from_disk_source():
    keys = load_intake_keys_from_disk_source(
        {"case_intake": {"whatsapp_key_hex": "deadbeef"}, "ios_backup_password": "x"}
    )
    assert keys["whatsapp_key_hex"] == "deadbeef"
    assert keys["ios_backup_password"] == "x"


def test_plugin_registry_has_core_and_recovery():
    reset_plugin_registry_for_tests()
    reg = get_plugin_registry()
    names = {p.name for p in reg.parsers}
    assert "sms_calls_parser" in names
    assert "contacts_parser" in names
    assert "whatsapp_parser" in names
    assert "files_media_parser" in names
    assert "browser_parser" in names
    recovery = {a.name for a in reg.recovery_analyzers}
    assert "sqlite_history_analyzer" in recovery
    assert "orphan_media_analyzer" in recovery
    assert "trash_path_analyzer" in recovery


def _make_sms_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, body TEXT, date INTEGER, type INTEGER, read INTEGER)"
    )
    conn.execute(
        "INSERT INTO sms VALUES (1, '+15551212', 'hello', 1700000000000, 1, 1)"
    )
    conn.commit()
    conn.close()


def test_sms_parser_normalized_envelope(tmp_path: Path):
    db_path = tmp_path / "mmssms.db"
    _make_sms_db(db_path)
    raw = db_path.read_bytes()
    item = InventoryItem(path="Dump/data/com.android.providers.telephony/databases/mmssms.db", size=len(raw))
    ctx = ParseContext(
        job_id="job-1",
        platform="Android",
        read_bytes=lambda p, max_bytes=0: raw,
    )
    arts = list(SmsCallsParser().parse(item, ctx))
    assert arts
    a = arts[0]
    assert a.artifact_type == "sms"
    assert a.source_domain == "sms_mms_rcs"
    assert a.forensic["state"] == "allocated"
    assert a.forensic["ui_label"] == UI_STATE_LABELS["allocated"]
    assert a.forensic["parser"] == "sms_calls_parser"
    assert a.forensic["source_path"]


def test_whatsapp_crypt_without_key_is_unverified(tmp_path: Path):
    crypt = tmp_path / "msgstore.db.crypt14"
    crypt.write_bytes(b"\x00" * 100)
    item = InventoryItem(path="Dump/WhatsApp/msgstore.db.crypt14", size=100, extension=".crypt14")
    ctx = ParseContext(job_id="job-1", platform="Android", whatsapp_key_hex=None)
    arts = list(WhatsAppParser().parse(item, ctx))
    assert arts
    assert arts[0].forensic["state"] == "unverified"
    assert arts[0].data.get("key_available") is False


def test_theme_crypt14_is_not_a_chat_backup(tmp_path: Path):
    item = InventoryItem(
        path="WhatsApp/Backups/006_travel_theme.webp.crypt14",
        size=40,
        extension=".crypt14",
    )
    ctx = ParseContext(job_id="job-1", platform="Android", whatsapp_key_hex=None)
    assert WhatsAppParser().supports(item, ctx) is False
    assert list(WhatsAppParser().parse(item, ctx)) == []


def test_recovery_not_auto_promoted():
    """Recovered candidates start pending_review; allocated accepted."""
    live = NormalizedArtifact.create(
        artifact_type="sms",
        source_domain="sms_mms_rcs",
        data={"body": "x"},
        state="allocated",
    )
    recovered = NormalizedArtifact.create(
        artifact_type="recovered_candidate",
        source_domain="messaging_apps",
        data={"body": "y"},
        state="freelist_candidate",
    )
    assert live.forensic["examiner_status"] == "accepted"
    assert recovered.forensic["examiner_status"] == "pending_review"
    assert recovered.forensic["ui_label"] == "UNVERIFIED"


def test_case_package_zip_structure(tmp_path: Path):
    """Export includes required folder layout + hash sidecar."""
    db = MagicMock()
    # fetchone for disk_source
    from unittest.mock import patch

    with patch(
        "app.services.mobile_forensic.case_export.fetchone",
        return_value={"disk_source": {"evidence_manifest": {"source_id": "S1", "job_id": "j1"}}},
    ), patch(
        "app.services.mobile_forensic.case_export.fetchall",
        return_value=[{"path": "Dump/a.txt", "size_bytes": 1, "extension": ".txt", "status": "parsed", "parser": "x", "sha256": None}],
    ), patch(
        "app.services.mobile_forensic.case_export.list_artifacts",
        return_value=[
            {"artifact_id": "A1", "state": "allocated", "artifact_type": "sms"},
            {"artifact_id": "A2", "state": "orphaned", "artifact_type": "photo"},
        ],
    ), patch(
        "app.services.mobile_forensic.case_export.timeline_rows",
        return_value=[],
    ), patch(
        "app.services.mobile_forensic.case_export.ensure_mobile_case_schema",
        return_value=None,
    ):
        dest = tmp_path / "case.zip"
        meta = build_case_package_zip(db, "00000000-0000-0000-0000-000000000099", dest)
        assert dest.is_file()
        with zipfile.ZipFile(dest) as zf:
            names = set(zf.namelist())
        assert "manifest/evidence_manifest.json" in names
        assert "inventory/inventory.json" in names
        assert "parsed/artifacts.json" in names
        assert "recovered/candidates.json" in names
        assert "reports/summary.json" in names
        assert "hashes/package_files.sha256.json" in names
        assert meta["file_count"] >= 6


def test_ui_state_labels_cover_vocabulary():
    required = {
        "allocated",
        "historical",
        "database_deleted",
        "wal_recovered",
        "freelist_candidate",
        "orphaned",
        "fragment",
        "cache_derived",
        "unverified",
    }
    assert required.issubset(set(UI_STATE_LABELS))
