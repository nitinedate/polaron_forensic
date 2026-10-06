"""Tests for handbook-aligned evidence scope (extensions + extensionless paths)."""

from app.services.forensic_handbook_scope import (
    HANDBOOK_EVIDENCE_EXTENSIONS,
    is_handbook_evidence_path,
    matches_handbook_extensionless_path,
    matches_handbook_special_basename,
)
from app.services.extract_filters import matches_forensic_include
from app.services.phase1_artifact_scope import is_phase1_evidence_path, should_materialize_path
from app.services.rag_index import _is_interesting


def test_handbook_includes_network_and_container_extensions() -> None:
    for ext in (".pcapng", ".vmem", ".vmdk", ".jsonlz4", ".tracev3", ".ics", ".vcf"):
        assert ext in HANDBOOK_EVIDENCE_EXTENSIONS


def test_maildir_extensionless_message() -> None:
    path = "Users/Jane/Maildir/cur/1234567890.abcdef"
    assert matches_handbook_extensionless_path(path) is True
    assert is_handbook_evidence_path(path) is True
    assert is_phase1_evidence_path(path) is True
    assert matches_forensic_include(path) is True
    assert should_materialize_path(path)[0] is True


def test_thunderbird_extensionless_mbox() -> None:
    path = "Users/Jane/AppData/Roaming/Thunderbird/Profiles/abc123.default/Mail/Local Folders/Inbox"
    assert matches_handbook_extensionless_path(path) is True
    assert is_phase1_evidence_path(path) is True


def test_apple_mail_extensionless_message() -> None:
    path = "Users/Jane/Library/Mail/V10/abc123-def456/Messages/12345"
    assert matches_handbook_extensionless_path(path) is True
    assert is_phase1_evidence_path(path) is True


def test_special_basename_history_and_envelope_index() -> None:
    history = "Users/Jane/AppData/Local/Google/Chrome/User Data/Default/History"
    envelope = "Users/Jane/Library/Mail/V10/abc/Messages/envelope index"
    assert matches_handbook_special_basename(history) is True
    assert matches_handbook_special_basename(envelope) is True
    assert is_handbook_evidence_path(history) is True


def test_rag_indexes_extensionless_handbook_mail() -> None:
    path = "Users/Jane/Maildir/new/9876543210.123456"
    assert _is_interesting(path) is True


def test_random_extensionless_outside_markers_not_handbook() -> None:
    path = "Windows/System32/drivers/etc/hosts"
    assert matches_handbook_extensionless_path(path) is False


def test_whatsapp_key_file_is_kept() -> None:
    path = "data/data/com.whatsapp/files/key"
    assert matches_handbook_special_basename(path) is True
    assert is_handbook_evidence_path(path) is True
    assert should_materialize_path(path)[0] is True
    assert matches_handbook_special_basename("usr/share/misc/key") is False
