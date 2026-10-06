"""Evidence extension/extensionless retention + coverage helpers."""

from __future__ import annotations

from app.services.extract_filters import matches_forensic_include, matches_mobile_forensic_include
from app.services.forensic_handbook_scope import (
    is_handbook_evidence_path,
    matches_handbook_extensionless_path,
)
from app.services.phase1_artifact_scope import is_phase1_evidence_path, should_materialize_path


def test_extensionless_under_evidence_trees_kept():
    assert matches_handbook_extensionless_path("Users/Bob/AppData/Local/Google/Chrome/User Data/Default/History")
    assert matches_handbook_extensionless_path("Users/Bob/AppData/Roaming/Mozilla/Firefox/Profiles/x.default/places.sqlite") is False  # has .sqlite
    assert matches_handbook_extensionless_path("data/data/com.whatsapp/shared_prefs/com.whatsapp_preferences.xml") is False
    assert matches_handbook_extensionless_path("data/data/com.whatsapp/shared_prefs/prefs_store")
    assert matches_handbook_extensionless_path("Maildir/cur/1234567.M123.hostname:2,S")
    assert is_handbook_evidence_path("Users/Bob/AppData/Local/Google/Chrome/User Data/Default/Cookies")


def test_new_mobile_extensions_kept():
    assert is_handbook_evidence_path("sdcard/WhatsApp/Databases/msgstore.db.crypt14")
    assert is_phase1_evidence_path("Download/app-release.apk")
    assert should_materialize_path("Media/WhatsApp/msgstore.db.crypt14")[0]
    assert matches_mobile_forensic_include("data/data/com.whatsapp/databases/msgstore.db", "msgstore.db")
    assert is_handbook_evidence_path("data/data/com.whatsapp/files/key")
    assert is_handbook_evidence_path("Dump/App/com.whatsapp/files/key")
    assert matches_handbook_extensionless_path("data/data/com.whatsapp/files/key")


def test_tiny_extensionless_materialize():
    # Size is not part of materialize path check — path rules alone retain tiny files.
    ok, reason = should_materialize_path("Users/A/AppData/Local/Google/Chrome/User Data/Default/Network Persistent State")
    assert ok and reason is None


def test_windows_forensic_keeps_history_basename():
    assert matches_forensic_include(
        "Users/Bob/AppData/Local/Google/Chrome/User Data/Default/History",
        "History",
        os_family="windows",
    )
