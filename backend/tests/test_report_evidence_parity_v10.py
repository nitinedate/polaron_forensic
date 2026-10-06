from __future__ import annotations

import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path


def _filetime(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


def _recycle_i_bytes(original_path: str, deleted_at: datetime) -> bytes:
    encoded = (original_path + "\x00").encode("utf-16-le")
    chars = len(original_path) + 1
    return struct.pack("<QQQI", 2, 1234, _filetime(deleted_at), chars) + encoded


def test_cloud_detector_uses_persisted_snapshot_when_raw_history_unavailable(monkeypatch):
    from app.services import report_objective_case_facts as mod

    monkeypatch.setattr(mod, "_primary_browser_records", lambda *_a, **_k: [])

    def fake_fetchall(_db, sql, _params=None):
        if "job_axiom_artifact_results" in sql:
            return [{
                "artifact_name": "Browser History",
                "query_snapshot": {
                    "records": [
                        {"url": "https://drive.google.com/drive/folders/abc"},
                        {"url": "https://mega.nz/"},
                        {"url": "https://www.dropbox.com/"},
                        {"url": "https://api.onedrive.com/v1.0/drive/root"},
                    ]
                },
            }]
        return []

    monkeypatch.setattr(mod, "fetchall", fake_fetchall)
    fact = mod._cloud_access_fact(None, "job", "Access to Cloud Storage Services")
    assert fact["status"] == "CONFIRMED"
    assert fact["key_entities"]["providers"] == ["Google Drive", "Mega", "Dropbox", "OneDrive"]


def test_external_disk_classifier_uses_usbstor_provenance_when_bus_label_was_lost():
    from app.services.report_objective_case_facts import classify_external_storage_devices

    devices = [
        {
            "bus": "USB",
            "device_name": "Apacer Portable HDD USB Device",
            "serial": "_201711281557&0",
            "source": r"SYSTEM\ControlSet001\Enum\USBSTOR",
        },
        {"bus": "USB", "device_name": "USB Root Hub (USB 3.0)", "serial": "hub"},
    ]
    physical = classify_external_storage_devices(devices)
    assert len(physical) == 1
    assert "Apacer" in physical[0]["device_name"]


def test_live_recycle_reader_pairs_i_and_r_and_parses_deletion_time(monkeypatch):
    from app.services import report_objective_case_facts as mod
    import sys
    import types

    i_path = r"Users/LENOVO/$Recycle.Bin/S-1-5-21/$IABC123"
    r_path = r"Users/LENOVO/$Recycle.Bin/S-1-5-21/$RABC123"
    rows = [
        {"id": "1", "file_path": i_path, "file_name": "$IABC123", "size_bytes": 200, "metadata": {}},
        {"id": "2", "file_path": r_path, "file_name": "$RABC123", "size_bytes": 1234, "metadata": {}},
    ]
    monkeypatch.setattr(mod, "fetchall", lambda *_a, **_k: rows)
    data = _recycle_i_bytes(r"C:\\Users\\LENOVO\\Desktop\\RRP-plan.xlsx", datetime(2025, 2, 21, 12, 22, tzinfo=timezone.utc))
    fake_live = types.ModuleType("app.services.artifact_live_counts")
    fake_live._read_job_files = lambda *_a, **_k: {i_path: data}
    monkeypatch.setitem(sys.modules, "app.services.artifact_live_counts", fake_live)

    records = mod._live_recycle_bin_records(None, "job")
    assert len(records) == 1
    assert records[0]["original_name"] == "RRP-plan.xlsx"
    assert records[0]["descriptor_path"] == i_path
    assert records[0]["payload_path"] == r_path
    assert records[0]["deleted_at"].startswith("2025-02-21T12:22")


def test_chromium_login_data_extracts_account_but_never_password(tmp_path: Path):
    from app.parsers.sqlite_parser import parse_sqlite

    db_path = tmp_path / "Login Data"
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB, date_last_used INTEGER)"
    )
    con.execute(
        "INSERT INTO logins VALUES (?,?,?,?)",
        ("https://outlook.office.com/", "Project@rrpelectronics.com", b"TOP-SECRET", 0),
    )
    con.commit()
    con.close()

    records = parse_sqlite(db_path.read_bytes(), "Users/LENOVO/AppData/Local/Edge/User Data/Default/Login Data")
    accounts = [r for r in records if r.get("record_type") == "browser_login_account"]
    assert len(accounts) == 1
    assert accounts[0]["account"] == "Project@rrpelectronics.com"
    assert "password" not in accounts[0]
    assert "TOP-SECRET" not in repr(accounts[0])


def test_recycle_bin_is_in_priority_parse_and_full_read_paths():
    from app.services.critical_forensic_paths import (
        FORENSIC_PARSE_PATH_SQL,
        is_critical_forensic_path,
        is_forensic_full_read_path,
    )

    path = r"Users/LENOVO/$Recycle.Bin/S-1-5-21/$IABC123"
    assert "$recycle.bin" in FORENSIC_PARSE_PATH_SQL.lower()
    assert is_forensic_full_read_path(path)
    assert is_critical_forensic_path(path)


def test_missing_section_c_card_does_not_invent_negative_finding():
    from app.services.report_generator_agent import ensure_all_objectives_in_report

    md = "## C. OBJECTIVE, PROCEDURE & OBSERVATION\n"
    out = ensure_all_objectives_in_report(md, [{
        "id": "custom-1",
        "title": "Custom Evidence Question",
        "objective": "To examine a custom evidence question.",
        "procedure_text": "The relevant evidence was examined.",
    }])
    assert "Nothing suspicious was found" not in out
    assert "Examiner review is required" in out


def test_client_objective_and_procedure_hide_internal_kb_jargon():
    from app.services.report_examination_narratives import format_client_objective, format_client_procedure

    objective = format_client_objective("Access to Cloud Storage Services")
    procedure = format_client_procedure("Access to Cloud Storage Services")
    combined = f"{objective} {procedure}".lower()

    assert "controlled" not in combined
    assert "primary evidence rules" not in combined
    assert "procedure(s)" not in combined
    assert "1. " not in procedure
    assert "browser history" in procedure
    assert objective == "To examine the device for evidence related to access to cloud storage services."


def test_forensic_imaging_does_not_mislabel_sha256_or_extracted_bytes_as_capacity():
    from app.services.report_template import gather_forensic_imaging_markdown

    sha256 = "a" * 64
    intake = {"organization": "RRP", "vol18_form_json": {}}
    job = {
        "disk_source": {
            "base_name": "Seger Ex-1",
            "segment_hashes": [sha256],
            "bytes_extracted": 32 * 1024**3,
        }
    }
    md = gather_forensic_imaging_markdown(intake, job)
    assert "Evidence File SHA-256" in md
    assert sha256 in md
    assert "Image Hash SHA1" not in md
    assert "32 GB" not in md
    assert "| RRP | Laptop | — | — | — | RRP |" in md


def test_forensic_imaging_prefers_explicit_acquisition_sha1_and_exhibit_capacity():
    from app.services.report_template import gather_forensic_imaging_markdown

    sha1 = "b" * 40
    intake = {
        "organization": "RRP",
        "vol18_form_json": {
            "image_hash_sha1": sha1,
            "exhibit": {
                "custodian": "RRP",
                "type": "Laptop",
                "model": "SKHynix_HFM256GDHTNI-87A0B",
                "serial": "ACE4_2E00_1A05_454A",
                "capacity": "256 GB",
                "location": "RRP",
            },
        },
    }
    job = {"disk_source": {"segment_hashes": ["a" * 64], "bytes_extracted": 32 * 1024**3}}
    md = gather_forensic_imaging_markdown(intake, job)
    assert "Image Hash SHA1" in md
    assert sha1 in md
    assert "256 GB" in md
    assert "Evidence File SHA-256" not in md
