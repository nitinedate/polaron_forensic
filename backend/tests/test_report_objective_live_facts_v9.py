from __future__ import annotations

from app.services.report_objective_case_facts import (
    _cloud_access_fact,
    _malware_web_fact,
    classify_external_storage_devices,
)
from app.services.axiom_forensic_report_engine import validate_observation_against_brief


def test_external_storage_classification_matches_axiom_style_physical_devices_not_raw_usb_rows():
    rows = [
        {"bus": "USB", "device_name": "Intel(R) Wireless Bluetooth(R)", "serial": "BT1"},
        {"bus": "USB", "device_name": "USB Composite Device", "serial": "CMP1"},
        {"bus": "USB", "device_name": "Integrated Camera", "serial": "CAM1"},
        {"bus": "USB", "device_name": "USB Attached SCSI (UAS) Mass Storage Device", "serial": "MSFT30"},
        {"bus": "USB", "device_name": "USB Input Device", "serial": "HID1"},
        {"bus": "USB", "device_name": "USB Root Hub (USB 3.0)", "serial": "HUB1"},
        {"bus": "USBSTOR", "device_name": "Apacer Portable HDD USB Device", "serial": "_201711281557&0"},
        {"bus": "SCSI_STORAGE", "device_name": "Seagate Expansion SCSI Disk Device", "serial": "SEAGATE-01"},
        {"bus": "SCSI_STORAGE", "device_name": "SKHynix_HFM256GDHTNI-87A0B", "serial": "INTERNAL"},
        # Interface row for the same Apacer device must not be a third disk.
        {"bus": "USB", "device_name": "USB Mass Storage Device", "serial": "_201711281557"},
    ]
    physical = classify_external_storage_devices(rows)
    assert [x["device_name"] for x in physical] == [
        "Apacer Portable HDD USB Device",
        "Seagate Expansion SCSI Disk Device",
    ]


def test_cloud_access_fact_names_the_services_in_current_evidence(monkeypatch):
    from app.services import report_objective_case_facts as mod

    monkeypatch.setattr(
        mod,
        "_primary_browser_records",
        lambda *_a, **_k: [
            {"url": "https://drive.google.com/drive/folders/abc", "record_origin": "browser_history"},
            {"url": "https://mega.nz/", "record_origin": "browser_history"},
            {"url": "https://www.dropbox.com/", "record_origin": "browser_history"},
            {"url": "https://api.onedrive.com/v1.0/drive/root", "record_origin": "browser_history"},
        ],
    )
    fact = _cloud_access_fact(None, "job", "Access to Cloud Storage Services")
    assert fact["status"] == "CONFIRMED"
    assert fact["key_entities"]["providers"] == ["Google Drive", "Mega", "Dropbox", "OneDrive"]
    assert "Google Drive, Mega, Dropbox, OneDrive" in fact["observation"]
    assert "does not prove" in fact["simple_explanation"].lower()


def test_malware_web_fact_returns_explicit_zero_instead_of_relevant_traces(monkeypatch):
    from app.services import report_objective_case_facts as mod

    monkeypatch.setattr(mod, "_primary_browser_records", lambda *_a, **_k: [])
    fact = _malware_web_fact(None, "job", "Malware, Phishing and Pornography URLs")
    assert fact["status"] == "NOT_FOUND"
    assert fact["allowed_counts"][0]["count"] == 0
    assert "No browser-history URLs" in fact["observation"]
    assert "relevant traces were found" not in fact["observation"].lower()


def test_validator_rejects_summary_style_contradiction_when_case_fact_is_confirmed():
    brief = {
        "allowed_counts": [{"count": 4}],
        "case_fact": {
            "status": "CONFIRMED",
            "key_entities": {"providers": ["Google Drive", "Mega"]},
        },
    }
    bad = "No traces of cloud storage were found. This means nothing was found."
    ok, errors = validate_observation_against_brief(bad, brief)
    assert not ok
    assert any("contradicts confirmed" in e for e in errors)


def test_validator_rejects_vague_confirmed_wording_that_omits_named_evidence():
    brief = {
        "allowed_counts": [],
        "case_fact": {
            "status": "CONFIRMED",
            "key_entities": {"devices": ["Apacer Portable HDD"]},
        },
    }
    bad = "Relevant traces were found for external devices. This means devices were present."
    ok, errors = validate_observation_against_brief(bad, brief)
    assert not ok
    assert any("omitted the objective-specific evidence identity" in e for e in errors)


def test_validator_accepts_specific_confirmed_wording_with_simple_explanation():
    brief = {
        "allowed_counts": [{"count": 1}],
        "case_fact": {
            "status": "CONFIRMED",
            "key_entities": {"devices": ["Apacer Portable HDD"]},
        },
    }
    good = (
        "One external storage device, Apacer Portable HDD, was identified as connected to the computer. "
        "This means the connection is supported, but the record alone does not prove a file transfer."
    )
    ok, errors = validate_observation_against_brief(good, brief)
    assert ok, errors
