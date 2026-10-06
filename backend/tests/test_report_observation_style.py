from __future__ import annotations

from app.services.report_observation_style import (
    client_safe_observation,
    ensure_simple_explanation,
    format_client_observation,
    observation_is_client_length,
    observation_leaks_technical,
)


def test_fail_closed_observation_is_title_specific_and_simple():
    out = format_client_observation("File Access and Handling", status="INCONCLUSIVE")
    assert "File Access and Handling" in out
    assert "not specific enough" in out.lower()
    assert "This means" in out
    assert observation_is_client_length(out)


def test_usb_fallback_does_not_claim_file_copy():
    out = format_client_observation("USB and External Device Usage", status="NOT_FOUND")
    assert "USB and External Device Usage" in out
    assert "copied" not in out.lower()
    assert "transferred" not in out.lower()


def test_cloud_fallback_does_not_claim_upload_download():
    out = format_client_observation("Access to Cloud Storage Services", status="INCONCLUSIVE")
    assert "Access to Cloud Storage Services" in out
    assert "uploaded" not in out.lower()
    assert "downloaded" not in out.lower()


def test_observation_rejects_windows_paths_registry_and_appx_payloads():
    assert observation_leaks_technical(r"Found C:\Users\Seger\Desktop\passwords.txt")
    assert observation_leaks_technical("Reviewed NTUSER.DAT and USBSTOR")
    assert observation_leaks_technical("Windows/SoftwareDistribution/Download and Users/LENOVO/AppData/Local/Packages")
    assert observation_leaks_technical('<?xml version="1.0"?><BlockMap />')


def test_client_safe_observation_fails_closed_if_path_was_removed():
    out = client_safe_observation(
        "973 log files were analyzed from Windows/SoftwareDistribution/Download and Users/LENOVO/AppData/Local/Packages.",
        title="File Access and Handling",
    )
    assert "973" not in out
    assert "AppData" not in out
    assert "no direct primary evidence" in out.lower()
    assert "This means" in out


def test_raw_catalog_totals_are_never_reused_as_client_observation():
    out = client_safe_observation(
        "Relevant traces were found. 0 items (Remote Desktop Protocol (RDP)).",
        title="File Access and Handling",
    )
    assert "0 items" not in out
    assert "Remote Desktop" not in out
    assert "File Access and Handling" in out


def test_simple_explanation_is_added_once():
    first = ensure_simple_explanation("Evidence was reviewed.", title="USB and External Device Usage")
    second = ensure_simple_explanation(first, title="USB and External Device Usage")
    assert first == second
    assert first.lower().count("this means") == 1
