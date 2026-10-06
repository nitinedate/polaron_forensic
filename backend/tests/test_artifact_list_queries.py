"""Tests for artifact browse SQL resolution."""

from app.services.artifact_list_queries import list_where_for_artifact_name
from app.services.catalog_categories import EMAIL_CALENDAR_CATEGORY, canonical_category


def test_canonical_email_calendar_category() -> None:
    assert canonical_category("Email and Calendar") == EMAIL_CALENDAR_CATEGORY
    assert canonical_category("Email & Calendar") == EMAIL_CALENDAR_CATEGORY


def test_email_attachments_list_where_uses_attachment_paths() -> None:
    suffix, params = list_where_for_artifact_name(
        None,  # type: ignore[arg-type]
        "job",
        artifact_name="Email Attachments",
        category=EMAIL_CALENDAR_CATEGORY,
        platform="Windows",
    )
    assert "attach" in suffix.lower()
    assert "Email Attachments" not in suffix
    assert params.get("jid") == "job" or "jid" not in params


def test_eml_files_list_where_uses_extension() -> None:
    suffix, _params = list_where_for_artifact_name(
        None,  # type: ignore[arg-type]
        "job",
        artifact_name="EML(X) Files",
        category=EMAIL_CALENDAR_CATEGORY,
        platform="Windows",
    )
    assert ".eml" in suffix.lower()


def test_csv_documents_list_where_uses_extension() -> None:
    suffix, params = list_where_for_artifact_name(
        None,  # type: ignore[arg-type]
        "job",
        artifact_name="CSV Documents",
        category="Documents",
        platform="Windows",
    )
    assert "ext0" in suffix.lower() or "extension" in suffix.lower()
    assert ".csv" in " ".join(str(v).lower() for v in params.values())


def test_usb_devices_list_where_uses_source_hives() -> None:
    suffix, _params = list_where_for_artifact_name(
        None,  # type: ignore[arg-type]
        "job",
        artifact_name="USB Devices",
        category="Connected Devices",
        platform="Windows",
    )
    assert "setupapi" in suffix.lower()
    assert "system" in suffix.lower()


def test_usb_devices_use_record_browse_mode() -> None:
    from app.services.artifact_evidence_browse import evidence_browse_mode

    assert evidence_browse_mode("USB Devices", "Connected Devices") == "usb_device"
    assert evidence_browse_mode("Your Phone Device", "Connected Devices") == "phone_device"
    assert evidence_browse_mode("Remote Desktop Protocol", "Connected Devices") == "rdp_connection"
