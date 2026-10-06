"""Tests for catalog ↔ section collector title matching."""

from app.services.axiom_artifact_runner import _find_exact_section_item, _title_matches_collector


def test_connected_device_title_aliases() -> None:
    inventory = {
        "sections": [
            {
                "key": "connected_devices",
                "title": "Connected Devices",
                "items": [
                    {"key": "usb_devices", "title": "USB Devices", "count": 39},
                    {"key": "phone_devices", "title": "Your Phone Device", "count": 2},
                    {"key": "rdp", "title": "Remote Desktop Protocol (RDP)", "count": 6},
                ],
            }
        ]
    }
    _sec, usb = _find_exact_section_item(inventory, "USB Devices")
    assert usb and usb["count"] == 39

    _sec, phone = _find_exact_section_item(inventory, "Your Phone Devices")
    assert phone and phone["count"] == 2

    _sec, rdp = _find_exact_section_item(inventory, "Remote Desktop Protocol")
    assert rdp and rdp["count"] == 6

    assert _title_matches_collector("Your Phone Contacts", "Your Phone Device")
    assert not _title_matches_collector("Remote Desktop Protocol Bitmap Cache", "Remote Desktop Protocol (RDP)")
