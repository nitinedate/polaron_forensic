"""Report section B reconciliation helpers."""

from app.services.axiom_report_reconciliation import (
    app_count_for_report_artifact,
    build_report_reconciliation,
)


def test_app_count_resolves_jump_list_alias() -> None:
    rows = {
        "jump lists": {"count": 712, "artifact": "Jump Lists"},
    }
    assert app_count_for_report_artifact(rows, "Jump List") == 712


def test_build_report_reconciliation_match_usb() -> None:
    rows = {"usb devices": {"count": 39, "artifact": "USB Devices"}}
    report = build_report_reconciliation(rows)
    usb = next(r for r in report if r["artifact"] == "USB Devices")
    assert usb["status"] == "match"
    assert usb["delta"] == 0
