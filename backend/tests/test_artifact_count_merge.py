"""Tests for merged artifact count resolution."""

from app.services.axiom_catalog_ingest import overlay_section_collector_counts


def test_overlay_prefers_higher_collector_count() -> None:
    counts = {"AX-USB": 26}
    ax_rows = [{"artifact_id": "AX-USB", "artifact_name": "USB Devices", "category": "Connected Devices"}]

    class FakeDb:
        def execute(self, *_args, **_kwargs):
            class Result:
                def mappings(self):
                    return self

                def all(self):
                    return ax_rows

            return Result()

    db = FakeDb()

    from app.services import artifact_sections as sections_mod

    original = sections_mod.collect_connected_device_title_counts
    sections_mod.collect_connected_device_title_counts = lambda _db, _jid: {"usb devices": 39}
    try:
        out = overlay_section_collector_counts(
            db,
            "job",
            "Windows",
            counts,
            include_application_usage=False,
            include_communication_urls=False,
            include_documents=False,
            include_email=False,
            include_encryption=False,
            include_media=False,
            include_operating_system=False,
            include_web_related=False,
        )
    finally:
        sections_mod.collect_connected_device_title_counts = original

    assert out["AX-USB"] == 39


def test_apply_section_counts_keeps_stored_when_collector_lower() -> None:
    counts = {"AX-MS": 31}
    ax_rows = [{"artifact_id": "AX-MS", "artifact_name": "Installed Microsoft Programs", "category": "Application Usages"}]

    class FakeDb:
        def execute(self, *_args, **_kwargs):
            class Result:
                def mappings(self):
                    return self

                def all(self):
                    return ax_rows

            return Result()

    db = FakeDb()

    from app.services import artifact_sections as sections_mod

    original = sections_mod.collect_application_usage_title_counts
    sections_mod.collect_application_usage_title_counts = lambda _db, _jid: {"installed microsoft programs": 26}
    try:
        out = overlay_section_collector_counts(
            db,
            "job",
            "Windows",
            counts,
            include_connected_devices=False,
            include_communication_urls=False,
            include_documents=False,
            include_email=False,
            include_encryption=False,
            include_media=False,
            include_operating_system=False,
            include_web_related=False,
        )
    finally:
        sections_mod.collect_application_usage_title_counts = original

    assert out["AX-MS"] == 31
