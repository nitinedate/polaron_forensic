"""Tests for AXIOM-aligned artifact counting helpers."""

from app.services.axiom_aligned_counts import (
    DOCUMENT_EXTENSIONS,
    _DOCUMENT_EXTENSIONS,
    _normalized_extensions,
    _norm_axiom_name,
    _setupapi_device_key,
    _usb_record_key,
)


def test_normalized_extensions() -> None:
    assert _normalized_extensions(["pdf", ".DOCX"]) == [".pdf", ".docx"]


def test_shim_exports_document_extensions() -> None:
    """Star-import shim must still expose document maps used by browse/export."""
    assert DOCUMENT_EXTENSIONS["csv documents"] == [".csv"]
    assert _DOCUMENT_EXTENSIONS is DOCUMENT_EXTENSIONS
    assert _norm_axiom_name("  USB   Devices ") == "usb devices"
    # The live API error was exactly this import form.
    from app.services.axiom_aligned_counts import _DOCUMENT_EXTENSIONS as imported

    assert imported["pdf documents"] == [".pdf"]


def test_usb_record_key_distinguishes_instances() -> None:
    a = {"bus": "USBSTOR", "class_id": "Disk&Ven_SanDisk", "serial": "123", "device_name": "Drive A"}
    b = {"bus": "USBSTOR", "class_id": "Disk&Ven_SanDisk", "serial": "456", "device_name": "Drive B"}
    assert _usb_record_key(a) != _usb_record_key(b)


def test_setupapi_device_key_extracts_usbstor() -> None:
    did = r"USBSTOR\Disk&Ven_Kingston&Prod_DT101G2&Rev_\1234567890&0"
    assert "usbstor" in _setupapi_device_key(did)


def test_compute_axiom_artifact_counts_maps_all_section_items() -> None:
    from app.services.axiom_catalog_ingest import compute_axiom_artifact_counts

    ax_rows = [
        {"artifact_id": "AX-0143", "artifact_name": "USB Devices", "category": "Connected Devices"},
        {"artifact_id": "AX-0009", "artifact_name": "Feature Usage", "category": "Application Usage"},
        {"artifact_id": "AX-9999", "artifact_name": "Obscure App Cache", "category": "Application Usage"},
    ]

    class FakeDb:
        def execute(self, *_args, **_kwargs):
            class Result:
                def mappings(self):
                    return self

                def all(self):
                    return ax_rows

            return Result()

    db = FakeDb()

    from app.services import axiom_aligned_counts as aligned_mod

    original_counter = aligned_mod.count_axiom_catalog_artifact

    def _fake_counter(_db, _jid, *, artifact_name, category):
        name = (artifact_name or "").lower()
        if "usb" in name:
            return 39
        if "feature usage" in name:
            return 42
        return 7

    aligned_mod.count_axiom_catalog_artifact = _fake_counter
    try:
        out = compute_axiom_artifact_counts(db, "job", "Windows")
    finally:
        aligned_mod.count_axiom_catalog_artifact = original_counter

    assert out["AX-0143"] == 39
    assert out["AX-0009"] == 42
    assert out["AX-9999"] == 7


def test_merge_live_collector_still_prefers_higher_usb() -> None:
    from app.services.axiom_catalog_ingest import overlay_section_collector_counts

    counts = {"AX-0143": 26}
    ax_rows = [{"artifact_id": "AX-0143", "artifact_name": "USB Devices", "category": "Connected Devices"}]

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

    assert out["AX-0143"] == 39
