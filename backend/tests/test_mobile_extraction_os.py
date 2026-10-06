"""Tests for Mobile Extraction OS select, capability labels, and import adapters."""

from __future__ import annotations

from app.services.mobile_adapters.registry import build_import_collection_summary, select_import_adapter
from app.services.mobile_capability import evaluate_mobile_capability
from app.services.mobile_os import (
    build_mobile_disk_source_seed,
    merge_mobile_meta_into_disk_source,
    mobile_os_to_axiom_platform,
    normalize_mobile_os,
)
from app.services.mobile_segments import infer_mobile_axiom_platform


def test_normalize_mobile_os():
    assert normalize_mobile_os("Android") == "android"
    assert normalize_mobile_os("iOS") == "ios"
    assert normalize_mobile_os("Other / Unknown") == "other"
    assert normalize_mobile_os("") is None


def test_mobile_os_to_axiom_platform():
    assert mobile_os_to_axiom_platform("android") == "Android"
    assert mobile_os_to_axiom_platform("ios") == "iOS"
    assert mobile_os_to_axiom_platform("other") is None


def test_examiner_os_overrides_filename_inference():
    # Filenames look Android, examiner selected iOS.
    platform = infer_mobile_axiom_platform(
        evidence_names=["28_01_2025Vivo.pas", "28_01_2025Vivo.pas001"],
        disk_format="pas",
        examiner_mobile_os="ios",
    )
    assert platform == "iOS"


def test_inference_used_when_examiner_os_other():
    platform = infer_mobile_axiom_platform(
        evidence_names=["28_01_2025Vivo.pas"],
        disk_format="pas",
        examiner_mobile_os="other",
    )
    assert platform == "Android"


def test_capability_supported_import_for_pas():
    cap = evaluate_mobile_capability(
        mobile_os="android",
        acquisition_mode="import",
        evidence_names=["device.pas", "device.pas001"],
    )
    assert cap["capability_label"] == "SUPPORTED_IMPORT"
    assert "import" in cap["permitted_actions"]
    assert "pas" in cap["detected_formats"]


def test_capability_os_mismatch_warning():
    cap = evaluate_mobile_capability(
        mobile_os="ios",
        acquisition_mode="import",
        evidence_names=["samsung_backup.pas"],
    )
    assert cap["capability_label"] == "SUPPORTED_IMPORT"
    assert cap.get("os_mismatch_warning")
    assert "Examiner selected iOS" in cap["os_mismatch_warning"]


def test_live_device_external_tool_required():
    cap = evaluate_mobile_capability(mobile_os="android", live_device=True)
    assert cap["capability_label"] == "EXTERNAL_TOOL_REQUIRED"


def test_select_ufed_adapter_for_pas():
    adapter = select_import_adapter(names=["export.pas", "export.pas001"], mobile_os="android")
    assert adapter.name == "import_ufed"


def test_select_zip_adapter():
    adapter = select_import_adapter(names=["vivo_export.zip"], mobile_os="android")
    assert adapter.name == "import_zip"


def test_collection_summary_provenance_import():
    summary = build_import_collection_summary(
        names=["export.ufd"],
        mobile_os="android",
        capability={"capability_label": "SUPPORTED_IMPORT", "detected_formats": ["ufd"]},
    )
    assert summary["provenance"] == "import"
    assert summary["immutable_original"] is True
    assert summary["adapter"] == "import_ufed"


def test_disk_source_seed_and_merge_preserves_examiner_os():
    seed = build_mobile_disk_source_seed(
        mobile_os="android",
        legal_authority_acknowledged=True,
        capability={"capability_label": "SUPPORTED_IMPORT", "reasons": [], "permitted_actions": ["import"]},
    )
    assert seed["mobile_os"] == "android"
    assert seed["os_selection_source"] == "examiner"
    assert seed["axiom_platform"] == "Android"

    mount = {"mounted": True, "format": "pas", "mode": "folder"}
    merged = merge_mobile_meta_into_disk_source(mount, seed)
    assert merged["mobile_os"] == "android"
    assert merged["axiom_platform"] == "Android"
    assert merged["mounted"] is True

    # Inference must not overwrite examiner OS.
    overwritten = merge_mobile_meta_into_disk_source(
        merged,
        {"mobile_os": "ios", "os_selection_source": "inferred", "axiom_platform": "iOS"},
    )
    assert overwritten["mobile_os"] == "android"
    assert overwritten["os_selection_source"] == "examiner"
    assert overwritten["axiom_platform"] == "Android"
