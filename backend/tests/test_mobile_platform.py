"""Mobile platform detection and extract filter tests."""

from __future__ import annotations

from app.services.artifact_selection_catalog import resolve_job_axiom_platform
from app.services.extract_filters import matches_forensic_include, matches_mobile_forensic_include
from app.services.mobile_segments import infer_mobile_axiom_platform
from app.services.os_detect import detect_os_from_paths


def test_infer_mobile_platform_from_vivo_names():
    assert infer_mobile_axiom_platform(
        evidence_names=["28_01_2025Vivo.pas", "vivo_V2403.ufd"],
        disk_format="pas",
    ) == "Android"


def test_android_os_detect_from_dump_paths():
    os_info = detect_os_from_paths([
        {"path": "vivo_V2403.zip/Dump/apex/com.android.tethering/bin/ethtool"},
        {"path": "vivo_V2403.zip/data/data/com.whatsapp/databases/msgstore.db"},
    ])
    assert os_info["family"] == "android"
    assert os_info["confidence"] in ("medium", "high")


def test_mobile_forensic_include_android_db():
    assert matches_mobile_forensic_include("vivo_V2403.zip/data/data/com.whatsapp/databases/msgstore.db")
    assert matches_forensic_include(
        "vivo_V2403.zip/data/data/com.whatsapp/databases/msgstore.db",
        os_family="android",
    )


def test_resolve_job_axiom_platform_mobile(monkeypatch):
    class FakeDB:
        pass

    db = FakeDB()

    def fake_fetchone(_db, sql, params):
        return {
            "disk_source": {"format": "pas", "detected_os": {"family": "unknown"}},
            "evidence_names": ["28_01_2025Vivo.pas", "vivo_V2403.zip"],
            "host_paths": ["/host/e/data/MOBILE/FileSystem 01/28_01_2025Vivo.pas"],
        }

    monkeypatch.setattr("app.services.artifact_selection_catalog.fetchone", fake_fetchone)
    assert resolve_job_axiom_platform(db, "job-1") == "Android"
