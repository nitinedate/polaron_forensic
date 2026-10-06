from __future__ import annotations

from pathlib import Path

from app.services.mobile_acquire import run_registry as rr


def test_file_count_uses_inventory_totals_without_walking_disk():
    data = {
        "ok": False,
        "errors": [],
        "acquisition_record": {"file_count": 0, "output_size": 0},
        "content_inventory": {"totals": {"files": 24151, "bytes": 55716008407}},
        "evidence_package": {"file_count": 0, "complete": False, "extraction_data": []},
    }
    assert rr._result_file_count(data) == 24151
    assert rr._result_output_size(data) == 55716008407
    out = rr._normalize_result(data)
    assert out["ok"] is True
    assert out["stage_reached"] == "complete"
    assert out["evidence_package"]["file_count"] == 24151
    assert out["evidence_package"]["complete"] is True


def test_recover_summary_does_not_rglob_original(tmp_path: Path, monkeypatch):
    case_id = "CASE-20260921-OPPOA5PRO5"
    case_root = tmp_path / "cases"
    logs = case_root / case_id / "07_Logs" / f"{case_id}_RUN"
    logs.mkdir(parents=True)
    original = case_root / case_id / "02_Original_Extraction" / f"{case_id}_RUN"
    original.mkdir(parents=True)
    (original / "never-walk-me.bin").write_bytes(b"x")
    (logs / "collection_summary.json").write_text(
        '{"ok": true, "run_name": "%s_RUN", "file_count": 24151, '
        '"acquisition_record": {"file_count": 24151, "output_size": 55}, '
        '"errors": [], "paths": {"original": "%s"}}'
        % (case_id, str(original).replace("\\", "\\\\")),
        encoding="utf-8",
    )

    original_rglob = Path.rglob

    def guarded(self: Path, pattern: str):
        resolved = self.resolve()
        if original.resolve() == resolved or original.resolve() in resolved.parents:
            raise AssertionError("recover must not walk the original tree")
        return original_rglob(self, pattern)

    monkeypatch.setattr(Path, "rglob", guarded)
    result = rr._recover_summary_from_disk(str(case_root), case_id)
    assert result is not None
    assert result["ok"] is True
    assert result["acquisition_record"]["file_count"] == 24151


def test_case_root_candidates_include_f_drive_evidence():
    paths = [str(p).replace("\\", "/").lower() for p in rr._case_root_candidates("/evidence/cases")]
    assert any(p.endswith("/host/f/evidence/cases") or p.endswith("f:/evidence/cases") for p in paths)
    known = [str(p).replace("\\", "/").lower() for p in rr._known_evidence_case_roots()]
    assert any("f:" in p or "/host/f/" in p for p in known)


def test_adapter_for_oppo_stays_android():
    assert (
        rr._adapter_for_recovered(
            {"device_profile": {"os_family": "android"}},
            "CASE-20260921-OPPOA5PRO5_E-764759_OPPO_A5_Pro_5G_FFS_20260921_201702",
            "CASE-20260921-OPPOA5PRO5",
        )
        == "android_adb"
    )
    assert (
        rr._adapter_for_recovered(
            {},
            "CASE-20260921-APPLEIPHON_E-590401_Apple_iPhone_ADVANCED_LOGICAL",
            "CASE-20260921-APPLEIPHON",
        )
        == "ios_lockdown"
    )
