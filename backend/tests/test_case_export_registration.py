"""Regression: registering a case-layout iPhone run must find the 05_Exports payload.

Reproduces the examiner-facing error
``No registerable evidence found at the selected location. Folder listing found
0 item(s)`` — the analysis job was pointed at an empty 03_Working_Copy/<run>
folder while export_catalog.json + 22 payload shards sat in 05_Exports/<run>.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from app.services import host_evidence as he
from app.services import mobile_segments as ms

RUN = "CASE-20260921-APPLEIPHON_E-590401_Apple_iPhone_ADVANCED_LOGICAL_20260921_222644"


@pytest.fixture
def case_tree(tmp_path: Path, monkeypatch):
    import app.services.dir_walk as dw

    monkeypatch.setattr(dw, "HOST_MOUNT", tmp_path)
    case = tmp_path / "e" / "projects" / "aetheris_project" / "evidence" / "cases" / "CASE-20260921-APPLEIPHON"
    for sub in ("02_Original_Extraction", "03_Working_Copy", "05_Exports", "07_Logs"):
        (case / sub / RUN).mkdir(parents=True)
    exp = case / "05_Exports" / RUN
    (exp / "readable_artifacts").mkdir()
    shards = []
    for i in range(22):
        p = exp / f"{RUN}.part-{i:05d}.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("02_Original_Extraction/x.txt", "x")
        shards.append(f"E:\\projects\\aetheris_project\\evidence\\cases\\CASE-20260921-APPLEIPHON\\05_Exports\\{RUN}\\{p.name}")
    for ext in (".pas", ".ufd", ".ufdx"):
        with zipfile.ZipFile(exp / f"{RUN}{ext}", "w") as z:
            z.writestr("manifest.xml", "<x/>")
    with zipfile.ZipFile(exp / f"{RUN}.zip", "w") as z:  # 4 MB metadata zip in production
        z.writestr("export_catalog.json", "{}")
    (exp / "export_catalog.json").write_text(json.dumps({"run_name": RUN, "payload_shards": shards}))
    (exp / "content_inventory.json").write_text("{}")
    return case


@pytest.mark.parametrize("sub", ["03_Working_Copy", "02_Original_Extraction", "05_Exports"])
@pytest.mark.parametrize("source_type", ["disk", "mobile"])
def test_case_run_folder_resolves_to_payload_shards(case_tree, sub, source_type):
    folder = case_tree / sub / RUN
    files = he._collect_segment_files(folder, None, source_type)
    assert len(files) == 22
    assert files[0].name.endswith(".part-00000.zip")
    assert files[-1].name.endswith(".part-00021.zip")
    # metadata-only full zip and companions are not mixed into the shard set
    assert all(".part-" in f.name for f in files)


def test_case_root_and_exports_root_resolve(case_tree):
    assert len(he._collect_segment_files(case_tree, None, "disk")) == 22
    assert len(he._collect_segment_files(case_tree / "05_Exports", None, "disk")) == 22


def test_listing_is_shallow_and_fast_for_case_run(case_tree):
    work = case_tree / "03_Working_Copy" / RUN
    entries = he._walk_folder_entries(work)
    names = {e["name"] for e in entries}
    assert f"{RUN}.part-00000.zip" in names
    assert "export_catalog.json" in names
    assert "readable_artifacts" in names  # listed as a dir, never walked
    assert he.folder_lists_fast(work)
    assert he.folder_lists_fast(case_tree / "05_Exports" / RUN)


def test_companions_only_when_no_shards(case_tree):
    exp = case_tree / "05_Exports" / RUN
    for p in exp.glob("*.part-*.zip"):
        p.unlink()
    (exp / "export_catalog.json").write_text(json.dumps({"payload_shards": []}))
    files = ms.case_export_segment_paths(exp)
    # the metadata zip has no payload → fall back to .pas/.ufd/.ufdx companions
    assert {f.suffix for f in files} == {".pas", ".ufd", ".ufdx"}


def test_plain_disk_folder_unchanged(tmp_path):
    d = tmp_path / "disk"
    d.mkdir()
    for n in ("img.E01", "img.E02"):
        (d / n).write_bytes(b"x")
    assert [f.name for f in he._collect_segment_files(d, None, "disk")] == ["img.E01", "img.E02"]
    assert he._collect_segment_files(tmp_path / "nothing_here", None, "disk") == []


# ---------------------------------------------------------------------------
# V22: four-file export layout (<run>.zip/.ufd/.pas/.ufdx only; sidecars in 07_Logs)
# ---------------------------------------------------------------------------

def _make_original(case: Path, run: str) -> Path:
    import os

    orig = case / "02_Original_Extraction" / run
    for d in (orig / "ios_image" / "UDID", orig / "afc_media" / "DCIM", orig / "readable_artifacts" / "whatsapp"):
        d.mkdir(parents=True)
    (orig / "ios_image" / "UDID" / "Manifest.db").write_bytes(os.urandom(2048))
    for i in range(3):
        (orig / "afc_media" / "DCIM" / f"IMG_{i}.JPG").write_bytes(os.urandom(10_000))
    (orig / "readable_artifacts" / "whatsapp" / "ChatStorage.sqlite").write_bytes(os.urandom(512))
    return orig


def test_export_writes_exactly_four_files(tmp_path: Path, monkeypatch):
    import app.services.dir_walk as dw
    from app.services.mobile_acquire import export_cli

    monkeypatch.setattr(dw, "HOST_MOUNT", tmp_path)
    monkeypatch.delenv("AETHERIS_EXPORT_SHARDS", raising=False)
    case = tmp_path / "e" / "cases" / "CASE-T"
    run = "CASE-T_E-1_Apple_iPhone_ADVANCED_LOGICAL_20260922_010101"
    orig = _make_original(case, run)
    exp = case / "05_Exports" / run
    logs = case / "07_Logs" / run
    work = case / "03_Working_Copy" / run
    for d in (exp, logs, work):
        d.mkdir(parents=True)
    (exp / "content_inventory.json").write_text("{}")  # legacy leftover

    assert export_cli.main(["--original", str(orig), "--exports", str(exp), "--logs", str(logs), "--full"]) == 0

    assert sorted(p.suffix for p in exp.iterdir()) == [".pas", ".ufd", ".ufdx", ".zip"]
    assert all(p.is_file() and p.stem == run for p in exp.iterdir())
    assert (logs / "export_catalog.json").is_file()
    assert (logs / "content_inventory.json").is_file()
    with zipfile.ZipFile(exp / f"{run}.zip") as z:
        names = z.namelist()
    assert sum(n.startswith("02_Original_Extraction/") for n in names) == 4
    assert any(n.startswith("readable_artifacts/whatsapp/") for n in names)

    # analysis side resolves every case folder to the single zip
    for folder in (work, exp, orig, case):
        assert [f.name for f in he._collect_segment_files(folder, None, "disk")] == [f"{run}.zip"]
    assert he.folder_lists_fast(work)
    assert [p.name for p in ms.list_payload_zip_archives(work, [str(work)])] == [f"{run}.zip"]
