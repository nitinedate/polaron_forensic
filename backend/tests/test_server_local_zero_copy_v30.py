from pathlib import Path

from app.services import host_evidence

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_browser_selection_resolver_matches_server_disk_by_name_and_exact_size(tmp_path, monkeypatch):
    drive = tmp_path / "usb"
    case = drive / "Ex-5 Histotechlab 512GB"
    case.mkdir(parents=True)
    (case / "Ex-5 Histotechlab 512GB.E01").write_bytes(b"a" * 11)
    (case / "Ex-5 Histotechlab 512GB.E02").write_bytes(b"b" * 17)

    monkeypatch.setattr(host_evidence, "_accessible_drive_roots", lambda: [drive])

    result = host_evidence.find_folder_with_segment_files(
        ["Ex-5 Histotechlab 512GB.E01", "Ex-5 Histotechlab 512GB.E02"],
        folder_hint="Ex-5 Histotechlab 512GB",
        relative_paths=[
            "Ex-5 Histotechlab 512GB/Ex-5 Histotechlab 512GB.E01",
            "Ex-5 Histotechlab 512GB/Ex-5 Histotechlab 512GB.E02",
        ],
        file_sizes={
            "Ex-5 Histotechlab 512GB.E01": 11,
            "Ex-5 Histotechlab 512GB.E02": 17,
        },
    )

    assert result["path"]
    assert result["segment_count"] == 2
    assert result["source_residency"] == "server_local"
    assert result["verified_by"] == "filename_size"


def test_browser_selection_resolver_rejects_same_name_with_wrong_size(tmp_path, monkeypatch):
    drive = tmp_path / "usb"
    case = drive / "Case"
    case.mkdir(parents=True)
    (case / "image.E01").write_bytes(b"x" * 10)
    (case / "image.E02").write_bytes(b"y" * 10)

    monkeypatch.setattr(host_evidence, "_accessible_drive_roots", lambda: [drive])

    result = host_evidence.find_folder_with_segment_files(
        ["image.E01", "image.E02"],
        folder_hint="Case",
        relative_paths=["Case/image.E01", "Case/image.E02"],
        file_sizes={"image.E01": 10, "image.E02": 999},
    )

    assert result["path"] is None


def test_frontend_resolves_server_local_disk_before_starting_download_agent():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    api = read("frontend/src/lib/forensicApi.ts")
    assert "resolveServerLocalDiskSelection" in panel
    assert "Checking server HDD/SSD/USB drives for this disk image before any transfer starts" in panel
    assert "Download skipped — processing .E01 directly from that disk" in panel
    assert "Disk-image upload is disabled on the forensic server" in panel
    assert "file_sizes: fileSizes" in panel
    assert "file_sizes?: Record<string, number>" in api


def test_server_local_registration_clears_old_upload_and_mobile_ownership_markers():
    host = read("backend/app/services/host_evidence.py")
    assert 'source_ds["source_type"] = "disk"' in host
    assert '"upload_status"' in host
    assert '"upload_expected_files"' in host
    assert '"upload_received_files"' in host
    assert 'source_ds.pop(upload_key, None)' in host
    assert 'or bool(mobile_meta.get("mobile_os"))' not in host


def test_disk_job_ui_does_not_become_android_or_ios_from_stale_metadata():
    stages = read("frontend/src/lib/orchestrationStages.ts")
    assert "A host_disk E01 must never be reclassified as Android/iOS" in stages
    assert 'if (String(ds.source_type || "").toLowerCase() === "mobile") return true;' in stages
    assert "return !type && mobileJobPlatform(job) != null;" in stages


def test_server_local_download_card_is_explicitly_zero_copy():
    backend = read("backend/app/services/pipeline_orchestrator.py")
    frontend = read("frontend/src/lib/orchestrationStages.ts")
    assert "Download skipped — server-local evidence is processed in place (zero copy)" in backend
    assert "Skipped — server-local HDD/SSD/USB evidence is processed in place (zero copy)." in frontend


def test_backend_refuses_client_upload_after_server_local_registration():
    jobs = read("backend/app/routers/jobs.py")
    assert '"code": "server_local_zero_copy"' in jobs
    assert "Client upload refused: this evidence is already registered" in jobs
    assert 'str(current_ds.get("source_residency") or "").strip().lower() == "server_local"' in jobs


def test_action_huddle_calls_server_local_download_a_skip_not_a_transfer():
    agents = read("backend/app/services/action_agents.py")
    assert "Download skipped — server-local evidence stays on the HDD/SSD/USB host path (zero copy)" in agents


def test_server_local_selection_clears_stale_browser_upload_activity():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    session = read("frontend/src/lib/jobUploadSession.ts")
    assert "jobUploadSession.markServerLocalZeroCopy(jobId)" in panel
    assert "markServerLocalZeroCopy(jobId: string): boolean" in session
    assert "Download Agent was not started" in session
