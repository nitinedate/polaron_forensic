from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_required_drive_is_kept_for_exact_path_resolution_before_root_bind_succeeds():
    generator = read("scripts/generate-drive-mounts.ps1")
    refresh = read("scripts/refresh-drive-mounts-job.ps1")
    assert "KeepRequiredForResolution" in generator
    assert "$requested -contains $letter" in generator
    assert "-KeepRequiredForResolution" in refresh
    # Exact selected path resolution must happen after the first discovery pass.
    assert "Invoke-DriveSourceResolver -Letter $letter -ExactPath $exact" in refresh


def test_selected_file_can_be_bound_as_narrow_read_only_parent_folder():
    resolver = read("scripts/resolve-docker-drive-source.ps1")
    generator = read("scripts/generate-drive-mounts.ps1")
    assert "function Get-ExactMountPlan" in resolver
    assert 'mode           = "docker-exact-path"' in resolver
    assert 'source_scope   = "selected-folder"' in resolver
    assert "sibling E02/E03 segments remain" in resolver
    assert "mount_target" in generator
    assert "read_only: true" in generator


def test_exact_path_mount_does_not_require_whole_host_drive_root_mount():
    refresh = read("scripts/refresh-drive-mounts-job.ps1")
    assert "Test-IsExactPathMount" in refresh
    assert "$rootVerifyLetters" in refresh
    assert "Get-StateMountTarget" in refresh
    assert "Test-RequiredPathInContainer -Path $normalizedRequiredPath" in refresh


def test_server_source_clears_client_download_activity_and_client_source_is_explicit():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    session = read("frontend/src/lib/jobUploadSession.ts")
    page = read("frontend/src/pages/forensic/JobDetailPage.tsx")
    activity = read("frontend/src/components/forensic/JobActivityPanel.tsx")
    assert "resetForServerSource" in session
    assert 'onSourceModeChange?.("server")' in panel
    assert 'onSourceModeChange?.("client")' in panel
    assert 'showUploadActivity={evidenceTransferMode === "client"}' in page
    assert "showUploadActivity &&" in activity


def test_disk_pipeline_download_stage_exists_only_for_browser_upload_intake():
    stages = read("frontend/src/lib/orchestrationStages.ts")
    assert 'const clientUpload = String(ds.intake || "") === "browser_upload"' in stages
    assert 'if (!mobile && id === "download_agent") return clientUpload' in stages


def test_mount_failure_surfaces_background_refresh_error():
    agent = read("backend/app/services/drive_mount_agent.py")
    assert "refresh_failed" in agent
    assert 'result["refresh_error"]' in agent
    assert "Mount recovery detail:" in agent


def test_manual_server_path_repair_script_is_powershell_51_compatible():
    script = read("scripts/repair-server-evidence-path.ps1")
    assert "refresh-drive-mounts-job.ps1" in script
    assert "-RequiredPath $RequiredPath" in script
    assert "??" not in script
    assert "Test-Path -LiteralPath $RequiredPath" in script


def test_backend_persists_transport_boundary_in_job_metadata():
    evidence = read("backend/app/services/host_evidence.py")
    assert '"source_origin": "server_accessible"' in evidence
    assert '"transport_mode": "zero_copy"' in evidence
    assert '"source_origin": "client_browser"' in evidence
    assert '"transport_mode": "staged_upload"' in evidence


def test_first_pass_drive_discovery_does_not_overwrite_active_compose_override():
    refresh = read("scripts/refresh-drive-mounts-job.ps1")
    assert 'docker-compose.drives.detect.yml' in refresh
    first = refresh.split("# Discovery writes to a disposable override", 1)[1].split("$detectedLetters", 1)[0]
    assert "-OutputPath $detectCompose" in first
    assert "-KeepRequiredForResolution" in first
