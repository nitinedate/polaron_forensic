from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_dynamic_drive_file_is_override_not_include():
    for name in ("docker-compose.yml", "docker-compose.https.yml"):
        data = yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))
        assert "docker-compose.drives.generated.yml" not in (data.get("include") or [])


def test_generated_drive_override_only_adds_host_letter_targets():
    data = yaml.safe_load(
        (ROOT / "docker-compose.drives.generated.yml").read_text(encoding="utf-8-sig")
    )
    expected_services = {"api", "worker-disk", "worker-mobile", "worker-report"}
    assert set(data["services"]) == expected_services

    for service in expected_services:
        mounts = data["services"][service]["volumes"]
        assert mounts
        for mount in mounts:
            assert mount["type"] == "bind"
            assert mount["target"].startswith("/host/")
            assert mount["read_only"] is True
            assert mount["bind"]["create_host_path"] is False


def test_drive_generator_scans_all_letters_and_uses_safe_bind_syntax():
    script = (ROOT / "scripts" / "generate-drive-mounts.ps1").read_text(encoding="utf-8")
    assert "([int][char]'A')..([int][char]'Z')" in script
    assert "[string[]]$RequireDrive" in script
    assert "create_host_path: false" in script
    assert "@('F', 'G', 'H', 'I', 'J')" not in script


def test_helper_quotes_required_path_for_background_process():
    script = (ROOT / "scripts" / "host-drive-helper.ps1").read_text(encoding="utf-8")
    assert "function Format-CommandLineArgument" in script
    assert "(Format-CommandLineArgument $required)" in script
    assert "(Format-CommandLineArgument $root)" in script
    # A trailing slash must be doubled so "G:\" is not parsed as G:" .
    assert "('\\' * ($tail * 2))" in script
    job = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")
    assert "function Repair-CorruptedDriveRootPath" in job


def test_drive_generator_powershell_yaml_source_quoting_is_valid():
    script = (ROOT / "scripts" / "generate-drive-mounts.ps1").read_text(encoding="utf-8")
    # Source paths can now be Windows direct paths or WSL bridge paths. YAML
    # single-quoted scalars preserve backslashes literally and safely escape '.
    assert "function Convert-ToYamlSingleQuoted" in script
    assert "source: {0}" in script
    assert "SourceMapPath" in script
    assert 'source: \\"${letter}:/\\"' not in script


def test_drive_resolver_has_content_probe_and_wsl_drvfs_fallback():
    script = (ROOT / "scripts" / "resolve-docker-drive-source.ps1").read_text(encoding="utf-8")
    assert "target.exists()" in script
    assert "mount -t drvfs" in script
    assert "mount -t drvfs -o metadata,ro" in script
    assert "mount -t drvfs -o ro" in script
    # Current WSL builds can reject ro/metadata combinations on some removable
    # filesystems, so the resolver also has a plain DrvFs fallback. Container
    # mounts remain read-only regardless of backing-bridge mode.
    assert "mount -t drvfs $qDrive $qMount" in script
    assert "__AETHERIS_BRIDGE_MODE__" in script
    assert "/mnt/aetheris-host-drives/" in script
    assert "readonly" in script
    assert "ForceWslBridge" in script


def test_refresh_job_detects_active_compose_and_verifies_exact_path():
    script = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")
    assert "com.docker.compose.project.config_files" in script
    assert "docker-compose.https.yml" in script
    assert "Test-RequiredPathInContainer" in script
    assert "resolve-docker-drive-source.ps1" in script
    assert "powershell.exe -File cannot reliably pass multiple" in script


def test_wsl_fallback_uses_docker_desktop_wsl_integration_and_wsl_compose():
    generator = (ROOT / "scripts" / "generate-drive-mounts.ps1").read_text(encoding="utf-8")
    refresh = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")
    resolver = (ROOT / "scripts" / "resolve-docker-drive-source.ps1").read_text(encoding="utf-8")

    # v4.4 must probe Docker from the same WSL distro that owns the DrvFs mount.
    assert "function Test-WslDockerIntegration" in resolver
    assert "function Test-DockerSourceViaWsl" in resolver
    assert "wsl.exe -d $Distro --exec docker run" in resolver
    assert 'mode           = "wsl-compose"' in resolver
    assert "Docker Desktop WSL Integration" in resolver

    # When that mode wins, Compose itself also runs through WSL integration;
    # do not try to treat the Ubuntu mount as a daemon-local volume.
    assert '[ValidateSet("Windows", "Wsl")][string]$ExecutionMode' in generator
    assert "$ExecutionMode -eq 'Wsl'" in generator
    assert "docker-compose.drives.wsl.generated.yml" in refresh
    assert "wsl.exe -d $WslDistro --exec docker @cargs up" in refresh
    assert "-ExecutionMode Wsl" in refresh


def test_windows_daemon_path_strategy_is_not_used_for_wsl_compose_mode():
    refresh = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")
    # Legacy direct daemon paths can still use local volumes, but the new WSL
    # execution branch explicitly skips Ensure-DaemonPathVolumes.
    branch = refresh.split("if ($wslDistro) {", 1)[1].split("$letters = @($final.letters)", 1)[0]
    assert "Ensure-DaemonPathVolumes" not in branch.split("else {", 1)[0]

def test_refresh_verifies_selected_path_in_all_forensic_services():
    script = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")
    for service in ("api", "worker-disk", "worker-mobile", "worker-report"):
        assert service in script
    assert "cannot read the selected evidence path" in script


def test_picker_does_not_open_receiving_modal_before_mount_verification():
    panel = (ROOT / "frontend" / "src" / "components" / "forensic" / "HostEvidencePanel.tsx").read_text(encoding="utf-8")
    native = panel.split("const onNativeFolderSelected", 1)[1].split("async function registerPickedFolder", 1)[0]
    staged = panel.split("const confirmStagedBrowseFolders", 1)[1].split("const onNativeFolderSelected", 1)[0]
    assert "beginReceivingSegments();" not in native
    assert "beginReceivingSegments();" not in staged
    ingest = panel.split("async function ingestAtResolvedPath", 1)[1].split("async function startLiveExtraction", 1)[0]
    assert "ensureOfficePathMounted" in ingest
    assert ingest.index("ensureOfficePathMounted") < ingest.index("beginReceivingSegments();")
    retry = panel.split("registerManualPath: () => {", 1)[1].split("registerHostPath:", 1)[0]
    assert "ingestHostPathRef.current(saved" in retry
    assert "recalledEvidenceFolder" in retry
    assert "shouldRefuseBrowserCopy" in panel
    assert "if (sourceType === \"disk\") return true" not in panel
    assert "uploadClientFiles" in panel
    assert 'folder.intake !== "office"' in panel
    assert "Uploading the selected folder from this computer" in panel

    browse = panel.split("async function registerFromBrowse", 1)[1].split("async function registerFolderAt", 1)[0]
    assert "ensureOfficePathMounted" in browse
    assert browse.index("ensureOfficePathMounted") < browse.index("beginReceivingSegments();")


def test_v4_deploy_script_targets_windows_powershell_51_and_preserves_data():
    script = (ROOT / "scripts" / "deploy-dynamic-drive-v4.ps1").read_text(encoding="utf-8")
    assert "??" not in script
    assert "docker compose down" not in script.lower()
    assert "down -v" not in script.lower()
    assert "ConvertFrom-Json" in script
    assert "com.docker.compose.project.config_files" in script
    assert "Invoke-ExactRefresh" in script


def test_drive_generator_emits_letters_on_success_stream_and_refresh_has_yaml_fallback():
    generator = (ROOT / "scripts" / "generate-drive-mounts.ps1").read_text(encoding="utf-8")
    refresh = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")
    # Windows PowerShell 5.1 Write-Host is not the normal success/output stream.
    # The refresh job captures the success stream, so Letters must be Write-Output.
    assert "Write-Output \"Letters: $($letters -join ', ')\"" in generator
    # Even if stream semantics change again, the generated Compose file remains
    # authoritative and lets the refresh job recover the actual letters.
    assert "target:\\s*/host/([a-zA-Z])" in refresh
    assert "$yamlPath = if ($OutputPath) { $OutputPath } else { $composeDrives }" in refresh
    assert "if (-not $letters.Count -and (Test-Path -LiteralPath $yamlPath))" in refresh


def test_windows_powershell_51_dynamic_drive_scripts_avoid_new_object_generic_list_array_bug():
    """Regression for Windows PowerShell 5.1 'Argument types do not match'.

    PowerShell can fail when @($list) wraps a Generic List created through
    New-Object. The drive resolver/refresh path runs under Windows PowerShell,
    so use plain arrays/hashtables there instead.
    """
    resolver = (ROOT / "scripts" / "resolve-docker-drive-source.ps1").read_text(encoding="utf-8")
    refresh = (ROOT / "scripts" / "refresh-drive-mounts-job.ps1").read_text(encoding="utf-8")

    assert "New-Object System.Collections.Generic.List" not in resolver
    assert "New-Object System.Collections.Generic.List" not in refresh
    assert "$attempts = @()" in resolver
    assert "$ordered = @()" in resolver
    assert "return $ordered" in resolver
    assert "$excluded = @()" in refresh
    assert "$resolutionLog = @()" in refresh


def test_e2e_drive_test_understands_wsl_compose_mode():
    script = (ROOT / "scripts" / "test-dynamic-drive-mounts.ps1").read_text(encoding="utf-8")
    assert "docker-compose.drives.wsl.generated.yml" in script
    assert "if ($state.mount_mode -eq 'wsl-compose')" in script
    assert "wsl.exe -d ([string]$state.wsl_distro) --exec docker @wslArgs config --quiet" in script
    assert "docker exec $id python -c $probeCode" in script
