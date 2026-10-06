from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_same_host_drive_listing_prefers_windows_helper_before_api():
    src = _read("frontend/src/lib/hostDriveHelper.ts")
    fn = src.split("export async function listOfficeServerDriveLetters", 1)[1].split(
        "export async function listOfficeServerDirectory", 1
    )[0]
    assert "listOfficeHostDriveLettersDirect" in fn
    assert '"/api/hostdrive/drives"' in fn
    assert fn.index("listOfficeHostDriveLettersDirect") < fn.index('"/api/hostdrive/drives"')


def test_server_browse_ui_is_explicit_and_zero_copy():
    src = _read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    assert "Server drives — HDD / SSD / USB / network — process in place" in src
    assert "Detection is read-only" in src
    assert "Use this folder" in src
    assert "Refresh server drives" in src
    assert "Start HostDrive helper" in src


def test_drive_presence_watchers_do_not_automatically_recreate_docker():
    helper = _read("scripts/host-drive-helper.ps1")
    block = helper.split("function Start-DrivePresenceWatcher {", 1)[1].split(
        "function Resolve-MobileOsHint", 1
    )[0]
    assert "Start-RefreshDriveMountsAsync" not in block
    assert "/refresh-drive-mounts" in block  # documentation of the removed old behavior
    assert "recreate Docker/API containers" in block

    agent = _read("scripts/hostdrive-agent.ps1")
    loop = agent.split('Write-Host "[HostDrive agent] Watching for new drives', 1)[1]
    assert "does NOT call Invoke-RefreshMounts here" in loop
    # The explicit -RefreshNow code remains before the watcher; the watcher body
    # itself must not invoke a remount when a letter changes.
    changed = loop.split('Write-Host "[HostDrive agent] Drive set changed:', 1)[1]
    assert "Invoke-RefreshMounts | Out-Null" not in changed


def test_job_polling_pauses_during_exact_drive_mount():
    src = _read("frontend/src/pages/forensic/JobDetailPage.tsx")
    assert 'registerProgress.phase === "mounting"' in src
    assert 'active={!pollStopped && registerProgress.phase !== "mounting"}' in src


def test_browse_registration_marks_mounting_before_helper_remount():
    src = _read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    block = src.split("async function registerFromBrowse", 1)[1].split(
        "async function registerHost", 1
    )[0]
    assert 'phase: "mounting"' in block
    assert block.index('phase: "mounting"') < block.index("ensureOfficePathMounted(exactPath)")


def test_v39_helper_versions_force_old_windows_process_restart():
    helper = _read("scripts/host-drive-helper.ps1")
    ensure = _read("scripts/ensure-host-drive-helper.ps1")
    assert '$script:HelperVersion = "5.39"' in helper
    assert '$ExpectedHelperVersion = "5.39"' in ensure


def test_start_stack_replaces_legacy_auto_remount_agent():
    src = _read("scripts/start-stack.ps1")
    assert "install-hostdrive-agent.ps1" in src
    assert "V39 HostDrive detection agent" in src
