from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_job_detail_disk_does_not_hide_server_browser_in_auto_process_mode():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    assert "const fullyAutomated = embedded && autoProcess && isLiveMobileSource" in panel
    assert "Server evidence browser — zero-copy" in panel
    assert "Detect server drives" in panel


def test_server_drive_inventory_is_not_gated_by_client_localhost_helper():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    root = panel.split("if (isBrowseRoot(opts))", 1)[1].split("applyBrowse", 1)[0]
    assert "listHostDriveLetters" in root
    assert "hostDriveHelperHealth" not in root


def test_new_attached_server_drive_triggers_sync_attached_mount():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    assert "syncAttached: !opts?.requiredPath" in panel
    assert "syncAttached: true" in dialog
    assert "Server drive(s)" in panel and "mounting read-only" in panel


def test_server_drive_poll_does_not_require_browser_helper_cache():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    block = panel.split("const pollExternalDrives", 1)[1].split("const id =", 1)[0]
    assert "getCachedHelperOnline" not in block
    assert "syncDriveMountsIfNeeded" in block


def test_parse_worker_is_part_of_dynamic_remount_target():
    refresh = read("scripts/refresh-drive-mounts-job.ps1")
    generator = read("scripts/generate-drive-mounts.ps1")
    assert "@('api', 'worker-disk', 'worker-parse', 'worker-report', 'worker-agent')" in refresh
    assert "aetheris-mobile-android" in refresh
    assert "@('api', 'worker-build', 'worker-parse')" in refresh
    assert "@('api', 'worker-disk', 'worker-parse', 'worker-mobile', 'worker-report', 'worker-agent')" in generator
