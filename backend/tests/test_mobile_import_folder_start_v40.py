from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_mobile_folder_picker_uses_server_drive_browser_not_windows_file_open():
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    assert "Use this directory" in dialog
    assert "Available drives" in dialog
    assert "listOfficeServerDriveLetters" in dialog
    # Must not open a Windows file Open dialog for folder selection.
    assert 'type="file"' not in dialog


def test_mobile_compact_job_opens_host_evidence_browser_for_folder_import():
    page = read("frontend/src/pages/mobile/MobileCompactJobPage.tsx")
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    assert "HostEvidencePanel" in page
    assert 'allowLiveMobileAcquisition={false}' in page
    assert "allowLiveMobileAcquisition?: boolean" in panel
    assert 'sourceType === "mobile" && allowLiveMobileAcquisition' in panel
    assert "Select folder & start" in page
    assert "openEvidenceFolder" in page
    assert "Use this directory" in page
    assert "Windows file Open dialog" in page
    # Never auto-click a raw file input after a timer (loses user activation → file picker).
    assert "inputRef.current?.click()" not in page
    assert "webkitdirectory" not in page


def test_mobile_job_does_not_offer_process_before_evidence_is_selected():
    page = read("frontend/src/pages/mobile/MobileCompactJobPage.tsx")

    assert "const PIPELINE_STARTED = new Set" in page
    assert "return !PIPELINE_STARTED.has(status);" in page
    assert "Select folder & start" in page
    assert "The Process / Resume / Stop controls appear only after evidence has been registered" in page
    assert "{showImport ? (" in page


def test_recent_jobs_hide_empty_created_or_registered_rows_until_start():
    page = read("frontend/src/pages/mobile/MobileConsolePages.tsx")

    assert "const PIPELINE_STARTED_STATUSES = new Set" in page
    assert "progress > 0 || PIPELINE_STARTED_STATUSES.has(status)" in page
    assert 'status === "failed" && evidence > 0' in page
    assert 'status !== "created"' not in page
    assert "{startedItems.length > 0 ? (" in page
    started_block = page.split("const PIPELINE_STARTED_STATUSES = new Set([", 1)[1].split("]);", 1)[0]
    assert '"failed"' not in started_block
