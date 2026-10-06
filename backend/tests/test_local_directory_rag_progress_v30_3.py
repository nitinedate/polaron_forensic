from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_host_evidence_flow_uses_directory_browser_not_native_file_picker():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    assert 'setBrowseDialogOpen(true)' in panel
    assert 'type="file"' not in panel
    assert 'webkitdirectory' not in panel
    assert 'Use this directory' in dialog
    assert 'Select evidence directory' in dialog
    assert 'Start extraction' in dialog


def test_mobile_compact_import_is_folder_selection():
    page = read("frontend/src/pages/mobile/MobileCompactJobPage.tsx")
    assert 'Select evidence folder' in page
    assert 'webkitdirectory' in page


def test_rag_progress_has_one_current_process_bar_and_completed_ticks():
    panel = read("frontend/src/components/mobile/MobileRagProgressPanel.tsx")
    assert 'Current process' in panel
    assert 'RAG Processing' in panel
    assert 'completed.map' in panel
    assert 'Exceptions / Errors' in panel
    assert 'collectErrors' in panel
    assert 'Only the process currently running is shown on the progress bar.' in panel


def test_compact_page_does_not_show_error_before_rag_panel():
    page = read("frontend/src/pages/mobile/MobileCompactJobPage.tsx")
    assert 'job.error ? <Card' not in page
    assert '<MobileRagProgressPanel job={job} />' in page
