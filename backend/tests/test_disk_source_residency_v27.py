from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_server_drives_are_available_from_lan_console_without_loopback_gate():
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    helper = read("frontend/src/lib/hostDriveHelper.ts")
    assert "listOfficeServerDriveLetters" in dialog
    assert "listOfficeServerDirectory" in dialog
    assert "Server / network / removable drives — process in place (no copy)" in dialog
    assert "isBrowserOnOfficeHost() &&" not in dialog
    assert "export async function listOfficeServerDriveLetters" in helper
    assert "export async function listOfficeServerDirectory" in helper


def test_server_source_ui_explicitly_promises_zero_copy_and_client_is_separate():
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    detail = read("frontend/src/pages/forensic/JobDetailPage.tsx")
    assert "processed in place with zero upload" in dialog
    assert "no duplicate source" in dialog
    assert "Upload from client" in dialog
    assert "processed in place with no upload or duplicate source" in detail


def test_client_upload_is_fail_closed_and_exactly_five_parallel_workers():
    upload = read("frontend/src/lib/jobUploadSession.ts")
    assert "export const DOWNLOAD_PARALLELISM = 5" in upload
    assert "Download Agent gate could not be opened safely" in upload
    assert "continuing copies" not in upload
    assert "throw new Error(msg)" in upload
    assert "await forensicApi.completeClientUpload(jobId, false)" in upload
    assert "remain held until all ${total} are verified on the server" in upload


def test_client_upload_server_gate_checks_received_and_staged_counts():
    jobs = read("backend/app/routers/jobs.py")
    host = read("backend/app/services/host_evidence.py")
    assert "if n_disk < expected or received < expected" in jobs
    assert "upload_manifest_missing" in jobs
    assert 'ds["upload_status"] = "verifying"' in host
    assert 'ds["upload_status"] = "complete"' in host
    assert 'status != "complete"' in host
    assert "expected > 0 and received < expected" in host


def test_process_endpoint_cannot_reregister_partial_client_dump():
    jobs = read("backend/app/routers/jobs.py")
    process_pos = jobs.index("def process_job(")
    gate_pos = jobs.index("if is_client_upload_pending(load_job_disk_source(gate_row))", process_pos)
    reregister_pos = jobs.index("reregister_job_evidence_from_saved_folder", process_pos)
    assert gate_pos < reregister_pos
    assert "Extraction, parsing, OCR, RAG and reporting remain held" in jobs


def test_client_staging_uses_atomic_partial_names():
    intake = read("backend/app/services/client_intake.py")
    assert '_PARTIAL_UPLOAD_MARKER = ".uploading-"' in intake
    assert "os.replace(temp, dest)" in intake
    assert "not _is_partial_upload_file(p)" in intake


def test_background_pipeline_stages_fail_closed_while_client_intake_is_incomplete():
    tasks = read("backend/app/tasks.py")
    assert "def _client_intake_hold" in tasks
    assert '"reason": "client_upload_incomplete"' in tasks
    # Defensive task-level gates: even an accidentally queued downstream task
    # must not process a partially transferred multi-segment image.
    for stage in (
        "extract",
        "parse",
        "parse_shard",
        "parse_bucket",
        "ocr",
        "rag_index",
        "rag_append",
        "image_embed",
        "rag_enrich",
        "inventory",
        "phase3",
        "phase3_shard",
        "phase3_finalize",
        "graph",
        "report",
    ):
        assert f'_client_intake_hold(schema_name, job_id, "{stage}")' in tasks


def test_huddle_and_supervisor_do_not_dispatch_while_client_upload_is_pending():
    huddle = read("backend/app/services/agent_huddle.py")
    supervisor = read("backend/app/services/pipeline_supervisor.py")
    assert 'if snap.get("client_upload_pending"):' in huddle
    assert "return []" in huddle[huddle.index('if snap.get("client_upload_pending"):'):]
    assert "if is_client_upload_pending(load_job_disk_source(row))" in supervisor


def test_upload_activity_visibly_marks_full_pipeline_hold():
    panel = read("frontend/src/components/forensic/JobActivityPanel.tsx")
    assert "Pipeline hold · extract / parse / OCR / RAG / report paused" in panel


def test_embedded_disk_job_still_exposes_server_zero_copy_browser():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    assert "const fullyAutomated = embedded && autoProcess && isLiveMobileSource" in panel
    assert "Server / network / removable HDD, SSD or USB — process in place" in panel
    assert "Detect server drives" in panel
    assert "await syncDriveMountsIfNeeded();" in panel
    # Office/server inventory must not depend on the remote browser's localhost helper.
    root_browse = panel.split("if (isBrowseRoot(opts))", 1)[1].split("if (", 1)[0]
    assert "hostDriveHelperHealth" not in root_browse
    assert "listHostDriveLetters" in root_browse


def test_new_server_hdd_uses_sync_attached_remount_and_parse_worker_mounts():
    panel = read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    refresh = read("scripts/refresh-drive-mounts-job.ps1")
    assert "{ syncAttached: !opts?.requiredPath }" in panel
    assert "runHostDriveAgentRefresh(undefined, { syncAttached: true })" in dialog
    assert "worker-parse" in refresh
