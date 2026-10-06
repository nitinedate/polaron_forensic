from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_disk_modal_uses_product_specific_steps_not_mobile_fixed_indexes() -> None:
    modal = _read("frontend/src/lib/pipelineStepModal.ts")
    tracker = _read("frontend/src/hooks/usePipelineStepTracker.ts")
    component = _read("frontend/src/components/forensic/PipelineStepModal.tsx")
    assert "pipelineStepDefsForJob" in modal
    assert "agentOrderForJob(job)" in modal
    assert "agents.map(agentStepDef)" in modal
    assert 'stepIndexForAgent(job, "list_folder_agent")' in modal
    assert 'stepIndexForAgent(job, "segments_agent")' in modal
    assert "if (opts?.listingFolder) return 0" not in modal
    assert "if (registering) return 1" not in modal
    assert "pipelineStepDefsForJob(job, { includeClientDownload })" in tracker
    assert "steps: stepDefs" in tracker
    assert "visibleSteps.slice(0, -1)" in component


def test_server_office_evidence_never_falls_back_to_client_upload() -> None:
    panel = _read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    # One legitimate use remains: the explicit browser/client intake branch.
    assert panel.count("await uploadClientFiles(folder.fileBlobs)") == 1
    assert "Server-side evidence is never copied through the browser" in panel
    assert "Upload from client computer…" in panel


def test_disk_retry_uses_step_identity_not_numeric_android_index() -> None:
    page = _read("frontend/src/pages/forensic/JobDetailPage.tsx")
    assert 'evidenceStepId === "download_agent"' in page
    assert '"drive_mount_agent", "list_folder_agent", "segments_agent"' in page
    assert "setPipelineErrorStep(1)" not in page
    assert "steps={pipelineSteps.steps}" in page


def test_timeout_copy_does_not_tell_unified_console_to_start_legacy_root_stack() -> None:
    api = _read("frontend/src/lib/api.ts")
    assert "Ensure docker compose is up (API + frontend)" not in api
    assert "selected product backend" in api
