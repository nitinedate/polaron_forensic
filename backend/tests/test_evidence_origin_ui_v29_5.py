from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_server_and_client_source_identity_is_durable() -> None:
    src = _read("backend/app/services/host_evidence.py")
    assert '"source_origin": "forensic_server"' in src
    assert '"transport": "in_place"' in src
    assert '"download_required": False' in src
    assert 'ds["source_origin"] = "client_workstation"' in src
    assert 'ds["transport"] = "staged_upload"' in src
    assert 'ds["download_required"] = True' in src


def test_upload_activity_is_client_only() -> None:
    page = _read("frontend/src/pages/forensic/JobDetailPage.tsx")
    panel = _read("frontend/src/components/forensic/JobActivityPanel.tsx")
    host = _read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    assert 'showClientTransfer={clientTransferActive}' in page
    assert 'showClientTransfer &&' in panel
    assert 'onEvidenceOriginChange?.("server")' in host
    assert 'onEvidenceOriginChange?.("client")' in host
    assert 'jobUploadSession.reset(jobId)' in host
    assert host.count('onEvidenceOriginChange?.("server")') >= 3
    assert 'Select server evidence or upload from client' in page


def test_download_stage_only_appears_for_client_intake() -> None:
    stages = _read("frontend/src/lib/orchestrationStages.ts")
    modal = _read("frontend/src/lib/pipelineStepModal.ts")
    assert 'id === "download_agent") return intake === "client"' in stages
    assert 'includeClientDownload' in modal
    assert 'clientTransferContext' in modal


def test_partial_v294_compile_regression_is_guarded() -> None:
    stages = _read("frontend/src/lib/orchestrationStages.ts")
    banner = _read("frontend/src/components/forensic/AgentPipelineBanner.tsx")
    assert 'export function hasSelectedEvidence' in stages
    # V29.5 full file must not import a symbol that is absent.
    if 'hasSelectedEvidence' in banner:
        assert 'export function hasSelectedEvidence' in stages
