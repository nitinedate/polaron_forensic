from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_disk_pipeline_only_shows_download_for_explicit_client_transfer() -> None:
    orch = _read("frontend/src/lib/orchestrationStages.ts")
    assert 'export type EvidenceTransportMode = "server" | "client" | "unknown"' in orch
    assert 'if (!mobile && id === "download_agent") return transport === "client";' in orch
    assert 'if (!mobile && id === "drive_mount_agent") return transport !== "client";' in orch
    assert 'origin === "client_browser"' in orch
    assert 'origin.startsWith("server_")' in orch


def test_upload_activity_is_hidden_for_server_source_and_labeled_client_transfer() -> None:
    panel = _read("frontend/src/components/forensic/JobActivityPanel.tsx")
    assert 'sourceTransport?: "server" | "client" | "unknown"' in panel
    assert 'sourceTransport === "client"' in panel
    assert "Client transfer activity" in panel
    assert "Upload activity" not in panel


def test_server_selection_clears_stale_client_transfer_state() -> None:
    host = _read("frontend/src/components/forensic/HostEvidencePanel.tsx")
    upload = _read("frontend/src/lib/jobUploadSession.ts")
    assert 'onSourceTransportChanged?.("server")' in host
    assert 'onSourceTransportChanged?.("client")' in host
    assert "clearInactiveForServerSource" in host
    assert "clearInactiveForServerSource(jobId: string): boolean" in upload
    assert "if (this.runners.has(jobId)) return false" in upload


def test_backend_persists_transport_origin_and_zero_copy_contract() -> None:
    host = _read("backend/app/services/host_evidence.py")
    assert '"source_origin": "client_browser"' in host
    assert '"transfer_required": True' in host
    assert 'source_origin = "server_network"' in host
    assert 'source_origin = "server_attached_or_mapped"' in host
    assert '"transfer_required": False' in host
    assert '"cleanup_policy": "never_delete_source"' in host


def test_job_detail_uses_source_mode_for_transfer_panel() -> None:
    page = _read("frontend/src/pages/forensic/JobDetailPage.tsx")
    assert "evidenceTransportModeForJob" in page
    assert "selectedTransportMode" in page
    assert "clientTransferActive" in page
    assert "sourceTransport={evidenceTransportMode}" in page
    assert "Select server evidence or upload from client" in page
