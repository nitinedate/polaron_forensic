from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_runtime_defaults_enforce_extract_then_process_barrier():
    env = read(".env")
    compose = read("docker-compose.yml")
    config = read("backend/app/config.py")
    capacity = read("backend/app/services/host_capacity.py")

    assert "EXTRACT_THEN_PROCESS=true" in env
    assert "PHASE3_STREAM_DURING_EXTRACT=false" in env
    assert "PHASE3_STREAM_OCR_DURING_EXTRACT=false" in env
    assert 'extract_then_process: bool = Field(default=True, validation_alias="EXTRACT_THEN_PROCESS")' in config
    assert 'PHASE3_STREAM_DURING_EXTRACT: ${PHASE3_STREAM_DURING_EXTRACT:-false}' in compose
    assert '"PHASE3_STREAM_DURING_EXTRACT": "false"' in capacity
    assert '"PHASE3_STREAM_OCR_DURING_EXTRACT": "false"' in capacity
    assert '"PHASE3_STREAM_RAG_DURING_EXTRACT": "false"' in capacity


def test_extract_worker_never_streams_phase3_when_barrier_enabled():
    extract = read("backend/app/services/extracted_disk.py")
    disk = read("backend/app/services/disk.py")

    assert 'not bool(getattr(settings, "extract_then_process", True))' in extract
    assert 'not bool(getattr(settings, "extract_then_process", True))' in disk
    assert '"subphase": "enumerating"' in extract
    assert '"subphase": "copying"' in extract
    assert '"files_remaining": max(total - extracted, 0)' in extract


def test_supervisor_and_orchestrator_hold_downstream_until_extract_finalized():
    supervisor = read("backend/app/services/pipeline_supervisor.py")
    orchestrator = read("backend/app/services/pipeline_orchestrator.py")

    barrier_return = supervisor.index('if bool(getattr(settings, "extract_then_process", True)):\n            return None')
    inventory_observer = supervisor.index("observed = _observe_stalled_inventory")
    assert barrier_return < inventory_observer
    assert '"Waiting for evidence extraction to finish"' in orchestrator
    assert 'not row.get("extracted_disk_uri")' in orchestrator


def test_frontend_shows_one_time_extract_and_remaining_work():
    banner = read("frontend/src/components/forensic/AgentPipelineBanner.tsx")
    stages = read("frontend/src/lib/orchestrationStages.ts")

    assert "Phase 1 · One-time evidence extraction" in banner
    assert "files left" in banner
    assert "locked until extraction reaches 100%" in banner
    assert "Waiting for evidence extraction to finish" in stages
    assert "total still growing" in stages


def test_extract_percentage_does_not_pin_post_extract_pipeline_at_99():
    orchestrator = read("backend/app/services/pipeline_orchestrator.py")
    stages = read("frontend/src/lib/orchestrationStages.ts")

    assert 'previous_was_extract = previous_agent_id == "extraction_agent"' in orchestrator
    assert "if extract_incomplete or previous_was_extract:" in orchestrator
    assert "const legacyJobPct = orch ? 0 : (job.progress_pct ?? 0);" in stages
    assert "const staleExtractionSnapshot =" in stages


def test_banner_labels_extraction_progress_separately_from_pipeline_progress():
    banner = read("frontend/src/components/forensic/AgentPipelineBanner.tsx")
    assert '{extracting ? "Extraction progress" : "Overall pipeline"}' in banner
    assert "required stage" in banner


def test_post_extract_pipeline_does_not_reopen_source_image():
    materialize = read("backend/app/services/artifact_materialize.py")
    filters = read("backend/app/services/extract_filters.py")

    assert "source image reread disabled after extraction" in materialize
    assert 'row.get("extracted_disk_uri")' in materialize
    assert "is_critical_forensic_path(path) or is_forensic_extract_waived(path)" in filters


def test_artifact_registration_publishes_real_denominator_and_counts():
    materialize = read("backend/app/services/artifact_materialize.py")
    stages = read("frontend/src/lib/orchestrationStages.ts")

    assert '"entries_inspected": inspected' in materialize
    assert '"entries_total": total_entries' in materialize
    assert '"artifacts_registered": created' in materialize
    assert 'label: "Register artifacts"' in stages


def test_extraction_progress_reports_file_and_byte_remaining_counts():
    extract = read("backend/app/services/extracted_disk.py")
    types = read("frontend/src/lib/types/forensic.ts")
    banner = read("frontend/src/components/forensic/AgentPipelineBanner.tsx")

    assert 'planned_bytes_total = sum(' in extract
    assert '"bytes_remaining": (' in extract
    assert 'bytes_remaining?: number | null;' in types
    assert "remaining by size" in banner


def test_extraction_has_explicit_finalizing_subphase_before_phase2():
    extract = read("backend/app/services/extracted_disk.py")
    banner = read("frontend/src/components/forensic/AgentPipelineBanner.tsx")

    assert '"subphase": "finalizing"' in extract
    assert "Finalizing the immutable evidence manifest" in banner
