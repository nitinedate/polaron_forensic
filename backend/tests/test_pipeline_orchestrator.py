"""Tests for sequential pipeline orchestrator."""

from unittest.mock import MagicMock, patch

from app.services.pipeline_orchestrator import (
    build_orchestration_progress_snapshot,
    compute_overall_pct,
    current_agent,
    finalize_pipeline_after_inventory,
    pipeline_intake_started,
    prior_supervisor_keys_done,
    sync_orchestration_from_job,
    _empty_agent_states,
)


def test_pipeline_intake_started_false_for_created_job_without_evidence():
    assert pipeline_intake_started(
        {
            "status": "created",
            "disk_source": None,
            "files_total": 0,
            "files_extracted": 0,
            "extracted_disk_uri": None,
        }
    ) is False


def test_pipeline_intake_started_ignores_mobile_metadata_seed():
    assert pipeline_intake_started(
        {
            "status": "created",
            "disk_source": {
                "source_type": "mobile",
                "mobile_os": "ios",
                "owner_agent": "iosagent",
            },
            "files_total": 0,
            "files_extracted": 0,
            "extracted_disk_uri": None,
        }
    ) is False


def test_pipeline_intake_started_true_for_selected_host_folder():
    assert pipeline_intake_started(
        {
            "status": "created",
            "disk_source": {"evidence_folder": "/host/g/case-1"},
            "files_total": 0,
            "files_extracted": 0,
            "extracted_disk_uri": None,
        }
    ) is True


def test_pipeline_intake_started_true_for_browser_upload_gate():
    assert pipeline_intake_started(
        {
            "status": "created",
            "disk_source": {
                "intake": "browser_upload",
                "upload_status": "receiving",
                "upload_expected_files": 2,
            },
            "files_total": 0,
            "files_extracted": 0,
            "extracted_disk_uri": None,
        }
    ) is True


def test_pipeline_intake_started_registered_without_evidence_is_still_false():
    assert pipeline_intake_started(
        {
            "status": "registered",
            "disk_source": {},
            "segment_readiness": {"ready": False},
            "files_total": 0,
            "files_extracted": 0,
            "extracted_disk_uri": None,
        }
    ) is False


def test_pipeline_intake_started_true_for_ready_registered_segments():
    assert pipeline_intake_started(
        {
            "status": "registered",
            "disk_source": {},
            "segment_readiness": {"ready": True},
            "files_total": 0,
            "files_extracted": 0,
            "extracted_disk_uri": None,
        }
    ) is True


def test_sync_orchestration_keeps_unselected_job_at_zero_without_count_queries():
    row = {
        "status": "created",
        "progress_pct": 26,
        "files_total": 0,
        "files_extracted": 0,
        "bytes_extracted": 0,
        "pipeline_progress": {
            "phase": "extract",
            "orchestration": {
                "current_agent_id": "list_folder_agent",
                "pipeline_started_at": "2026-09-26T01:13:00Z",
            },
        },
        "disk_source": None,
        "extracted_disk_uri": None,
    }
    with patch("app.services.pipeline_orchestrator.fetchone", return_value=row) as mock_fetch:
        orch = sync_orchestration_from_job(MagicMock(), "job-1")

    # Only the job row lookup is allowed; expensive artifact/OCR/RAG counts must
    # not run before the examiner selects evidence.
    assert mock_fetch.call_count == 1
    assert orch["overall_pct"] == 0
    assert orch["progress_high_water"] == 0
    assert orch["current_agent_id"] is None
    assert orch["pipeline_started_at"] is None
    assert orch["intake_started"] is False
    assert all(a["state"] == "pending" and a["pct"] == 0 for a in orch["agents"].values())


def test_build_snapshot_heals_stale_unselected_progress_to_idle_zero():
    row = {
        "status": "created",
        "progress_pct": 26,
        "files_total": 0,
        "files_extracted": 0,
        "pipeline_progress": {
            "phase": "extract",
            "completed": 1,
            "total": 1,
            "orchestration": {
                "overall_pct": 26,
                "current_agent_id": "list_folder_agent",
            },
        },
        "disk_source": None,
        "extracted_disk_uri": None,
    }
    snapshot = build_orchestration_progress_snapshot(MagicMock(), "job-1", row=row)

    assert snapshot is not None
    assert snapshot["phase"] == "idle"
    assert snapshot["progress_pct"] == 0
    assert snapshot["completed"] == 0
    assert snapshot["orchestration"]["overall_pct"] == 0
    assert snapshot["orchestration"]["current_agent_id"] is None
    assert all(
        a["state"] == "pending" and a["pct"] == 0
        for a in snapshot["orchestration"]["agents"].values()
    )


def test_compute_overall_pct_ignores_optional_embedding():
    states = _empty_agent_states()
    for agent_id in states:
        if agent_id == "embed_agent":
            states[agent_id] = {**states[agent_id], "state": "running", "pct": 58}
        else:
            states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    assert compute_overall_pct(states) == 100


def test_compute_overall_pct_embed_disabled_pending_can_be_100():
    states = _empty_agent_states()
    for agent_id in states:
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    states["embed_agent"] = {**states["embed_agent"], "state": "pending", "pct": 0}
    assert compute_overall_pct(states) == 100


def test_compute_overall_pct_ocr_and_neo4j_still_count():
    states = _empty_agent_states()
    for agent_id in states:
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    states["embed_agent"] = {**states["embed_agent"], "state": "pending", "pct": 0}
    states["ocr_agent"] = {**states["ocr_agent"], "state": "running", "pct": 40}
    assert compute_overall_pct(states) <= 99
    states["ocr_agent"] = {**states["ocr_agent"], "state": "done", "pct": 100}
    states["neo4j_agent"] = {**states["neo4j_agent"], "state": "pending", "pct": 0}
    assert compute_overall_pct(states) < 100


def test_compute_overall_pct_caps_while_ocr_still_running():
    states = _empty_agent_states()
    for agent_id in states:
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    states["ocr_agent"] = {**states["ocr_agent"], "state": "running", "pct": 50}
    for agent_id in (
        "parse_agent",
        "chunk_agent",
        "entity_agent",
        "neo4j_agent",
        "annotation_agent",
        "ontology_agent",
        "artifacts_agent",
    ):
        states[agent_id] = {**states[agent_id], "state": "pending", "pct": 0}
    assert compute_overall_pct(states) <= 99


def test_chunk_agent_counts_in_overall_progress():
    states = _empty_agent_states()
    for agent_id in states:
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    states["chunk_agent"] = {**states["chunk_agent"], "state": "pending", "pct": 0}
    assert compute_overall_pct(states) < 100


def test_compute_overall_pct_all_done():
    states = _empty_agent_states()
    for agent_id in states:
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    assert compute_overall_pct(states) == 100


def test_patch_extract_orchestration_uses_file_ratio_not_card_average():
    from app.services.pipeline_orchestrator import patch_extract_orchestration

    captured: dict = {}

    def fake_fetchone(_db, _sql, _params):
        return {"pipeline_progress": {}}

    def fake_execute(_db, _sql, params):
        captured.update(params)

    with patch("app.services.pipeline_orchestrator.fetchone", fake_fetchone), patch(
        "app.services.pipeline_orchestrator.execute", fake_execute
    ):
        patch_extract_orchestration(
            MagicMock(),
            "job-1",
            files_done=212000,
            files_total=233797,
            extract_pct=91,
        )

    import json

    pp = json.loads(captured["pp"])
    orch = pp["orchestration"]
    assert orch["overall_pct"] == 90
    assert orch["progress_high_water"] == 90
    assert orch["agents"]["extraction_agent"]["pct"] == 91
    assert orch["agents"]["ocr_agent"]["state"] == "pending"
    assert pp["phase"] == "extract"
    assert pp["completed"] == 212000
    assert pp["total"] == 233797


def test_prior_supervisor_keys_done_blocks_rag_before_parse():
    states = _empty_agent_states()
    for agent_id in (
        "drive_mount_agent",
        "download_agent",
        "list_folder_agent",
        "segments_agent",
        "virtual_disk_agent",
        "extraction_agent",
        "materialize_agent",
    ):
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}
    assert prior_supervisor_keys_done(states, "parse_agent") is True
    assert prior_supervisor_keys_done(states, "rag_agent") is False


def test_current_agent_returns_running_before_pending():
    states = _empty_agent_states()
    states["segments_agent"] = {**states["segments_agent"], "state": "done", "pct": 100}
    states["virtual_disk_agent"] = {**states["virtual_disk_agent"], "state": "running", "pct": 40}
    agent_id, label, state = current_agent(states)
    assert agent_id == "virtual_disk_agent"
    assert label == "Virtual disk"
    assert state == "running"


def test_current_agent_returns_pending_when_none_running():
    states = _empty_agent_states()
    states["drive_mount_agent"] = {**states["drive_mount_agent"], "state": "done", "pct": 100}
    states["download_agent"] = {**states["download_agent"], "state": "done", "pct": 100}
    states["list_folder_agent"] = {**states["list_folder_agent"], "state": "done", "pct": 100}
    states["segments_agent"] = {**states["segments_agent"], "state": "pending", "pct": 0}
    agent_id, label, state = current_agent(states)
    assert agent_id == "segments_agent"
    assert label == "Get segments"
    assert state == "pending"


def test_finalize_pipeline_after_inventory_noop_when_incomplete():
    db = MagicMock()
    with patch(
        "app.services.catalog_artifact_runner.axiom_inventory_progress",
        return_value={"done": False, "completed": 0, "total": 10},
    ):
        assert finalize_pipeline_after_inventory(db, "job-1") is None


def test_finalize_pipeline_after_inventory_marks_ready_when_all_agents_done():
    db = MagicMock()
    inv = {"done": True, "completed": 670, "total": 670, "platform": "Android"}
    orch = {
        "agents": _empty_agent_states(),
        "overall_pct": 100,
        "current_agent_id": None,
        "current_agent_label": None,
        "current_agent_state": None,
    }
    for agent_id in orch["agents"]:
        orch["agents"][agent_id] = {**orch["agents"][agent_id], "state": "done", "pct": 100}

    def fake_fetchone(_db, sql, params=None):
        s = (sql or "").lower()
        if "ocr_status='pending'" in s or 'ocr_status="pending"' in s:
            return {"c": 0}
        return {
            "status": "indexed",
            "pipeline_progress": {"phase": "artifact_inventory", "orchestration": orch},
        }

    with patch("app.services.catalog_artifact_runner.axiom_inventory_progress", return_value=inv), patch(
        "app.services.pipeline_orchestrator.fetchone",
        side_effect=fake_fetchone,
    ), patch("app.services.pipeline_orchestrator.sync_orchestration_from_job", return_value=orch), patch(
        "app.services.dual_rag_index._count_indexable_without_chunks",
        return_value=0,
    ), patch("app.services.pipeline_orchestrator.execute") as mock_execute, patch(
        "app.services.pipeline_orchestrator.log_agent"
    ):
        result = finalize_pipeline_after_inventory(db, "job-1")
    assert result is not None
    assert result["phase"] == "complete"
    assert result["orchestration"]["overall_pct"] == 100
    assert result["orchestration"]["current_agent_id"] is None
    for agent in result["orchestration"]["agents"].values():
        assert agent["state"] == "done"
    mock_execute.assert_called_once()


def test_finalize_pipeline_after_inventory_keeps_honest_agents_when_ocr_pending():
    db = MagicMock()
    inv = {"done": True, "completed": 670, "total": 670, "platform": "Windows"}
    orch = {
        "agents": _empty_agent_states(),
        "overall_pct": 90,
        "current_agent_id": "ocr_agent",
        "current_agent_label": "OCR enrich",
        "current_agent_state": "running",
    }
    for agent_id in orch["agents"]:
        state = "done" if agent_id != "ocr_agent" else "running"
        pct = 100 if state == "done" else 80
        orch["agents"][agent_id] = {**orch["agents"][agent_id], "state": state, "pct": pct}

    def fake_fetchone(_db, sql, params=None):
        s = (sql or "").lower()
        if "ocr_status='pending'" in s:
            return {"c": 54}
        return {
            "status": "indexed",
            "pipeline_progress": {"phase": "artifact_inventory", "orchestration": orch},
        }

    with patch("app.services.catalog_artifact_runner.axiom_inventory_progress", return_value=inv), patch(
        "app.services.pipeline_orchestrator.fetchone",
        side_effect=fake_fetchone,
    ), patch("app.services.pipeline_orchestrator.sync_orchestration_from_job", return_value=orch), patch(
        "app.services.dual_rag_index._count_indexable_without_chunks",
        return_value=4000,
    ), patch("app.services.pipeline_orchestrator.execute") as mock_execute, patch(
        "app.services.pipeline_orchestrator.log_agent"
    ):
        result = finalize_pipeline_after_inventory(db, "job-1")
    assert result is not None
    assert result["phase"] != "complete"
    assert result["orchestration"]["overall_pct"] <= 99
    assert result["orchestration"]["agents"]["ocr_agent"]["state"] == "running"
    mock_execute.assert_called_once()


def test_stick_agent_progress_never_drops_done_to_pending():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {"parse_agent": {"state": "done", "pct": 100, "detail": "12 parsed"}}
    states = {"parse_agent": {"state": "running", "pct": 70}}
    _stick_agent_progress(prev, states)
    assert states["parse_agent"]["state"] == "running"
    assert states["parse_agent"]["pct"] == 99


def test_persist_drive_mount_complete_resets_false_ocr_on_created_job():
    import json
    from types import SimpleNamespace

    from app.services.pipeline_orchestrator import persist_drive_mount_complete

    captured: dict = {}
    states = _empty_agent_states()
    states["drive_mount_agent"] = {**states["drive_mount_agent"], "state": "done", "pct": 100}
    states["list_folder_agent"] = {**states["list_folder_agent"], "state": "running", "pct": 10}
    states["ocr_agent"] = {
        **states["ocr_agent"],
        "state": "done",
        "pct": 100,
        "detail": "No OCR-eligible documents",
    }
    pp = {"orchestration": {"agents": states, "current_agent_id": "list_folder_agent"}}

    def fake_fetchone(_db, _sql, _params):
        # This regression case is after the examiner selected a folder. The new
        # pre-intake gate intentionally makes the same call a no-op before that.
        return {
            "status": "created",
            "pipeline_progress": pp,
            "disk_source": {"evidence_folder": "/host/g/case-1"},
        }

    def fake_execute(_db, _sql, params):
        captured.update(params)

    with (
        patch("app.services.pipeline_orchestrator.fetchone", fake_fetchone),
        patch("app.services.pipeline_orchestrator.execute", fake_execute),
        patch(
            "app.config.get_settings",
            return_value=SimpleNamespace(rag_embedding_enabled=False, pipeline_sequential_agents=False),
        ),
    ):
        persist_drive_mount_complete(MagicMock(), "job-1", mounted=["C", "D", "G"])

    out = json.loads(captured["pp"])
    ocr = out["orchestration"]["agents"]["ocr_agent"]
    assert ocr["state"] == "pending"
    assert ocr["pct"] == 0
    assert out["orchestration"]["agents"]["embed_agent"]["state"] == "done"
    assert out["orchestration"]["current_agent_id"] == "list_folder_agent"


def test_false_complete_ocr_can_return_to_pending():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {"ocr_agent": {"state": "done", "pct": 100, "detail": "No OCR-eligible documents"}}
    states = {"ocr_agent": {"state": "pending", "pct": 0, "detail": "Waiting for extracted files"}}
    _stick_agent_progress(prev, states, extract_incomplete=True)
    assert states["ocr_agent"]["state"] == "pending"
    assert states["ocr_agent"]["pct"] == 0


def test_stick_keeps_finished_cards_at_100_when_rebuild_says_pending():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {
        "list_folder_agent": {"state": "done", "pct": 100, "detail": "Listed folder"},
        "extraction_agent": {"state": "done", "pct": 100},
        "parse_agent": {"state": "done", "pct": 100, "detail": "12 parsed"},
        "ocr_agent": {"state": "done", "pct": 100},
    }
    states = {
        "list_folder_agent": {"state": "pending", "pct": 0},
        "extraction_agent": {"state": "pending", "pct": 0},
        "parse_agent": {"state": "pending", "pct": 0},
        "ocr_agent": {"state": "pending", "pct": 0},
    }
    _stick_agent_progress(prev, states, extract_incomplete=False)
    assert states["list_folder_agent"]["state"] == "done"
    assert states["list_folder_agent"]["pct"] == 100
    assert states["extraction_agent"]["pct"] == 100
    assert states["parse_agent"]["state"] == "done"
    assert states["parse_agent"]["pct"] == 100
    assert states["ocr_agent"]["state"] == "done"
    assert states["ocr_agent"]["pct"] == 100


def test_stick_agent_progress_never_drops_percent():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {"neo4j_agent": {"state": "running", "pct": 90}}
    states = {"neo4j_agent": {"state": "running", "pct": 40}}
    _stick_agent_progress(prev, states)
    assert states["neo4j_agent"]["state"] == "running"
    assert states["neo4j_agent"]["pct"] == 90


def test_stick_live_ratio_uses_current_counts():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {"parse_agent": {"state": "running", "pct": 90}}
    states = {"parse_agent": {"state": "running", "pct": 40}}
    _stick_agent_progress(prev, states)
    assert states["parse_agent"]["pct"] == 40


def test_stick_does_not_zero_a_working_card():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {"entity_agent": {"state": "running", "pct": 60}}
    states = {"entity_agent": {"state": "pending", "pct": 0}}
    _stick_agent_progress(prev, states)
    assert states["entity_agent"]["state"] == "running"
    assert states["entity_agent"]["pct"] == 60


def test_stick_agent_progress_reopen_done_stays_near_complete():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {"ocr_agent": {"state": "done", "pct": 100}}
    states = {"ocr_agent": {"state": "running", "pct": 12}}
    _stick_agent_progress(prev, states)
    assert states["ocr_agent"]["state"] == "running"
    assert states["ocr_agent"]["pct"] == 99


def test_extract_barrier_parks_all_later_agents():
    from app.services.pipeline_orchestrator import (
        _empty_agent_states,
        reopen_false_complete_during_extract,
    )

    states = _empty_agent_states()
    for agent_id in ("materialize_agent", "parse_agent", "chunk_agent", "ocr_agent"):
        states[agent_id] = {**states[agent_id], "state": "done", "pct": 100}

    reopen_false_complete_during_extract(
        states,
        extract_pct=38,
        registered=64000,
        parsed_n=27,
        pending_n=0,
        chunk_n=1200,
        ocr_n=0,
        ocr_pending_n=0,
        embed_on=False,
    )

    for agent_id in ("materialize_agent", "parse_agent", "chunk_agent", "ocr_agent"):
        assert states[agent_id]["state"] == "pending"
        assert states[agent_id]["pct"] == 0
        assert "Waiting for evidence extraction" in states[agent_id]["detail"]


def test_stick_hard_parks_later_cards_during_extract():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {
        "materialize_agent": {"state": "done", "pct": 100, "detail": "64,238 artifacts registered"},
        "chunk_agent": {"state": "done", "pct": 100},
    }
    states = {
        "materialize_agent": {"state": "running", "pct": 38, "detail": "extract still running"},
        "chunk_agent": {"state": "running", "pct": 38},
    }
    _stick_agent_progress(prev, states, extract_incomplete=True)
    assert states["materialize_agent"]["state"] == "pending"
    assert states["materialize_agent"]["pct"] == 0
    assert states["chunk_agent"]["state"] == "pending"
    assert states["chunk_agent"]["pct"] == 0


def test_patch_extract_parks_false_complete_later_cards():
    from app.services.pipeline_orchestrator import patch_extract_orchestration

    captured: dict = {}
    prev_agents = _empty_agent_states()
    for agent_id in ("materialize_agent", "parse_agent", "chunk_agent"):
        prev_agents[agent_id] = {**prev_agents[agent_id], "state": "done", "pct": 100}

    def fake_fetchone(_db, _sql, _params):
        return {"pipeline_progress": {"orchestration": {"agents": prev_agents}}}

    def fake_execute(_db, _sql, params):
        captured.update(params)

    with patch("app.services.pipeline_orchestrator.fetchone", fake_fetchone), patch(
        "app.services.pipeline_orchestrator.execute", fake_execute
    ):
        patch_extract_orchestration(
            MagicMock(),
            "job-1",
            files_done=165147,
            files_total=325791,
            extract_pct=50,
        )

    import json

    pp = json.loads(captured["pp"])
    agents = pp["orchestration"]["agents"]
    for agent_id in ("materialize_agent", "parse_agent", "chunk_agent"):
        assert agents[agent_id]["state"] == "pending"
        assert agents[agent_id]["pct"] == 0


def test_stick_reopens_log_only_enrich_cards():
    from app.services.pipeline_orchestrator import _stick_agent_progress

    prev = {
        "entity_agent": {"state": "done", "pct": 100, "detail": "Structured fields indexed"},
        "annotation_agent": {"state": "done", "pct": 100},
        "ontology_agent": {"state": "done", "pct": 100},
    }
    states = {
        "entity_agent": {"state": "pending", "pct": 0, "detail": "Waiting for entity extraction"},
        "annotation_agent": {"state": "pending", "pct": 0},
        "ontology_agent": {"state": "pending", "pct": 0},
    }
    _stick_agent_progress(prev, states, enrich_incomplete=True)
    assert states["entity_agent"]["state"] == "pending"
    assert states["entity_agent"]["pct"] == 0
    assert states["annotation_agent"]["state"] == "pending"
