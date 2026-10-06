"""OCR Agent and Performance Agent duties — queue honesty and chassis heat."""

from app.services.action_agents import collect_action_votes, performance_arbitrate
from app.services.agent_duties import (
    assess_chassis_for_ocr,
    extract_agent_health,
    ocr_queue_health,
)
from app.services.agent_huddle import _observe_speech


def test_ocr_agent_treats_skipped_gap_as_finished_not_leftover():
    snap = {
        "ocr_pending": 0,
        "ocr_unfinished": 0,
        "ocr_eligible": 51,
        "ocr_done": 7,
        "parse_pending": 0,
        "artifact_n": 100,
        "agent_states": {"ocr_agent": {"state": "running", "pct": 85}},
    }
    health = ocr_queue_health(snap)
    assert health["should_run"] is False
    assert health["should_stand_down"] is True
    assert health["skipped_gap"] is True
    assert health["fake_running"] is True


def test_ocr_agent_runs_only_when_unfinished():
    health = ocr_queue_health(
        {
            "ocr_pending": 0,
            "ocr_unfinished": 12,
            "ocr_eligible": 51,
            "ocr_done": 7,
            "parse_pending": 0,
            "artifact_n": 100,
        }
    )
    assert health["should_run"] is True
    assert health["should_stand_down"] is False


def test_performance_cpu_80_gpu_55_is_not_chassis_abort():
    chassis = assess_chassis_for_ocr(
        55,
        80,
        gpu_throttle_c=87,
        gpu_pause_c=92,
        gpu_abort_c=94,
        cpu_throttle_c=86,
        cpu_pause_c=94,
    )
    assert chassis["ocr_may_run"] is True
    assert chassis["too_hot"] is False
    assert chassis["cpu_warm_gpu_cool"] is True
    assert "not chassis abort" in chassis["reason"]


def test_performance_holds_ocr_at_cpu_pause_or_gpu_abort():
    cpu_pause = assess_chassis_for_ocr(55, 94, cpu_throttle_c=86, cpu_pause_c=94, gpu_abort_c=94, gpu_pause_c=92)
    assert cpu_pause["ocr_may_run"] is False
    gpu_abort = assess_chassis_for_ocr(95, 70, gpu_abort_c=94, gpu_pause_c=92, cpu_pause_c=94)
    assert gpu_abort["ocr_may_run"] is False


def test_performance_does_not_hold_ocr_vote_when_cpu_throttle_gpu_cool():
    snap = {
        "row": {"disk_source": {"evidence_folder": "/host/g/disk"}, "extracted_disk_uri": "s3://x"},
        "status": "indexing",
        "files_total": 10,
        "files_done": 10,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {},
        "chunk_n": 100,
        "artifact_n": 100,
        "parse_pending": 0,
        "ocr_pending": 8,
        "ocr_unfinished": 8,
        "ocr_done": 2,
        "ocr_eligible": 10,
        "rag_remaining": 0,
        "graph_status": "ok",
        "extract_live": False,
        "list_folder_done": True,
        "chassis": assess_chassis_for_ocr(55, 80, cpu_throttle_c=86, cpu_pause_c=94, gpu_throttle_c=87),
    }
    votes = collect_action_votes(snap)
    ocr = next(v for v in votes if v["id"] == "ocr_agent")
    assert ocr["want"] == "run"
    approved = performance_arbitrate(
        votes,
        {
            "allow_parallel": True,
            "gpu": {"too_hot": False},
            "chassis": snap["chassis"],
            "lanes": {"gpu_slots_free": 2, "gpu_slots_total": 2, "can_start_cpu_heavy": True},
        },
        gpu_abort=False,
    )
    ocr_decided = next(v for v in votes if v["id"] == "ocr_agent")
    assert ocr_decided["decision"] == "go"
    assert "not chassis abort" in (ocr_decided.get("chair") or "").lower() or "keeps draining" in (
        ocr_decided.get("chair") or ""
    ).lower()
    assert any(v["id"] == "ocr_agent" for v in approved)


def test_observe_reports_ocr_unfinished_and_cpu_throttle_duty():
    line = _observe_speech(
        {
            "status": "indexing",
            "parse_pending": 0,
            "ocr_pending": 0,
            "ocr_unfinished": 0,
            "chunk_n": 114657,
            "rag_remaining": 0,
            "inventory": {"completed": 36, "total": 36},
            "graph_status": "ok",
            "cpu_temp_c": 80,
            "ocr_health": ocr_queue_health(
                {
                    "ocr_pending": 0,
                    "ocr_unfinished": 0,
                    "ocr_eligible": 51,
                    "ocr_done": 7,
                    "parse_pending": 0,
                    "artifact_n": 100,
                    "agent_states": {"ocr_agent": {"state": "running", "pct": 85}},
                }
            ),
            "chassis": assess_chassis_for_ocr(55, 80, cpu_throttle_c=86, cpu_pause_c=94, gpu_throttle_c=87),
        },
        gpu_temp=55.0,
        gpu_abort=False,
    )
    assert "0 unfinished" in line
    assert "skipped gap is finished" in line
    assert "CPU 80°C" in line
    assert "OCR Agent keeps draining" in line


def test_entity_agents_run_when_graph_ready_and_enrich_not_scanning():
    from app.services.agent_duties import enrich_agent_health
    from app.services.action_agents import collect_action_votes

    snap = {
        "row": {"disk_source": {"evidence_folder": "/host/g/disk"}, "extracted_disk_uri": "s3://x"},
        "status": "indexing",
        "files_total": 10,
        "files_done": 10,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {"done": True, "total": 36, "completed": 36},
        "chunk_n": 114657,
        "artifact_n": 100,
        "parse_pending": 0,
        "ocr_pending": 0,
        "ocr_unfinished": 0,
        "ocr_done": 32,
        "ocr_eligible": 56,
        "rag_remaining": 0,
        "graph_status": "ok",
        "extract_live": False,
        "list_folder_done": True,
        "enrich_done": False,
        "enrich_busy": True,  # fake dispatch log must not idle these agents
        "enrich_lock_held": False,
    }
    health = enrich_agent_health(snap)
    assert health["should_run"] is True
    assert health["live"] is False
    votes = {v["id"]: v for v in collect_action_votes(snap)}
    assert votes["entity_agent"]["want"] == "run"
    assert votes["annotation_agent"]["want"] == "run"
    assert votes["ontology_agent"]["want"] == "run"
    assert "start" in votes["entity_agent"]["reason"].lower()


def test_entity_agents_idle_only_when_lock_held():
    from datetime import datetime, timezone

    from app.services.action_agents import collect_action_votes

    snap = {
        "row": {"disk_source": {"evidence_folder": "/host/g/disk"}, "extracted_disk_uri": "s3://x"},
        "status": "indexing",
        "files_total": 10,
        "files_done": 10,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {},
        "chunk_n": 500,
        "artifact_n": 100,
        "parse_pending": 0,
        "ocr_pending": 0,
        "rag_remaining": 0,
        "graph_status": "ok",
        "extract_live": False,
        "list_folder_done": True,
        "enrich_done": False,
        "enrich_lock_held": True,
        "enrich_scanned": 40,
        "enrich_parse_total": 8000,
        "enrich_updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "enrich_lock_age_sec": 12,
    }
    votes = {v["id"]: v for v in collect_action_votes(snap)}
    assert votes["entity_agent"]["want"] == "idle"
    assert votes["annotation_agent"]["want"] == "idle"
    assert votes["ontology_agent"]["want"] == "idle"


def test_observe_calls_out_enrich_not_scanning():
    line = _observe_speech(
        {
            "status": "indexing",
            "parse_pending": 0,
            "chunk_n": 114657,
            "rag_remaining": 0,
            "inventory": {"completed": 36, "total": 36},
            "graph_status": "ok",
            "ocr_health": {"pending": 0, "unfinished": 0},
            "enrich_health": {
                "should_run": True,
                "live": False,
            },
            "chassis": {},
        },
        gpu_temp=51.0,
        gpu_abort=False,
    )
    assert "enrich not scanning" in line


def test_entity_agents_restart_when_enrich_frozen():
    from datetime import datetime, timedelta, timezone

    from app.services.action_agents import collect_action_votes
    from app.services.agent_duties import enrich_agent_health

    stale = (datetime.now(timezone.utc) - timedelta(seconds=240)).isoformat().replace("+00:00", "Z")
    snap = {
        "row": {"disk_source": {"evidence_folder": "/host/g/disk"}, "extracted_disk_uri": "s3://x"},
        "status": "indexing",
        "files_total": 10,
        "files_done": 10,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {"done": True, "total": 36, "completed": 36},
        "chunk_n": 114657,
        "artifact_n": 100,
        "parse_pending": 0,
        "ocr_pending": 0,
        "ocr_unfinished": 0,
        "rag_remaining": 0,
        "graph_status": "ok",
        "extract_live": False,
        "list_folder_done": True,
        "enrich_done": False,
        "enrich_lock_held": True,
        "enrich_scanned": 0,
        "enrich_parse_total": 18432,
        "enrich_updated_at": stale,
        "enrich_lock_age_sec": 240,
    }
    health = enrich_agent_health(snap)
    assert health["frozen"] is True
    assert health["live"] is False
    assert health["should_run"] is True
    votes = {v["id"]: v for v in collect_action_votes(snap)}
    assert votes["entity_agent"]["want"] == "run"
    assert "frozen" in votes["entity_agent"]["reason"].lower()
    assert votes["annotation_agent"]["want"] == "run"
    assert votes["ontology_agent"]["want"] == "run"


def test_observe_reports_entity_scan_counts():
    line = _observe_speech(
        {
            "status": "indexing",
            "parse_pending": 0,
            "chunk_n": 114657,
            "rag_remaining": 0,
            "inventory": {"completed": 36, "total": 36},
            "graph_status": "ok",
            "ocr_health": {"pending": 0, "unfinished": 0},
            "enrich_scanned": 240,
            "enrich_parse_total": 18432,
            "enrich_health": {
                "should_run": False,
                "live": True,
                "frozen": False,
                "scanned": 240,
                "parse_total": 18432,
            },
            "chassis": {},
        },
        gpu_temp=51.0,
        gpu_abort=False,
    )
    assert "Entity scanned 240/18,432" in line or "Entity scanned 240/18432" in line


def test_extract_agent_stands_down_when_counts_complete_and_status_processing():
    snap = {
        "status": "processing",
        "files_total": 325791,
        "files_done": 325791,
        "extract_live": False,
    }
    health = extract_agent_health(snap)
    assert health["complete"] is True
    assert health["should_run"] is False
    assert health["should_stand_down"] is True
    assert health["stuck_restarting"] is True
    votes = {v["id"]: v for v in collect_action_votes({
        "row": {"disk_source": {"evidence_folder": "/host/g/disk"}, "extracted_disk_uri": "s3://x"},
        "status": "processing",
        "files_total": 325791,
        "files_done": 325791,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {},
        "chunk_n": 100,
        "artifact_n": 100,
        "parse_pending": 0,
        "ocr_pending": 0,
        "ocr_unfinished": 0,
        "rag_remaining": 0,
        "graph_status": "ok",
        "extract_live": True,
        "list_folder_done": True,
    })}
    assert votes["extraction_agent"]["want"] == "done"
    assert "do not resume" in votes["extraction_agent"]["reason"].lower()


def test_extract_agent_runs_only_when_copy_is_unfinished():
    health = extract_agent_health(
        {
            "status": "building_disk",
            "files_total": 325791,
            "files_done": 1000,
            "extract_live": False,
        }
    )
    assert health["complete"] is False
    assert health["should_run"] is True


def test_extract_agent_runs_for_mobile_awaiting_segments_with_zero_files():
    health = extract_agent_health(
        {
            "status": "awaiting_segments",
            "is_mobile": True,
            "files_total": 0,
            "files_done": 0,
            "extract_live": False,
        }
    )
    assert health["complete"] is False
    assert health["should_run"] is True
    assert health["live"] is False


def test_observe_reports_extract_complete_do_not_resume():
    line = _observe_speech(
        {
            "status": "processing",
            "parse_pending": 0,
            "chunk_n": 1,
            "rag_remaining": 0,
            "inventory": {"completed": 1, "total": 1},
            "graph_status": "ok",
            "ocr_health": {"pending": 0, "unfinished": 0},
            "extract_health": {
                "should_stand_down": True,
                "stuck_restarting": True,
                "files_done": 325791,
                "files_total": 325791,
            },
            "chassis": {},
        },
        gpu_temp=51.0,
        gpu_abort=False,
    )
    assert "Extraction Agent" in line
    assert "do not resume" in line.lower()
