from app.services.action_agents import collect_action_votes, performance_arbitrate


def _snap(**overrides):
    row = {
        "disk_source": {"evidence_folder": "/host/g/disk"},
        "extracted_disk_uri": overrides.pop("extracted_disk_uri", "s3://old/manifest.json"),
    }
    snap = {
        "row": row,
        "status": "building_disk",
        "files_total": 380000,
        "files_done": 380000,
        "drives_ready": True,
        "mounted_letters": ["G"],
        "inventory": {},
        "chunk_n": 0,
        "artifact_n": 0,
        "parse_pending": 0,
        "ocr_pending": 0,
        "rag_remaining": 0,
        "graph_status": "",
        "extract_live": False,
    }
    snap.update(overrides)
    if "extracted_disk_uri" in overrides:
        row["extracted_disk_uri"] = overrides["extracted_disk_uri"]
    return snap


def _vote(snap, agent_id="extraction_agent"):
    return next(v for v in collect_action_votes(snap) if v["id"] == agent_id)


def test_extraction_stands_down_when_counts_complete_even_if_processing():
    vote = _vote(_snap())
    assert vote["want"] == "done"
    assert "do not resume" in vote["reason"].lower()


def test_extraction_votes_run_while_building_disk_until_counts_complete():
    vote = _vote(_snap(files_done=120000, files_total=380000))
    assert vote["want"] == "run"


def test_extraction_votes_done_only_after_disk_ready():
    vote = _vote(_snap(status="disk_ready"))
    assert vote["want"] == "done"


def test_extraction_votes_run_during_minio_copy():
    vote = _vote(_snap(files_done=120000, files_total=233797))
    assert vote["want"] == "run"


def test_ocr_waits_while_extract_is_running():
    vote = _vote(_snap(files_done=100, files_total=380000), "ocr_agent")
    assert vote["want"] == "wait"
    assert "extraction" in vote["reason"].lower()


def test_ocr_does_not_wait_for_extraction_when_copy_is_complete():
    vote = _vote(_snap(), "ocr_agent")
    assert "extraction" not in vote["reason"].lower()


def test_embed_done_when_embeddings_disabled():
    vote = _vote(_snap(status="indexing", files_done=10, files_total=10), "embed_agent")
    assert vote["want"] == "done"
    assert "disabled" in vote["reason"].lower() or "100" in vote["reason"]


def test_embed_done_during_extract_when_embeddings_disabled():
    vote = _vote(_snap(), "embed_agent")
    assert vote["want"] == "done"


def test_done_agent_stands_down_without_leftover():
    snap = _snap(
        status="indexing",
        files_done=10,
        files_total=10,
        ocr_pending=0,
        ocr_done=7,
        ocr_eligible=7,
        artifact_n=100,
        parse_pending=0,
    )
    snap["agent_states"] = {"ocr_agent": {"state": "done", "pct": 100}}
    vote = _vote(snap, "ocr_agent")
    assert vote["want"] == "done"
    assert "standing down" in vote["reason"].lower()


def test_ocr_votes_done_when_skipped_gap_has_no_queue():
    vote = _vote(
        _snap(
            status="indexing",
            files_done=10,
            files_total=10,
            ocr_pending=0,
            ocr_done=7,
            ocr_eligible=51,
            ocr_unfinished=0,
            artifact_n=100,
            parse_pending=0,
        ),
        "ocr_agent",
    )
    assert vote["want"] == "done"


def test_ocr_votes_run_when_failed_without_results():
    vote = _vote(
        _snap(
            status="indexing",
            files_done=10,
            files_total=10,
            ocr_pending=0,
            ocr_done=7,
            ocr_eligible=51,
            ocr_unfinished=12,
            artifact_n=100,
            parse_pending=0,
        ),
        "ocr_agent",
    )
    assert vote["want"] == "run"
    assert "ocr" in vote["reason"].lower()


def test_ocr_not_done_when_no_artifacts_after_extract():
    vote = _vote(_snap(status="disk_ready", files_done=10, files_total=10), "ocr_agent")
    assert vote["want"] != "done"


def test_extraction_votes_idle_when_already_running():
    vote = _vote(_snap(extract_live=True, files_done=210000, files_total=233797))
    assert vote["want"] == "idle"
    assert "already running" in vote["reason"].lower()


def test_segments_do_not_requeue_extract_while_building_disk():
    vote = _vote(_snap(files_done=0, extracted_disk_uri=None), "segments_agent")
    assert vote["want"] != "run"


def test_virtual_disk_does_not_requeue_extract_while_building_disk():
    vote = _vote(_snap(files_done=0, extracted_disk_uri=None), "virtual_disk_agent")
    assert vote["want"] != "run"


def test_extraction_votes_done_after_indexed():
    vote = _vote(
        _snap(status="indexed", files_done=233797, files_total=233797, extract_live=False)
    )
    assert vote["want"] == "done"


def test_ocr_runs_without_gpu_lanes():
    vote = _vote(
        _snap(
            status="indexing",
            ocr_pending=40,
            artifact_n=100,
            lanes={"can_start_gpu": False, "gpu_slots_free": 0, "gpu_holders": [{"reason": "rag"}]},
        ),
        "ocr_agent",
    )
    assert vote["want"] == "run"
    assert "gpu" not in vote["reason"].lower()
    assert "cpu" in vote["reason"].lower()


def test_neo4j_votes_run_when_queued_graph_is_stale():
    snap = _snap(
        status="indexing",
        files_done=10,
        files_total=10,
        graph_status="queued",
        graph_stale=True,
        chunk_n=500,
        artifact_n=50,
    )
    vote = _vote(snap, "neo4j_agent")
    assert vote["want"] == "run"
    assert "stale" in vote["reason"].lower()


def test_drive_mount_votes_done_when_docker_already_has_letters():
    snap = _snap(
        status="created",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        mounted_letters=["C", "D", "E", "F", "G"],
        windows_letters=["C", "D", "E", "F", "G", "H"],
        missing_letters=["H"],
    )
    snap["row"]["disk_source"] = {}
    vote = _vote(snap, "drive_mount_agent")
    assert vote["want"] == "done"
    assert "already mounted" in vote["reason"].lower() or "mounted" in vote["reason"].lower()


def test_drive_mount_votes_run_only_when_evidence_letter_is_missing():
    snap = _snap(
        status="created",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        mounted_letters=["C", "D", "E", "F"],
        windows_letters=["C", "D", "E", "F", "G"],
        missing_letters=["G"],
    )
    snap["row"]["disk_source"] = {"evidence_folder": r"G:\DISK2\DataExtration\SegerEx-1"}
    vote = _vote(snap, "drive_mount_agent")
    assert vote["want"] == "run"
    assert "G" in vote["reason"]


def test_drive_mount_votes_idle_when_no_evidence_yet():
    snap = _snap(
        status="created",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=False,
        mounted_letters=[],
        windows_letters=["C", "D", "E", "F", "G"],
        missing_letters=["C", "D", "E", "F", "G"],
    )
    snap["row"]["disk_source"] = {}
    vote = _vote(snap, "drive_mount_agent")
    assert vote["want"] == "idle"
    assert "no office disk mount" in vote["reason"].lower()


def test_drive_mount_votes_done_when_windows_and_docker_match():
    snap = _snap(
        status="created",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        mounted_letters=["C", "D", "E", "F", "G"],
        windows_letters=["C", "D", "E", "F", "G"],
        missing_letters=[],
    )
    snap["row"]["disk_source"] = {}
    vote = _vote(snap, "drive_mount_agent")
    assert vote["want"] == "done"


def test_list_folder_votes_run_until_listing_completes():
    snap = _snap(
        status="registered",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        list_folder_done=False,
    )
    snap["row"]["disk_source"] = {"evidence_folder": r"G:\DISK\image"}
    snap["agent_states"] = {"list_folder_agent": {"state": "running", "pct": 10}}
    vote = _vote(snap, "list_folder_agent")
    assert vote["want"] == "idle"
    extract = _vote(snap, "extraction_agent")
    assert extract["want"] == "wait"
    assert "list folder" in extract["reason"].lower()
    ocr = _vote(snap, "ocr_agent")
    assert ocr["want"] == "wait"


def test_later_agents_run_after_list_folder_completes():
    snap = _snap(
        status="registered",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        list_folder_done=True,
        client_upload=True,
    )
    snap["row"]["disk_source"] = {
        "intake": "browser_upload",
        "evidence_folder": "/app/data/uploads/job/intake",
    }
    snap["agent_states"] = {"list_folder_agent": {"state": "done", "pct": 100}}
    vote = _vote(snap, "list_folder_agent")
    assert vote["want"] == "done"
    segments = _vote(snap, "segments_agent")
    assert segments["want"] == "run"


def test_agents_wait_until_client_images_finish_uploading():
    snap = _snap(
        status="created",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        client_upload=True,
        client_upload_pending=True,
        list_folder_done=False,
    )
    snap["row"]["disk_source"] = {
        "intake": "browser_upload",
        "upload_status": "receiving",
        "staging_container_path": "/app/data/uploads/job/intake",
    }
    assert _vote(snap, "drive_mount_agent")["want"] == "done"
    download = _vote(snap, "download_agent")
    assert download["want"] == "run"
    assert "parallel" in download["reason"].lower()
    list_vote = _vote(snap, "list_folder_agent")
    assert list_vote["want"] == "wait"
    assert "download" in list_vote["reason"].lower() or "upload" in list_vote["reason"].lower()
    extract = _vote(snap, "extraction_agent")
    assert extract["want"] == "wait"
    assert "download" in extract["reason"].lower() or "upload" in extract["reason"].lower()
    ocr = _vote(snap, "ocr_agent")
    assert ocr["want"] == "wait"
    segs = _vote(snap, "segments_agent")
    assert segs["want"] == "wait"


def test_list_folder_waits_then_lists_after_upload_completes():
    snap = _snap(
        status="registered",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        client_upload=True,
        client_upload_pending=False,
        list_folder_done=False,
    )
    snap["row"]["disk_source"] = {
        "intake": "browser_upload",
        "upload_status": "complete",
        "evidence_folder": "/app/data/uploads/job/intake",
    }
    vote = _vote(snap, "list_folder_agent")
    assert vote["want"] == "idle"
    download = _vote(snap, "download_agent")
    assert download["want"] == "done"
    assert "signal" in download["reason"].lower() or "received" in download["reason"].lower()
    extract = _vote(snap, "extraction_agent")
    assert extract["want"] == "wait"
    assert "list folder" in extract["reason"].lower()


def test_drive_mount_votes_done_for_client_browser_upload():
    snap = _snap(
        status="registered",
        files_done=0,
        files_total=0,
        extracted_disk_uri=None,
        drives_ready=True,
        client_upload=True,
        mounted_letters=[],
        windows_letters=[],
        missing_letters=[],
    )
    snap["row"]["disk_source"] = {"intake": "browser_upload", "evidence_folder": "/app/data/uploads/job/intake"}
    vote = _vote(snap, "drive_mount_agent")
    assert vote["want"] == "done"
    assert "client upload" in vote["reason"].lower()


def test_performance_lets_extract_run_while_gpu_is_busy():
    extract = {
        "want": "run",
        "lane": "cpu",
        "id": "extract_agent",
        "dispatch_agent": "extract_agent",
    }
    performance_arbitrate(
        [extract],
        {
            "allow_parallel": True,
            "lanes": {
                "gpu_slots_free": 0,
                "gpu_slots_total": 1,
                "can_start_cpu_heavy": True,
            },
        },
        gpu_abort=False,
    )
    assert extract["decision"] == "go"


def test_performance_does_not_count_ocr_against_gpu_slots():
    votes = collect_action_votes(
        _snap(status="indexing", ocr_pending=10, rag_remaining=20, artifact_n=50, chunk_n=10)
    )
    ocr = next(v for v in votes if v["id"] == "ocr_agent")
    embed = next(v for v in votes if v["id"] == "embed_agent")
    ocr["want"] = "run"
    embed["want"] = "run"
    ocr["lane"] = "cpu"
    embed["lane"] = "gpu"
    performance_arbitrate(
        [ocr, embed],
        {"allow_parallel": True, "lanes": {"gpu_slots_free": 1, "gpu_slots_total": 2, "gpu_slots_used": 1}},
        gpu_abort=False,
    )
    assert ocr["decision"] == "go"
    assert embed["decision"] == "go"


def test_ocr_agent_lane_is_gpu():
    from app.services.action_agents import ACTION_AGENTS

    ocr = next(a for a in ACTION_AGENTS if a["id"] == "ocr_agent")
    assert ocr["lane"] == "gpu"


def test_ocr_drain_not_a_gpu_action():
    from app.services.agent_huddle import _GPU_ACTIONS

    assert "ocr_drain" not in _GPU_ACTIONS


def test_all_action_agents_idle_before_evidence_selection():
    votes = collect_action_votes(
        {
            "intake_started": False,
            "row": {"status": "created", "disk_source": None, "extracted_disk_uri": None},
            "status": "created",
        }
    )
    assert votes
    assert all(v["want"] == "idle" for v in votes)
    assert all("select evidence" in v["reason"].lower() for v in votes)
