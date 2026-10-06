from copy import deepcopy

from agent.target_progress import build_target_progress


def test_snapshot_covers_waiting_running_failed_skipped_and_degraded_hosts():
    hosts = [f"10.0.0.{i}" for i in range(1, 7)]
    states = build_target_progress(hosts, chunks=[[h] for h in hosts[:5]],
        in_flight={0: "t1"}, poll_results={0: {"status": "running", "progress": 1000}},
        done_details={1: {"status": "completed", "evidence": {"assessment_complete": True}},
                      2: {"status": "completed", "evidence": {"host_coverage": {hosts[2]: {"verdict": "degraded_ports", "reason": "unfinished port scan"}}}},
                      3: {"status": "completed", "_agent_skip_reason": "poll_error"}},
        skipped_hosts=[{"host": hosts[3], "reason": "poll_error"}, {"host": hosts[5], "reason": "unreachable"}])
    assert [states[h]["status"] for h in hosts] == ["scanning", "completed", "incomplete", "failed", "pending", "skipped"]
    assert states[hosts[0]]["progress_pct"] == 99
    assert states[hosts[4]]["progress_pct"] == 0
    assert states[hosts[5]]["progress_pct"] == 0


def test_non_finite_progress_and_extra_hosts_are_not_uploaded():
    states = build_target_progress(["10.0.0.1"], chunks=[["10.0.0.1"], ["10.0.0.99"]],
        in_flight={0: "t"}, done_details={}, poll_results={0: {"progress": float("inf")}})
    assert list(states) == ["10.0.0.1"]
    assert states["10.0.0.1"]["progress_pct"] == 0


def test_multi_host_resume_chunk_updates_every_selected_host():
    states = build_target_progress(["a", "b"], chunks=[["a", "b"]], in_flight={0: "t"},
        done_details={}, poll_results={0: {"progress": 41}})
    assert [x["progress_pct"] for x in states.values()] == [41, 41]


def test_job_loop_posts_complete_snapshots_including_waiting_hosts(monkeypatch):
    from agent import main

    hosts = [f"10.0.0.{i}" for i in range(1, 8)]
    patches = []
    results = []
    class Api:
        def patch_job(self, job_id, payload):
            patches.append(deepcopy(payload))
        def upload_results(self, job_id, payload):
            results.append(deepcopy(payload))
            return {"status": "completed"}
    class Scanner:
        port_profile = "full"
        def start_scan(self, *, name, targets, port_range):
            return targets[0]
        def get_task_hosts(self, task_id):
            return [task_id]
        def poll(self, task_id, **kwargs):
            cov = {"verdict": "degraded_ports" if task_id == hosts[0] else "full", "reason": "unfinished"}
            return {"status": "completed", "gmp_status": "Done", "progress": 100,
                    "task_id": task_id, "vulnerabilities": [], "evidence": {
                        "report_id": "report-" + task_id, "hosts_attempted": 1, "hosts_assessed": 1,
                        "assessed_hosts": [task_id], "task_status": "Done", "report_read_ok": True,
                        "assessment_complete": True, "host_coverage": {task_id: cov}}}
        def stop(self, task_id):
            raise AssertionError("No healthy task should be stopped")
    monkeypatch.setattr(main.time, "sleep", lambda _: None)
    monkeypatch.setattr(main, "should_watch_lan", lambda *args, **kwargs: False)
    monkeypatch.setattr(main, "probe_laptop_capacity", lambda **kwargs: {
        "chunk_size": 1, "ip_workers": 5, "configured_ceiling": 5, "hot": False,
        "admission_paused": False})
    monkeypatch.setenv("SKIP_UNREACHABLE_TARGETS", "false")
    monkeypatch.setenv("SCAN_DEGRADED_RETRY", "0")
    import agent.reachability
    monkeypatch.setattr(agent.reachability, "partition_targets", lambda targets, **kwargs:
        {"reachable": list(targets), "unreachable": []})
    monkeypatch.setattr(main, "emit_ip_event", lambda *args, **kwargs: None)
    main._run_job_body({"api": Api(), "openvas": Scanner(), "poll": 0,
        "high_progress_warn_sec": 300, "high_progress_stall_sec": 0, "max_scan_runtime_sec": 0},
        {"id": "00000000-0000-0000-0000-000000000001", "targets": [{"target": h} for h in hosts]})
    snapshots = [p["target_progress"] for p in patches if "target_progress" in p]
    assert snapshots
    assert all(set(s) == set(hosts) for s in snapshots)
    assert sum(x["status"] == "scanning" for x in snapshots[0].values()) == 5
    assert sum(x["status"] == "pending" for x in snapshots[0].values()) == 2
    assert snapshots[-1][hosts[0]]["status"] == "incomplete"
    assert all(snapshots[-1][h]["status"] == "completed" for h in hosts[1:])
    assert results
