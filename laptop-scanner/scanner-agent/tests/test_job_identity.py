from agent.job_identity import (
    host_set,
    network_key,
    plan_resume_chunks,
    remaining_hosts,
    stored_task_entries,
)


def test_network_key_separates_private_ranges():
    a = network_key(["10.10.80.12", "10.10.80.99"])
    b = network_key(["192.168.1.10", "192.168.1.20"])
    assert a != b
    assert a == network_key(["10.10.80.1"])


def test_remaining_hosts_skips_assessed_only():
    selected = ["10.10.80.1", "10.10.80.2", "10.10.80.3"]
    left = remaining_hosts(selected=selected, assessed=["10.10.80.2"])
    assert left == ["10.10.80.1", "10.10.80.3"]


def test_resume_binds_by_live_hosts_not_chunk_index():
    """A leftover task for another /24 must not attach to this job's chunks."""
    job_hosts = ["10.10.80.1", "10.10.80.2"]
    remaining = ["10.10.80.1", "10.10.80.2"]
    stored = [
        {"task_id": "task-other-net", "hosts": ["192.168.1.10"]},
        {"task_id": "task-this-net", "hosts": ["10.10.80.1"]},
    ]
    live = {
        "task-other-net": ["192.168.1.10"],
        "task-this-net": ["10.10.80.1"],
    }
    chunks, resume_map, dropped = plan_resume_chunks(
        job_hosts=job_hosts,
        remaining=remaining,
        stored_tasks=stored,
        live_hosts=live,
        chunk_size=1,
    )
    assert dropped == ["task-other-net"]
    assert resume_map == {0: "task-this-net"}
    assert chunks[0] == ["10.10.80.1"]
    assert chunks[1] == ["10.10.80.2"]
    assert "192.168.1.10" not in {h for chunk in chunks for h in chunk}


def test_unverified_task_is_not_index_mapped():
    chunks, resume_map, dropped = plan_resume_chunks(
        job_hosts=["10.10.80.1", "10.10.80.2"],
        remaining=["10.10.80.1", "10.10.80.2"],
        stored_tasks=[{"task_id": "ghost", "hosts": ["10.10.80.1"]}],
        live_hosts={"ghost": None},
        chunk_size=2,
    )
    assert dropped == ["ghost"]
    assert resume_map == {}
    assert chunks == [["10.10.80.1", "10.10.80.2"]]


def test_stored_task_entries_do_not_invent_foreign_ids():
    entries = stored_task_entries(
        chunk_tasks=[{"task_id": "a", "hosts": ["10.0.0.1"]}],
        external_scan_id='["a","b"]',
    )
    assert [e["task_id"] for e in entries] == ["a", "b"]
    assert host_set(["10.0.0.1"]) == host_set(entries[0]["hosts"])


def test_stale_missing_task_does_not_block_skip_complete():
    from agent.job_identity import leftover_blocks_skip_complete

    assert (
        leftover_blocks_skip_complete(
            dropped_tasks=["864c428d-d584-4aed-a72e-fde8a59b7864"],
            live_hosts={"864c428d-d584-4aed-a72e-fde8a59b7864": []},
            job_hosts=["192.168.0.146", "192.168.29.85"],
        )
        is False
    )


def test_gmp_error_still_blocks_skip_complete():
    from agent.job_identity import leftover_blocks_skip_complete

    assert leftover_blocks_skip_complete(
        dropped_tasks=["ghost"],
        live_hosts={"ghost": None},
        job_hosts=["10.10.80.1"],
    )


def test_wrong_network_leftover_blocks_skip_complete():
    from agent.job_identity import leftover_blocks_skip_complete

    assert leftover_blocks_skip_complete(
        dropped_tasks=["other"],
        live_hosts={"other": ["192.168.1.10"]},
        job_hosts=["10.10.80.1"],
    )


def test_resume_leftover_does_not_require_skipped_hosts():
    """OpenVAS leftover still lists 2 hosts; agent already skipped one."""
    chunks, resume_map, dropped = plan_resume_chunks(
        job_hosts=["192.168.0.163", "192.168.0.103"],
        remaining=["192.168.0.163"],
        stored_tasks=[
            {
                "task_id": "49700bc1-cd46-4e65-af2a-6dd4feabc213",
                "hosts": ["192.168.0.163", "192.168.0.103"],
            }
        ],
        live_hosts={
            "49700bc1-cd46-4e65-af2a-6dd4feabc213": [
                "192.168.0.163",
                "192.168.0.103",
            ]
        },
        chunk_size=8,
    )
    assert dropped == []
    assert resume_map == {0: "49700bc1-cd46-4e65-af2a-6dd4feabc213"}
    assert chunks == [["192.168.0.163"]]
    assert "192.168.0.103" not in {h for chunk in chunks for h in chunk}

