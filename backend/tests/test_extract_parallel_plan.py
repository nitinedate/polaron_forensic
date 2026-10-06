from types import SimpleNamespace

from app.services.extracted_disk import plan_ewf_extract_io, plan_mobile_extract_io


def test_ewf_caps_readers_at_four_on_a_22_core_host():
    nodes = [{"path": f"windows/system32/{i:05d}.dll"} for i in range(20000)]
    readers, shards, reason = plan_ewf_extract_io(
        nodes,
        configured_workers=12,
        configured_shards=14,
        live_workers=12,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=22,
        stream_phase3=True,
    )
    assert readers == 4
    assert shards >= readers
    assert reason.startswith("ewf_parallel")


def test_ewf_caps_legacy_eight_reader_requests():
    nodes = [{"path": f"windows/system32/{i:05d}.dll"} for i in range(12000)]
    readers, shards, reason = plan_ewf_extract_io(
        nodes,
        configured_workers=8,
        configured_shards=12,
        live_workers=8,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
        stream_phase3=True,
    )
    assert readers == 4
    assert shards >= 12
    assert reason.startswith("ewf_parallel")


def test_ewf_caps_legacy_six_reader_requests():
    nodes = [{"path": f"windows/system32/{i:05d}.dll"} for i in range(8000)]
    readers, shards, reason = plan_ewf_extract_io(
        nodes,
        configured_workers=6,
        configured_shards=8,
        live_workers=6,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
        stream_phase3=True,
    )
    assert readers == 4
    assert shards >= readers
    assert reason.startswith("ewf_parallel")


def test_ewf_uses_parallel_readers_by_default():
    nodes = [{"path": f"windows/system32/{i:05d}.dll"} for i in range(5000)]
    readers, shards, reason = plan_ewf_extract_io(
        nodes,
        configured_workers=3,
        configured_shards=8,
        live_workers=3,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
        stream_phase3=True,
    )
    assert readers >= 2
    assert shards >= readers
    assert reason.startswith("ewf_parallel")


def test_ewf_thermal_can_drop_but_stays_moving():
    nodes = [{"path": f"file{i}"} for i in range(2000)]
    readers, _, reason = plan_ewf_extract_io(
        nodes,
        configured_workers=4,
        configured_shards=8,
        live_workers=4,
        thermal_pace=0.30,
        busy_extracts=1,
        cpu_count=16,
        stream_phase3=True,
    )
    assert 1 <= readers <= 2
    assert "thermal" in reason


def test_plain_ios_folder_uses_four_readers():
    vd = SimpleNamespace(mode="folder", format="mobile")
    nodes = [{"path": f"backup/{i:05d}"} for i in range(200)]
    readers, shards, reason = plan_mobile_extract_io(
        vd,
        nodes,
        configured_workers=8,
        live_workers=1,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
    )
    assert readers == 4
    assert shards >= readers  # Resumable logical shards may outnumber running readers.
    assert reason.startswith("plain_folder")


def test_metadata_zip_sealed_paths_use_folder_readers():
    vd = SimpleNamespace(mode="folder", format="zip")
    nodes = [{"path": f"_sealed/run1/ios_image/{i:05d}"} for i in range(200)]
    readers, shards, reason = plan_mobile_extract_io(
        vd,
        nodes,
        configured_workers=8,
        live_workers=1,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
    )
    assert readers == 4
    assert shards >= readers
    assert reason.startswith("plain_folder")


def test_zip_dump_uses_payload_parallel_readers():
    vd = SimpleNamespace(mode="folder", format="zip")
    nodes = [{"path": f"dump.zip/file{i}"} for i in range(200)]
    readers, shards, reason = plan_mobile_extract_io(
        vd,
        nodes,
        configured_workers=8,
        live_workers=8,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
    )
    assert readers == 4
    assert shards >= readers
    assert reason.startswith("zip_payload_parallel")


def test_small_ufed_zip_stays_modest():
    vd = SimpleNamespace(mode="folder", format="zip")
    nodes = [{"path": f"dump.zip/file{i}"} for i in range(6)]
    readers, _, reason = plan_mobile_extract_io(
        vd,
        nodes,
        configured_workers=8,
        live_workers=8,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
    )
    assert readers == 4
    assert reason.startswith("zip_or_ufed")


def test_thermal_does_not_collapse_to_one_reader():
    vd = SimpleNamespace(mode="folder", format="backup")
    nodes = [{"path": f"ios/{i}"} for i in range(50)]
    readers, _, reason = plan_mobile_extract_io(
        vd,
        nodes,
        configured_workers=8,
        live_workers=8,
        thermal_pace=0.35,
        busy_extracts=1,
        cpu_count=16,
    )
    assert readers >= 2
    assert "thermal" in reason
