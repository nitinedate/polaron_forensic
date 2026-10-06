from pathlib import Path

from app.services.source_media import classify_source_path, sequential_read_mbps


def test_source_media_override_hdd_does_not_need_probe(tmp_path: Path):
    p = tmp_path / "evidence.E01"
    p.write_bytes(b"evidence")
    profile = classify_source_path(p, override="hdd")
    assert profile.kind == "hdd"
    assert profile.rotational is True
    assert profile.reason == "operator_override"


def test_source_media_override_nvme(tmp_path: Path):
    p = tmp_path / "evidence.raw"
    p.write_bytes(b"evidence")
    profile = classify_source_path(p, override="nvme")
    assert profile.kind == "nvme"
    assert profile.rotational is False


def test_sequential_benchmark_is_read_only(tmp_path: Path):
    p = tmp_path / "sample.img"
    original = b"A" * (2 * 1024 * 1024)
    p.write_bytes(original)
    rate = sequential_read_mbps(p, sample_bytes=1024 * 1024)
    assert rate is not None and rate > 0
    assert p.read_bytes() == original
