from __future__ import annotations

import io
import tarfile
from types import SimpleNamespace

import zstandard as zstd

from app.services.extracted_disk import plan_ewf_extract_io
from app.services import tar_cache
from app.services.dual_rag_index import chunk_rows_for_embedding
from app.services.disk_io_profile import detect_source_io_profile


def _tar_zst(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    cctx = zstd.ZstdCompressor(level=1)
    with cctx.stream_writer(raw, closefd=False) as zw:
        with tarfile.open(fileobj=zw, mode="w|") as tf:
            for name, data in files.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def test_hdd_plan_is_one_sequential_source_reader() -> None:
    nodes = [{"path": f"Users/A/file-{i}.txt"} for i in range(10000)]
    readers, shards, reason = plan_ewf_extract_io(
        nodes,
        configured_workers=8,
        configured_shards=12,
        live_workers=8,
        thermal_pace=1.0,
        busy_extracts=1,
        cpu_count=16,
        stream_phase3=True,
        source_media="hdd",
    )
    assert readers == 1
    assert 4 <= shards <= 8
    assert reason == "hdd_sequential"


def test_media_override_is_deterministic(monkeypatch) -> None:
    monkeypatch.setenv("DISK_SOURCE_MEDIA", "hdd")
    prof = detect_source_io_profile(["/not/required/when/overridden.E01"])
    assert prof.media == "hdd"
    assert prof.rotational is True
    assert prof.detection == "environment_override"


def test_tar_budget_reader_scans_part_once(monkeypatch) -> None:
    payload = _tar_zst({
        "a.txt": b"abcdefghijklmnopqrstuvwxyz",
        "b.txt": b"0123456789",
    })
    opens = {"n": 0}

    def open_stream(_uri):
        opens["n"] += 1
        return io.BytesIO(payload)

    tar_cache.clear_tar_cache()
    monkeypatch.setattr(tar_cache, "open_object_stream", open_stream)
    got = dict(
        tar_cache.iter_files_from_part_budgets(
            "s3://case/part.tar.zst",
            {"a.txt": 5, "b.txt": None},
        )
    )
    assert opens["n"] == 1
    assert got["a.txt"] == b"abcde"
    assert got["b.txt"] == b"0123456789"


def test_rag_fallback_groups_same_part_into_one_pass(monkeypatch) -> None:
    calls: list[dict[str, int | None]] = []

    def fake_iter(part_uri, budgets):
        calls.append(dict(budgets))
        assert part_uri == "s3://case/part-1"
        for path in budgets:
            yield path, f"raw fallback for {path}".encode()

    monkeypatch.setattr(
        "app.services.dual_rag_index.iter_files_from_part_budgets",
        fake_iter,
    )
    rows = [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "file_path": "Users/A/one.txt",
            "normalized": None,
            "ocr_text": None,
            "encyclopedia_artifact_id": None,
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "file_path": "Users/A/two.txt",
            "normalized": None,
            "ocr_text": None,
            "encyclopedia_artifact_id": None,
        },
    ]
    settings = SimpleNamespace(rag_chunk_size=500, rag_chunk_overlap=0)
    index_map = {
        "Users/A/one.txt": "s3://case/part-1",
        "Users/A/two.txt": "s3://case/part-1",
    }
    texts, meta, skip_ids, fallback = chunk_rows_for_embedding(rows, settings, index_map=index_map)
    assert len(calls) == 1
    assert set(calls[0]) == {"Users/A/one.txt", "Users/A/two.txt"}
    assert fallback == 2
    assert skip_ids == []
    assert len(texts) == 2
    assert len(meta) == 2
