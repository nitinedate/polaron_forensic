import ast
import hashlib
import os
from pathlib import Path

from app.services.extract_filters import should_extract_node
from app.services.source_media import classify_source_path, sequential_read_mbps


def _load_subset():
    src = Path('app/services/extracted_disk.py').read_text()
    tree = ast.parse(src)
    body = [
        n for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef))
        and n.name in {'plan_ewf_extract_io', '_IterFileReader'}
    ]
    ns = {'os': os, 'hashlib': hashlib}
    exec(compile(ast.Module(body=body, type_ignores=[]), 'subset', 'exec'), ns)
    return ns


def test_hdd_planner_is_seek_safe():
    ns = _load_subset()
    nodes = [{'path': f'f{i}', 'inode': i} for i in range(10000)]
    readers, shards, reason = ns['plan_ewf_extract_io'](
        nodes,
        configured_workers=8,
        configured_shards=16,
        source_kind='hdd',
        hdd_readers=1,
        hdd_max_readers=2,
        hdd_shards=8,
        cpu_count=24,
    )
    assert readers == 1
    assert shards == 8
    assert reason == 'hdd_sequential_locality'


def test_hdd_planner_caps_even_if_global_workers_are_high():
    ns = _load_subset()
    nodes = [{'path': f'f{i}', 'inode': i} for i in range(10000)]
    readers, _, _ = ns['plan_ewf_extract_io'](
        nodes,
        configured_workers=32,
        configured_shards=16,
        source_kind='hdd',
        hdd_readers=4,
        hdd_max_readers=2,
        hdd_shards=8,
        cpu_count=32,
    )
    assert readers == 2


def test_stream_reader_hashes_same_pass():
    ns = _load_subset()
    r = ns['_IterFileReader'](iter([b'abc', b'defgh', b'ijk']), hash_enabled=True)
    assert r.read(4) == b'abcd'
    assert r.read(3) == b'efg'
    assert r.read(99) == b'hijk'
    assert r.bytes_read == 11
    assert r.hexdigest() == hashlib.sha256(b'abcdefghijk').hexdigest()


def test_full_mode_does_not_drop_large_evidence_by_generic_size_cap():
    keep, reason = should_extract_node(
        'Users/Examiner/Documents/large-evidence.bin',
        5 * 1024 * 1024 * 1024,
        mode='full',
        max_file_bytes=100_000_000,
        skip_system_paths=False,
        os_family='windows',
    )
    assert keep is True
    assert reason is None


def test_media_override_hdd_is_read_only(tmp_path: Path):
    p = tmp_path / 'case.E01'
    p.write_bytes(b'A' * 1024)
    before = p.read_bytes()
    profile = classify_source_path(p, override='hdd')
    assert profile.kind == 'hdd'
    assert p.read_bytes() == before


def test_small_sequential_probe_never_modifies_source(tmp_path: Path):
    p = tmp_path / 'case.raw'
    before = b'B' * (2 * 1024 * 1024)
    p.write_bytes(before)
    assert sequential_read_mbps(p, sample_bytes=1024 * 1024) > 0
    assert p.read_bytes() == before
