"""Shared helpers for extracted-disk manifests and path → part URI maps."""

from __future__ import annotations

import json
from typing import Any

import zstandard as zstd

from app.services.storage import get_bytes, put_bytes


def disk_prefix(job_id: str) -> str:
    return f"jobs/{job_id}/extracted-disk"


def upload_shard_index(job_id: str, shard_id: int, entries: list[dict], *, zstd_level: int = 1) -> str:
    """Upload one shard's index entries to MinIO (keeps checkpoint JSONB small)."""
    if not entries:
        return ""
    lines = "\n".join(json.dumps(e, separators=(",", ":")) for e in entries).encode("utf-8")
    compressed = zstd.ZstdCompressor(level=zstd_level).compress(lines)
    key = f"{disk_prefix(job_id)}/parts/index-{shard_id:05d}.jsonl.zst"
    return put_bytes(key, compressed, content_type="application/zstd")


def upload_extract_nodes(job_id: str, nodes: list[dict], *, zstd_level: int = 1) -> str:
    """Persist filtered extract node list so resume skips re-enumerating the disk."""
    lines = "\n".join(json.dumps(n, separators=(",", ":")) for n in nodes).encode("utf-8")
    compressed = zstd.ZstdCompressor(level=zstd_level).compress(lines)
    key = f"{disk_prefix(job_id)}/extract-nodes.jsonl.zst"
    return put_bytes(key, compressed, content_type="application/zstd")


def load_extract_nodes(nodes_uri: str) -> list[dict]:
    raw = get_bytes(nodes_uri)
    if not raw:
        return []
    data = zstd.ZstdDecompressor().decompress(raw)
    return [
        json.loads(line)
        for line in data.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def load_index_entries(manifest: dict) -> list[dict]:
    """Load all index entries from manifest index_uri and/or per-shard index files."""
    entries: list[dict] = []
    index_uri = manifest.get("index_uri") or ""
    if index_uri:
        raw = get_bytes(index_uri)
        if raw:
            data = zstd.ZstdDecompressor().decompress(raw)
            entries.extend(
                json.loads(line)
                for line in data.decode("utf-8", errors="replace").splitlines()
                if line.strip()
            )
    for sid, uri in sorted((manifest.get("shard_indexes") or {}).items(), key=lambda x: int(x[0])):
        if not uri:
            continue
        raw = get_bytes(uri)
        if not raw:
            continue
        data = zstd.ZstdDecompressor().decompress(raw)
        entries.extend(
            json.loads(line)
            for line in data.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        )
    return entries


def resolve_part_uri(manifest: dict, part_id: int) -> str | None:
    parts_map = manifest.get("parts_map") or {}
    key = str(part_id)
    if key in parts_map and parts_map[key]:
        return parts_map[key]
    if part_id in parts_map and parts_map[part_id]:
        return parts_map[part_id]
    parts = manifest.get("parts") or []
    if part_id < len(parts) and parts[part_id]:
        return parts[part_id]
    return None


def build_index_map(manifest: dict, *, extra_entries: list[dict] | None = None) -> dict[str, str]:
    """Map file path → MinIO part URI using part_id on each index entry."""
    index_map: dict[str, str] = {}
    entries = load_index_entries(manifest) if manifest.get("index_uri") or manifest.get("shard_indexes") else []
    if extra_entries:
        entries = list(entries) + list(extra_entries)
    for e in entries:
        path = e.get("path")
        if not path:
            continue
        sid = int(e.get("part_id", 0))
        uri = resolve_part_uri(manifest, sid)
        if uri:
            index_map[path] = uri
    return index_map


def build_partial_manifest(
    *,
    job_id: str,
    vd_meta: dict[str, Any],
    checkpoint: dict,
    mode: str,
    filter_stats: dict,
    streaming: bool = False,
) -> dict:
    """Build disk_source manifest from extraction checkpoint (partial or complete)."""
    parts_map: dict[str, str] = dict(checkpoint.get("parts_map") or {})
    shard_indexes: dict[str, str] = dict(checkpoint.get("shard_indexes") or {})
    worker_count = int(checkpoint.get("worker_count") or len(parts_map) or 1)
    parts_ordered = [parts_map.get(str(i)) or parts_map.get(i) for i in range(worker_count)]
    completed = checkpoint.get("completed_shards") or []
    files_extracted = int(checkpoint.get("files_extracted") or 0)
    bytes_extracted = int(checkpoint.get("bytes_extracted") or 0)
    return {
        "job_id": job_id,
        "base_name": vd_meta.get("base_name", ""),
        "format": vd_meta.get("format", ""),
        "mode": vd_meta.get("mode", ""),
        "segment_paths": vd_meta.get("segment_paths", []),
        "segment_hashes": vd_meta.get("segment_hashes", []),
        "extract_mode": mode,
        "filter_stats": filter_stats,
        "shard_count": worker_count,
        "parts": [p for p in parts_ordered if p],
        "parts_map": parts_map,
        "shard_indexes": shard_indexes,
        "index_uri": checkpoint.get("index_uri") or "",
        "files_total": int(checkpoint.get("nodes_total") or 0),
        "files_extracted": files_extracted,
        "bytes_extracted": bytes_extracted,
        "files_skipped": int(checkpoint.get("files_skipped") or 0),
        "completed_shard_count": len(completed),
        "streaming": streaming,
        "partial": streaming and len(completed) < worker_count,
    }
