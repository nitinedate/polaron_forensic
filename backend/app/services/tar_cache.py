"""Cached tar shard reader — streams zstd tar parts without loading whole archives."""

from __future__ import annotations

import io
import logging
import tarfile
import threading
from collections import OrderedDict
from collections.abc import Iterator

import zstandard as zstd

from app.services.storage import open_object_stream

log = logging.getLogger("tar_cache")

_CACHE_MAX = 8
_MAX_CACHED_FILE_BYTES = 10_000_000
_lock = threading.Lock()
_cache: OrderedDict[str, dict[str, bytes | None]] = OrderedDict()


def _decompress_zstd(raw: bytes) -> bytes | None:
    """Decompress single-frame zstd blobs (e.g. index.jsonl.zst)."""
    if not raw:
        return None
    try:
        return zstd.ZstdDecompressor().decompress(raw)
    except zstd.ZstdError:
        return None


def _cache_file(part_uri: str, path: str, content: bytes | None) -> None:
    if content is None or len(content) > _MAX_CACHED_FILE_BYTES:
        return
    with _lock:
        bucket = _cache.setdefault(part_uri, {})
        bucket[path] = content
        _cache.move_to_end(part_uri)
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)


def _cached_file(part_uri: str, path: str) -> bytes | None:
    with _lock:
        bucket = _cache.get(part_uri)
        if bucket is not None and path in bucket:
            _cache.move_to_end(part_uri)
            return bucket[path]
    return None


def iter_files_from_part(
    part_uri: str,
    paths: set[str],
    *,
    max_bytes: int | None = None,
) -> Iterator[tuple[str, bytes | None]]:
    """Yield ``(path, content)`` for wanted members via streamed MinIO/zstd/tar.

    Never buffers the compressed shard in RAM (parts can be 5–13+ GB).
    """
    wanted = {p.replace("\\", "/") for p in paths}
    if not wanted:
        return

    # Serve tiny cache hits first without touching the stream.
    remaining = set(wanted)
    for p in list(remaining):
        if max_bytes is None:
            hit = _cached_file(part_uri, p)
            if hit is not None:
                remaining.discard(p)
                yield p, hit
        else:
            cached = _cached_file(part_uri, p)
            if cached is not None:
                remaining.discard(p)
                yield p, cached[:max_bytes]
    if not remaining:
        return

    stream = open_object_stream(part_uri)
    if stream is None:
        for p in remaining:
            yield p, None
        return

    try:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(stream) as zreader:
            with tarfile.open(fileobj=zreader, mode="r|") as tar:
                for member in tar:
                    if not remaining:
                        break
                    if not member.isfile():
                        continue
                    norm = member.name.replace("\\", "/")
                    if norm not in remaining:
                        continue
                    f = tar.extractfile(member)
                    if not f:
                        remaining.discard(norm)
                        yield norm, None
                        continue
                    content = f.read(max_bytes) if max_bytes else f.read()
                    if max_bytes is None:
                        _cache_file(part_uri, norm, content)
                    remaining.discard(norm)
                    yield norm, content
    except Exception as exc:
        log.warning("Streamed tar read failed part=%s: %s", part_uri, exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass

    for p in remaining:
        yield p, None


def read_file_from_part(part_uri: str, path: str, *, max_bytes: int | None = None) -> bytes | None:
    """Read a single file from a tar shard (streaming — low memory)."""
    for _norm, content in iter_files_from_part(part_uri, {path}, max_bytes=max_bytes):
        return content
    return None


def read_files_from_part(
    part_uri: str,
    paths: set[str],
    *,
    max_bytes: int | None = None,
) -> dict[str, bytes | None]:
    """Read many paths from one shard in a single streaming pass.

    Prefer :func:`iter_files_from_part` when callers can process members
    incrementally — this helper still materializes the full result dict.
    """
    wanted = {p.replace("\\", "/") for p in paths}
    found: dict[str, bytes | None] = {p: None for p in wanted}
    for norm, content in iter_files_from_part(part_uri, wanted, max_bytes=max_bytes):
        found[norm] = content
    return found


def clear_tar_cache() -> None:
    with _lock:
        _cache.clear()
