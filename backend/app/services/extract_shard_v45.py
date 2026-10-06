"""Disk extraction shard worker — V45 (streaming, DB-free, semaphore-gated).

Replaces ``extracted_disk._shard_worker``. Behavioural contract (checkpoint
format, part naming ``parts/part-NNNNN.tar.zst``, index entries, return dict,
``JobStopRequested`` semantics) is unchanged so resume/Phase-3 keep working.

Fixes shipped here
------------------
1. **No DB connection inside shard threads.**  The pre-V45 worker opened a
   ``firm_session`` for the start log, every ``_check_stop`` (each 1 000 files)
   and every unreadable-file log.  With a Celery worker pool of 2+2 and the
   main session + flusher + stop-poller + heartbeat already holding 4, the
   first shard that needed a connection waited 30 s and died with
   ``QueuePool limit of size 2 overflow 2 reached``.  Shard threads now push
   events onto ``ShardEventBus``; the single flusher thread drains it.

2. **Streaming reads.**  Files are streamed from the image in 1–8 MiB chunks
   through a ``SpooledTemporaryFile`` (RAM up to ``EXTRACT_SPOOL_MAX_BYTES``,
   then scratch disk) straight into the tar, with SHA-256 computed in the same
   pass.  No more ``read_full_file_from_disk`` → ``io.BytesIO`` copies.

3. **Bounded read semaphore.**  ``EXTRACT_READ_SEMAPHORE`` (default/max 4) caps
   *concurrent image reads* independently of the shard count, so 14 resumable
   shards no longer mean 14 random-seeking pyewf handles.  Rotational/USB
   sources get an automatic cap of ``EXTRACT_HDD_READERS`` (default 2) via
   ``disk_io_profile`` (which existed but was never imported).

4. **Uploads within the shard worker.** A finished part uploads before that
   evidence worker completes. The four-worker extraction pool therefore also
   bounds upload work and retains checkpoint correctness.

5. **Scratch on fast storage.**  Temporary parts go to ``EXTRACT_SCRATCH_DIR``
   when set (point it at NVMe/SSD when the evidence is on a USB HDD).
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import tarfile
import tempfile
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterator

import zstandard as zstd

from app.services.job_control import JobStopRequested
from app.services.storage import put_file
from app.services.virtual_disk import VirtualDisk, iter_file_from_disk, open_virtual_disk

log = logging.getLogger("extracted_disk.v45")


# ---------------------------------------------------------------------------
# Tunables (env, with safe defaults)
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.environ.get(name) or default)))
    except (TypeError, ValueError):
        return default


READ_SEMAPHORE_SIZE = _env_int("EXTRACT_READ_SEMAPHORE", 4, 1, 4)
HDD_READERS = _env_int("EXTRACT_HDD_READERS", 2, 1, 4)
SPOOL_MAX_BYTES = _env_int("EXTRACT_SPOOL_MAX_BYTES", 32 * 1024 * 1024, 1 << 20, 1 << 30)
READ_CHUNK_BYTES = _env_int("EXTRACT_READ_CHUNK_BYTES", 4 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024)
HDD_READ_CHUNK_BYTES = _env_int("EXTRACT_HDD_CHUNK_BYTES", 8 * 1024 * 1024, 1 << 20, 64 * 1024 * 1024)
UPLOAD_POOL_SIZE = _env_int("EXTRACT_UPLOAD_CONCURRENCY", 4, 1, 4)
SCRATCH_DIR = (os.environ.get("EXTRACT_SCRATCH_DIR") or "").strip() or None


# ---------------------------------------------------------------------------
# Shared gates (one per worker process)
# ---------------------------------------------------------------------------

_read_gate_lock = threading.Lock()
_read_gate: threading.BoundedSemaphore | None = None
_read_gate_size = 0


def configure_read_gate(size: int) -> threading.BoundedSemaphore:
    """(Re)size the process-wide image-read semaphore. Safe to call per job."""
    global _read_gate, _read_gate_size
    size = max(1, min(4, int(size)))
    with _read_gate_lock:
        if _read_gate is None or _read_gate_size != size:
            _read_gate = threading.BoundedSemaphore(size)
            _read_gate_size = size
        return _read_gate


def read_gate() -> threading.BoundedSemaphore:
    return configure_read_gate(_read_gate_size or READ_SEMAPHORE_SIZE)


_upload_pool: ThreadPoolExecutor | None = None
_upload_pool_lock = threading.Lock()


def upload_pool() -> ThreadPoolExecutor:
    global _upload_pool
    with _upload_pool_lock:
        if _upload_pool is None:
            _upload_pool = ThreadPoolExecutor(max_workers=UPLOAD_POOL_SIZE, thread_name_prefix="extract-upload")
        return _upload_pool


# ---------------------------------------------------------------------------
# Source-aware reader planning
# ---------------------------------------------------------------------------

def plan_readers(vd: VirtualDisk, requested_readers: int) -> tuple[int, int, str]:
    """Return (parallel_readers, read_semaphore, reason) honoring the physical source.

    Rotational / USB / network sources collapse to a sequential-ish profile:
    one or two readers, bigger chunks. SSD/NVMe keep the planner's number but
    never exceed the configured semaphore.
    """
    requested = max(1, int(requested_readers))
    media, detection = "unknown", "unavailable"
    try:
        from app.services.disk_io_profile import detect_source_io_profile

        prof = detect_source_io_profile(list(getattr(vd, "segment_paths", []) or []))
        media, detection = prof.media, prof.detection
    except Exception:
        pass
    sem = READ_SEMAPHORE_SIZE
    if media in ("hdd", "network"):
        readers = min(requested, HDD_READERS)
        return readers, min(sem, readers), f"{media}:{detection}:readers<={HDD_READERS}"
    if media == "unknown":
        # Docker Desktop on Windows hides the block device. Be conservative but
        # not sequential: half the semaphore until the examiner sets
        # DISK_SOURCE_MEDIA=ssd|nvme|hdd explicitly.
        readers = min(requested, max(2, sem // 2))
        return readers, min(sem, readers), f"unknown_media:{detection}:readers<={readers}"
    readers = min(requested, sem)
    return readers, min(sem, readers), f"{media}:{detection}:readers<={sem}"


def read_chunk_size(vd: VirtualDisk) -> int:
    try:
        from app.services.disk_io_profile import detect_source_io_profile

        if detect_source_io_profile(list(getattr(vd, "segment_paths", []) or [])).media in ("hdd", "network"):
            return HDD_READ_CHUNK_BYTES
    except Exception:
        pass
    return READ_CHUNK_BYTES


# ---------------------------------------------------------------------------
# Event bus: shard threads never touch the DB
# ---------------------------------------------------------------------------

class ShardEventBus:
    """Thread-safe queue of log/progress events, drained by the flusher thread.

    ``drain()`` returns (level, message, metadata) tuples ready for
    ``write_disk_log``. Capped so a pathological shard cannot grow RAM.
    """

    def __init__(self, maxsize: int = 5000) -> None:
        self._q: queue.Queue[tuple[str, str, dict[str, Any]]] = queue.Queue(maxsize=maxsize)
        self.dropped = 0

    def emit(self, message: str, *, level: str = "info", metadata: dict[str, Any] | None = None) -> None:
        try:
            self._q.put_nowait((level, message, dict(metadata or {})))
        except queue.Full:
            self.dropped += 1

    def drain(self, limit: int = 500) -> list[tuple[str, str, dict[str, Any]]]:
        out: list[tuple[str, str, dict[str, Any]]] = []
        while len(out) < limit:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out


# ---------------------------------------------------------------------------
# Streaming file → tar
# ---------------------------------------------------------------------------

class _CountingHasher:
    __slots__ = ("h", "n")

    def __init__(self, enabled: bool) -> None:
        self.h = hashlib.sha256() if enabled else None
        self.n = 0

    def update(self, b: bytes) -> None:
        self.n += len(b)
        if self.h is not None:
            self.h.update(b)

    def hexdigest(self) -> str:
        return self.h.hexdigest() if self.h is not None else ""


def _stream_into_spool(
    chunks: Iterator[bytes],
    *,
    hash_files: bool,
    spool_dir: str | None,
) -> tuple[tempfile.SpooledTemporaryFile, int, str]:
    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MAX_BYTES, dir=spool_dir)
    ch = _CountingHasher(hash_files)
    for chunk in chunks:
        if not chunk:
            continue
        spool.write(chunk)
        ch.update(chunk)
    spool.seek(0)
    return spool, ch.n, ch.hexdigest()


def open_shard_vd(schema_name: str, job_id: str, payload: dict) -> VirtualDisk:
    """Open a VirtualDisk for a shard WITHOUT a DB session when the payload carries the plan.

    ``extracted_disk`` is patched to put ``vd_plan`` (segment_paths, mode,
    format, root_folder, base_name) into each payload; if an old payload lacks
    it we fall back to the DB-backed opener using a short-lived session.
    """
    plan = payload.get("vd_plan") or {}
    paths = list(plan.get("segment_paths") or [])
    if paths:
        try:
            from app.services.virtual_disk import open_virtual_disk_from_paths  # V45 helper (patched in)

            return open_virtual_disk_from_paths(
                job_id,
                paths,
                hashes=list(plan.get("segment_hashes") or []),
                base_name=str(plan.get("base_name") or ""),
                fmt=str(plan.get("format") or ""),
                root_folder=plan.get("root_folder"),
            )
        except ImportError:
            pass
    from app.db.session import firm_session

    with firm_session(schema_name) as db:
        return open_virtual_disk(db, job_id)


def shard_worker_v45(
    payload: dict,
    progress: Any,
    flusher: Any | None,
    stop_poller: Any | None,
    *,
    shared_vd: VirtualDisk | None = None,
    event_bus: ShardEventBus | None = None,
) -> dict:
    """Extract one shard to a zstd tar part and upload it. Never touches the DB."""
    schema_name = payload["schema_name"]
    job_id = payload["job_id"]
    shard_id = int(payload["shard_id"])
    shard_count = int(payload["shard_count"])
    nodes = sorted(
        payload["nodes"],
        key=lambda n: (
            n.get("inode") is None,
            int(n["inode"]) if n.get("inode") is not None else 0,
            n.get("path", ""),
        ),
    )
    zstd_level = max(int(payload.get("zstd_level") or 1), 1)
    hash_files = bool(payload.get("hash_files"))
    stop_check_interval = max(int(payload.get("stop_check_interval") or 200), 1)
    tar_bufsize = max(int(payload.get("tar_bufsize") or 1_048_576), 65_536)
    bus = event_bus
    emit = bus.emit if bus is not None else (lambda *a, **k: None)

    part_name = f"parts/part-{shard_id:05d}.tar.zst"
    part_key = f"{payload.get('part_prefix') or f'jobs/{job_id}/extracted-disk'}/{part_name}"

    index_entries: list[dict] = []
    bytes_written = 0
    skip_count = 0
    stopped = False
    owns_vd = shared_vd is None
    vd = shared_vd or open_shard_vd(schema_name, job_id, payload)
    gate = read_gate()
    chunk = read_chunk_size(vd)
    spool_dir = SCRATCH_DIR if SCRATCH_DIR and os.path.isdir(SCRATCH_DIR) else None

    emit(
        f"Shard {shard_id}/{shard_count - 1} started — {len(nodes):,} files "
        f"(stream, gate={_read_gate_size}, chunk={chunk // (1 << 20)} MiB, mode={vd.mode})",
        metadata={"shard_id": shard_id, "files_in_shard": len(nodes), "mode": vd.mode, "v45": True},
    )

    try:
        from app.services.adaptive_semaphore import cpu_backoff_delay
    except Exception:
        cpu_backoff_delay = None
    thermal_check_every = 64

    fd, tmp_name = tempfile.mkstemp(suffix=".tar.zst", dir=spool_dir)
    os.close(fd)
    tmp_path = Path(tmp_name)
    part_uri = ""
    file_idx = 0
    detail_every = max(stop_check_interval * 10, 5_000)
    t0 = time.monotonic()

    try:
        cctx = zstd.ZstdCompressor(level=zstd_level, threads=1)
        with tmp_path.open("wb") as raw_out, cctx.stream_writer(raw_out) as compressed, tarfile.open(
            fileobj=compressed, mode="w|", bufsize=tar_bufsize
        ) as tar:
            offset = 0
            for node in nodes:
                file_idx += 1
                if cpu_backoff_delay is not None and file_idx % thermal_check_every == 0:
                    try:
                        delay = float(cpu_backoff_delay())
                        if delay > 0:
                            time.sleep(delay)
                    except Exception:
                        pass
                if file_idx % stop_check_interval == 0 and stop_poller is not None and stop_poller.is_requested():
                    stopped = True
                    break
                rel = node["path"]
                inode = node.get("inode")
                size_hint = int(node.get("size_bytes") or 0)
                progress.set_current(rel, action="reading", shard_id=shard_id)
                if flusher and (file_idx == 1 or file_idx % max(stop_check_interval, 200) == 0):
                    flusher.mark_dirty()
                try:
                    with gate:   # bounded concurrent image reads
                        spool, nbytes, digest = _stream_into_spool(
                            iter_file_from_disk(
                                vd, rel, inode=int(inode) if inode is not None else None, chunk_size=chunk
                            ),
                            hash_files=hash_files,
                            spool_dir=spool_dir,
                        )
                except Exception as exc:
                    skip_count += 1
                    progress.record_read_skipped()
                    progress.set_current(rel, action="skip_unreadable", shard_id=shard_id)
                    if skip_count <= 10:
                        emit(
                            f"Shard {shard_id}: could not read {rel} — {exc}",
                            level="warning",
                            metadata={"shard_id": shard_id, "current_path": rel, "error": str(exc)[:300], "action": "skip_unreadable"},
                        )
                    continue
                try:
                    progress.set_current(rel, action="packing", shard_id=shard_id)
                    info = tarfile.TarInfo(name=rel.replace("\\", "/"))
                    info.size = nbytes
                    info.mtime = int(node.get("mtime") or 0) or int(time.time())
                    tar.addfile(info, spool)
                finally:
                    spool.close()
                index_entries.append(
                    {"path": rel, "size_bytes": nbytes, "sha256": digest, "part_id": shard_id, "offset": offset}
                )
                offset += nbytes
                bytes_written += nbytes
                progress.record_extracted(nbytes)
                progress.set_current(rel, action="stored", shard_id=shard_id)
                if file_idx == 1 or file_idx % detail_every == 0:
                    emit(
                        f"Shard {shard_id}: processed #{file_idx:,}/{len(nodes):,} — {rel} ({nbytes:,} bytes"
                        + (f", listed {size_hint:,}" if size_hint and size_hint != nbytes else "")
                        + ")",
                        metadata={"shard_id": shard_id, "file_index": file_idx, "files_in_shard": len(nodes), "current_path": rel, "action": "processed"},
                    )

        if index_entries and not stopped:
            progress.set_current(f"part-{shard_id:05d}.tar.zst", action="uploading", shard_id=shard_id)
            # Upload on this evidence slot; a nested uploader pool multiplied the
            # real concurrency beyond the four source work units.
            part_uri = put_file(part_key, tmp_path, "application/zstd")
    except JobStopRequested:
        stopped = True
    except Exception as exc:
        emit(f"Shard {shard_id} failed: {exc}", level="error", metadata={"shard_id": shard_id, "error": str(exc)[:500]})
        raise
    finally:
        tmp_path.unlink(missing_ok=True)
        if owns_vd and vd is not None:
            try:
                vd.close()
            except Exception:
                pass

    if stopped:
        raise JobStopRequested()

    elapsed = max(time.monotonic() - t0, 0.001)
    emit(
        f"Shard {shard_id} complete — {len(index_entries):,} files, {bytes_written:,} bytes "
        f"in {elapsed:,.0f}s ({bytes_written / elapsed / 1048576:,.1f} MiB/s)"
        + (f", {skip_count} read skips" if skip_count else ""),
        metadata={"shard_id": shard_id, "files": len(index_entries), "bytes": bytes_written, "seconds": round(elapsed, 1), "mib_per_s": round(bytes_written / elapsed / 1048576, 2)},
    )
    progress.mark_shard_done(shard_id)
    return {
        "shard_id": shard_id,
        "part_key": part_key if part_uri else None,
        "part_uri": part_uri or None,
        "index_entries": index_entries,
        "files_extracted": len(index_entries),
        "bytes_extracted": bytes_written,
        "files_skipped": skip_count,
    }
