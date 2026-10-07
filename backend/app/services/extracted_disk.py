"""Parallel full-filesystem extraction into sharded MinIO extracted disk."""

from __future__ import annotations

from app.services.forensic_serial_policy import serial_enabled

import hashlib
import io
import json
import logging
import os
import tarfile
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import zstandard as zstd

from app.config import get_settings
from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.disk_build_log import (
    disk_log_heartbeat,
    make_session_progress,
    write_disk_log,
    write_disk_log_committed,
)
from app.services.extract_filters import filter_policy_summary, resolve_skip_system_paths, should_extract_node_v2
from app.services.extract_noise import NoiseLedger, policy_for_mode
from app.services.job_control import (
    JobStopRequested,
    checkpoint_index_and_parts,
    completed_shard_ids,
    empty_checkpoint,
    is_stop_requested,
    load_extraction_checkpoint,
    mark_job_paused,
    merge_checkpoint_shard,
    save_extraction_checkpoint,
)
from app.services.os_detect import detect_os_from_paths
from app.services.storage import put_bytes, put_file
from app.services.virtual_disk import VirtualDisk, enumerate_all_files, open_virtual_disk, read_full_file_from_disk
from app.services.extract_shard_v45 import (
    ShardEventBus,
    configure_read_gate,
    plan_readers as plan_readers_v45,
    shard_worker_v45,
)
from app.services.virtual_disk import vd_plan as _vd_plan


def _mark_live_step(job_id: str, name: str, **extra) -> None:
    """V45.5: step marker for the task-level liveness thread (no-op when absent)."""
    try:
        from app.services.job_liveness import mark_step

        mark_step(job_id, name, **extra)
    except Exception:
        pass

log = logging.getLogger("extracted_disk")

_PROGRESS_LOG_INTERVAL_SEC = 12
_PROGRESS_FLUSH_INTERVAL_SEC = 6.0
_PROGRESS_LOG_DB_INTERVAL_SEC = 15.0
_STOP_POLL_INTERVAL_SEC = 3.0


class _StopPoller:
    """Poll stop_requested once every few seconds — avoids DB round-trip per file."""

    def __init__(self, schema_name: str, job_id: str, *, interval_sec: float = _STOP_POLL_INTERVAL_SEC) -> None:
        self.schema_name = schema_name
        self.job_id = job_id
        self.interval_sec = max(float(interval_sec), 1.0)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._requested = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name=f"stop-poller-{self.job_id[:8]}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def is_requested(self) -> bool:
        with self._lock:
            return self._requested

    def _run(self) -> None:
        while not self._stop.wait(self.interval_sec):
            try:
                from app.db.session import firm_session_readonly

                with firm_session_readonly(self.schema_name) as db:
                    requested = is_stop_requested(db, self.job_id)
                with self._lock:
                    self._requested = requested
                if requested:
                    return
            except Exception:
                log.debug("stop poll failed for job %s", self.job_id, exc_info=True)


class _ProgressFlusher:
    """Background DB flush for extraction counters — one writer instead of N shard threads."""

    def __init__(
        self,
        schema_name: str,
        job_id: str,
        progress: "_ExtractionProgress",
        *,
        shard_count: int,
        total_bytes: int = 0,
        flush_interval_sec: float = _PROGRESS_FLUSH_INTERVAL_SEC,
        log_interval_sec: float = _PROGRESS_LOG_DB_INTERVAL_SEC,
    ) -> None:
        self.schema_name = schema_name
        self.job_id = job_id
        self.progress = progress
        self.shard_count = shard_count
        self.total_bytes = max(int(total_bytes or 0), 0)
        self.flush_interval_sec = max(float(flush_interval_sec), 2.0)
        self.log_interval_sec = max(float(log_interval_sec), 10.0)
        self._dirty = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_log_monotonic = 0.0
        # V45: shard threads emit here; this thread is the only DB writer.
        self.event_bus = ShardEventBus()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name=f"progress-{self.job_id[:8]}", daemon=True)
        self._thread.start()

    def mark_dirty(self) -> None:
        self._dirty.set()

    def _drain_events(self, db) -> int:
        events = self.event_bus.drain()
        for level, message, metadata in events:
            write_disk_log(db, self.job_id, message, stage="extract", level=level, metadata=metadata)
        if self.event_bus.dropped:
            write_disk_log(
                db, self.job_id,
                f"{self.event_bus.dropped} shard log events dropped (bus full)",
                stage="extract", level="warning",
            )
            self.event_bus.dropped = 0
        return len(events)

    def stop(self, *, flush: bool = True) -> None:
        self._stop.set()
        self._dirty.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        if flush:
            self._flush(write_log=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            triggered = self._dirty.wait(self.flush_interval_sec)
            if self._stop.is_set() and not triggered:
                break
            self._dirty.clear()
            now = time.monotonic()
            write_log = (now - self._last_log_monotonic) >= self.log_interval_sec
            self._flush(write_log=write_log)
            if write_log:
                self._last_log_monotonic = now

    def _flush(self, *, write_log: bool) -> None:
        snap = self.progress.snapshot()
        total = snap["total_files"]
        extracted = snap["files_extracted"]
        if total <= 0 and extracted <= 0:
            try:
                with firm_session(self.schema_name) as db:
                    self._drain_events(db)
                    db.commit()
            except Exception:
                log.debug("event drain failed for job %s", self.job_id, exc_info=True)
            return
        pct = _progress_pct(extracted, total, snap["shards_done"], self.shard_count)
        pre_filtered = snap["pre_filtered"]
        read_skipped = snap["read_skipped"]
        suffix = ""
        if pre_filtered:
            suffix += f" · {pre_filtered:,} pre-filtered"
        if read_skipped:
            suffix += f" · {read_skipped:,} unreadable"
        message = (
            f"Extracting files — {extracted:,} / {total:,} ({pct}%)"
            f" · {snap['bytes_extracted']:,} bytes"
            + suffix
        )
        try:
            with firm_session(self.schema_name) as db:
                self._drain_events(db)
                if write_log:
                    write_disk_log(
                        db,
                        self.job_id,
                        message,
                        stage="extract",
                        metadata={
                            "files_extracted": extracted,
                            "files_total": total,
                            "pre_filtered": pre_filtered,
                            "read_skipped": read_skipped,
                            "bytes_extracted": snap["bytes_extracted"],
                            "progress_pct": pct,
                        },
                    )
                from app.services.pipeline_progress import write_merged_pipeline_progress

                write_merged_pipeline_progress(
                    db,
                    self.job_id,
                    {
                        "phase": "extract",
                        "completed": extracted,
                        "total": total,
                        "label": message,
                        "extraction_activity": {
                            "subphase": "copying",
                            "label": message,
                            "files_extracted": extracted,
                            "files_total": total,
                            "files_remaining": max(total - extracted, 0),
                            "bytes_extracted": int(snap["bytes_extracted"] or 0),
                            "bytes_total": self.total_bytes or None,
                            "bytes_remaining": (
                                max(self.total_bytes - int(snap["bytes_extracted"] or 0), 0)
                                if self.total_bytes > 0
                                else None
                            ),
                            "shards_done": int(snap["shards_done"] or 0),
                            "shards_total": int(self.shard_count or 0),
                        },
                    },
                    writer="extract",
                    progress_pct=pct,
                    extra_sets="files_extracted=:fe, bytes_extracted=:be",
                    extra_params={"fe": extracted, "be": snap["bytes_extracted"]},
                )
                db.commit()
            try:
                from app.services.job_locks import DEFAULT_EXTRACT_LOCK_TTL_SEC, refresh_job_lock

                refresh_job_lock("extract", self.job_id, ttl_sec=DEFAULT_EXTRACT_LOCK_TTL_SEC)
            except Exception:
                pass
        except Exception:
            log.debug("progress flush failed for job %s", self.job_id, exc_info=True)


def _disk_prefix(job_id: str) -> str:
    return f"jobs/{job_id}/extracted-disk"


def _filter_nodes(
    nodes: list[dict],
    settings,
    *,
    os_info: dict | None = None,
    on_progress=None,
) -> tuple[list[dict], dict]:
    """Pre-filter file list before sharding — avoids expensive TSK reads on junk paths.

    OS-aware: Windows full mode never broad-skips WinSxS/WindowsApps/LogFiles/etc.
    """
    mode = (settings.extract_mode or "full").strip().lower()
    family = (os_info or {}).get("family") or "unknown"
    skip_system, policy_reason = resolve_skip_system_paths(
        mode=mode,
        extract_skip_system_paths=bool(getattr(settings, "extract_skip_system_paths", False)),
        os_family=family,
    )
    policy = filter_policy_summary(
        mode=mode,
        extract_skip_system_paths=bool(getattr(settings, "extract_skip_system_paths", False)),
        os_info=os_info,
    )
    noise_policy = policy_for_mode(mode)
    noise_ledger = NoiseLedger()
    kept: list[dict] = []
    stats: dict = {
        "enumerated": len(nodes),
        "filtered_out": 0,
        "detected_os": os_info or {"family": "unknown"},
        "filter_policy": policy,
        "skip_system_paths": skip_system,
        "policy_reason": policy_reason,
        "noise": noise_ledger.as_dict(),
    }
    # V45: tree-level OS/vendor exclusion (AXIOM-aligned). Runs before the
    # per-file rules; a scope-pack *specific* claim always wins inside it.
    try:
        from app.services.extract_os_vendor_noise import os_vendor_mode, should_skip_os_vendor
    except Exception:  # pragma: no cover
        os_vendor_mode = lambda: "keep"  # noqa: E731
        should_skip_os_vendor = lambda *a, **k: (False, None)  # noqa: E731
    stats["os_vendor_mode"] = os_vendor_mode()
    total = len(nodes)
    last_report = time.monotonic()
    if on_progress and total:
        on_progress(
            f"Applying extract filters — 0 of {total:,} considered, 0 kept…",
            {"files_considered": 0, "files_kept": 0, "files_total": total},
        )
    for index, node in enumerate(nodes, start=1):
        rel = node["path"]
        size = int(node.get("size_bytes") or 0)
        skip_vendor, vendor_rule = should_skip_os_vendor(rel, size_bytes=size, os_family=family)
        if skip_vendor:
            stats["filtered_out"] += 1
            stats[vendor_rule or "os_vendor_tree"] = stats.get(vendor_rule or "os_vendor_tree", 0) + 1
        else:
            ok, reason = should_extract_node_v2(
                rel,
                size,
                mode=mode,
                max_file_bytes=settings.extract_max_file_bytes,
                skip_system_paths=skip_system,
                os_family=family,
                uncertain_max_bytes=settings.extract_uncertain_max_bytes,
                noise_policy=noise_policy,
                noise_ledger=noise_ledger,
            )
            if ok:
                kept.append(node)
            else:
                stats["filtered_out"] += 1
                stats[reason or "other"] = stats.get(reason or "other", 0) + 1
        now = time.monotonic()
        if on_progress and (index == total or index % 25_000 == 0 or (now - last_report) >= 15.0):
            last_report = now
            on_progress(
                f"Applying extract filters — {index:,} of {total:,} considered, {len(kept):,} kept…",
                {
                    "files_considered": index,
                    "files_kept": len(kept),
                    "files_total": total,
                },
            )
    kept, duplicate_paths = _unique_extract_nodes(kept)
    stats["duplicate_paths"] = duplicate_paths
    stats["to_extract"] = len(kept)
    stats["noise"] = noise_ledger.as_dict()
    return kept, stats


def _unique_extract_nodes(nodes: list[dict]) -> tuple[list[dict], int]:
    """Keep one node per normalized path so the same file is not extracted twice."""
    seen: set[str] = set()
    unique: list[dict] = []
    duplicates = 0
    for node in nodes:
        key = str(node.get("path") or "").replace("\\", "/")
        if key and key in seen:
            duplicates += 1
            continue
        if key:
            seen.add(key)
        unique.append(node)
    return unique, duplicates


def _shard_nodes(
    nodes: list[dict],
    worker_count: int,
    *,
    strategy: str = "path_range",
) -> dict[int, list[dict]]:
    """Partition nodes into shards.

    path_range (default): contiguous sorted path slices → sequential E01 reads.
    hash: legacy layout for resume compatibility with in-flight checkpoints.

    Every node is assigned exactly once — no evidence is dropped.
    """
    if worker_count <= 1:
        return {0: list(nodes)}
    if strategy == "hash":
        shards: dict[int, list[dict]] = {i: [] for i in range(worker_count)}
        for node in nodes:
            sid = hash(node["path"]) % worker_count
            shards[sid].append(node)
        return shards
    # Contiguous path/inode ranges — preserves all nodes, maximizes E01 locality
    ordered = sorted(
        nodes,
        key=lambda n: (
            n.get("inode") is None,
            int(n["inode"]) if n.get("inode") is not None else 0,
            n.get("path", ""),
        ),
    )
    n = len(ordered)
    return {
        i: ordered[(i * n) // worker_count : ((i + 1) * n) // worker_count]
        for i in range(worker_count)
    }


class _ExtractionProgress:
    """Thread-safe counters shared across shard workers."""

    def __init__(
        self,
        total_files: int,
        *,
        progress_step: int,
        initial_extracted: int = 0,
        initial_bytes: int = 0,
        pre_filtered: int = 0,
    ) -> None:
        self.lock = threading.Lock()
        self.total_files = total_files
        self.progress_step = max(progress_step, 500)
        self.files_extracted = initial_extracted
        self.pre_filtered = pre_filtered
        self.read_skipped = 0
        self.bytes_extracted = initial_bytes
        self.shard_done: set[int] = set()
        self.last_log_monotonic = 0.0
        self.last_logged_extracted = -1
        self.current_path = ""
        self.current_action = ""
        self.current_shard_id: int | None = None

    def record_extracted(self, size: int) -> None:
        with self.lock:
            self.files_extracted += 1
            self.bytes_extracted += size

    def record_read_skipped(self) -> int:
        with self.lock:
            self.read_skipped += 1
            return self.read_skipped

    def set_current(self, path: str, *, action: str = "processing", shard_id: int | None = None) -> None:
        with self.lock:
            self.current_path = path or ""
            self.current_action = action or ""
            if shard_id is not None:
                self.current_shard_id = shard_id

    def mark_shard_done(self, shard_id: int) -> None:
        with self.lock:
            self.shard_done.add(shard_id)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "total_files": self.total_files,
                "files_extracted": self.files_extracted,
                "pre_filtered": self.pre_filtered,
                "read_skipped": self.read_skipped,
                "bytes_extracted": self.bytes_extracted,
                "shards_done": len(self.shard_done),
                "current_path": self.current_path,
                "current_action": self.current_action,
                "current_shard_id": self.current_shard_id,
            }

    def should_log_progress(self) -> bool:
        with self.lock:
            now = time.monotonic()
            extracted = self.files_extracted
            # Seed timer on first check so we can heartbeat even before first file.
            if self.last_log_monotonic <= 0:
                self.last_log_monotonic = now
                return False
            if now - self.last_log_monotonic >= _PROGRESS_LOG_INTERVAL_SEC:
                self.last_log_monotonic = now
                self.last_logged_extracted = extracted
                return True
            if extracted > 0 and extracted - self.last_logged_extracted >= self.progress_step:
                self.last_logged_extracted = extracted
                self.last_log_monotonic = now
                return True
            return False


def _is_plain_folder_extract(vd, nodes: list[dict]) -> bool:
    """True when files live on disk (iOS backup / working copy), not inside a ZIP."""
    if str(getattr(vd, "mode", "") or "") != "folder":
        return False
    sample = nodes[:80]
    sealed = 0
    zipish = 0
    for node in sample:
        path = str(node.get("path") or "").replace("\\", "/").lower()
        if path.startswith("_sealed/") or "/ios_image/" in path or path.startswith("ios_image/"):
            sealed += 1
        if ".zip/" in path or path.endswith(".zip"):
            zipish += 1
    if sealed >= 8 or (sealed and sealed >= zipish):
        return True
    fmt = str(getattr(vd, "format", "") or "").lower()
    if fmt in {"pas", "ufd", "ufdx", "zip"}:
        return False
    return zipish < 8


def plan_ewf_extract_io(
    nodes: list[dict],
    *,
    configured_workers: int,
    configured_shards: int,
    live_workers: int | None = None,
    thermal_pace: float = 1.0,
    busy_extracts: int = 1,
    cpu_count: int | None = None,
    stream_phase3: bool = False,
) -> tuple[int, int, str]:
    """Return (parallel_readers, shard_count, reason) for E01/EWF/raw disks.

    A single shared E01 handle looks idle for a long time because only one
    inode-ordered shard runs. Separate libewf readers on disjoint shards keep
    extract moving without pinning every host core.
    """
    cpus = max(int(cpu_count or os.cpu_count() or 8), 1)
    usable = max(2, cpus - 2)
    configured = max(int(configured_workers or 1), 1)
    live = configured if live_workers is None else max(int(live_workers), 1)
    wanted = max(configured, live)
    n = max(len(nodes), 1)
    reason = "ewf_parallel"

    # Leave two cores for Postgres, MinIO, and the API. A 22-core host can
    # run more than eight EWF readers; the old ceiling left most CPUs idle.
    if usable >= 16:
        hi = 14
    elif usable >= 10:
        hi = 12
    elif usable >= 8:
        hi = 8
    else:
        hi = 4
    readers = min(max(wanted, 2), hi, usable, n)
    if float(thermal_pace) < 0.40:
        readers = max(1, readers // 2)
        reason += "+thermal"
    if int(busy_extracts) > 1:
        readers = max(1, min(readers, 2))
        reason += "+multijob"
    readers = max(1, min(readers, n, 4))

    shards = min(max(int(configured_shards or readers), readers, 4 if stream_phase3 else readers), 16, n)
    shards = max(readers, min(shards, n))
    return readers, shards, reason


def _is_payload_zip_extract(nodes: list[dict]) -> bool:
    """True when extract nodes are members of payload/part zips, not a live folder."""
    sample = nodes[:80]
    zipish = 0
    sealed = 0
    for node in sample:
        path = str(node.get("path") or "").replace("\\", "/").lower()
        if path.startswith("_sealed/"):
            sealed += 1
        if ".zip/" in path or ".part-" in path:
            zipish += 1
    return zipish >= 8 and zipish > sealed


def plan_mobile_extract_io(
    vd,
    nodes: list[dict],
    *,
    configured_workers: int,
    live_workers: int | None = None,
    thermal_pace: float = 1.0,
    busy_extracts: int = 1,
    cpu_count: int | None = None,
) -> tuple[int, int, str]:
    """Return (parallel_readers, worker_count, reason).

    Folder dumps and payload ZIP shards are independent I/O — more readers
    plus more shards let Phase 3/RAG start while extract continues. Tiny UFED
    dumps stay modest because each worker opens its own archive handle.
    """
    cpus = max(int(cpu_count or os.cpu_count() or 8), 1)
    configured = max(int(configured_workers or 1), 1)
    live = configured if live_workers is None else max(int(live_workers), 1)
    wanted = max(configured, live)
    n = max(len(nodes), 1)

    if _is_plain_folder_extract(vd, nodes):
        readers = min(max(wanted, 8), 16, max(cpus - 2, 4), n)
        shards = min(max(readers, 8), 16, n)
        reason = "plain_folder"
    elif _is_payload_zip_extract(nodes):
        readers = min(max(wanted, 8), 16, max(cpus - 2, 4), n)
        shards = min(max(readers, 8), 16, n)
        reason = "zip_payload_parallel"
    else:
        readers = min(max(wanted, 4), 8, cpus, n)
        shards = readers
        reason = "zip_or_ufed"

    if float(thermal_pace) < 0.40:
        readers = max(2, readers // 2)
        shards = max(readers, shards // 2)
        reason += "+thermal"
    if int(busy_extracts) > 1:
        readers = max(2, min(readers, 6))
        shards = max(readers, min(shards, 8))
        reason += "+multijob"
    readers = max(1, min(readers, n, 4))
    shards = max(readers, min(shards, n))
    return readers, shards, reason


def _pack_full_evidence_zip(dest: Path, original: Path, on_progress) -> None:
    """Late packaging: same four-file layout the acquisition writes (V22).

    Honors AETHERIS_EXPORT_SHARDS for operators who still want multi-part output.
    """
    from app.services.mobile_acquire.export_packages import build_export_packages

    case_id = ""
    try:
        if dest.parent.name.lower() in {"05_exports", "05_export"}:
            case_id = dest.parent.parent.name
    except Exception:
        case_id = ""
    build_export_packages(
        run_name=original.name,
        export_dir=dest,
        original=original,
        case_id=case_id,
        method="late_pack",
        full_payload=True,
        progress=(
            (lambda ev: on_progress(str(ev.get("item") or "packing evidence zip"), ev))
            if on_progress
            else None
        ),
    )


def _ensure_mobile_payload_zips(vd: VirtualDisk, on_progress) -> None:
    """Pack payload ZIP shards when analysis still points at a metadata zip / live folder."""
    from app.services.mobile_acquire.export_packages import (
        ExportSpaceError,
        is_sealed_mobile_original,
        payload_shard_catalog_complete,
    )
    from app.services.mobile_segments import list_payload_zip_archives
    from app.services.virtual_disk import _package_original_dirs

    root = Path(vd.root_folder) if vd.root_folder else None
    existing = list_payload_zip_archives(root, list(vd.segment_paths or []))
    if existing:
        if on_progress:
            on_progress(
                f"Using {len(existing)} payload ZIP archive(s) for zip-only extract",
                {"payload_zips": [str(p) for p in existing[:12]], "action": "zip_payload_ready"},
            )
        return

    archives: list[Path] = []
    live_dirs: list[Path] = []
    for raw in vd.segment_paths or []:
        path = Path(raw)
        if path.is_file() and path.suffix.lower() == ".zip":
            archives.append(path)
        elif path.is_dir():
            live_dirs.append(path)
            try:
                archives.extend(p for p in path.glob("*.zip") if p.is_file())
            except OSError:
                pass
    if root and root.is_dir():
        try:
            archives.extend(p for p in root.glob("*.zip") if p.is_file())
        except OSError:
            pass

    seen: set[str] = set()
    for archive in archives:
        try:
            key = str(archive.resolve())
        except OSError:
            key = str(archive)
        if key in seen:
            continue
        seen.add(key)
        originals = _package_original_dirs(archive)
        if not originals:
            continue
        original = originals[0]
        dest = archive.parent
        if payload_shard_catalog_complete(dest) or list_payload_zip_archives(dest, [str(dest)]):
            return
        if on_progress:
            on_progress(
                "Packing sealed original into the full evidence ZIP for zip-only extract/RAG…",
                {"original": str(original), "dest": str(dest), "action": "pack_payload_zip"},
            )
        try:
            _pack_full_evidence_zip(dest, original, on_progress)
        except ExportSpaceError as exc:
            if on_progress:
                on_progress(f"Payload ZIP shards skipped (storage): {exc}", {"error": str(exc)})
            return
        except OSError as exc:
            if on_progress:
                on_progress(f"Payload ZIP shards failed: {exc}", {"error": str(exc)})
            return
        return

    for live in live_dirs:
        run_root = live
        for _ in range(4):
            if is_sealed_mobile_original(run_root):
                dest = run_root / "05_Exports"
                parent = run_root.parent
                if parent.name.lower() in {"02_original_extraction", "original"}:
                    dest = parent.parent / "05_Exports" / run_root.name
                dest.mkdir(parents=True, exist_ok=True)
                if payload_shard_catalog_complete(dest) or list_payload_zip_archives(dest, [str(dest)]):
                    return
                if on_progress:
                    on_progress(
                        "Packing sealed original into the full evidence ZIP…",
                        {"original": str(run_root), "dest": str(dest), "action": "pack_payload_zip"},
                    )
                try:
                    _pack_full_evidence_zip(dest, run_root, on_progress)
                except (ExportSpaceError, OSError) as exc:
                    if on_progress:
                        on_progress(f"Payload ZIP shards skipped: {exc}", {"error": str(exc)})
                return
            if run_root.parent == run_root:
                break
            run_root = run_root.parent


def _progress_pct(files_extracted: int, total_files: int, shards_done: int, shard_count: int) -> int:
    if total_files <= 0:
        return 5
    file_pct = int(90 * files_extracted / total_files)
    return min(94, 5 + file_pct)


def _flush_progress(
    schema_name: str,
    job_id: str,
    progress: _ExtractionProgress,
    *,
    shard_count: int,
    message: str | None = None,
    level: str = "info",
) -> None:
    snap = progress.snapshot()
    total = snap["total_files"]
    extracted = snap["files_extracted"]
    pre_filtered = snap["pre_filtered"]
    read_skipped = snap["read_skipped"]
    pct = _progress_pct(extracted, total, snap["shards_done"], shard_count)
    suffix = ""
    if pre_filtered:
        suffix += f" · {pre_filtered:,} pre-filtered"
    if read_skipped:
        suffix += f" · {read_skipped:,} unreadable"
    current_path = str(snap.get("current_path") or "")
    current_action = str(snap.get("current_action") or "")
    if not message:
        current_bit = ""
        if current_path:
            verb = current_action or "processing"
            current_bit = f" · {verb}: {current_path}"
        message = (
            f"Extracting files — {extracted:,} / {total:,} ({pct}%)"
            f" · {snap['bytes_extracted']:,} bytes"
            + suffix
            + current_bit
        )
    with firm_session(schema_name) as db:
        write_disk_log(
            db,
            job_id,
            message,
            stage="extract",
            level=level,
            metadata={
                "files_extracted": extracted,
                "files_total": total,
                "pre_filtered": pre_filtered,
                "read_skipped": read_skipped,
                "bytes_extracted": snap["bytes_extracted"],
                "progress_pct": pct,
                "current_path": current_path or None,
                "current_action": current_action or None,
                "current_shard_id": snap.get("current_shard_id"),
            },
        )
        execute(
            db,
            """UPDATE jobs SET files_extracted=:fe, bytes_extracted=:be, progress_pct=:pct, updated_at=NOW()
               WHERE id=:job_id""",
            {
                "fe": extracted,
                "be": snap["bytes_extracted"],
                "pct": pct,
                "job_id": job_id,
            },
        )
        try:
            from app.services.pipeline_orchestrator import patch_extract_orchestration

            patch_extract_orchestration(
                db,
                job_id,
                files_done=extracted,
                files_total=total,
                extract_pct=pct,
            )
        except Exception:
            pass


def _check_stop(schema_name: str, job_id: str) -> None:
    with firm_session(schema_name) as db:
        if is_stop_requested(db, job_id):
            raise JobStopRequested()


def _shard_worker(
    payload: dict,
    progress: _ExtractionProgress,
    flusher: _ProgressFlusher | None,
    stop_poller: _StopPoller | None,
    *,
    shared_vd: VirtualDisk | None = None,
) -> dict:
    """Extract one shard to a zstd tar part and upload.

    When shared_vd is provided (sequential E01 path), reuse the open image handle —
    do not reopen pyewf (major speed win on NVMe).
    """
    schema_name = payload["schema_name"]
    job_id = payload["job_id"]
    shard_id = payload["shard_id"]
    nodes = sorted(
        payload["nodes"],
        key=lambda n: (
            n.get("inode") is None,
            int(n["inode"]) if n.get("inode") is not None else 0,
            n.get("path", ""),
        ),
    )
    zstd_level = payload["zstd_level"]
    shard_count = payload["shard_count"]
    hash_files = bool(payload.get("hash_files"))
    stop_check_interval = max(int(payload.get("stop_check_interval") or 200), 1)
    tar_bufsize = max(int(payload.get("tar_bufsize") or 262_144), 65_536)

    index_entries: list[dict] = []
    bytes_written = 0
    skip_count = 0
    stopped = False
    part_name = f"parts/part-{shard_id:05d}.tar.zst"
    part_key = f"{_disk_prefix(job_id)}/{part_name}"

    owns_vd = shared_vd is None
    vd = shared_vd
    if vd is None:
        with firm_session(schema_name) as db:
            vd = open_virtual_disk(db, job_id)
            write_disk_log(
                db,
                job_id,
                f"Shard {shard_id} started — {len(nodes):,} files "
                f"({'cached ZipFile reader' if vd.mode == 'folder' else 'inode-ordered sequential E01 reads'})",
                stage="extract",
                metadata={"shard_id": shard_id, "files_in_shard": len(nodes), "mode": vd.mode},
            )
            db.commit()
    else:
        with firm_session(schema_name) as db:
            write_disk_log(
                db,
                job_id,
                f"Shard {shard_id}/{shard_count - 1} — {len(nodes):,} files "
                f"(shared E01 handle, sequential)",
                stage="extract",
                metadata={"shard_id": shard_id, "files_in_shard": len(nodes), "mode": vd.mode, "shared_vd": True},
            )
            db.commit()

    tmp_path = Path(tempfile.mkstemp(suffix=".tar.zst")[1])
    part_uri = ""
    file_idx = 0
    # Avoid per-file DB commits (was ~1 log / 100 files and starved extract I/O).
    # Progress flusher already surfaces current_path every ~15–30s.
    detail_every = max(stop_check_interval * 10, 5_000)
    # Admission is adaptive at job start, but a long shard can become hot later.
    # Cooperative pauses let in-flight readers cool without cancelling a shard
    # or changing evidence selection/checkpoint semantics.
    try:
        from app.services.adaptive_semaphore import cpu_backoff_delay
    except Exception:
        cpu_backoff_delay = None
    thermal_check_every = 64
    try:
        # One compression thread per reader. Extra zstd threads steal cores
        # from the parallel shard readers.
        cctx = zstd.ZstdCompressor(level=max(int(zstd_level), 1), threads=1)
        with tmp_path.open("wb") as raw_out:
            with cctx.stream_writer(raw_out) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", bufsize=tar_bufsize) as tar:
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
                        if file_idx % stop_check_interval == 0:
                            if stop_poller and stop_poller.is_requested():
                                stopped = True
                                break
                            try:
                                _check_stop(schema_name, job_id)
                            except JobStopRequested:
                                stopped = True
                                break
                        rel = node["path"]
                        inode = node.get("inode")
                        size_hint = int(node.get("size_bytes") or 0)
                        progress.set_current(rel, action="reading", shard_id=shard_id)
                        if file_idx == 1 or file_idx % detail_every == 0:
                            if flusher:
                                flusher.mark_dirty()
                        try:
                            data = read_full_file_from_disk(
                                vd, rel, inode=int(inode) if inode is not None else None
                            )
                        except Exception as exc:
                            log.debug("skip %s: %s", rel, exc)
                            skip_count += 1
                            progress.record_read_skipped()
                            progress.set_current(rel, action="skip_unreadable", shard_id=shard_id)
                            if flusher:
                                flusher.mark_dirty()
                            if skip_count <= 10:
                                write_disk_log_committed(
                                    schema_name,
                                    job_id,
                                    f"Shard {shard_id}: could not read {rel} — {exc}",
                                    stage="extract",
                                    level="warning",
                                    metadata={
                                        "shard_id": shard_id,
                                        "current_path": rel,
                                        "error": str(exc),
                                        "action": "skip_unreadable",
                                    },
                                )
                            continue
                        progress.set_current(rel, action="packing", shard_id=shard_id)
                        info = tarfile.TarInfo(name=rel.replace("\\", "/"))
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                        digest = hashlib.sha256(data).hexdigest() if hash_files else ""
                        index_entries.append({
                            "path": rel,
                            "size_bytes": len(data),
                            "sha256": digest,
                            "part_id": shard_id,
                            "offset": offset,
                        })
                        offset += len(data)
                        bytes_written += len(data)
                        progress.record_extracted(len(data))
                        progress.set_current(rel, action="stored", shard_id=shard_id)
                        if flusher and (file_idx == 1 or file_idx % max(stop_check_interval, 200) == 0):
                            flusher.mark_dirty()
                        if file_idx == 1 or file_idx % detail_every == 0:
                            write_disk_log_committed(
                                schema_name,
                                job_id,
                                f"Shard {shard_id}: processed #{file_idx:,}/{len(nodes):,} — "
                                f"{rel} ({len(data):,} bytes"
                                + (f", listed {size_hint:,}" if size_hint and size_hint != len(data) else "")
                                + ")",
                                stage="extract",
                                metadata={
                                    "shard_id": shard_id,
                                    "file_index": file_idx,
                                    "files_in_shard": len(nodes),
                                    "current_path": rel,
                                    "bytes_read": len(data),
                                    "action": "processed",
                                },
                            )

        if index_entries and not stopped:
            part_uri = put_file(part_key, tmp_path, content_type="application/zstd")
    except JobStopRequested:
        stopped = True
    except Exception as exc:
        with firm_session(schema_name) as db:
            write_disk_log(
                db,
                job_id,
                f"Shard {shard_id} failed: {exc}",
                stage="extract",
                level="error",
                metadata={"shard_id": shard_id},
            )
        raise
    finally:
        if tmp_path.is_file():
            tmp_path.unlink(missing_ok=True)
        if owns_vd and vd is not None:
            try:
                vd.close()
            except Exception:
                pass

    if stopped:
        raise JobStopRequested()

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


def _finalize_manifest(
    *,
    job_id: str,
    vd: VirtualDisk,
    nodes: list[dict],
    all_nodes: list[dict],
    all_index: list[dict],
    part_uris: list[str],
    total_files: int,
    total_bytes: int,
    total_skipped: int,
    mode: str,
    filter_stats: dict,
    payload_count: int,
    settings,
    checkpoint: dict | None = None,
) -> dict:
    all_index.sort(key=lambda e: e["path"])
    index_lines = "\n".join(json.dumps(e, separators=(",", ":")) for e in all_index).encode("utf-8")
    cctx = zstd.ZstdCompressor(level=settings.extract_zstd_level)
    index_compressed = cctx.compress(index_lines)
    index_key = f"{_disk_prefix(job_id)}/index.jsonl.zst"
    index_uri = put_bytes(index_key, index_compressed, content_type="application/zstd")

    parts_map = dict((checkpoint or {}).get("parts_map") or {})
    if not parts_map:
        parts_map = {str(i): uri for i, uri in enumerate(part_uris) if uri}
    ordered_parts = [
        parts_map.get(str(i)) or parts_map.get(i)
        for i in range(payload_count)
    ]
    ordered_parts = [p for p in ordered_parts if p]

    manifest = {
        "job_id": job_id,
        "base_name": vd.base_name,
        "format": vd.format,
        "mode": vd.mode,
        "segment_paths": vd.segment_paths,
        "segment_hashes": vd.segment_hashes,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "files_total": len(nodes),
        "files_enumerated": len(all_nodes),
        "files_extracted": total_files,
        "files_skipped": total_skipped,
        "bytes_extracted": total_bytes,
        "extract_mode": mode,
        "detected_os": filter_stats.get("detected_os") or {"family": "unknown"},
        "filter_policy": filter_stats.get("filter_policy"),
        "filter_stats": filter_stats,
        "shard_count": payload_count,
        "parts": ordered_parts or part_uris,
        "parts_map": parts_map,
        "shard_indexes": dict((checkpoint or {}).get("shard_indexes") or {}),
        "index_uri": index_uri,
        "streaming": bool((checkpoint or {}).get("phase3_completed_shards")),
        "phase3_completed_shards": list((checkpoint or {}).get("phase3_completed_shards") or []),
        "forensic_libs": __import__("app.services.virtual_disk", fromlist=["forensic_libs_available"]).forensic_libs_available(),
    }
    manifest_key = f"{_disk_prefix(job_id)}/manifest.json"
    manifest_uri = put_bytes(manifest_key, json.dumps(manifest, indent=2).encode(), "application/json")

    return {
        "status": "disk_ready",
        "extracted_disk_uri": manifest_uri,
        "manifest": manifest,
        "files_total": len(nodes),
        "files_extracted": total_files,
        "bytes_extracted": total_bytes,
        "index_uri": index_uri,
    }


def _handle_stop(
    db,
    job_id: str,
    *,
    schema_name: str,
    checkpoint: dict,
    progress: _ExtractionProgress,
    worker_count: int,
) -> dict:
    completed = checkpoint.get("completed_shards") or []
    files_saved = sum(int(s.get("files_extracted") or 0) for s in completed)
    bytes_saved = sum(int(s.get("bytes_extracted") or 0) for s in completed)
    total = int(checkpoint.get("nodes_total") or progress.snapshot()["total_files"])
    pct = _progress_pct(files_saved, total, len(completed), worker_count)
    checkpoint["progress_pct"] = pct
    checkpoint["files_extracted"] = files_saved
    checkpoint["bytes_extracted"] = bytes_saved
    save_extraction_checkpoint(db, job_id, checkpoint)
    mark_job_paused(
        db,
        job_id,
        message=f"Stopped at {files_saved:,} / {total:,} files — click Resume to continue",
    )
    write_disk_log(
        db,
        job_id,
        f"Extraction stopped — {files_saved:,} / {total:,} files saved "
        f"({len(completed)} shard(s) complete; in-progress shard will restart on resume)",
        stage="extract",
        level="info",
        metadata={
            "files_extracted": files_saved,
            "files_total": total,
            "completed_shards": len(completed),
        },
    )
    db.commit()
    return {
        "status": "paused",
        "files_extracted": files_saved,
        "files_total": total,
        "checkpoint": checkpoint,
    }


def _persist_partial_manifest(
    db,
    job_id: str,
    vd: VirtualDisk,
    checkpoint: dict,
    *,
    mode: str,
    filter_stats: dict,
) -> None:
    from app.services.disk_manifest import build_partial_manifest

    manifest = build_partial_manifest(
        job_id=job_id,
        vd_meta={
            "base_name": vd.base_name,
            "format": vd.format,
            "mode": vd.mode,
            "segment_paths": vd.segment_paths,
            "segment_hashes": vd.segment_hashes,
        },
        checkpoint=checkpoint,
        mode=mode,
        filter_stats=filter_stats,
        streaming=True,
    )
    from app.services.mobile_os import extract_mobile_meta, load_job_disk_source, merge_mobile_meta_into_disk_source

    prior = load_job_disk_source(
        fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id})
    )
    merged = merge_mobile_meta_into_disk_source(manifest, extract_mobile_meta(prior))
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:job_id",
        {"ds": json.dumps(merged), "job_id": job_id},
    )


def _on_shard_complete(
    db,
    *,
    schema_name: str,
    job_id: str,
    vd: VirtualDisk,
    checkpoint: dict,
    result: dict,
    mode: str,
    filter_stats: dict,
    settings,
) -> dict:
    """Upload shard index, update checkpoint/manifest, optionally queue streaming Phase 3."""
    from app.services.disk_manifest import upload_shard_index

    index_entries = result.get("index_entries") or []
    if index_entries and result.get("part_uri"):
        index_uri = upload_shard_index(
            job_id, int(result["shard_id"]), index_entries, zstd_level=settings.extract_zstd_level,
        )
        result = {**result, "index_uri": index_uri, "index_entries": []}

    checkpoint = merge_checkpoint_shard(checkpoint, result, strip_index=True)
    save_extraction_checkpoint(db, job_id, checkpoint)
    _persist_partial_manifest(db, job_id, vd, checkpoint, mode=mode, filter_stats=filter_stats)
    db.commit()

    if (
        not bool(getattr(settings, "extract_then_process", True)) and not serial_enabled()
        and settings.phase3_stream_during_extract
        and settings.phase3_auto_after_disk
        and result.get("part_uri")
    ):
        from app.tasks import phase3_shard_task

        phase3_shard_task.delay(schema_name, job_id, int(result["shard_id"]))
    return checkpoint


def build_extracted_disk_to_minio(db, job_id: str, vd: VirtualDisk, *, schema_name: str) -> dict:
    settings = get_settings()
    existing_cp = load_extraction_checkpoint(db, job_id)
    # End any open transaction before long E01/S3 I/O so workers are not
    # idle-in-transaction (Postgres would kill the connection).
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    resume = bool(
        existing_cp
        and (existing_cp.get("completed_shards") or existing_cp.get("nodes_uri") or existing_cp.get("nodes_total"))
    )

    # Drop a leftover disk_ready URI so observers do not treat this pass as done.
    # Do not zero file counts — a stacked resume would look like a new walk and
    # the huddle would queue another extract.
    execute(
        db,
        "UPDATE jobs SET extracted_disk_uri=NULL, updated_at=NOW() WHERE id=:job_id",
        {"job_id": job_id},
    )
    db.commit()

    nodes: list[dict] = []
    filter_stats: dict = {}
    all_nodes: list[dict] = []
    mode = (settings.extract_mode or "forensic").strip().lower()
    nodes_uri = (existing_cp or {}).get("nodes_uri")
    loaded_from_cache = False

    if resume and nodes_uri:
        from app.services.disk_manifest import load_extract_nodes

        write_disk_log(
            db,
            job_id,
            "Resuming extraction — loading saved extract plan (skipping filesystem walk)",
            stage="extract",
            metadata={"nodes_uri": nodes_uri},
        )
        db.commit()
        nodes = load_extract_nodes(nodes_uri)
        if nodes:
            loaded_from_cache = True
            filter_stats = dict((existing_cp or {}).get("filter_stats") or {})
            all_nodes = nodes
            mode = str((existing_cp or {}).get("extract_mode") or mode).strip().lower()
        else:
            write_disk_log(db, job_id, "Saved extract plan missing — re-enumerating disk", stage="extract", level="warning")
            db.commit()

    if not loaded_from_cache:
        from app.services.pipeline_progress import write_merged_pipeline_progress

        write_merged_pipeline_progress(
            db,
            job_id,
            {
                "phase": "extract",
                "completed": 0,
                "total": None,
                "label": "Enumerating filesystem — file count is still growing",
                "extraction_activity": {
                    "subphase": "enumerating",
                    "label": "Enumerating filesystem tree",
                    "files_found": 0,
                },
            },
            writer="extract",
        )
        write_disk_log(
            db,
            job_id,
            "Enumerating complete filesystem (this can take several minutes on large disks)…",
            stage="extract",
        )
        db.commit()

        log_enum_progress = make_session_progress(
            db, job_id, stage="extract", commit=True, schema_name=schema_name
        )

        def on_enum_progress(message: str, metadata: dict | None = None) -> None:
            log_enum_progress(message, metadata)
            files_found = int((metadata or {}).get("files_found") or 0)
            if files_found <= 0:
                return
            try:
                from app.db.session import firm_session
                from app.services.pipeline_progress import write_merged_pipeline_progress

                with firm_session(schema_name) as progress_db:
                    write_merged_pipeline_progress(
                        progress_db,
                        job_id,
                        {
                            "phase": "extract",
                            "completed": files_found,
                            "total": None,
                            "label": f"Filesystem inventory — {files_found:,} files discovered",
                            "extraction_activity": {
                                "subphase": "enumerating",
                                "label": f"Filesystem inventory — {files_found:,} files discovered",
                                "files_found": files_found,
                            },
                        },
                        writer="extract",
                    )
                    progress_db.commit()
            except Exception:
                log.debug("enumeration progress snapshot failed for job %s", job_id, exc_info=True)
        mobile_hint = (
            str(getattr(vd, "mode", "") or "") == "folder"
            or str(getattr(vd, "format", "") or "").lower()
            in {"mobile", "pas", "ufd", "ufdx", "zip", "backup"}
        )
        if mobile_hint:
            write_disk_log(
                db,
                job_id,
                "Ensuring payload ZIP shards so extract/RAG reads zips only…",
                stage="extract",
            )
            db.commit()
            try:
                _ensure_mobile_payload_zips(vd, on_enum_progress)
            except Exception as exc:
                write_disk_log(
                    db,
                    job_id,
                    f"Payload ZIP ensure skipped: {exc}",
                    stage="extract",
                    level="warning",
                )
                db.commit()
        _mark_live_step(job_id, "enumerate filesystem")
        with disk_log_heartbeat(
            schema_name,
            job_id,
            "Enumerating filesystem tree",
            stage="extract",
            interval_sec=15.0,
        ):
            all_nodes = enumerate_all_files(vd, on_progress=on_enum_progress)

        if not all_nodes:
            root_hint = getattr(vd, "root_folder", None) or (vd.segment_paths[0] if vd.segment_paths else "?")
            msg = (
                f"No files found under virtual disk root ({root_hint}). "
                "For mobile packages, ensure the export folder (or .zip) is readable on this worker "
                "and the registered evidence path is visible to this worker."
            )
            write_disk_log(db, job_id, msg, stage="extract", level="error")
            db.commit()
            return {"status": "failed", "error": "No files found on mounted disk"}

        write_disk_log(
            db,
            job_id,
            f"Enumeration finished — {len(all_nodes):,} files; detecting guest OS…",
            stage="extract",
            metadata={"files_enumerated": len(all_nodes)},
        )
        db.commit()

        os_info = detect_os_from_paths(all_nodes)
        if (os_info or {}).get("family") in (None, "unknown") and vd.format in ("pas", "mobile", "ufd", "zip"):
            from app.services.mobile_os import load_job_disk_source
            from app.services.mobile_segments import infer_mobile_axiom_platform

            prior_ds = load_job_disk_source(
                fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id})
            )
            names = [Path(p).name for p in vd.segment_paths if p]
            mobile_platform = infer_mobile_axiom_platform(
                evidence_names=names,
                host_paths=list(vd.segment_paths),
                disk_format=vd.format,
                examiner_mobile_os=str(prior_ds.get("mobile_os") or "") or None,
            )
            examiner = (prior_ds.get("os_selection_source") or "") == "examiner"
            if mobile_platform == "Android":
                os_info = {
                    "family": "android",
                    "confidence": "high" if examiner else "medium",
                    "scores": {"android": 10, "ios": 0, "windows": 0, "linux": 0, "macos": 0},
                    "signals": ["examiner_mobile_os"] if examiner else ["mobile_evidence"],
                    "method": "examiner_os" if examiner else "mobile_evidence",
                }
            elif mobile_platform == "iOS":
                os_info = {
                    "family": "ios",
                    "confidence": "high" if examiner else "medium",
                    "scores": {"android": 0, "ios": 10, "windows": 0, "linux": 0, "macos": 0},
                    "signals": ["examiner_mobile_os"] if examiner else ["mobile_evidence"],
                    "method": "examiner_os" if examiner else "mobile_evidence",
                }
        write_disk_log(
            db,
            job_id,
            f"Detected guest OS — family={os_info.get('family')} "
            f"confidence={os_info.get('confidence')} scores={os_info.get('scores')}",
            stage="extract",
            metadata={"detected_os": os_info},
        )
        db.commit()

        write_disk_log(
            db,
            job_id,
            f"Applying extract filters (mode={settings.extract_mode})…",
            stage="extract",
        )
        db.commit()
        _mark_live_step(job_id, "filter + save plan")

        def on_filter_progress(message: str, metadata: dict | None = None) -> None:
            write_disk_log_committed(schema_name, job_id, message, stage="extract", metadata=metadata)

        with disk_log_heartbeat(
            schema_name,
            job_id,
            "Applying extract filters / saving extract plan",
            stage="extract",
            interval_sec=15.0,
        ):
            nodes, filter_stats = _filter_nodes(
                all_nodes, settings, os_info=os_info, on_progress=on_filter_progress
            )
            if not nodes:
                write_disk_log(db, job_id, "No files matched extraction filter", stage="extract", level="error")
                db.commit()
                return {"status": "failed", "error": "No files matched extraction filter"}

            from app.services.disk_manifest import upload_extract_nodes

            write_disk_log(
                db,
                job_id,
                f"Saving extract plan — {len(nodes):,} files…",
                stage="extract",
                metadata={"to_extract": len(nodes)},
            )
            db.commit()
            nodes_uri = upload_extract_nodes(job_id, nodes, zstd_level=settings.extract_zstd_level)

    if not nodes:
        write_disk_log(db, job_id, "No files matched extraction filter", stage="extract", level="error")
        db.commit()
        return {"status": "failed", "error": "No files matched extraction filter"}

    if not loaded_from_cache:
        write_disk_log(
            db,
            job_id,
            f"Filter complete — {len(nodes):,} to extract, "
            f"{filter_stats.get('filtered_out', 0):,} skipped "
            f"(policy={filter_stats.get('policy_reason')})",
            stage="extract",
            metadata={"filter_stats": filter_stats},
        )
        db.commit()
        if resume and existing_cp and nodes_uri:
            existing_cp["nodes_uri"] = nodes_uri
            save_extraction_checkpoint(db, job_id, existing_cp)

    _mark_live_step(job_id, "plan I/O")
    # E01: one reader (random seeks kill throughput). Folder iOS backups: many
    # parallel readers — this stage is I/O, not GPU/NPU.
    configured_readers = max(int(settings.extract_disk_workers or 1), 1)
    live_disk = None
    live_mobile = None
    try:
        from app.services.perf_broadcast import live_extract_disk_workers, live_extract_mobile_workers

        live_disk = live_extract_disk_workers(configured_readers)
        live_mobile = live_extract_mobile_workers(
            max(int(getattr(settings, "extract_mobile_workers", 8) or 8), 1)
        )
    except Exception:
        live_disk = None
        live_mobile = None
    thermal_pace = 1.0
    try:
        from app.services.host_capacity import cpu_thermal_pace

        thermal_pace = float(cpu_thermal_pace())
    except Exception:
        thermal_pace = 1.0
    ewf_mode = bool(getattr(vd, "mode", "") in ("ewf", "raw") or getattr(vd, "_fs_info", None))
    mobile_mode = (
        str(getattr(vd, "mode", "") or "") == "folder"
        or str(getattr(vd, "format", "") or "").lower()
        in {"mobile", "pas", "ufd", "ufdx", "zip", "backup"}
        or any(".zip/" in str(n.get("path") or "").replace("\\", "/").lower() for n in nodes[:50])
    )
    stream_phase3 = bool(
        not bool(getattr(settings, "extract_then_process", True)) and not serial_enabled()
        and settings.phase3_stream_during_extract
        and settings.phase3_auto_after_disk
    )
    configured_shards = max(int(getattr(settings, "extract_shard_count", 8) or 8), 1)
    busy_n = 1
    try:
        row = fetchone(
            db,
            """SELECT count(*)::int AS n FROM jobs
               WHERE status IN ('building_disk', 'processing')
                 AND coalesce(files_total, 0) > 0""",
        )
        busy_n = max(int((row or {}).get("n") or 1), 1)
    except Exception:
        busy_n = 1
    io_reason = "ewf"
    if ewf_mode:
        parallel_readers, worker_count, io_reason = plan_ewf_extract_io(
            nodes,
            configured_workers=configured_readers,
            configured_shards=configured_shards,
            live_workers=live_disk,
            thermal_pace=thermal_pace,
            busy_extracts=busy_n,
            stream_phase3=stream_phase3,
        )
        upload_n = max(int(getattr(settings, "extract_upload_concurrency", 4) or 4), 1)
        if parallel_readers > 1:
            parallel_readers = min(
                max(parallel_readers, min(upload_n, worker_count)),
                16,
                worker_count,
            )
    elif mobile_mode:
        parallel_readers, worker_count, io_reason = plan_mobile_extract_io(
            vd,
            nodes,
            configured_workers=int(getattr(settings, "extract_mobile_workers", 8) or 8),
            live_workers=live_mobile,
            thermal_pace=thermal_pace,
            busy_extracts=busy_n,
        )
    else:
        parallel_readers = min(max(configured_readers, 1), 4)
        worker_count = max(min(parallel_readers, len(nodes)), 1)
        io_reason = "generic_folder"

    # Final admission control comes from the host-wide adaptive semaphore.  The
    # planner above decides the ideal I/O shape; this cap reacts to *current*
    # CPU temperature/load/RAM so a second case or hot chassis cannot multiply
    # readers beyond the machine's live headroom.  Shard count stays unchanged
    # so resumability/Phase-3 streaming are not affected.
    try:
        from app.services.adaptive_semaphore import cap_parallelism

        before_readers = parallel_readers
        parallel_readers = cap_parallelism(
            "mobile_readers" if mobile_mode else "disk_readers",
            parallel_readers,
            min_workers=1,
        )
        if parallel_readers < before_readers:
            io_reason += f"+adaptive_cap_{parallel_readers}"
    except Exception:
        pass

    parallel_readers = max(1, min(parallel_readers, 4))

    # V45: physical-source cap (HDD/USB => 1-2 readers) + bounded read semaphore.
    try:
        parallel_readers, read_gate_n, media_reason = plan_readers_v45(vd, parallel_readers)
        configure_read_gate(read_gate_n)
        io_reason += f"+v45[{media_reason};gate={read_gate_n}]"
    except Exception:
        log.debug("v45 reader planning failed", exc_info=True)

    write_disk_log(
        db,
        job_id,
        f"Extract I/O plan — shards={worker_count}, parallel_readers={parallel_readers}, "
        f"reason={io_reason}, stream_phase3={stream_phase3}, ewf={ewf_mode}, busy={busy_n}",
        stage="extract",
        level="info",
        metadata={
            "shards": worker_count,
            "parallel_readers": parallel_readers,
            "io_reason": io_reason,
            "stream_phase3": stream_phase3,
            "ewf_mode": ewf_mode,
            "busy_extracts": busy_n,
        },
    )
    db.commit()

    # Resume must keep the original shard layout once any shard has completed — unless
    # EXTRACT_REPLAN_ON_RESUME=true (safe re-extract of the full forensic set with path_range).
    shard_strategy = "path_range"
    force_replan = bool(getattr(settings, "extract_replan_on_resume", False))
    if resume and existing_cp and force_replan:
        write_disk_log(
            db,
            job_id,
            f"EXTRACT_REPLAN_ON_RESUME — fresh inode-ordered plan with {worker_count} sequential "
            f"shards (full forensic set; Phase 3 streams per shard)",
            stage="extract",
            level="warning",
            metadata={"workers": worker_count, "shard_strategy": "path_range"},
        )
        db.commit()
        existing_cp = {
            **existing_cp,
            "worker_count": worker_count,
            "shard_strategy": "path_range",
            "completed_shards": [],
            "files_extracted": 0,
            "bytes_extracted": 0,
            "shard_indexes": {},
            "parts": {},
            "phase3_completed_shards": [],
            "nodes_uri": None,  # force re-enumerate to capture inodes
        }
        save_extraction_checkpoint(db, job_id, existing_cp)
        db.commit()
        # Always re-enumerate on replan so inode metadata is present (path-open is too slow).
        write_disk_log(db, job_id, "Re-enumerating filesystem for inode-ordered extract…", stage="extract")
        db.commit()
        on_enum_progress = make_session_progress(
            db, job_id, stage="extract", commit=True, schema_name=schema_name
        )
        try:
            _ensure_mobile_payload_zips(vd, on_enum_progress)
        except Exception:
            pass
        with disk_log_heartbeat(
            schema_name, job_id, "Re-enumerating filesystem tree", stage="extract", interval_sec=15.0
        ):
            all_nodes = enumerate_all_files(vd, on_progress=on_enum_progress)
        os_info = detect_os_from_paths(all_nodes)
        nodes, filter_stats = _filter_nodes(
            all_nodes,
            settings,
            os_info=os_info,
            on_progress=lambda message, metadata=None: write_disk_log_committed(
                schema_name, job_id, message, stage="extract", metadata=metadata
            ),
        )
        from app.services.disk_manifest import upload_extract_nodes

        nodes_uri = upload_extract_nodes(job_id, nodes, zstd_level=settings.extract_zstd_level)
        existing_cp["nodes_uri"] = nodes_uri
        existing_cp["filter_stats"] = filter_stats
        existing_cp["nodes_total"] = len(nodes)
        save_extraction_checkpoint(db, job_id, existing_cp)
        db.commit()
        resume = True
        shard_strategy = "path_range"
    elif resume and existing_cp:
        done_preview = completed_shard_ids(existing_cp)
        saved_workers = int(existing_cp.get("worker_count") or worker_count)
        if done_preview:
            if saved_workers != worker_count:
                write_disk_log(
                    db,
                    job_id,
                    f"Resume uses saved shard layout ({saved_workers} workers, "
                    f"strategy={existing_cp.get('shard_strategy') or 'hash'}) — "
                    f"set EXTRACT_REPLAN_ON_RESUME=true to adopt path_range on next start",
                    stage="extract",
                    level="info",
                )
            worker_count = saved_workers
            shard_strategy = str(existing_cp.get("shard_strategy") or "hash")
        else:
            write_disk_log(
                db,
                job_id,
                f"No completed shards yet — replanning with path_range sharding "
                f"and {worker_count} thermal-safe workers (full forensic file set preserved)",
                stage="extract",
                level="info",
                metadata={"workers": worker_count, "shard_strategy": "path_range"},
            )
            db.commit()
            shard_strategy = "path_range"
            existing_cp = {
                **existing_cp,
                "worker_count": worker_count,
                "shard_strategy": shard_strategy,
                "completed_shards": [],
            }
            save_extraction_checkpoint(db, job_id, existing_cp)
            db.commit()

    shards = _shard_nodes(nodes, worker_count, strategy=shard_strategy)
    planned_bytes_total = sum(max(int(n.get("size_bytes") or 0), 0) for n in nodes)
    done_ids = completed_shard_ids(existing_cp) if resume else set()
    phase3_done = {int(x) for x in (existing_cp or {}).get("phase3_completed_shards") or []}

    if (
        not bool(getattr(settings, "extract_then_process", True)) and not serial_enabled()
        and settings.phase3_stream_during_extract
        and settings.phase3_auto_after_disk
        and done_ids - phase3_done
    ):
        from app.tasks import phase3_shard_task

        for sid in sorted(done_ids - phase3_done):
            phase3_shard_task.delay(schema_name, job_id, sid)

    if resume:
        write_disk_log(
            db,
            job_id,
            f"Resuming extraction — {len(done_ids)} shard(s) already complete, "
            f"{worker_count - len(done_ids)} remaining of {worker_count}",
            stage="extract",
            metadata={"completed_shards": sorted(done_ids), "worker_count": worker_count},
        )
        checkpoint = dict(existing_cp or {})
    else:
        write_disk_log(
            db,
            job_id,
            f"Extract plan — mode={mode}, os={filter_stats.get('detected_os', {}).get('family', 'unknown')}, "
            f"skip_system={filter_stats.get('skip_system_paths')} ({filter_stats.get('policy_reason')}), "
            f"{len(nodes):,} files to extract "
            f"({filter_stats.get('filtered_out', 0):,} pre-filtered from {filter_stats.get('enumerated', 0):,}), "
            f"{worker_count} parallel shard(s) strategy={shard_strategy}, "
            f"zstd={settings.extract_zstd_level}, hash={settings.extract_hash_files}",
            stage="extract",
            metadata={
                "files_total": len(nodes),
                "workers": worker_count,
                "shard_strategy": shard_strategy,
                "extract_mode": mode,
                "detected_os": filter_stats.get("detected_os"),
                "filter_policy": filter_stats.get("filter_policy"),
                "filter_stats": filter_stats,
            },
        )
        checkpoint = empty_checkpoint(
            worker_count=worker_count,
            mode=mode,
            filter_stats=filter_stats,
            nodes_total=len(nodes),
            files_skipped=filter_stats.get("filtered_out", 0),
            shard_strategy=shard_strategy,
        )
        if nodes_uri:
            checkpoint["nodes_uri"] = nodes_uri
        save_extraction_checkpoint(db, job_id, checkpoint)

    from app.services.pipeline_progress import write_merged_pipeline_progress

    write_merged_pipeline_progress(
        db,
        job_id,
        {
            "phase": "extract",
            "completed": int(checkpoint.get("files_extracted") or 0),
            "total": len(nodes),
            "label": (
                f"Extraction plan ready — {len(nodes):,} files; "
                f"{max(len(nodes) - int(checkpoint.get('files_extracted') or 0), 0):,} remaining"
            ),
            "extraction_activity": {
                "subphase": "copying",
                "label": "Extracting evidence files into immutable shards",
                "files_extracted": int(checkpoint.get("files_extracted") or 0),
                "files_total": len(nodes),
                "files_remaining": max(len(nodes) - int(checkpoint.get("files_extracted") or 0), 0),
                "bytes_extracted": int(checkpoint.get("bytes_extracted") or 0),
                "bytes_total": planned_bytes_total,
                "bytes_remaining": max(planned_bytes_total - int(checkpoint.get("bytes_extracted") or 0), 0),
                "shards_total": worker_count,
            },
        },
        writer="extract",
        progress_pct=5,
        extra_sets="files_total=:ft, stop_requested=FALSE",
        extra_params={"ft": len(nodes)},
    )
    db.commit()

    payloads = [
        {
            "schema_name": schema_name,
            "job_id": job_id,
            "shard_id": shard_id,
            "nodes": shard_nodes,
            "zstd_level": settings.extract_zstd_level,
            "shard_count": worker_count,
            "hash_files": settings.extract_hash_files,
            "stop_check_interval": settings.extract_stop_check_interval,
            "tar_bufsize": getattr(settings, "extract_tar_bufsize", 262_144),
            "vd_plan": _vd_plan(vd),
            "part_prefix": _disk_prefix(job_id),
        }
        for shard_id, shard_nodes in shards.items()
        if shard_nodes and shard_id not in done_ids
    ]

    prior_index, prior_parts = checkpoint_index_and_parts(checkpoint)
    prior_extracted = int(checkpoint.get("files_extracted") or 0)
    prior_bytes = int(checkpoint.get("bytes_extracted") or 0)
    prior_skipped = int(checkpoint.get("files_skipped") or filter_stats.get("filtered_out", 0))

    progress = _ExtractionProgress(
        len(nodes),
        progress_step=settings.extract_progress_step,
        initial_extracted=prior_extracted,
        initial_bytes=prior_bytes,
        pre_filtered=filter_stats.get("filtered_out", 0),
    )
    for sid in done_ids:
        progress.mark_shard_done(sid)

    all_index: list[dict] = list(prior_index)
    total_files = prior_extracted
    total_bytes = prior_bytes
    total_skipped = prior_skipped
    part_uris: list[str] = list(prior_parts)

    def _mark_finalizing() -> None:
        from app.services.pipeline_progress import write_merged_pipeline_progress

        write_merged_pipeline_progress(
            db,
            job_id,
            {
                "phase": "extract",
                "completed": len(nodes),
                "total": len(nodes),
                "label": "Extraction data complete — finalizing immutable evidence manifest",
                "extraction_activity": {
                    "subphase": "finalizing",
                    "label": "Finalizing extracted evidence manifest",
                    "files_extracted": len(nodes),
                    "files_total": len(nodes),
                    "files_remaining": 0,
                    "bytes_extracted": int(total_bytes or prior_bytes or 0),
                    "bytes_total": planned_bytes_total,
                    "bytes_remaining": max(planned_bytes_total - int(total_bytes or prior_bytes or 0), 0),
                    "shards_done": len(done_ids),
                    "shards_total": worker_count,
                },
            },
            writer="extract",
            progress_pct=99,
            extra_sets="files_extracted=:fe, bytes_extracted=:be",
            extra_params={"fe": len(nodes), "be": int(total_bytes or prior_bytes or 0)},
        )
        db.commit()

    if not payloads:
        _mark_finalizing()
        return _finalize_manifest(
            job_id=job_id,
            vd=vd,
            nodes=nodes,
            all_nodes=all_nodes,
            all_index=all_index,
            part_uris=part_uris,
            total_files=total_files,
            total_bytes=total_bytes,
            total_skipped=total_skipped,
            mode=mode,
            filter_stats=filter_stats,
            payload_count=worker_count,
            settings=settings,
            checkpoint=checkpoint,
        )

    write_disk_log(
        db,
        job_id,
        f"Starting {len(payloads)} extract shard(s) — "
        f"{'sequential shared-E01' if parallel_readers <= 1 else f'{parallel_readers} parallel readers'}…",
        stage="extract",
        metadata={
            "shard_workers": len(payloads),
            "worker_count": worker_count,
            "parallel_readers": parallel_readers,
        },
    )
    db.commit()

    stop_poller = _StopPoller(schema_name, job_id)
    progress_flusher = _ProgressFlusher(
        schema_name,
        job_id,
        progress,
        shard_count=worker_count,
        total_bytes=planned_bytes_total,
        flush_interval_sec=float(getattr(settings, "extract_progress_flush_sec", _PROGRESS_FLUSH_INTERVAL_SEC)),
        log_interval_sec=float(getattr(settings, "extract_progress_log_sec", _PROGRESS_LOG_DB_INTERVAL_SEC)),
    )
    stop_poller.start()
    progress_flusher.start()

    def _consume_shard_result(result: dict, done_shards: int) -> tuple[dict, int, list, int, int, int]:
        nonlocal checkpoint, all_index, total_files, total_bytes, total_skipped, part_uris
        checkpoint = _on_shard_complete(
            db,
            schema_name=schema_name,
            job_id=job_id,
            vd=vd,
            checkpoint=checkpoint,
            result=result,
            mode=mode,
            filter_stats=filter_stats,
            settings=settings,
        )
        all_index.extend(result.get("index_entries") or [])
        total_files = int(checkpoint["files_extracted"])
        total_bytes = int(checkpoint["bytes_extracted"])
        total_skipped = int(checkpoint.get("files_skipped") or 0)
        if result.get("part_uri"):
            part_uris.append(result["part_uri"])
        done_shards += 1
        pct = _progress_pct(total_files, len(nodes), done_shards, worker_count)
        progress_flusher.mark_dirty()
        execute(
            db,
            """UPDATE jobs SET files_extracted=:fe, bytes_extracted=:be, progress_pct=:pct, updated_at=NOW()
               WHERE id=:job_id""",
            {"fe": total_files, "be": total_bytes, "pct": pct, "job_id": job_id},
        )
        write_disk_log(
            db,
            job_id,
            f"Shard {result['shard_id']} complete — {result['files_extracted']:,} files uploaded to MinIO"
            + (f" ({result.get('files_skipped', 0)} read skips)" if result.get("files_skipped") else ""),
            stage="extract",
            metadata={"shard_id": result["shard_id"], "progress_pct": pct},
        )
        db.commit()
        return checkpoint, done_shards, all_index, total_files, total_bytes, total_skipped

    try:
        _mark_live_step(job_id, "extract shards")
        with disk_log_heartbeat(
            schema_name,
            job_id,
            "Extracting files into MinIO shards",
            stage="extract",
            interval_sec=20.0,
        ):
            done_shards = len(done_ids)
            ordered_payloads = sorted(payloads, key=lambda p: int(p["shard_id"]))

            if parallel_readers <= 1:
                # Fast NVMe path: one E01 handle, sequential inode-ordered shards; downstream stays behind the barrier
                for p in ordered_payloads:
                    if stop_poller.is_requested() or is_stop_requested(db, job_id):
                        return _handle_stop(
                            db,
                            job_id,
                            schema_name=schema_name,
                            checkpoint=checkpoint,
                            progress=progress,
                            worker_count=worker_count,
                        )
                    try:
                        result = shard_worker_v45(
                            p, progress, progress_flusher, stop_poller,
                            shared_vd=vd, event_bus=progress_flusher.event_bus,
                        )
                    except JobStopRequested:
                        return _handle_stop(
                            db,
                            job_id,
                            schema_name=schema_name,
                            checkpoint=checkpoint,
                            progress=progress,
                            worker_count=worker_count,
                        )
                    except Exception as exc:
                        log.exception("Shard %s failed for job %s", p["shard_id"], job_id)
                        write_disk_log(
                            db,
                            job_id,
                            f"Extraction aborted — shard {p['shard_id']} failed: {exc}",
                            stage="extract",
                            level="error",
                        )
                        db.commit()
                        return {"status": "failed", "error": f"Shard {p['shard_id']} failed: {exc}"}
                    _, done_shards, _, total_files, total_bytes, total_skipped = _consume_shard_result(
                        result, done_shards
                    )
            else:
                with ThreadPoolExecutor(max_workers=min(parallel_readers, len(payloads))) as pool:
                    futures = {
                        pool.submit(
                            shard_worker_v45, p, progress, progress_flusher, stop_poller,
                            event_bus=progress_flusher.event_bus,
                        ): p["shard_id"]
                        for p in payloads
                    }
                    for future in as_completed(futures):
                        shard_id = futures[future]
                        if stop_poller.is_requested() or is_stop_requested(db, job_id):
                            return _handle_stop(
                                db,
                                job_id,
                                schema_name=schema_name,
                                checkpoint=checkpoint,
                                progress=progress,
                                worker_count=worker_count,
                            )
                        try:
                            result = future.result()
                        except JobStopRequested:
                            return _handle_stop(
                                db,
                                job_id,
                                schema_name=schema_name,
                                checkpoint=checkpoint,
                                progress=progress,
                                worker_count=worker_count,
                            )
                        except Exception as exc:
                            log.exception("Shard %s failed for job %s", shard_id, job_id)
                            write_disk_log(
                                db,
                                job_id,
                                f"Extraction aborted — shard {shard_id} failed: {exc}",
                                stage="extract",
                                level="error",
                            )
                            db.commit()
                            return {"status": "failed", "error": f"Shard {shard_id} failed: {exc}"}
                        _, done_shards, _, total_files, total_bytes, total_skipped = _consume_shard_result(
                            result, done_shards
                        )
    finally:
        progress_flusher.stop(flush=True)
        stop_poller.stop()

    if total_skipped > 0:
        write_disk_log(
            db,
            job_id,
            f"Extraction finished — {total_skipped:,} path(s) pre-filtered or unreadable (normal on Windows images)",
            stage="extract",
            level="info",
            metadata={"files_skipped": total_skipped, "filter_stats": filter_stats},
        )
        db.commit()

    _mark_live_step(job_id, "finalize manifest")
    all_index, part_uris = checkpoint_index_and_parts(checkpoint)
    _mark_finalizing()
    return _finalize_manifest(
        job_id=job_id,
        vd=vd,
        nodes=nodes,
        all_nodes=all_nodes,
        all_index=all_index,
        part_uris=part_uris,
        total_files=total_files,
        total_bytes=total_bytes,
        total_skipped=total_skipped,
        mode=mode,
        filter_stats=filter_stats,
        payload_count=worker_count,
        settings=settings,
        checkpoint=checkpoint,
    )
