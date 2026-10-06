"""Read-only source-media classification for forensic disk performance planning.

The classifier never writes to evidence.  It prefers Linux block-device metadata
(``/sys/dev/block/.../queue/rotational``) and falls back to a small sequential
read benchmark of the registered image segment when the backing device cannot
be resolved (common with bind mounts / removable USB media).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path


NETWORK_FS_TYPES = {
    "nfs", "nfs4", "cifs", "smb3", "sshfs", "fuse.sshfs", "ceph", "glusterfs",
}


@dataclass(frozen=True)
class SourceMediaProfile:
    kind: str  # hdd | ssd | nvme | network | unknown
    rotational: bool | None
    benchmark_mbps: float | None
    reason: str
    path: str


def _mount_fs_type(path: Path) -> str | None:
    try:
        resolved = str(path.resolve())
    except Exception:
        resolved = str(path)
    best_mount = ""
    best_type = None
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mount = parts[1].replace("\\040", " ")
                if resolved == mount or resolved.startswith(mount.rstrip("/") + "/"):
                    if len(mount) >= len(best_mount):
                        best_mount = mount
                        best_type = parts[2]
    except OSError:
        return None
    return best_type


def _sysfs_block_info(path: Path) -> tuple[bool | None, str | None]:
    """Return (rotational, kernel-device-name) when Linux exposes the backing device."""
    try:
        st = path.stat()
        major = os.major(st.st_dev)
        minor = os.minor(st.st_dev)
        dev_link = Path(f"/sys/dev/block/{major}:{minor}")
        if not dev_link.exists():
            return None, None
        real = dev_link.resolve()
        device_name = real.name
        # Partitions expose queue data on their parent block device.
        candidates = [real / "queue" / "rotational", real.parent / "queue" / "rotational"]
        for candidate in candidates:
            if candidate.is_file():
                val = candidate.read_text(encoding="ascii", errors="ignore").strip()
                if val in {"0", "1"}:
                    return val == "1", device_name
    except (OSError, ValueError):
        pass
    return None, None


def sequential_read_mbps(path: Path, *, sample_bytes: int = 64 * 1024 * 1024) -> float | None:
    """Small read-only sequential benchmark used only when media type is unknown.

    This reads image-container bytes, not logical evidence files, and never modifies
    access metadata intentionally.  ``O_NOATIME`` is requested when permitted.
    """
    if not path.is_file() or sample_bytes <= 0:
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOATIME"):
        flags |= os.O_NOATIME
    fd = None
    try:
        try:
            fd = os.open(path, flags)
        except PermissionError:
            fd = os.open(path, os.O_RDONLY)
        remaining = min(int(sample_bytes), max(int(path.stat().st_size), 0))
        if remaining <= 0:
            return None
        started = time.perf_counter()
        total = 0
        while remaining > 0:
            chunk = os.read(fd, min(4 * 1024 * 1024, remaining))
            if not chunk:
                break
            total += len(chunk)
            remaining -= len(chunk)
        elapsed = max(time.perf_counter() - started, 1e-6)
        return round((total / (1024 * 1024)) / elapsed, 1) if total else None
    except OSError:
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def classify_source_path(
    raw_path: str | Path,
    *,
    override: str = "auto",
    benchmark_mb: int = 64,
) -> SourceMediaProfile:
    path = Path(raw_path)
    forced = (override or "auto").strip().lower()
    if forced in {"hdd", "ssd", "nvme", "network"}:
        return SourceMediaProfile(forced, forced == "hdd", None, "operator_override", str(path))

    fs_type = (_mount_fs_type(path) or "").lower()
    if fs_type in NETWORK_FS_TYPES:
        return SourceMediaProfile("network", None, None, f"filesystem={fs_type}", str(path))

    rotational, dev_name = _sysfs_block_info(path)
    if rotational is True:
        return SourceMediaProfile("hdd", True, None, f"sysfs={dev_name or 'rotational'}", str(path))
    if rotational is False:
        kind = "nvme" if (dev_name or "").lower().startswith("nvme") else "ssd"
        return SourceMediaProfile(kind, False, None, f"sysfs={dev_name or 'nonrotational'}", str(path))

    mbps = sequential_read_mbps(path, sample_bytes=max(int(benchmark_mb), 0) * 1024 * 1024)
    if mbps is not None:
        # Conservative fallback.  USB SSDs can be slower than this, but the HDD
        # profile is safe and avoids random-seek collapse on ambiguous media.
        if mbps < 180.0:
            return SourceMediaProfile("hdd", None, mbps, "read_benchmark_hdd_like", str(path))
        if mbps >= 700.0:
            return SourceMediaProfile("nvme", None, mbps, "read_benchmark_nvme_like", str(path))
        return SourceMediaProfile("ssd", None, mbps, "read_benchmark_ssd_like", str(path))

    return SourceMediaProfile("unknown", None, None, "device_type_unresolved", str(path))
