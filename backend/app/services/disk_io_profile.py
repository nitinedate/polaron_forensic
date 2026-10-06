"""Source-media detection and evidence-safe disk I/O planning helpers.

The extraction code needs different read shapes for rotational HDDs and SSD/NVMe:
rotational media should stay sequential (one image reader) while solid-state media can
sustain multiple independent EWF/TSK readers.  Detection is best-effort and can be
overridden with DISK_SOURCE_MEDIA=hdd|ssd|nvme|auto for Docker/VM environments where
the physical device is hidden from /sys.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path


_VALID_MEDIA = {"auto", "hdd", "ssd", "nvme", "unknown"}


@dataclass(frozen=True)
class DiskIOProfile:
    media: str = "unknown"
    rotational: bool | None = None
    source_path: str = ""
    device: str = ""
    detection: str = "unknown"

    def to_dict(self) -> dict:
        return asdict(self)


def _override() -> str:
    raw = str(os.environ.get("DISK_SOURCE_MEDIA", "auto") or "auto").strip().lower()
    return raw if raw in _VALID_MEDIA else "auto"


def _first_existing_file(paths: list[str]) -> Path | None:
    for raw in paths or []:
        try:
            path = Path(str(raw).replace("file://", "", 1))
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def _linux_block_profile(path: Path) -> DiskIOProfile | None:
    """Resolve st_dev -> /sys/dev/block and read queue/rotational when available."""
    try:
        st = path.stat()
        major = os.major(st.st_dev)
        minor = os.minor(st.st_dev)
        sys_dev = Path(f"/sys/dev/block/{major}:{minor}")
        if not sys_dev.exists():
            return None
        resolved = sys_dev.resolve()
        device = resolved.name
        rotational_file = resolved / "queue" / "rotational"
        if not rotational_file.is_file():
            # Device-mapper partitions can expose queue on an ancestor.
            for parent in resolved.parents:
                candidate = parent / "queue" / "rotational"
                if candidate.is_file():
                    rotational_file = candidate
                    if not device:
                        device = parent.name
                    break
        rotational = None
        if rotational_file.is_file():
            raw = rotational_file.read_text(encoding="utf-8", errors="ignore").strip()
            if raw in {"0", "1"}:
                rotational = raw == "1"
        name = str(resolved).lower()
        if "nvme" in name:
            media = "nvme"
        elif rotational is True:
            media = "hdd"
        elif rotational is False:
            media = "ssd"
        else:
            media = "unknown"
        return DiskIOProfile(
            media=media,
            rotational=rotational,
            source_path=str(path),
            device=device,
            detection="linux_sysfs",
        )
    except (OSError, ValueError):
        return None


def detect_source_io_profile(paths: list[str]) -> DiskIOProfile:
    """Return the best available source-media profile without modifying evidence."""
    override = _override()
    path = _first_existing_file(paths)
    source = str(path) if path else (str(paths[0]) if paths else "")
    if override != "auto":
        rotational = True if override == "hdd" else False if override in {"ssd", "nvme"} else None
        return DiskIOProfile(
            media=override,
            rotational=rotational,
            source_path=source,
            detection="environment_override",
        )
    if path is not None:
        found = _linux_block_profile(path)
        if found is not None:
            return found
    return DiskIOProfile(source_path=source)
