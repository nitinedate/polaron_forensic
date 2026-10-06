"""Directory walks that follow Windows junctions / Linux dir symlinks.

iOS host staging stores the backup under a short path (E:\\ib\\…) and junctions
it into the case folder. Docker Desktop exposes that junction as a Linux symlink
whose target is ``/mnt/host/e/...``. This stack bind-mounts the same drive at
``/host/e``. Without rewriting the target, extract sees only backup.out/err and
the analysis pipeline freezes.

Android extract does not use this helper for ADB trees.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

_WIN_ABS = re.compile(r"^([A-Za-z]):[\\/](.*)$")
_MNT_HOST = re.compile(r"^/mnt/host/([A-Za-z])(/.*)?$", re.IGNORECASE)

# Compose mounts host drives here. Tests may replace this.
HOST_MOUNT = Path("/host")


def rewrite_container_host_path(path: str | os.PathLike[str]) -> Path | None:
    """Compose-mount equivalent of a Windows path or Docker Desktop junction target."""
    text = str(path).replace("\\", "/")
    match = _WIN_ABS.match(str(path))
    if match:
        rest = match.group(2).replace("\\", "/").lstrip("/")
        mapped = HOST_MOUNT / match.group(1).lower()
        return mapped / rest if rest else mapped
    mnt = _MNT_HOST.match(text)
    if mnt:
        rest = (mnt.group(2) or "").lstrip("/")
        mapped = HOST_MOUNT / mnt.group(1).lower()
        return mapped / rest if rest else mapped
    return None


def remap_host_path(path: str | os.PathLike[str]) -> Path:
    """Rewrite ``E:\\ib\\…`` / ``/mnt/host/e/ib/…`` to ``/host/e/ib/…`` when that exists."""
    rewritten = rewrite_container_host_path(path)
    if rewritten is not None and rewritten.exists():
        return rewritten
    return Path(path)


def map_windows_path_for_container(path: str | os.PathLike[str]) -> Path:
    """Backward-compatible alias used by callers and tests."""
    return remap_host_path(path)


def real_key(path: Path) -> str:
    try:
        return os.path.realpath(path)
    except OSError:
        return str(path)


def _read_link_target(path: Path) -> Path | None:
    try:
        raw = os.readlink(path)
    except OSError:
        return None
    target = Path(raw)
    if not target.is_absolute():
        target = path.parent / target
    return target


def resolve_openable_dir(path: Path) -> Path | None:
    """Directory to scandir, following junctions and remapped Docker Desktop targets."""
    candidates: list[Path] = [Path(path), remap_host_path(path)]
    link = _read_link_target(Path(path))
    if link is not None:
        candidates.append(link)
        candidates.append(remap_host_path(link))
        rewritten = rewrite_container_host_path(link)
        if rewritten is not None:
            candidates.append(rewritten)
    rewritten_self = rewrite_container_host_path(path)
    if rewritten_self is not None:
        candidates.append(rewritten_self)
    try:
        candidates.append(remap_host_path(os.path.realpath(path)))
    except OSError:
        pass
    seen: set[str] = set()
    for cand in candidates:
        key = str(cand)
        if key in seen:
            continue
        seen.add(key)
        try:
            if cand.is_dir():
                return cand
        except OSError:
            continue
    return None


def entry_is_dir(entry: os.DirEntry[str]) -> bool:
    """True for real dirs and for junctions/symlinks that point at a directory."""
    try:
        if entry.is_dir(follow_symlinks=True):
            return True
    except OSError:
        pass
    return resolve_openable_dir(Path(entry.path)) is not None


def iter_files_following_dir_links(
    root: Path,
    *,
    skip_dir_names: frozenset[str] | None = None,
) -> Iterator[tuple[Path, str]]:
    """Yield ``(file_path, relative_posix)``, descending into dir junctions."""
    skip = {n.lower() for n in (skip_dir_names or frozenset())}
    start = resolve_openable_dir(Path(root))
    if start is None:
        return
    seen: set[str] = set()
    stack: list[tuple[Path, Path]] = [(start, Path())]
    while stack:
        current, rel = stack.pop()
        key = real_key(current)
        if key in seen:
            continue
        seen.add(key)
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    name = entry.name
                    if not name or name in (".", "..") or name.startswith("$"):
                        continue
                    child_rel = rel / name
                    if entry_is_dir(entry):
                        if name.lower() in skip:
                            continue
                        opened = resolve_openable_dir(Path(entry.path))
                        if opened is None:
                            continue
                        stack.append((opened, child_rel))
                        continue
                    try:
                        if entry.is_file(follow_symlinks=True):
                            yield Path(entry.path), child_rel.as_posix()
                            continue
                    except OSError:
                        pass
                    opened = resolve_openable_dir(Path(entry.path))
                    if opened is not None:
                        if name.lower() in skip:
                            continue
                        stack.append((opened, child_rel))
        except OSError:
            continue
