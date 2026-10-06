"""Stream Android directories over ``adb exec-out tar`` and extract with long paths.

``adb pull`` on Windows fails once the destination exceeds MAX_PATH (~260). That
is why WhatsApp under Android/media never landed: the phone had the files, the
host path was too long. Streaming tar and extracting with the ``\\\\?\\`` prefix
avoids that without any exploit or extra privilege on the handset.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import tarfile
import shutil
from pathlib import Path
from typing import Any, IO

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def is_reparse_or_symlink(path: str | Path) -> bool:
    """True for symlinks and Windows junctions (os.walk follows those)."""
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = int(getattr(st, "st_file_attributes", 0) or 0)
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def windows_long_path(path: Path) -> str:
    resolved = str(Path(path).resolve())
    if os.name != "nt":
        return resolved
    if resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved[2:]
    return "\\\\?\\" + resolved


def _write_progress(path: str | None, files: int, remote: str, nbytes: int = 0) -> None:
    if not path:
        return
    try:
        Path(path).write_text(
            json.dumps(
                {
                    "stage": "acquire",
                    "item": "adb_filesystem",
                    "files_seen": files,
                    "bytes_done": int(nbytes or 0),
                    "detail": f"ADB filesystem {remote} - {files} file(s)",
                    "category": "Collecting",
                }
            ),
            encoding="utf-8",
        )
    except OSError:
        pass


def _safe_members(tf: tarfile.TarFile, dest: str) -> int:
    extracted = 0
    for member in tf:
        name = (member.name or "").replace("\\", "/")
        if not name or name.startswith("/") or ".." in Path(name).parts:
            continue
        if not (member.isfile() or member.isdir()):
            continue
        try:
            tf.extract(member, path=dest, set_attrs=False)
        except (OSError, tarfile.TarError):
            continue
        if member.isfile():
            extracted += 1
    return extracted


def extract_tar_stream(stream: IO[bytes], dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    target = windows_long_path(dest)
    with tarfile.open(fileobj=stream, mode="r|") as tf:
        return _safe_members(tf, target)


def iter_tree_files(
    path: Path,
    *,
    follow_junctions: bool = False,
    skip_dir_names: set[str] | frozenset[str] | None = None,
):
    """Yield ``(absolute_path, posix_rel)`` using ``\\\\?\\`` on Windows.

    Junctions (ios_image / afc_media pointing at F:\\ib) are not followed unless
    requested. Derived rematerialize folders can be skipped via skip_dir_names.
    """
    root = Path(path)
    if not root.exists():
        return
    skip = {str(name).lower() for name in (skip_dir_names or ())}
    walk_root = windows_long_path(root)
    for dirpath, dirnames, filenames in os.walk(walk_root, followlinks=False):
        if dirnames:
            kept = []
            for name in dirnames:
                if skip and name.lower() in skip:
                    continue
                if not follow_junctions and is_reparse_or_symlink(os.path.join(dirpath, name)):
                    continue
                kept.append(name)
            dirnames[:] = kept
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, walk_root).replace("\\", "/")
            yield full, rel


def count_tree(path: Path) -> dict[str, Any]:
    root = Path(path)
    files = 0
    nbytes = 0
    if not root.exists():
        return {"ok": False, "files": 0, "bytes": 0}
    for full, _rel in iter_tree_files(root):
        files += 1
        try:
            nbytes += os.path.getsize(full)
        except OSError:
            pass
    return {"ok": True, "files": files, "bytes": nbytes}


def copy_tree_longpath(src: Path, dest: Path, progress_file: str | None = None) -> dict[str, Any]:
    src = Path(src)
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    nbytes = 0
    if not src.exists():
        return {"ok": False, "files": 0, "bytes": 0, "error": "source missing"}
    src_root = windows_long_path(src)
    for dirpath, _dirnames, filenames in os.walk(src_root):
        rel = os.path.relpath(dirpath, src_root)
        dest_dir = dest if rel in (".", "") else dest / rel
        try:
            os.makedirs(windows_long_path(dest_dir), exist_ok=True)
        except OSError:
            continue
        for name in filenames:
            s = os.path.join(dirpath, name)
            d = dest_dir / name
            try:
                shutil.copy2(s, windows_long_path(d))
                copied += 1
                try:
                    nbytes += os.path.getsize(s)
                except OSError:
                    pass
                if copied % 20 == 0:
                    _write_progress(progress_file, copied, str(src), nbytes)
            except OSError:
                continue
    _write_progress(progress_file, copied, str(src), nbytes)
    return {"ok": copied > 0, "files": copied, "bytes": nbytes}


def pull_remote_tar(
    adb: str,
    remote_dir: str,
    dest: Path,
    *,
    progress_file: str | None = None,
    su: bool = False,
    timeout: int = 0,
) -> dict[str, Any]:
    """Disabled on the hot path: Android ``exec-out tar`` hung ~22 minutes with
    0 files on Galaxy A30s. Host collection uses short-path ``adb pull`` instead.
    Rooted FFS still goes through ``adb pull`` / ``su`` from PowerShell.
    """
    remote = (remote_dir or "").rstrip("/") or "/"
    _write_progress(progress_file, 0, remote)
    return {
        "ok": False,
        "files": 0,
        "error": "adb exec-out tar disabled (hangs with 0 files); use short-path adb pull",
        "remote": remote,
        "dest": str(dest),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Android long-path copy/count helpers")
    parser.add_argument("--adb", default="")
    parser.add_argument("--remote", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--progress", default="")
    parser.add_argument("--su", action="store_true")
    parser.add_argument("--count", default="")
    parser.add_argument("--copy-src", default="")
    parser.add_argument("--copy-dst", default="")
    args = parser.parse_args(argv)
    if args.count:
        result = count_tree(Path(args.count))
    elif args.copy_src and args.copy_dst:
        result = copy_tree_longpath(
            Path(args.copy_src),
            Path(args.copy_dst),
            progress_file=args.progress or None,
        )
    elif args.adb and args.remote and args.out:
        result = pull_remote_tar(
            args.adb,
            args.remote,
            Path(args.out),
            progress_file=args.progress or None,
            su=bool(args.su),
        )
    else:
        result = {"ok": False, "error": "need --count, --copy-src/--copy-dst, or --adb/--remote/--out"}
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
