"""Integrity monitor — Architecture §8, §12, §14.

Hashes are computed *while the stream is written*, not by re-reading the file
afterwards. Re-reading proves only that the file on disk is self-consistent; it
cannot detect a truncation that happened during transfer. Hashing inline means
the recorded digest is the digest of the bytes that actually arrived.

Dual-algorithm by default (MD5 + SHA-256): MD5 for cross-tool comparison with
legacy manifests, SHA-256 as the defensible digest.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from app.services.mobile_acquire.adb_tar_pull import iter_tree_files

DEFAULT_ALGORITHMS: tuple[str, ...] = ("md5", "sha256")
_CHUNK = 1024 * 1024


@dataclass
class FileIntegrity:
    relative_path: str
    size_bytes: int
    digests: dict[str, str]
    modified_utc: str | None = None

    def as_dict(self) -> dict:
        return {
            "path": self.relative_path,
            "size_bytes": self.size_bytes,
            "digests": self.digests,
            "modified_utc": self.modified_utc,
        }


@dataclass
class IntegrityManifest:
    run_name: str
    created_utc: str
    algorithms: tuple[str, ...]
    files: list[FileIntegrity] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(f.size_bytes for f in self.files)

    def as_dict(self) -> dict:
        return {
            "run_name": self.run_name,
            "created_utc": self.created_utc,
            "algorithms": list(self.algorithms),
            "file_count": len(self.files),
            "total_bytes": self.total_bytes,
            "files": [f.as_dict() for f in self.files],
        }

    def write(self, path: str | os.PathLike[str]) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.as_dict(), indent=2), encoding="utf-8")
        return str(target)


class HashingWriter:
    """Write bytes to disk and hash them in the same pass.

    Usage:
        with HashingWriter(dest) as w:
            for chunk in stream:
                w.write(chunk)
        w.digests  ->  {"md5": "...", "sha256": "..."}
    """

    def __init__(
        self,
        destination: str | os.PathLike[str],
        *,
        algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        self.destination = Path(destination)
        self.algorithms = tuple(algorithms)
        self._hashers = {a: hashlib.new(a) for a in self.algorithms}
        self._progress = progress
        self._fh = None
        self.bytes_written = 0

    def __enter__(self) -> "HashingWriter":
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.destination.open("wb")
        return self

    def write(self, chunk: bytes) -> int:
        if not chunk:
            return 0
        self._fh.write(chunk)
        for h in self._hashers.values():
            h.update(chunk)
        self.bytes_written += len(chunk)
        if self._progress:
            self._progress(self.bytes_written)
        return len(chunk)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            self._fh = None

    @property
    def digests(self) -> dict[str, str]:
        return {name: h.hexdigest() for name, h in self._hashers.items()}


def hash_file(
    path: str | os.PathLike[str],
    *,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
) -> dict[str, str]:
    hashers = {a: hashlib.new(a) for a in algorithms}
    with Path(path).open("rb") as fh:
        while chunk := fh.read(_CHUNK):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def build_manifest(
    root: str | os.PathLike[str],
    *,
    run_name: str,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    progress: Callable[[str], None] | None = None,
) -> IntegrityManifest:
    """Hash every file under `root` and return the manifest."""
    base = Path(root)
    algos = tuple(algorithms)
    manifest = IntegrityManifest(
        run_name=run_name,
        created_utc=datetime.now(timezone.utc).isoformat(),
        algorithms=algos,
    )
    rows = list(iter_tree_files(base, follow_junctions=True))
    rows.sort(key=lambda row: row[1])
    for full, rel in rows:
        path = Path(full)
        if progress:
            progress(rel)
        stat_result = path.stat()
        manifest.files.append(FileIntegrity(
            relative_path=rel,
            size_bytes=stat_result.st_size,
            digests=hash_file(path, algorithms=algos),
            modified_utc=datetime.fromtimestamp(
                stat_result.st_mtime, tz=timezone.utc).isoformat(),
        ))
    return manifest


@dataclass
class VerificationResult:
    ok: bool
    verified: int = 0
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "verified": self.verified,
            "mismatched": self.mismatched,
            "missing": self.missing,
            "unexpected": self.unexpected,
        }


def verify_against_manifest(
    root: str | os.PathLike[str],
    manifest: IntegrityManifest | dict,
) -> VerificationResult:
    """§12 — hash verification on ingest and transfer.

    Used to prove the working copy is a true copy of the immutable original
    before any analysis touches it.
    """
    data = manifest.as_dict() if isinstance(manifest, IntegrityManifest) else dict(manifest)
    base = Path(root)
    algos = tuple(data.get("algorithms") or DEFAULT_ALGORITHMS)

    result = VerificationResult(ok=True)
    expected_paths: set[str] = set()

    for entry in data.get("files") or []:
        rel = entry["path"]
        expected_paths.add(rel)
        target = base / rel
        if not target.is_file():
            result.missing.append(rel)
            result.ok = False
            continue
        actual = hash_file(target, algorithms=algos)
        if any(actual.get(a) != entry["digests"].get(a) for a in algos):
            result.mismatched.append(rel)
            result.ok = False
        else:
            result.verified += 1

    for path in base.rglob("*"):
        if path.is_file():
            rel = path.relative_to(base).as_posix()
            if rel not in expected_paths:
                result.unexpected.append(rel)

    # Extra files do not break integrity of what was acquired, but they must be
    # reported — they indicate the working copy was modified.
    return result


def copy_verified(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    manifest: IntegrityManifest,
) -> VerificationResult:
    """§12 — create the working copy and prove it matches the original."""
    import shutil

    src, dst = Path(source), Path(destination)
    dst.mkdir(parents=True, exist_ok=True)
    # Copy exactly the manifest entries.  This follows a case-folder junction to
    # an external iOS payload without silently omitting the backup tree.
    for entry in manifest.files:
        item = src / entry.relative_path
        target = dst / entry.relative_path
        if not item.is_file():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)
    return verify_against_manifest(dst, manifest)
