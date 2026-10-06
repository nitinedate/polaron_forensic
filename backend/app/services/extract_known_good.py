"""Known-good hash sets (NSRL RDS and equivalents) — Recommendation 2.

Hash-based exclusion is materially stronger than path-based exclusion: a file
that is byte-identical to a published vendor release is not case-relevant no
matter where it sits on the disk, and no renaming or relocation defeats it.

The engineering constraint is size. The NSRL RDS modern set runs to tens of
millions of digests. Holding those as Python `str` in a `frozenset` costs on the
order of 100 bytes each — gigabytes of RAM for a lookup table, on a workstation
that also needs its memory for imaging.

Two approaches were rejected before settling on the one implemented here:

  * a Bloom filter is compact and fast, but has false positives. A false
    positive in this position DISCARDS EVIDENCE. Probabilistic structures are
    not acceptable on the exclusion path, at any error rate.
  * a live SQLite query per file is exact but pays interpreter and cursor
    overhead on every one of several million files.

What is implemented is a sorted binary index searched by `bisect` over an
`mmap`: exact, O(log n), effectively zero resident memory (the OS pages in only
the blocks actually touched), and built once per RDS release.

    build_index("/rds/NSRLFile.txt", "/rds/nsrl_sha1.hgi", algorithm="sha1")
    index = KnownGoodIndex("/rds/nsrl_sha1.hgi")
    index.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709")   -> True/False
"""

from __future__ import annotations

import csv
import mmap
import os
import re
import sqlite3
import struct
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

MAGIC = b"HGIX"
FORMAT_VERSION = 1
HEADER = struct.Struct("<4sHH I Q")  # magic, version, digest_len, algo_len, count

DIGEST_LENGTHS: dict[str, int] = {
    "md5": 16,
    "sha1": 20,
    "sha256": 32,
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class KnownGoodError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Source readers
# ---------------------------------------------------------------------------

def _iter_plain_text(path: Path, digest_len: int) -> Iterator[bytes]:
    """One hex digest per line, optionally with trailing fields."""
    expected = digest_len * 2
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            token = line.strip().split()[0] if line.strip() else ""
            token = token.strip('"').strip(",")
            if len(token) == expected and _HEX_RE.match(token):
                yield bytes.fromhex(token)


def _iter_nsrl_csv(path: Path, algorithm: str, digest_len: int) -> Iterator[bytes]:
    """NSRL RDS 2.x NSRLFile.txt — CSV with a quoted header row.

    Columns are "SHA-1","MD5","CRC32","FileName","FileSize",... Column names are
    matched case-insensitively and with punctuation stripped, because the header
    spelling has changed between RDS releases.
    """
    expected = digest_len * 2
    wanted = algorithm.replace("-", "").lower()
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            return
        normalised = [h.strip().strip('"').replace("-", "").replace("_", "").lower()
                      for h in header]
        if wanted not in normalised:
            raise KnownGoodError(
                f"{path.name} has no '{algorithm}' column. Columns present: "
                + ", ".join(header)
            )
        col = normalised.index(wanted)
        for row in reader:
            if len(row) <= col:
                continue
            token = row[col].strip().strip('"')
            if len(token) == expected and _HEX_RE.match(token):
                yield bytes.fromhex(token)


def _iter_rds_sqlite(path: Path, algorithm: str, digest_len: int) -> Iterator[bytes]:
    """NSRL RDS 3.x distributes as SQLite. Table and column names vary by release."""
    expected = digest_len * 2
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        target_col = algorithm.lower()
        for table in tables:
            cols = [r[1].lower() for r in conn.execute(f'PRAGMA table_info("{table}")')]
            match = next((c for c in cols if c.replace("-", "") == target_col), None)
            if not match:
                continue
            cursor = conn.execute(f'SELECT "{match}" FROM "{table}"')
            for (value,) in cursor:
                if not value:
                    continue
                token = str(value).strip()
                if len(token) == expected and _HEX_RE.match(token):
                    yield bytes.fromhex(token)
            return
        raise KnownGoodError(
            f"No table in {path.name} exposes a '{algorithm}' column."
        )
    finally:
        conn.close()


def iter_source_digests(
    source: str | os.PathLike[str],
    *,
    algorithm: str = "sha1",
) -> Iterator[bytes]:
    """Read digests from an NSRL RDS export in whichever format it arrived."""
    path = Path(source)
    if not path.exists():
        raise KnownGoodError(f"Known-good source not found: {path}")
    digest_len = DIGEST_LENGTHS.get(algorithm.lower())
    if digest_len is None:
        raise KnownGoodError(
            f"Unsupported algorithm '{algorithm}'. Supported: "
            + ", ".join(sorted(DIGEST_LENGTHS))
        )

    if path.is_dir():
        for child in sorted(path.iterdir()):
            if child.is_file():
                yield from iter_source_digests(child, algorithm=algorithm)
        return

    suffix = path.suffix.lower()
    if suffix in (".db", ".sqlite", ".sqlite3", ".rds"):
        yield from _iter_rds_sqlite(path, algorithm, digest_len)
    elif suffix in (".csv", ".txt"):
        # NSRLFile.txt is CSV despite the extension; fall back to plain text.
        try:
            yield from _iter_nsrl_csv(path, algorithm, digest_len)
        except KnownGoodError:
            yield from _iter_plain_text(path, digest_len)
    else:
        yield from _iter_plain_text(path, digest_len)


# ---------------------------------------------------------------------------
# Index build
# ---------------------------------------------------------------------------

@dataclass
class BuildStats:
    algorithm: str
    digest_len: int
    read: int
    unique: int
    output: str
    bytes_written: int

    def as_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "digest_length": self.digest_len,
            "digests_read": self.read,
            "digests_unique": self.unique,
            "index_path": self.output,
            "index_bytes": self.bytes_written,
        }


def build_index(
    sources: str | os.PathLike[str] | Iterable[str | os.PathLike[str]],
    destination: str | os.PathLike[str],
    *,
    algorithm: str = "sha1",
    progress_every: int = 1_000_000,
    on_progress=None,
) -> BuildStats:
    """Build a sorted binary index from one or more RDS exports.

    Digests are collected as raw bytes, de-duplicated and sorted before writing.
    For a very large RDS this peaks at roughly digest_len bytes per unique entry
    plus set overhead — around 4 GB for a 40M-entry SHA-1 set. Build it once on a
    machine with headroom; the resulting index is queried with almost no memory.
    """
    algorithm = algorithm.lower()
    digest_len = DIGEST_LENGTHS.get(algorithm)
    if digest_len is None:
        raise KnownGoodError(f"Unsupported algorithm '{algorithm}'.")

    source_list = [sources] if isinstance(sources, (str, os.PathLike)) else list(sources)

    seen: set[bytes] = set()
    read = 0
    for source in source_list:
        for digest in iter_source_digests(source, algorithm=algorithm):
            read += 1
            seen.add(digest)
            if on_progress and read % progress_every == 0:
                on_progress(read, len(seen))

    ordered = sorted(seen)
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)

    algo_bytes = algorithm.encode()
    with target.open("wb") as fh:
        fh.write(HEADER.pack(MAGIC, FORMAT_VERSION, digest_len,
                             len(algo_bytes), len(ordered)))
        fh.write(algo_bytes)
        for digest in ordered:
            fh.write(digest)
        fh.flush()
        os.fsync(fh.fileno())

    return BuildStats(
        algorithm=algorithm,
        digest_len=digest_len,
        read=read,
        unique=len(ordered),
        output=str(target),
        bytes_written=target.stat().st_size,
    )


# ---------------------------------------------------------------------------
# Index query
# ---------------------------------------------------------------------------

class _DigestView:
    """Sequence view over the memory-mapped digest block, for `bisect`."""

    __slots__ = ("_mm", "_offset", "_len", "_count")

    def __init__(self, mm: mmap.mmap, offset: int, digest_len: int, count: int) -> None:
        self._mm = mm
        self._offset = offset
        self._len = digest_len
        self._count = count

    def __len__(self) -> int:
        return self._count

    def __getitem__(self, i: int) -> bytes:
        start = self._offset + i * self._len
        return self._mm[start:start + self._len]


class KnownGoodIndex:
    """Exact membership test over a sorted, memory-mapped digest set.

    Supports `in` so it can be dropped straight into the noise policy:

        policy.known_good_index = KnownGoodIndex(path)
        if content_hash in policy.known_good_index: ...
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise KnownGoodError(f"Known-good index not found: {self.path}")

        self._fh = self.path.open("rb")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)

        magic, version, digest_len, algo_len, count = HEADER.unpack(
            self._mm[:HEADER.size])
        if magic != MAGIC:
            raise KnownGoodError(f"{self.path} is not a known-good index file.")
        if version != FORMAT_VERSION:
            raise KnownGoodError(
                f"{self.path} is format version {version}; this build expects "
                f"{FORMAT_VERSION}. Rebuild the index."
            )
        self.digest_len = digest_len
        self.count = count
        self.algorithm = self._mm[HEADER.size:HEADER.size + algo_len].decode()
        self._offset = HEADER.size + algo_len
        self._view = _DigestView(self._mm, self._offset, digest_len, count)

        expected = self._offset + count * digest_len
        actual = self._mm.size()
        if actual != expected:
            raise KnownGoodError(
                f"{self.path} is truncated: expected {expected} bytes for {count} "
                f"digests, found {actual}. Rebuild the index."
            )

    def contains_bytes(self, digest: bytes) -> bool:
        if len(digest) != self.digest_len or self.count == 0:
            return False
        i = bisect_left(self._view, digest)
        return i < self.count and self._view[i] == digest

    def contains(self, hexdigest: str) -> bool:
        if not hexdigest:
            return False
        token = hexdigest.strip().lower()
        if len(token) != self.digest_len * 2:
            return False
        try:
            return self.contains_bytes(bytes.fromhex(token))
        except ValueError:
            return False

    def __contains__(self, hexdigest: object) -> bool:
        return isinstance(hexdigest, str) and self.contains(hexdigest)

    def __len__(self) -> int:
        return self.count

    def summary(self) -> dict:
        return {
            "path": str(self.path),
            "algorithm": self.algorithm,
            "digest_count": self.count,
            "digest_length": self.digest_len,
            "index_bytes": self.path.stat().st_size,
        }

    def close(self) -> None:
        try:
            self._mm.close()
        finally:
            self._fh.close()

    def __enter__(self) -> "KnownGoodIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Loading from configuration
# ---------------------------------------------------------------------------

_CACHE: dict[str, KnownGoodIndex] = {}


def load_index(path: str | os.PathLike[str] | None) -> KnownGoodIndex | None:
    """Open (and cache) a known-good index. Returns None when not configured.

    Never raises on a misconfigured path: a missing hash set must degrade to
    "no hash-based exclusion", never to a failed extraction.
    """
    if not path:
        return None
    key = str(path)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    try:
        index = KnownGoodIndex(key)
    except KnownGoodError:
        return None
    _CACHE[key] = index
    return index


def index_from_env(var: str = "FORENSIC_KNOWN_GOOD_INDEX") -> KnownGoodIndex | None:
    return load_index(os.environ.get(var))
