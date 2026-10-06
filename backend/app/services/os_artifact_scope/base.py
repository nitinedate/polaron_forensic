"""Per-OS artifact scope pack contract.

Each supported operating system owns one pack. A pack is a *declarative* description
of everything that must survive extraction filtering for that OS, expressed as:

    keep_prefixes        trees kept wholesale (evidence density is high enough)
    keep_regexes         path patterns that cannot be expressed as a prefix
    special_basenames    exact filenames that are evidence regardless of location
    basename_prefixes    filename prefixes (thumbcache_, tombstone_, MPLog-)
    basename_suffixes    filename suffixes that are not real extensions (-wal, .LOG1)
    extensions           OS-specific extensions on top of the handbook set
    extensionless_dirs   directories where an extensionless file is evidence by default
    noise_prefixes       trees reduced to "extensions / special names only"
    catalog              path -> AXIOM platform/category provenance (audit + reporting)

Design rules (court-defensibility):
  1. A pack may only ever ADD coverage. Packs never veto a match made elsewhere.
  2. Every entry carries a catalog note so the report appendix can explain *why*
     a file was collected and which AXIOM artifact family it feeds.
  3. Sidecar files (WAL/SHM/journal/transaction logs) follow their parent
     automatically — losing a WAL loses unflushed messages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# Sidecars are collected whenever the stem would be collected. Losing these is the
# single most common cause of "the message was in AXIOM but not in our output".
UNIVERSAL_SIDECAR_SUFFIXES: tuple[str, ...] = (
    "-wal", "-shm", "-journal", "-wal.bak",
    ".log1", ".log2", ".log", ".blf", ".regtrans-ms",
    ".bak", ".old", ".orig", ".tmp", ".part", ".crswap",
    "~",
)

# Stems that make a sidecar meaningful (avoid dragging in every foo.log).
SIDECAR_STEM_EXTENSIONS: frozenset[str] = frozenset({
    ".db", ".sqlite", ".sqlite3", ".sqlitedb", ".storedata", ".dat", ".hve",
    ".edb", ".mdb", ".accdb", ".plist", ".realm",
})


@dataclass(frozen=True)
class CatalogEntry:
    """Provenance record: why this path is collected and where it lands in AXIOM."""

    pattern: str
    artifact: str
    axiom_category: str
    why: str
    parser: str = "path_inventory"
    critical: bool = False


@dataclass(frozen=True)
class ArtifactScopePack:
    os_family: str
    axiom_platform: str
    keep_prefixes: tuple[str, ...] = ()
    keep_regexes: tuple[re.Pattern[str], ...] = ()
    special_basenames: frozenset[str] = frozenset()
    basename_prefixes: tuple[str, ...] = ()
    basename_suffixes: tuple[str, ...] = ()
    extensions: frozenset[str] = frozenset()
    extensionless_dirs: tuple[str, ...] = ()
    noise_prefixes: tuple[str, ...] = ()
    catalog: tuple[CatalogEntry, ...] = field(default=())

    # ---------- matching ----------

    def matches(self, path: str, name: str | None = None, size_bytes: int = 0) -> bool:
        p = _norm(path)
        if not p:
            return False
        base = (name or PurePosixPath(p).name).lower()

        # Named evidence always wins, even inside a noise tree.
        if base in self.special_basenames:
            return True
        if _is_sidecar(base):
            return True

        # Noise trees (framework binaries, shared libs, fonts, locale data) are
        # reduced to exact-name hits only. Checked before the broad rules below so
        # a generic prefix/regex cannot drag a whole OS image back in.
        in_noise = _contains_any(p, self.noise_prefixes)
        if in_noise:
            return False

        if any(base.startswith(pfx) for pfx in self.basename_prefixes):
            return True
        if any(base.endswith(sfx) for sfx in self.basename_suffixes):
            return True
        if _contains_any(p, self.keep_prefixes):
            return True
        if any(rx.search(p) for rx in self.keep_regexes):
            return True

        ext = PurePosixPath(base).suffix.lower()
        if ext and ext in self.extensions:
            return True

        # Extensionless evidence directories (scheduled tasks, FSEvents, BSM audit,
        # iOS backup hash buckets, DPAPI blobs, keystore blobs...).
        if _contains_any(p, self.extensionless_dirs):
            if not ext or _looks_opaque(base):
                return True
            if ext in self.extensions:
                return True
        return False

    def claim_strength(self, path: str, name: str | None = None) -> str:
        """How strongly does this pack claim the path? 'specific' | 'broad' | 'none'.

        A *specific* claim means this exact file is evidence: it matched a named
        artifact, a sidecar, a structural regex, or sits in an extensionless
        evidence directory. Specific claims are absolute — nothing downstream may
        discard them.

        A *broad* claim means the path merely falls inside a tree we collect by
        default (`users/`, `home/`, `var/cache/apt/`). That is a collection
        policy, not a statement that the file is evidence, so noise suppression
        is still permitted. Without this distinction a single `home/` prefix
        would shield every node_modules tree on the disk from being filtered.
        """
        p = _norm(path)
        if not p:
            return "none"
        base = (name or PurePosixPath(p).name).lower()

        if base in self.special_basenames:
            return "specific"
        if _is_sidecar(base):
            return "specific"
        if _contains_any(p, self.noise_prefixes):
            return "none"
        if any(base.startswith(pfx) for pfx in self.basename_prefixes):
            return "specific"
        if any(base.endswith(sfx) for sfx in self.basename_suffixes):
            return "specific"
        if any(rx.search(p) for rx in self.keep_regexes):
            return "specific"
        if _contains_any(p, self.extensionless_dirs):
            ext = PurePosixPath(base).suffix.lower()
            if not ext or _looks_opaque(base) or ext in self.extensions:
                return "specific"
        if _contains_any(p, self.keep_prefixes):
            return "broad"
        if PurePosixPath(base).suffix.lower() in self.extensions:
            return "broad"
        return "none"

    def catalog_for(self, path: str) -> CatalogEntry | None:
        p = _norm(path)
        for entry in self.catalog:
            if re.search(entry.pattern, p, re.I):
                return entry
        return None

    def summary(self) -> dict:
        return {
            "os_family": self.os_family,
            "axiom_platform": self.axiom_platform,
            "keep_prefixes": len(self.keep_prefixes),
            "special_basenames": len(self.special_basenames),
            "extensions": len(self.extensions),
            "extensionless_dirs": len(self.extensionless_dirs),
            "catalog_entries": len(self.catalog),
        }


# ---------- helpers ----------

_HEX_RE = re.compile(r"^[0-9a-f]{8,64}$", re.I)
_UUID_RE = re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I)
_NUMERIC_RE = re.compile(r"^[0-9._-]{4,}$")


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").strip("/").lower()


def _contains_any(path: str, prefixes: tuple[str, ...]) -> bool:
    padded = f"/{path}/"
    for prefix in prefixes:
        pfx = prefix.strip("/")
        if not pfx:
            continue
        if path.startswith(pfx) or f"/{pfx}/" in padded:
            return True
    return False


def _looks_opaque(base: str) -> bool:
    """Hash / UUID / timestamp filenames — the classic 'extensionless evidence'."""
    stem = base.split(".", 1)[0]
    return bool(_HEX_RE.match(stem) or _UUID_RE.match(base) or _NUMERIC_RE.match(base))


def _is_sidecar(base: str) -> bool:
    for sfx in UNIVERSAL_SIDECAR_SUFFIXES:
        if not base.endswith(sfx):
            continue
        stem = base[: -len(sfx)]
        if PurePosixPath(stem).suffix.lower() in SIDECAR_STEM_EXTENSIONS:
            return True
    return False
