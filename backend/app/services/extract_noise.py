"""Noise suppression — exclude files with no evidentiary value.

This module is the counterweight to the scope packs, and it is deliberately the
weakest actor in the pipeline. Over-collection wastes disk and analyst time;
under-collection loses a case. So every rule here obeys four constraints:

  1. NEVER vetoes a scope-pack hit, a special basename, or a sidecar. The
     noise filter runs LAST and only ever sees files nothing else claimed.
  2. Only excludes on a POSITIVE match against an explicit rule. There is no
     "exclude anything we don't recognise" path — unknown files are kept.
  3. Every exclusion is counted by rule, so the report can state exactly what
     was dropped and why. An examiner can defend "3.2M vendor binaries excluded
     by rule os_vendor_binary"; they cannot defend "the tool skipped some files".
  4. Every rule is individually switchable. `full` mode leaves the filter off.
     `defensible` applies only positive noise matches (vendor binaries in a
     vendor tree, caches, fonts, dependency trees) and never an unknown file.

The classic failure this guards against is renamed malware in a system tree.
That is why binary exclusion requires the file to be in a vendor-owned tree AND
carry a system binary extension AND exceed a size floor — a dropper renamed to
kernel32.dll and left in a user's Temp folder matches none of those.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any

from app.services.extract_known_good import KnownGoodIndex, index_from_env
from app.services.os_artifact_scope import scope_claim_strength

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

# Vendor-owned trees whose contents ship identically on every machine of that
# build. User content never lands here; anything that does is a red flag and is
# caught by the size/extension conditions below rather than blanket-excluded.
VENDOR_BINARY_TREES: tuple[str, ...] = (
    # Windows
    "windows/winsxs/",
    "windows/servicing/",
    "windows/system32/driverstore/filerepository/",
    "windows/assembly/",
    "windows/microsoft.net/assembly/",
    "windows/systemresources/",
    "windows/immersivecontrolpanel/",
    "program files/windowsapps/",
    "programdata/package cache/",
    # macOS
    "system/library/frameworks/",
    "system/library/privateframeworks/",
    "system/library/extensions/",
    "system/library/templates/",
    "system/applications/",
    "system/library/coreservices/",
    "library/updates/",
    # Linux
    "usr/lib/x86_64-linux-gnu/",
    "usr/lib/aarch64-linux-gnu/",
    "usr/lib/modules/",
    "usr/lib/firmware/",
    "lib/modules/",
    "lib/firmware/",
    "usr/libexec/",
    # Android / iOS
    "system/framework/",
    "system/lib/",
    "system/lib64/",
    "vendor/lib/",
    "vendor/lib64/",
    "vendor/firmware/",
    "apex/",
    "usr/lib/",
    "usr/share/",
)

SYSTEM_BINARY_EXTS: frozenset[str] = frozenset({
    ".dll", ".sys", ".ocx", ".drv", ".cpl", ".ax", ".mui", ".mun",
    ".so", ".dylib", ".ko", ".o", ".a", ".lib", ".pdb", ".ilk", ".exp",
    ".oat", ".vdex", ".art", ".odex", ".apex", ".capex",
})

# Presentation-only assets. These are re-derivable from the OS media and carry
# no case-specific content.
FONT_EXTS: frozenset[str] = frozenset({
    ".ttf", ".otf", ".ttc", ".woff", ".woff2", ".eot", ".fon", ".fnt",
    ".pfb", ".pfm", ".afm", ".bdf", ".pcf",
})

LOCALE_EXTS: frozenset[str] = frozenset({
    ".mo", ".qm", ".gmo", ".po", ".pot", ".resx", ".resources",
})

LOCALE_TREES: tuple[str, ...] = (
    "usr/share/locale/",
    "usr/share/i18n/",
    "usr/share/man/",
    "usr/share/doc/",
    "usr/share/info/",
    "usr/share/icons/",
    "usr/share/pixmaps/",
    "usr/share/help/",
    "usr/share/zoneinfo/",
    "windows/schemas/",
    "windows/help/",
    "system/library/fonts/",
    "windows/fonts/",
    "usr/share/fonts/",
    "system/fonts/",
)

# Build and dependency trees. Near-zero value per file and enormous in count.
# package manifests and lockfiles ARE kept (see DEPENDENCY_KEEP_NAMES).
DEPENDENCY_TREES: tuple[str, ...] = (
    "/node_modules/",
    "/bower_components/",
    "/vendor/bundle/",
    "/.venv/lib/",
    "/venv/lib/",
    "/site-packages/",
    "/dist-packages/",
    "/.gradle/caches/",
    "/.m2/repository/",
    "/.nuget/packages/",
    "/.cargo/registry/",
    "/go/pkg/mod/",
    "/.cache/pip/",
    "/.npm/_cacache/",
    "/target/debug/deps/",
    "/target/release/deps/",
    "/build/intermediates/",
    "/obj/debug/",
    "/obj/release/",
    "/.git/objects/pack/",
)

DEPENDENCY_KEEP_NAMES: frozenset[str] = frozenset({
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pipfile", "pipfile.lock", "poetry.lock", "setup.py",
    "gemfile", "gemfile.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "packages.config",
    "composer.json", "composer.lock", ".env",
})

BUILD_ARTIFACT_EXTS: frozenset[str] = frozenset({
    ".obj", ".pch", ".idb", ".tlog", ".lastbuildstate", ".unsuccessfulbuild",
    ".d", ".gcno", ".gcda", ".gch", ".mod", ".smod",
})

# Browser and OS caches. A folder the user named "Cache" is not enough — the
# path must be a known browser or Windows cache tree. Named browser databases
# stay even if a parent folder contains "cache".
_REGENERABLE_CACHE_MARKERS: tuple[str, ...] = (
    "/inetcache/",
    "/temporary internet files/",
    "/webcache/",
    "/d3dscache/",
    "/code cache/",
    "/gpucache/",
    "/cache2/",
    "/blob_storage/",
    "/service worker/cachestorage/",
    "/dawngraphitecache/",
    "/dawnwebgpucache/",
    "/appdata/local/pip/",
    "/appdata/local/nuget/",
    "/appdata/local/yarn/",
    "/appdata/local/pnpm/",
    "/crashdumps/",
)
_BROWSER_CACHE_HOSTS: tuple[str, ...] = (
    "/chrome/", "/edge/", "/chromium/", "/brave", "/opera/", "/vivaldi/",
    "/firefox/", "/mozilla/",
)
_CACHE_KEEP_NAMES: frozenset[str] = frozenset({
    "history", "cookies", "web data", "login data", "favicons", "top sites",
    "places.sqlite", "cookies.sqlite", "bookmarks", "bookmarks.bak",
    "webcachev01.dat", "preferences",
})


def _is_regenerable_cache(path: str, base: str) -> bool:
    if base in _CACHE_KEEP_NAMES:
        return False
    if any(marker in path for marker in _REGENERABLE_CACHE_MARKERS):
        return True
    return "/cache/" in path and any(host in path for host in _BROWSER_CACHE_HOSTS)


# Package-manager download caches. The installer is re-downloadable and carries
# no user content. A dropper saved to Downloads matches none of these paths.
PACKAGE_CACHE_TREES: tuple[str, ...] = (
    "var/cache/apt/archives/",
    "var/cache/dnf/",
    "var/cache/yum/",
    "var/cache/pacman/pkg/",
    "var/cache/zypp/",
    "windows/softwaredistribution/download/",
    "windows/system32/driverstore/temp/",
    "data/dalvik-cache/",
    "data/app-lib/",
    "library/caches/com.apple.dyld/",
    "system/library/caches/com.apple.dyld/",
    "private/var/db/dyld/",
)

# Filesystem plumbing that contains no data at all.
STRUCTURAL_NAMES: frozenset[str] = frozenset({
    ".", "..", "$badclus", "$bitmap:$smb", "lost+found",
})

STRUCTURAL_TREES: tuple[str, ...] = (
    "proc/", "sys/", "dev/pts/", "dev/block/", "dev/input/",
    "run/udev/", "run/systemd/inaccessible/",
)


@dataclass
class NoiseRule:
    rule_id: str
    description: str
    justification: str
    enabled: bool = True


NOISE_RULES: tuple[NoiseRule, ...] = (
    NoiseRule(
        "os_vendor_binary",
        "Signed OS/vendor binary in a vendor-owned tree above the size floor.",
        "Ships identically on every device of this build; carries no case-specific "
        "content. Size floor and tree restriction mean a renamed dropper in a user "
        "or temp path is never matched.",
    ),
    NoiseRule(
        "font_asset",
        "Font file outside a user document path.",
        "Presentation asset with no recoverable user content or metadata of value.",
    ),
    NoiseRule(
        "locale_help_asset",
        "Translation catalogue, man page, icon or bundled help content.",
        "Static vendor content, re-derivable from installation media.",
    ),
    NoiseRule(
        "dependency_tree",
        "Third-party dependency or build cache (node_modules, site-packages, .m2).",
        "Machine-generated dependency copies. Manifests and lockfiles ARE retained, "
        "so the dependency set remains provable without keeping every file.",
    ),
    NoiseRule(
        "build_artifact",
        "Compiler intermediate output (.obj, .gcda, .tlog).",
        "Regenerable from source; contains no user data.",
    ),
    NoiseRule(
        "package_download_cache",
        "Package-manager download cache entry.",
        "Re-downloadable vendor installer in a cache path. Installers in user "
        "download or temp paths are NOT matched.",
    ),
    NoiseRule(
        "regenerable_cache",
        "Browser or OS cache payload (disk cache, INetCache, GPU cache, package cache).",
        "Rebuilt by the application. Browser databases and extensionless files "
        "outside those cache trees are kept, including unknowns in Temp.",
    ),
    NoiseRule(
        "structural_pseudo_file",
        "Kernel pseudo-filesystem entry or filesystem plumbing.",
        "Synthetic node with no on-disk content.",
    ),
    NoiseRule(
        "known_good_hash",
        "Content hash present in a known-good reference set (NSRL/RDS).",
        "Byte-identical to a published vendor file. The strongest available "
        "evidence that a file is not case-relevant.",
    ),
    NoiseRule(
        "duplicate_content",
        "Byte-identical to a file already collected in this job.",
        "Retained once, with every path recorded, so occurrence counts and "
        "timelines are unaffected.",
    ),
)

_RULES_BY_ID = {r.rule_id: r for r in NOISE_RULES}

# A vendor binary must exceed this to be dropped. Small binaries in system trees
# are exactly where droppers and patched stubs hide.
VENDOR_BINARY_MIN_BYTES = 65_536


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

@dataclass
class NoisePolicy:
    """Which rules are active, plus the reference data they need."""

    enabled: bool = True
    disabled_rules: frozenset[str] = frozenset()
    # Small inline sets (a lab's own known-good list) stay a frozenset. A full
    # NSRL RDS is loaded as a memory-mapped index instead — see
    # app.services.extract_known_good for why a Bloom filter is not acceptable
    # here. Both are consulted; either may be empty.
    known_good_hashes: frozenset[str] = frozenset()
    known_good_index: KnownGoodIndex | None = None
    dedupe: bool = True
    vendor_binary_min_bytes: int = VENDOR_BINARY_MIN_BYTES

    def rule_active(self, rule_id: str) -> bool:
        return self.enabled and rule_id not in self.disabled_rules

    def is_known_good(self, content_hash: str | None) -> bool:
        if not content_hash:
            return False
        token = content_hash.strip().lower()
        if self.known_good_hashes and token in self.known_good_hashes:
            return True
        return bool(self.known_good_index is not None
                    and self.known_good_index.contains(token))

    @property
    def known_good_size(self) -> int:
        return len(self.known_good_hashes) + (
            len(self.known_good_index) if self.known_good_index is not None else 0)

    def with_known_good(
        self,
        index: KnownGoodIndex | None = None,
        hashes: frozenset[str] | None = None,
    ) -> "NoisePolicy":
        """Return a copy carrying the reference data. Policies are shared
        module-level defaults, so they are never mutated in place."""
        return replace(
            self,
            known_good_index=index if index is not None else self.known_good_index,
            known_good_hashes=hashes if hashes is not None else self.known_good_hashes,
        )


# Mode defaults. `defensible` is the court-safe mode and suppresses nothing but
# exact duplicates and known-good hashes — both of which are lossless.
POLICY_BY_MODE: dict[str, NoisePolicy] = {
    "full": NoisePolicy(enabled=False, dedupe=False),
    # Defensible mode suppresses the categories that are provably regenerable
    # vendor or machine-generated content, but keeps `os_vendor_binary` ACTIVE-OFF:
    # a renamed binary in a system tree is the one place where dropping by
    # extension could conceivably lose a dropper, so in the court-safe mode we
    # pay the disk cost and keep them.
    # Defensible still drops only positive noise matches. Vendor binaries in a
    # vendor tree above the size floor are identical on every machine of that
    # build; user paths, small files, and named scope artifacts stay.
    "defensible": NoisePolicy(enabled=True),
    "forensic": NoisePolicy(enabled=True),
    "fast": NoisePolicy(enabled=True),
}


def policy_for_mode(mode: str, *, known_good: KnownGoodIndex | None = None) -> NoisePolicy:
    """Policy for an extraction mode, with the known-good index attached.

    When no index is passed, FORENSIC_KNOWN_GOOD_INDEX is consulted. A missing or
    unreadable index degrades to "no hash-based exclusion" — never to a failed
    extraction.
    """
    base = POLICY_BY_MODE.get((mode or "full").strip().lower(), POLICY_BY_MODE["full"])
    index = known_good if known_good is not None else index_from_env()
    return base.with_known_good(index) if index is not None else base


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").strip("/").lower()


def _contains(path: str, trees: tuple[str, ...]) -> bool:
    padded = f"/{path}/"
    return any(path.startswith(t.strip("/")) or f"/{t.strip('/')}/" in padded for t in trees)


_USER_TREES = (
    "users/", "documents and settings/", "home/", "root/",
    "/desktop/", "/documents/", "/downloads/", "/pictures/", "/videos/",
    "/music/", "/sdcard/", "data/media/", "/dcim/", "/mobile/media/",
)


def _in_user_space(path: str) -> bool:
    return _contains(path, _USER_TREES)


@dataclass
class NoiseVerdict:
    is_noise: bool
    rule_id: str | None = None
    detail: str = ""


def classify_noise(
    path: str,
    *,
    name: str | None = None,
    size_bytes: int = 0,
    os_family: str | None = None,
    policy: NoisePolicy | None = None,
    content_hash: str | None = None,
    seen_hashes: set[str] | None = None,
) -> NoiseVerdict:
    """Decide whether a file may be dropped as zero-evidentiary-value.

    Returns is_noise=False for everything the pipeline should keep, including
    every file this module does not positively recognise as noise.
    """
    pol = policy or POLICY_BY_MODE["full"]
    if not pol.enabled:
        return NoiseVerdict(False)

    p = _norm(path)
    if not p:
        return NoiseVerdict(False)
    base = (name or PurePosixPath(p).name).lower()
    ext = PurePosixPath(base).suffix.lower()

    # --- absolute protections -------------------------------------------------
    # A *specific* scope-pack claim (named artifact, sidecar, structural regex,
    # extensionless evidence directory) is evidence by definition — nothing below
    # may discard it. A *broad* claim only means the file sits inside a tree we
    # collect by default; that does not shield a node_modules copy of lodash.
    # A profile regex (Chrome "User Data/Default/") is a specific claim for the
    # profile, not for every cache body inside it. Named artifacts are not
    # regenerable cache, so they stay protected.
    if scope_claim_strength(p, os_family=os_family, name=base) == "specific" and not _is_regenerable_cache(p, base):
        return NoiseVerdict(False, detail="protected: specific OS artifact claim")

    # Zero-byte files are NOT noise. A zero-byte file proves a name existed —
    # .icloud placeholders, tombstoned app data, wiped-but-present files.
    # They cost nothing to keep and their absence cannot be reconstructed.
    if size_bytes == 0 and _in_user_space(p):
        return NoiseVerdict(False, detail="protected: zero-byte file in user space")

    # --- lossless rules (safe in every mode) ---------------------------------
    if pol.rule_active("known_good_hash") and pol.is_known_good(content_hash):
        return NoiseVerdict(True, "known_good_hash",
                            f"hash {content_hash[:16]}… present in known-good reference set")

    if pol.dedupe and pol.rule_active("duplicate_content") and content_hash and seen_hashes is not None:
        h = content_hash.lower()
        if h in seen_hashes:
            return NoiseVerdict(True, "duplicate_content",
                                f"byte-identical to a file already collected ({h[:16]}…)")
        seen_hashes.add(h)

    # --- structural ----------------------------------------------------------
    if pol.rule_active("structural_pseudo_file"):
        if base in STRUCTURAL_NAMES or _contains(p, STRUCTURAL_TREES):
            return NoiseVerdict(True, "structural_pseudo_file",
                                "kernel pseudo-filesystem or filesystem plumbing")

    # --- vendor binaries -----------------------------------------------------
    if pol.rule_active("os_vendor_binary"):
        if (ext in SYSTEM_BINARY_EXTS
                and _contains(p, VENDOR_BINARY_TREES)
                and size_bytes >= pol.vendor_binary_min_bytes
                and not _in_user_space(p)):
            return NoiseVerdict(True, "os_vendor_binary",
                                f"{ext} in vendor tree, {size_bytes} bytes")

    # --- presentation assets -------------------------------------------------
    if pol.rule_active("font_asset") and ext in FONT_EXTS and not _in_user_space(p):
        return NoiseVerdict(True, "font_asset", f"font asset {ext}")

    if pol.rule_active("locale_help_asset"):
        if ext in LOCALE_EXTS and not _in_user_space(p):
            return NoiseVerdict(True, "locale_help_asset", f"translation catalogue {ext}")
        if _contains(p, LOCALE_TREES) and not _in_user_space(p):
            return NoiseVerdict(True, "locale_help_asset", "vendor locale/help/icon tree")

    # --- developer noise -----------------------------------------------------
    if pol.rule_active("dependency_tree") and _contains(p, DEPENDENCY_TREES):
        if base not in DEPENDENCY_KEEP_NAMES:
            return NoiseVerdict(True, "dependency_tree", "third-party dependency cache")

    if pol.rule_active("build_artifact") and ext in BUILD_ARTIFACT_EXTS:
        return NoiseVerdict(True, "build_artifact", f"compiler intermediate {ext}")

    # --- package caches ------------------------------------------------------
    if pol.rule_active("package_download_cache") and _contains(p, PACKAGE_CACHE_TREES):
        return NoiseVerdict(True, "package_download_cache", "package-manager download cache")

    if pol.rule_active("regenerable_cache") and _is_regenerable_cache(p, base):
        return NoiseVerdict(True, "regenerable_cache", "browser or OS cache payload")

    return NoiseVerdict(False)


# ---------------------------------------------------------------------------
# Accounting — what was dropped, and why
# ---------------------------------------------------------------------------

@dataclass
class NoiseLedger:
    """Per-job accounting so exclusions are reportable and defensible."""

    excluded_files: int = 0
    excluded_bytes: int = 0
    by_rule: dict[str, dict[str, int]] = field(default_factory=dict)
    samples: dict[str, list[str]] = field(default_factory=dict)
    max_samples: int = 5

    def record(self, verdict: NoiseVerdict, path: str, size_bytes: int) -> None:
        if not verdict.is_noise or not verdict.rule_id:
            return
        self.excluded_files += 1
        self.excluded_bytes += max(size_bytes, 0)
        bucket = self.by_rule.setdefault(verdict.rule_id, {"files": 0, "bytes": 0})
        bucket["files"] += 1
        bucket["bytes"] += max(size_bytes, 0)
        samples = self.samples.setdefault(verdict.rule_id, [])
        if len(samples) < self.max_samples:
            samples.append(path)

    def as_dict(self) -> dict[str, Any]:
        return {
            "excluded_files": self.excluded_files,
            "excluded_bytes": self.excluded_bytes,
            "rules": [
                {
                    "rule_id": rule_id,
                    "description": _RULES_BY_ID[rule_id].description
                    if rule_id in _RULES_BY_ID else rule_id,
                    "justification": _RULES_BY_ID[rule_id].justification
                    if rule_id in _RULES_BY_ID else "",
                    "files": stats["files"],
                    "bytes": stats["bytes"],
                    "examples": self.samples.get(rule_id, []),
                }
                for rule_id, stats in sorted(
                    self.by_rule.items(), key=lambda kv: -kv[1]["files"])
            ],
        }

    def report_paragraph(self) -> str:
        """Text for the report's methodology section."""
        if not self.excluded_files:
            return "No files were excluded by noise suppression during this extraction."
        gb = self.excluded_bytes / (1024 ** 3)
        parts = ", ".join(
            f"{stats['files']:,} by rule '{rule_id}'"
            for rule_id, stats in sorted(self.by_rule.items(), key=lambda kv: -kv[1]["files"])
        )
        return (
            f"{self.excluded_files:,} files ({gb:.2f} GB) were excluded from extraction as "
            f"having no evidentiary value: {parts}. Exclusions were applied only to files "
            "that matched an explicit published rule and that were not claimed by the "
            "operating-system artifact scope. Each rule, its justification and example "
            "paths are listed in the extraction appendix, and the exclusion set can be "
            "re-run to recover any category on request."
        )


def noise_policy_summary(policy: NoisePolicy) -> dict[str, Any]:
    return {
        "enabled": policy.enabled,
        "dedupe": policy.dedupe,
        "vendor_binary_min_bytes": policy.vendor_binary_min_bytes,
        "known_good_hash_count": policy.known_good_size,
        "known_good_index": (
            policy.known_good_index.summary() if policy.known_good_index else None),
        "rules": [
            {
                "rule_id": r.rule_id,
                "active": policy.rule_active(r.rule_id),
                "description": r.description,
                "justification": r.justification,
            }
            for r in NOISE_RULES
        ],
    }
