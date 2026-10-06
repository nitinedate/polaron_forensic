"""OS-specific artifact scope packs.

    from app.services.os_artifact_scope import scope_pack, matches_os_scope

    matches_os_scope("etc/shadow", os_family="linux")   -> True

Dispatch is by OS family. Unknown/ambiguous families fall back to the *union* of
all packs: on an unidentified image we over-collect rather than lose evidence
(defensible-by-default). AXIOM platform names map back through `pack_for_platform`.
"""

from __future__ import annotations

from .base import ArtifactScopePack, CatalogEntry
from . import android as _android
from . import ios as _ios
from . import linux as _linux
from . import macos as _macos
from . import windows as _windows

PACKS: dict[str, ArtifactScopePack] = {
    "windows": _windows.PACK,
    "linux": _linux.PACK,
    "macos": _macos.PACK,
    "ios": _ios.PACK,
    "android": _android.PACK,
}

_ALIASES: dict[str, str] = {
    "win": "windows", "windows": "windows", "win32": "windows", "winnt": "windows",
    "windows memory": "windows", "windows phone": "windows",
    "linux": "linux", "unix": "linux", "gnu/linux": "linux", "ubuntu": "linux",
    "debian": "linux", "rhel": "linux", "centos": "linux", "chromebook": "linux",
    "chromeos": "linux",
    "macos": "macos", "mac": "macos", "osx": "macos", "mac os x": "macos", "darwin": "macos",
    "ios": "ios", "ipados": "ios", "iphone": "ios", "ipad": "ios", "apple": "ios",
    "android": "android", "aosp": "android", "kindle": "android", "fireos": "android",
}

_PLATFORM_BY_FAMILY = {f: p.axiom_platform for f, p in PACKS.items()}


def normalize_family(os_family: str | None) -> str | None:
    key = (os_family or "").strip().lower()
    return _ALIASES.get(key)


def scope_pack(os_family: str | None) -> ArtifactScopePack | None:
    fam = normalize_family(os_family)
    return PACKS.get(fam) if fam else None


def pack_for_platform(axiom_platform: str | None) -> ArtifactScopePack | None:
    return scope_pack(axiom_platform)


def matches_os_scope(path: str, *, os_family: str | None, name: str | None = None,
                     size_bytes: int = 0) -> bool:
    """True when the path is in scope for the given OS.

    Unknown family -> union of every pack (never under-collect on an unidentified image).
    """
    pack = scope_pack(os_family)
    if pack is not None:
        return pack.matches(path, name, size_bytes)
    return any(p.matches(path, name, size_bytes) for p in PACKS.values())


_STRENGTH_ORDER = {"none": 0, "broad": 1, "specific": 2}


def scope_claim_strength(path: str, *, os_family: str | None,
                         name: str | None = None) -> str:
    """Strongest claim any applicable pack makes on this path.

    'specific' -> a named artifact; must never be discarded.
    'broad'    -> inside a tree collected by default; noise rules may still apply.
    'none'     -> not claimed.
    """
    pack = scope_pack(os_family)
    packs = [pack] if pack is not None else list(PACKS.values())
    best = "none"
    for p in packs:
        strength = p.claim_strength(path, name)
        if _STRENGTH_ORDER[strength] > _STRENGTH_ORDER[best]:
            best = strength
        if best == "specific":
            break
    return best


def catalog_entry_for(path: str, *, os_family: str | None) -> CatalogEntry | None:
    pack = scope_pack(os_family)
    if pack is not None:
        return pack.catalog_for(path)
    for p in PACKS.values():
        hit = p.catalog_for(path)
        if hit:
            return hit
    return None


def scope_summary() -> list[dict]:
    return [p.summary() for p in PACKS.values()]


__all__ = [
    "PACKS",
    "ArtifactScopePack",
    "CatalogEntry",
    "catalog_entry_for",
    "matches_os_scope",
    "normalize_family",
    "pack_for_platform",
    "scope_claim_strength",
    "scope_pack",
    "scope_summary",
]
