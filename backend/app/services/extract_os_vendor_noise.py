"""OS / vendor tree exclusion for AXIOM-aligned extraction (V45).

Why
---
``defensible`` mode keeps every file under ``Windows\\`` with an extension below
512 KB plus anything <= EXTRACT_UNCERTAIN_MAX_BYTES elsewhere. On a stock
Windows 10/11 laptop that is ~150-180 k files (WinSxS, .mui, .cat, .manifest,
.pnf, .inf, driver stores, .NET assemblies) that no AXIOM artifact ever reads.
They cost hours of E01 seeks and MinIO uploads and then pollute the artifact
browser. The existing ``extract_noise`` rules are *file-level* (hash / cache /
size); this module is *tree-level* and runs BEFORE them.

Guarantee
---------
A path the OS scope pack claims **specifically** (named artifact: hives,
evtx, prefetch, amcache, srum, jump lists, lnk, $MFT/$UsnJrnl, browser data,
mail stores, WhatsApp, …) is never dropped — ``scope_claim_strength == "specific"``
short-circuits every rule. Only ``broad``/``none`` paths inside a known
regenerable vendor tree are excluded.

Enable with ``EXTRACT_OS_VENDOR_TREES=skip`` (default ``keep`` = current
behaviour). ``EXTRACT_OS_VENDOR_SMALL_KEEP_BYTES`` (default 0) optionally keeps
tiny extensionless unknowns inside vendor trees (dropper hunting) — AXIOM does
not, so the default is off.
"""

from __future__ import annotations

import os
from pathlib import PurePosixPath

# Regenerable vendor trees. Lower-case, forward slashes, no leading slash.
WINDOWS_VENDOR_TREES: tuple[str, ...] = (
    "windows/winsxs/",
    "windows/servicing/",
    "windows/systemapps/",
    "windows/systemresources/",
    "windows/system32/driverstore/",
    "windows/system32/catroot/",
    "windows/system32/catroot2/",
    "windows/system32/spool/drivers/",
    "windows/system32/wbem/",
    "windows/system32/winmetadata/",
    "windows/system32/inputmethod/",
    "windows/system32/speech/",
    "windows/system32/speech_onecore/",
    "windows/system32/migration/",
    "windows/system32/oobe/",
    "windows/system32/recovery/",
    "windows/system32/setup/",
    "windows/system32/windowspowershell/v1.0/modules/",
    "windows/syswow64/",
    "windows/microsoft.net/",
    "windows/assembly/",
    "windows/installer/",
    "windows/softwaredistribution/download/",
    "windows/softwaredistribution/datastore/",   # keep logs via scope pack if catalogued
    "windows/fonts/",
    "windows/help/",
    "windows/boot/",
    "windows/bcastdvr/",
    "windows/branding/",
    "windows/cursors/",
    "windows/diagnostics/",
    "windows/globalization/",
    "windows/immersivecontrolpanel/",
    "windows/inf/",
    "windows/l2schemas/",
    "windows/media/",
    "windows/performance/",
    "windows/policydefinitions/",
    "windows/printdialog/",
    "windows/provisioning/",
    "windows/schemas/",
    "windows/security/templates/",
    "windows/shellcomponents/",
    "windows/shellexperiences/",
    "windows/web/",
    "windows/winsxs.old/",
    "windows.old/windows/winsxs/",
    "windows.old/windows/servicing/",
    "program files/windowsapps/",
    "program files (x86)/windowsapps/",
    "program files/common files/microsoft shared/",
    "program files (x86)/common files/microsoft shared/",
    "program files/windows defender/",
    "program files (x86)/windows defender/",
    "program files/windows nt/",
    "program files/modifiablewindowsapps/",
    "program files/microsoft office/root/",
    "program files (x86)/microsoft office/root/",
    "program files/microsoft office/updates/",
    "program files/nvidia corporation/",
    "program files/intel/",
    "program files (x86)/intel/",
    "program files/amd/",
    "program files/realtek/",
    "program files/dell/",
    "program files (x86)/dell/",
    "program files/hp/",
    "program files (x86)/hp/",
    "program files/lenovo/",
    "program files (x86)/lenovo/",
    "program files/google/chrome/application/",       # binaries; profile data lives under Users
    "program files (x86)/google/chrome/application/",
    "program files/mozilla firefox/",
    "program files (x86)/mozilla firefox/",
    "program files (x86)/microsoft/edge/application/",
    "program files/microsoft/edge/application/",
    "programdata/microsoft/windows defender/definition updates/",
    "programdata/microsoft/windows defender/platform/",
    "programdata/package cache/",
    "programdata/microsoft/windows/wer/temp/",
    "programdata/nvidia corporation/",
    "programdata/intel/",
    "programdata/usoshared/",
    "programdata/microsoft/windows/appxprovisioning/",
    "$windows.~bt/",
    "$windows.~ws/",
    "$getcurrent/",
    "$sysreset/",
    "recovery/windowsre/",
    "system volume information/",   # VSS raw blocks — carving, not file extraction
    "perflogs/",
)

# Per-user regenerable application payloads (not the user's data).
USER_VENDOR_TREES: tuple[str, ...] = (
    "/appdata/local/microsoft/windowsapps/",
    "/appdata/local/microsoft/onedrive/",            # binaries; synced docs are under Users\<u>\OneDrive
    "/appdata/local/microsoft/teams/current/",
    "/appdata/local/microsoft/teams/previous/",
    "/appdata/local/microsoft/teams/stage/",
    "/appdata/local/packages/",                       # UWP state — keep only via scope pack (specific claims)
    "/appdata/local/programs/",                       # installed app binaries
    "/appdata/local/squirreltemp/",
    "/appdata/local/microsoft/edge/user data/default/service worker/cachestorage/",
    "/appdata/local/google/chrome/user data/default/service worker/cachestorage/",
    "/appdata/local/nvidia/",
    "/appdata/local/d3dscache/",
    "/appdata/local/microsoft/windows/inetcache/ie/",  # browser cache bodies (history/db still catalogued)
    "/appdata/locallow/microsoft/cryptneturlcache/",
    "/.cache/",
    "/node_modules/",
    "/.gradle/caches/",
    "/.nuget/packages/",
    "/appdata/local/pip/cache/",
    "/appdata/local/jetbrains/",
    "/appdata/roaming/npm-cache/",
)

LINUX_MAC_VENDOR_TREES: tuple[str, ...] = (
    "usr/lib/", "usr/lib64/", "usr/share/", "usr/libexec/", "usr/src/", "usr/include/",
    "lib/modules/", "lib/firmware/", "var/cache/apt/", "var/lib/apt/lists/", "var/lib/dpkg/info/",
    "snap/", "var/lib/snapd/", "var/lib/flatpak/", "opt/google/chrome/", "boot/",
    "system/library/", "library/apple/", "library/developer/", "usr/standalone/",
    "library/updates/", "system/applications/", "applications/",
    "private/var/db/dyld/", "private/var/folders/",
)

# Extensions that never carry user evidence when found inside the trees above.
VENDOR_BINARY_EXT: frozenset[str] = frozenset({
    ".dll", ".sys", ".mui", ".cat", ".manifest", ".pnf", ".inf", ".exe", ".ocx", ".cpl", ".drv",
    ".tlb", ".nls", ".fon", ".ttf", ".ttc", ".otf", ".mun", ".pri", ".winmd", ".dat", ".xml", ".json",
    ".png", ".jpg", ".gif", ".svg", ".ico", ".cur", ".ani", ".wav", ".mp3", ".mp4", ".msi", ".msp",
    ".msu", ".cab", ".esd", ".wim", ".so", ".a", ".o", ".dylib", ".h", ".py", ".pyc", ".js", ".css",
    ".map", ".pak", ".bin", ".nupkg", ".jar", ".class", ".ps1", ".psd1", ".psm1", ".chm", ".hlp",
    ".lic", ".txt", ".rtf", ".htm", ".html",
})


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").lstrip("/").lower()


def os_vendor_mode() -> str:
    mode = (os.environ.get("EXTRACT_OS_VENDOR_TREES") or "keep").strip().lower()
    return mode if mode in {"keep", "skip"} else "keep"


def _small_keep_bytes() -> int:
    try:
        return max(0, int(os.environ.get("EXTRACT_OS_VENDOR_SMALL_KEEP_BYTES") or 0))
    except ValueError:
        return 0


def classify_os_vendor(path: str, *, size_bytes: int = 0, os_family: str | None = None) -> str | None:
    """Return a rule id when ``path`` is inside a regenerable vendor tree, else None.

    Never returns a rule for a path the OS scope pack claims *specifically*.
    """
    p = _norm(path)
    if not p:
        return None
    try:
        from app.services.os_artifact_scope import scope_claim_strength

        if scope_claim_strength(p, os_family=os_family) == "specific":
            return None
    except Exception:
        # If the scope pack is unavailable, be conservative: never drop.
        return None

    base = PurePosixPath(p).name
    ext = PurePosixPath(base).suffix.lower()
    small_keep = _small_keep_bytes()

    fam = (os_family or "unknown").lower()
    trees: tuple[str, ...] = ()
    if fam in ("windows", "unknown"):
        trees += WINDOWS_VENDOR_TREES
    if fam in ("linux", "macos", "unknown"):
        trees += LINUX_MAC_VENDOR_TREES

    for tree in trees:
        if p.startswith(tree) or ("/" + tree) in ("/" + p):
            if not ext and small_keep and size_bytes <= small_keep:
                return None  # extensionless unknown kept for dropper hunting
            return f"os_vendor_tree:{tree.rstrip('/').rsplit('/', 1)[-1]}"

    padded = "/" + p
    for tree in USER_VENDOR_TREES:
        if tree in padded:
            if ext in VENDOR_BINARY_EXT or not ext:
                return f"user_vendor_tree:{tree.strip('/').rsplit('/', 1)[-1]}"
            return None
    return None


def should_skip_os_vendor(path: str, *, size_bytes: int = 0, os_family: str | None = None) -> tuple[bool, str | None]:
    if os_vendor_mode() != "skip":
        return False, None
    rule = classify_os_vendor(path, size_bytes=size_bytes, os_family=os_family)
    return (True, rule) if rule else (False, None)
