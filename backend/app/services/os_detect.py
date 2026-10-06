"""Detect guest OS family from enumerated disk paths (pre-extract)."""

from __future__ import annotations

from typing import Any


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/").lower()


def detect_os_from_paths(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """Return {family, confidence, scores, signals} from enumerated file paths.

    Runs before extraction filtering so Windows/Linux/macOS policy can be applied.
    """
    scores = {"windows": 0, "linux": 0, "macos": 0, "android": 0, "ios": 0}
    hits: dict[str, list[str]] = {"windows": [], "linux": [], "macos": [], "android": [], "ios": []}

    def _hit(family: str, label: str, pts: int) -> None:
        scores[family] += pts
        if label not in hits[family] and len(hits[family]) < 16:
            hits[family].append(label)

    for n in nodes:
        path = _norm(n.get("path") or "")
        if not path:
            continue

        # --- Windows ---
        if path.startswith("windows/system32/config/"):
            name = path.rsplit("/", 1)[-1]
            if name in {"software", "system", "sam", "security", "software.LOG1", "system.LOG1"}:
                _hit("windows", f"hive:{name}", 15)
            else:
                _hit("windows", "windows/system32/config/", 2)
        elif path.startswith("windows/system32/winevt/logs/"):
            _hit("windows", "winevt", 3)
        elif path.startswith("windows/winsxs/"):
            _hit("windows", "winsxs", 1)
        elif path.startswith("program files/windowsapps/") or path.startswith(
            "program files (x86)/windowsapps/"
        ):
            _hit("windows", "windowsapps", 4)
        elif path.startswith("windows/syswow64/") or path.startswith("windows/system32/"):
            _hit("windows", "system32", 1)
        elif path.startswith("programdata/microsoft/"):
            _hit("windows", "programdata", 1)
        elif path.startswith("users/") and "/appdata/" in path:
            _hit("windows", "users/appdata", 2)
        elif path in {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr"}:
            _hit("windows", path, 5)
        elif path.startswith("$recycle.bin/"):
            _hit("windows", "$recycle.bin", 1)

        # --- Linux ---
        if path in {"etc/passwd", "etc/shadow", "etc/os-release", "etc/issue"}:
            _hit("linux", path, 15)
        elif path.startswith("etc/systemd/") or path.startswith("usr/lib/systemd/"):
            _hit("linux", "systemd", 3)
        elif path.startswith("var/log/"):
            _hit("linux", "var/log", 1)
        elif path.startswith("boot/vmlinuz") or path.startswith("boot/initrd"):
            _hit("linux", "boot/kernel", 8)
        elif path.startswith("home/") and "/" in path[5:]:
            _hit("linux", "home", 1)

        # --- macOS ---
        if path.startswith("system/library/coreservices/"):
            _hit("macos", "coreservices", 12)
        elif path.startswith("system/library/"):
            _hit("macos", "system/library", 3)
        elif path.startswith("library/preferences/"):
            _hit("macos", "library/preferences", 4)
        elif path.startswith("private/var/"):
            _hit("macos", "private/var", 2)
        elif path.startswith("applications/") and path.endswith(".app/contents/info.plist"):
            _hit("macos", "app/info.plist", 6)

        # --- Android (mobile device dumps / UFED-style archives) ---
        if "/data/data/" in path or path.startswith("data/data/"):
            _hit("android", "data/data", 8)
        elif "/android/data/" in path or path.startswith("android/data/"):
            _hit("android", "android/data", 6)
        elif "/com.android." in path or "/com.google.android." in path:
            _hit("android", "android package", 4)
        elif path.endswith(".db") and any(
            seg in path for seg in ("/databases/", "/app_", "/whatsapp/", "/telegram/", "/signal/")
        ):
            _hit("android", "app database", 5)
        elif "/dump/" in path and any(seg in path for seg in ("apex", "acct", "anr", "tombstones")):
            _hit("android", "android dump", 6)
        elif any(seg in path for seg in ("installedappslist", ".ufd", ".ufdx", ".pas")):
            _hit("android", "mobile segment", 3)

        # --- iOS ---
        if path.endswith(".sqlite") and any(seg in path for seg in ("/mobile/", "/itunes_control/", "/wireless sync/")):
            _hit("ios", "ios sqlite", 6)
        elif path.endswith("manifest.plist") or path.endswith("info.plist"):
            if "backup" in path or "itunes" in path:
                _hit("ios", "ios backup", 8)

    mobile_scores = {k: scores[k] for k in ("android", "ios")}
    desktop_scores = {k: scores[k] for k in ("windows", "linux", "macos")}
    if max(mobile_scores.values(), default=0) >= 6:
        family = max(mobile_scores, key=lambda k: mobile_scores[k])
        best = mobile_scores[family]
        ranked = sorted(mobile_scores.values(), reverse=True)
        second = ranked[1] if len(ranked) > 1 else 0
        if best >= 10 and best >= max(second * 2, 1):
            confidence = "high"
        elif best >= 6:
            confidence = "medium"
        else:
            confidence = "low"
        return {
            "family": family,
            "confidence": confidence,
            "scores": scores,
            "signals": hits.get(family, []),
            "method": "path_heuristics",
        }

    family = max(desktop_scores, key=lambda k: desktop_scores[k])
    best = desktop_scores[family]
    ranked = sorted(desktop_scores.values(), reverse=True)
    second = ranked[1] if len(ranked) > 1 else 0

    if best <= 0:
        family, confidence = "unknown", "none"
    elif best >= 25 and best >= max(second * 2, 1):
        confidence = "high"
    elif best >= 10:
        confidence = "medium"
    else:
        confidence = "low"
        if best < 6:
            family = "unknown"

    return {
        "family": family,
        "confidence": confidence,
        "scores": scores,
        "signals": hits.get(family, []) if family != "unknown" else hits,
        "method": "path_heuristics",
    }
