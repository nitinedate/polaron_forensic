"""Browse and register disk evidence on the examiner host — no byte upload."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import stat as stat_mod
import string
import sys
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

log = logging.getLogger("host_evidence")

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.disk import SEGMENT_RE, segment_readiness, segment_key
from app.services.disk_build_log import write_disk_log, write_disk_logs_batch
from app.services.mobile_segments import (
    folder_has_mobile_segments,
    folder_is_live_mobile_collection,
    is_mobile_segment_filename,
    list_payload_zip_archives,
    live_mobile_collection_segments,
    mobile_package_has_payload,
    mobile_segments_in_folder,
)

# Host-disk images only — mobile packages (.pas/.ufd/.zip) use is_mobile_segment_filename.
DISK_EXT_RE = re.compile(
    r"\.(?:E\d{2}|e\d{2}|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx)$",
    re.I,
)
IOS_BACKUP_MARKERS = {"manifest.plist", "info.plist", "status.plist"}
ANDROID_BACKUP_EXT = {".ab", ".adb"}
WINDOWS_DRIVE_PATH_RE = re.compile(r"^([A-Za-z]):[/\\]?(.*)$", re.IGNORECASE)
_PLACEHOLDER_PATHS = {
    r"d:\path\to\your\e01-folder",
    r"d:\evidence\casename\segments",
    r"choose a folder — the path appears here",
    r"choose a folder - the path appears here",
}


def is_placeholder_evidence_path(raw: str) -> bool:
    """True for UI example paths — never treat these as a real D: (or any) drive."""
    n = (raw or "").strip().replace("/", "\\").lower().rstrip("\\")
    if not n:
        return False
    if n in _PLACEHOLDER_PATHS:
        return True
    if "..." in (raw or "") or "…" in (raw or ""):
        return True
    if "path\\to\\your" in n or "\\casename\\" in n:
        return True
    return False

_BUILTIN_CONTAINER_MAPPINGS: list[tuple[str, str]] = [
    ("/Volumes/", "/host/volumes/"),
    ("/Users/", "/host/users/"),
    ("/home/", "/host/home/"),
    ("/mnt/", "/host/mnt/"),
    ("/media/", "/host/media/"),
]


def _settings():
    return get_settings()


def _is_windows() -> bool:
    return os.name == "nt"


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _running_in_container() -> bool:
    return Path("/.dockerenv").exists()


def _host_mount_prefix() -> Path:
    return Path(os.environ.get("HOST_MOUNT_PREFIX", "/host"))


def _safe_is_dir(path: Path) -> bool:
    """is_dir() that treats a dead virtiofs/9p mount (ENODEV) as missing."""
    try:
        return path.is_dir()
    except OSError:
        return False


def _safe_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def _is_host_drive_letter_mount(path: Path) -> bool:
    """True when *path* is /host/<letter> (a Windows drive bind), not a subfolder."""
    prefix = _host_mount_prefix()
    try:
        rel = path.resolve().relative_to(prefix.resolve())
    except (OSError, ValueError):
        try:
            rel = Path(os.path.normpath(str(path))).relative_to(Path(os.path.normpath(str(prefix))))
        except ValueError:
            return False
    parts = rel.parts
    return len(parts) == 1 and len(parts[0]) == 1 and parts[0].isalpha()


def _is_stale_host_mount(path: Path) -> bool:
    """True when the mount point exists in the namespace but the device is gone.

    Docker Desktop also leaves an empty directory at /host/<letter> for a newly
    attached removable drive. That stub is not a usable Windows volume.
    """
    try:
        path.stat()
    except OSError as exc:
        return int(getattr(exc, "errno", 0) or 0) == 19
    try:
        if path.is_dir():
            first = next(path.iterdir(), None)
            if first is None and _is_host_drive_letter_mount(path):
                return True
        return False
    except OSError as exc:
        return int(getattr(exc, "errno", 0) or 0) == 19


def _looks_like_windows_drive_path(raw: str) -> bool:
    return bool(WINDOWS_DRIVE_PATH_RE.match(raw.strip()))


def _normalize_slashes(raw: str) -> str:
    return raw.strip().replace("\\", "/")


def _windows_drive_container_bases(letter: str) -> list[Path]:
    """Places a Windows drive letter may appear — no mount catalog required."""
    letter = (letter or "").strip().lower()
    if len(letter) != 1 or not letter.isalpha():
        return []
    seen: set[str] = set()
    out: list[Path] = []
    for base in (
        _host_mount_prefix() / letter,
        Path("/run/desktop/mnt/host") / letter,
        Path("/mnt/host") / letter,
        Path("/host_mnt") / letter,
        Path("/mnt") / letter,
    ):
        key = str(base).replace("\\", "/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(base)
    return out


def _translate_windows_path(raw: str) -> Path:
    stripped = raw.strip()
    match = WINDOWS_DRIVE_PATH_RE.match(stripped)
    if not match:
        return Path(_normalize_slashes(stripped))
    letter = match.group(1).lower()
    rest = match.group(2).replace("\\", "/").strip("/")
    bases = _windows_drive_container_bases(letter)
    base = bases[0] if bases else _host_mount_prefix() / letter
    if rest:
        return base / rest.replace("/", os.sep)
    return base


def _auto_detect_container_mappings() -> list[tuple[str, str]]:
    mappings: list[tuple[str, str]] = []
    prefix = _host_mount_prefix()
    if not _safe_is_dir(prefix):
        return mappings
    mount_names = {
        "home": "/home/",
        "mnt": "/mnt/",
        "media": "/media/",
        "volumes": "/Volumes/",
        "users": "/Users/",
    }
    for name, host_prefix in mount_names.items():
        mount = prefix / name
        if _safe_is_dir(mount) and not _is_stale_host_mount(mount):
            container_prefix = str(mount).replace("\\", "/").rstrip("/") + "/"
            mappings.append((host_prefix, container_prefix))
    for letter in string.ascii_lowercase:
        mount = prefix / letter
        if _safe_is_dir(mount) and not _is_stale_host_mount(mount):
            container_prefix = str(mount).replace("\\", "/").rstrip("/") + "/"
            upper = letter.upper()
            mappings.append((f"{upper}:\\", container_prefix))
            mappings.append((f"{upper}:/", container_prefix))
    return mappings


def _active_path_mappings() -> list[tuple[str, str]]:
    settings = _settings()
    combined: dict[str, str] = {}
    for host_prefix, container_prefix in (
        _BUILTIN_CONTAINER_MAPPINGS + _auto_detect_container_mappings() + list(settings.host_path_mappings_dict.items())
    ):
        combined[host_prefix.replace("\\", "/")] = container_prefix.replace("\\", "/")
    return sorted(combined.items(), key=lambda item: len(item[0]), reverse=True)


def _apply_path_mapping(raw: str, host_prefix: str, container_prefix: str) -> Path | None:
    norm = _normalize_slashes(raw)
    hp = host_prefix.replace("\\", "/")
    if hp.endswith(":"):
        hp = hp + "/"
    if not hp.endswith("/"):
        hp = hp + "/"
    if hp[1:2] == ":":
        if not norm.upper().startswith(hp.upper()):
            return None
        rest = norm[len(hp.rstrip("/")) :].lstrip("/")
    elif not norm.startswith(hp):
        return None
    else:
        rest = norm[len(hp) :].lstrip("/")
    base = container_prefix.replace("\\", "/").rstrip("/")
    return Path(base) / rest.replace("/", os.sep) if rest else Path(base)


def _path_candidates(raw: str) -> list[Path]:
    stripped = raw.strip()
    candidates: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        key = str(path)
        if key not in seen:
            seen.add(key)
            candidates.append(path)

    add(Path(_normalize_slashes(stripped)))
    match = WINDOWS_DRIVE_PATH_RE.match(stripped)
    if match:
        letter = match.group(1).lower()
        rest = match.group(2).replace("\\", "/").strip("/")
        for base in _windows_drive_container_bases(letter):
            add(base / rest.replace("/", os.sep) if rest else base)
        if not _running_in_container():
            win = Path(f"{letter.upper()}:\\")
            add(win / rest.replace("/", "\\") if rest else win)
    if _running_in_container():
        for host_prefix, container_prefix in _active_path_mappings():
            mapped = _apply_path_mapping(stripped, host_prefix, container_prefix)
            if mapped is not None:
                add(mapped)
    return candidates


def _resolve_raw_path(raw: str, *, strict: bool = False) -> Path:
    """Resolve a workstation path to a container/host Path.

    Exact match first, then per-segment near-miss matching (any folder names).
    When *strict* is True, whole-drive discovery is skipped — segment walk is still
    allowed so Register works for any pasted path with minor spelling differences.
    """
    stripped = raw.strip()
    probes = list(
        dict.fromkeys(
            [_trim_incomplete_path_tail(_normalize_slashes(v)) for v in _path_typo_variants(stripped)]
            + [stripped]
        )
    )
    if not _running_in_container():
        for probe in probes:
            try:
                resolved = _normalize_path(probe)
                if resolved.exists():
                    return resolved
            except OSError:
                continue
            hit = _resolve_existing_host_path(probe, strict=strict)
            if hit:
                return hit
            try:
                walked = _resolve_by_segment_walk(_normalize_path(probe))
                if walked is not None:
                    return walked
            except OSError:
                continue
        if not strict:
            discovered = _discover_segment_folder_from_hint(stripped)
            if discovered:
                return discovered
        return _normalize_path(stripped)

    for probe in probes:
        for candidate in _path_candidates(probe):
            try:
                if candidate.exists():
                    return candidate.resolve()
            except OSError:
                continue
    for probe in probes:
        hit = _resolve_existing_host_path(probe, strict=strict)
        if hit:
            return hit
    # Segment-by-segment fuzzy match for any evidence path (strict + non-strict).
    for probe in probes:
        for candidate in _path_candidates(probe):
            walked = _resolve_by_segment_walk(candidate)
            if walked is not None:
                return walked
    if not strict:
        discovered = _discover_segment_folder_from_hint(stripped)
        if discovered:
            return discovered
    candidates = _path_candidates(stripped)
    return candidates[0] if candidates else Path(_normalize_slashes(stripped))


def _normalize_path(raw: str) -> Path:
    p = raw.strip().replace("/", "\\") if _is_windows() else raw.strip().replace("\\", "/")
    return Path(p).resolve()


def container_to_workstation_path(container_path: Path) -> str:
    s = str(container_path.resolve()).replace("\\", "/")
    for host_prefix, container_prefix in _active_path_mappings():
        cp = container_prefix.replace("\\", "/").rstrip("/")
        if s == cp:
            hp = host_prefix.replace("\\", "/").rstrip("/")
            if len(hp) == 2 and hp[1] == ":":
                return f"{hp}\\"
            return hp
        if s.startswith(cp + "/"):
            rest = s[len(cp) + 1 :]
            hp = host_prefix.replace("\\", "/").rstrip("/")
            if len(hp) == 2 and hp[1] == ":":
                return f"{hp}\\{rest.replace('/', chr(92))}" if rest else f"{hp}\\"
            sep = "" if hp.endswith("/") else "/"
            return f"{hp}{sep}{rest}" if rest else hp.rstrip("/")
    if _is_windows() and not _running_in_container():
        return str(container_path).replace("/", "\\")
    return str(container_path)


def is_client_upload_pending(ds: dict | None) -> bool:
    """Return True until a browser/client upload is fully received and verified.

    The status flag alone is not trusted: an interrupted request or stale UI must
    never let extraction/RAG/report work start while the declared segment set is
    incomplete.  Server-local/network/removable sources never enter this gate.
    """
    if not isinstance(ds, dict):
        return False
    if str(ds.get("intake") or "") != "browser_upload":
        return False

    status = str(ds.get("upload_status") or "").strip().lower()
    try:
        expected = max(0, int(ds.get("upload_expected_files") or 0))
    except (TypeError, ValueError):
        expected = 0
    try:
        received = max(0, int(ds.get("upload_received_files") or 0))
    except (TypeError, ValueError):
        received = 0

    # receiving/verifying/failed/unknown are all fail-closed.  Only an explicit
    # complete state may release the pipeline, and when an expected count is
    # known the received count must satisfy it as an additional invariant.
    if status != "complete":
        return True
    if expected > 0 and received < expected:
        return True
    return False


def resolve_staged_upload_raw(raw: str | None) -> Path | None:
    """Map a Windows/host dump path back to the container DATA_ROOT/uploads tree."""
    text = (raw or "").strip()
    if not text:
        return None
    from app.services.client_intake import is_staged_upload_path, upload_root

    try:
        direct = Path(text)
        if direct.exists() and is_staged_upload_path(direct):
            return direct.resolve()
    except Exception:
        pass
    norm = text.replace("\\", "/")
    low = norm.lower()
    rest = ""
    for marker in ("/data/uploads/", "/uploads/"):
        idx = low.find(marker)
        if idx >= 0:
            rest = norm[idx + len(marker) :]
            break
    if not rest:
        return None
    cand = (upload_root() / rest).resolve()
    try:
        if cand.exists() and is_staged_upload_path(cand):
            return cand
    except Exception:
        return None
    return None


def _listing_display_path(folder: Path) -> str:
    try:
        from app.services.client_intake import is_staged_upload_path

        if is_staged_upload_path(folder):
            return str(folder.resolve())
    except Exception:
        pass
    mapped = resolve_staged_upload_raw(str(folder))
    if mapped is not None:
        return str(mapped)
    return container_to_workstation_path(folder)


def _segment_info(name: str) -> dict | None:
    sk = segment_key(name)
    if not sk:
        if DISK_EXT_RE.search(name) or is_mobile_segment_filename(name):
            return {"base": Path(name).stem, "part": 1, "ext": Path(name).suffix.lower(), "key": name, "single": True}
        return None
    key, part, fmt = sk
    base = key.rsplit(".", 1)[0] if fmt == "ewf" else key.replace(f".{fmt}", "")
    return {"base": base, "part": part, "ext": f".{fmt}" if fmt != "ewf" else ".ewf", "key": key}


def _segment_filenames_only(filenames: list[str]) -> list[str]:
    return [n for n in dict.fromkeys(filenames) if n and _segment_info(n)]


def _folder_contains_segment_names(folder: Path, names: list[str]) -> bool:
    if not names:
        return False
    try:
        return all((folder / name).is_file() for name in names)
    except OSError:
        return False


def _relative_folder_hint(relative_paths: list[str] | None) -> str | None:
    if not relative_paths:
        return None
    dir_paths: list[str] = []
    for rel in relative_paths:
        parts = [p for p in rel.replace("\\", "/").split("/") if p]
        if len(parts) <= 1:
            dir_paths.append("")
        else:
            dir_paths.append("/".join(parts[:-1]))
    if dir_paths and all(d == dir_paths[0] for d in dir_paths):
        return dir_paths[0] or None
    common: list[str] = []
    split_dirs = [d.split("/") if d else [] for d in dir_paths]
    if not split_dirs:
        return None
    min_len = min(len(parts) for parts in split_dirs)
    for i in range(min_len):
        part = split_dirs[0][i]
        if all(parts[i] == part for parts in split_dirs):
            common.append(part)
        else:
            break
    return "/".join(common) if common else None


def _hint_path_candidates(root: Path, hint: str) -> list[Path]:
    clean = hint.strip().replace("/", os.sep).strip("\\")
    if not clean:
        return [root]
    parts = [p for p in clean.split(os.sep) if p]
    candidates: list[Path] = [root / clean]
    for i in range(len(parts)):
        candidates.append(root / os.sep.join(parts[i:]))
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def _find_folder_by_segment_anchors(
    root: Path,
    names: list[str],
    anchors: list[str],
    *,
    max_depth: int = 12,
) -> Path | None:
    if not anchors:
        return None
    stack: list[tuple[Path, int]] = [(root, 0)]
    anchor_set = set(anchors)
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_file(follow_symlinks=False) and entry.name in anchor_set:
                            folder = Path(entry.path).parent
                            if _folder_contains_segment_names(folder, names):
                                return folder
                        elif entry.is_dir(follow_symlinks=False) and depth < max_depth:
                            stack.append((Path(entry.path), depth + 1))
                    except OSError:
                        continue
        except OSError:
            continue
    return None


def _path_typo_variants(raw: str) -> list[str]:
    """Optional bidirectional spelling pairs — primary resolution is segment fuzzy match."""
    replacements = [
        ("Forensics_Data", "Fotrensics_Data"),
        ("Fotrensics_Data", "Forensics_Data"),
        ("DataExtraction", "DataExtration"),
        ("DataExtration", "DataExtraction"),
        ("\\alf\\", "\\all\\"),
        ("\\all\\", "\\alf\\"),
        ("/alf/", "/all/"),
        ("/all/", "/alf/"),
    ]
    variants = [raw]
    seen = {raw}
    queue = [raw]
    while queue:
        current = queue.pop(0)
        for src, dst in replacements:
            if src in current:
                fixed = current.replace(src, dst)
                if fixed not in seen:
                    seen.add(fixed)
                    variants.append(fixed)
                    queue.append(fixed)
            # case-insensitive swap for mixed-case pastes
            idx = current.lower().find(src.lower())
            if idx >= 0:
                fixed = current[:idx] + dst + current[idx + len(src) :]
                if fixed not in seen:
                    seen.add(fixed)
                    variants.append(fixed)
                    queue.append(fixed)
    return variants


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _segment_name_score(actual: str, wanted: str) -> float:
    """0..1 similarity for one path segment (case-insensitive, near-miss tolerant)."""
    a = actual.strip().lower()
    w = wanted.strip().lower()
    if not a or not w:
        return 0.0
    if a == w:
        return 1.0
    if a.startswith(w) or w.startswith(a):
        return 0.92
    if w in a or a in w:
        return 0.88
    dist = _edit_distance(a, w)
    denom = max(len(a), len(w))
    return max(0.0, 1.0 - (dist / denom))


def _best_dir_child(parent: Path, wanted: str, *, min_score: float = 0.82) -> Path | None:
    """Pick the best matching child directory for a wanted segment name."""
    best: Path | None = None
    best_score = 0.0
    try:
        with os.scandir(parent) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                score = _segment_name_score(entry.name, wanted)
                if score > best_score:
                    best_score = score
                    best = Path(entry.path)
    except OSError:
        return None
    if best is not None and best_score >= min_score:
        return best
    return None


def _resolve_by_segment_walk(candidate: Path) -> Path | None:
    """Resolve a missing path by walking each segment with case/near-miss matching.

    Works for *any* evidence folder — not tied to a specific case name — so pastes like
    ``D:\\all\\Forensics_Data\\...\\DataExtraction\\CaseX`` still land on the real dirs.
    """
    try:
        parts = list(candidate.parts)
    except Exception:
        return None
    if not parts:
        return None

    # Build from root: on POSIX '/host/d/...' parts[0] is '/'; on Windows 'D:\\' etc.
    if candidate.is_absolute() and parts[0] == "/":
        cursor = Path("/")
        start = 1
    else:
        cursor = Path(parts[0])
        start = 1
        try:
            if not cursor.exists():
                return None
        except OSError:
            return None

    for part in parts[start:]:
        try:
            nxt = cursor / part
            if nxt.exists():
                cursor = nxt
                continue
        except OSError:
            pass
        matched = _best_dir_child(cursor, part)
        if matched is None:
            # Last segment may be a file name (segment) rather than a folder.
            try:
                with os.scandir(cursor) as it:
                    best_file: Path | None = None
                    best_score = 0.0
                    for entry in it:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        score = _segment_name_score(entry.name, part)
                        if score > best_score:
                            best_score = score
                            best_file = Path(entry.path)
                    if best_file is not None and best_score >= 0.9:
                        return best_file.resolve()
            except OSError:
                pass
            return None
        cursor = matched
    try:
        return cursor.resolve() if cursor.exists() else None
    except OSError:
        return None


def _trim_incomplete_path_tail(norm: str) -> str:
    """Drop a trailing single-letter folder segment (e.g. .../DISK2/D)."""
    parts = [p for p in norm.replace("\\", "/").split("/") if p]
    if len(parts) >= 2 and len(parts[-1]) == 1 and parts[-1].isalpha():
        return "/".join(parts[:-1])
    return norm


def _longest_existing_prefix(candidate: Path) -> Path | None:
    probe = candidate
    last_existing: Path | None = None
    for _ in range(24):
        try:
            if probe.is_dir():
                last_existing = probe.resolve()
        except OSError:
            pass
        parent = probe.parent
        if parent == probe:
            break
        probe = parent
    return last_existing


def _is_container_drive_root(path: Path) -> bool:
    if not _running_in_container():
        return len(path.parts) <= 1
    return bool(re.match(r"^/host/[a-z]$", str(path).replace("\\", "/"), re.I))


def _descend_hint_path(root: Path, hint_norm: str) -> Path:
    parts = [p for p in hint_norm.replace("\\", "/").split("/") if p]
    if parts and len(parts[0]) == 2 and parts[0][1] == ":":
        parts = parts[1:]
    current = root
    for part in parts:
        child = current / part
        try:
            if child.is_dir():
                current = child
        except OSError:
            break
    return current


def _segment_set_score(folder: Path) -> tuple[int, int]:
    """Return (largest multi-part set size, ewf-style segment count) for ranking folders."""
    names = _folder_segments(folder)
    if not names:
        return (0, 0)
    sets: dict[str, int] = {}
    ewf_count = 0
    for name in names:
        info = _segment_info(name)
        if not info or info.get("single"):
            continue
        key = info["key"]
        sets[key] = sets.get(key, 0) + 1
        ext = str(info.get("ext") or "").lower()
        if ext.startswith(".e") or ext == ".ewf":
            ewf_count += 1
    max_set = max(sets.values()) if sets else 0
    return (max_set, ewf_count)


def _find_segment_folder_under(root: Path, *, max_depth: int = 8) -> Path | None:
    best: Path | None = None
    best_score = (0, 0)
    queue: list[tuple[Path, int]] = [(root, 0)]
    head = 0
    while head < len(queue):
        current, depth = queue[head]
        head += 1
        if depth > max_depth:
            continue
        try:
            score = _segment_set_score(current)
            if score > best_score:
                best = current
                best_score = score
                if score[0] >= 2 and score[1] >= 2:
                    return current.resolve()
        except OSError:
            pass
        if depth >= max_depth:
            continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        queue.append((Path(entry.path), depth + 1))
        except OSError:
            continue
    return best.resolve() if best is not None and best_score[0] >= 2 else None


def _resolve_child_segment_folder(parent: Path, hint: str = "") -> Path | None:
    """Resolve a segment folder under parent, optionally matching a partial folder name."""
    if not parent.is_dir():
        return None
    hint_l = hint.strip().lower()
    ranked: list[tuple[tuple[int, int], Path]] = []
    only_segment_child: Path | None = None
    segment_child_count = 0
    try:
        with os.scandir(parent) as it:
            for entry in it:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                child = Path(entry.path)
                score = _segment_set_score(child)
                if score[0] < 2:
                    continue
                segment_child_count += 1
                only_segment_child = child
                name_l = entry.name.lower()
                if not hint_l:
                    rank = (1, score[0])
                elif name_l == hint_l:
                    rank = (4, score[0])
                elif name_l.startswith(hint_l):
                    rank = (3, score[0])
                elif hint_l in name_l:
                    rank = (2, score[0])
                else:
                    rank = (0, score[0])
                ranked.append((rank, child))
    except OSError:
        return None
    if ranked:
        ranked.sort(key=lambda item: item[0], reverse=True)
        if not hint_l or ranked[0][0][0] > 0:
            return ranked[0][1].resolve()
    if segment_child_count == 1 and only_segment_child is not None:
        return only_segment_child.resolve()
    return None


def _discover_segment_folder_from_hint(raw: str) -> Path | None:
    """When a pasted path is wrong or incomplete, search nearby mounted folders for E01 sets."""
    seen_roots: set[str] = set()
    probes = [
        _trim_incomplete_path_tail(_normalize_slashes(variant))
        for variant in _path_typo_variants(raw)
    ]
    # Prefer the drive letter from the hint — avoid scanning every mount (slow + wrong matches).
    scoped_roots = _accessible_drive_roots()
    drive_letter = None
    norm = _normalize_slashes(raw)
    if len(norm) >= 2 and norm[1] == ":":
        drive_letter = norm[0].lower()
        scoped_roots = [
            r for r in scoped_roots
            if str(r).replace("\\", "/").lower().startswith(f"/host/{drive_letter}")
            or str(r).replace("\\", "/").lower() in {f"/host/{drive_letter}", f"/host/{drive_letter}/"}
        ] or scoped_roots

    for probe in dict.fromkeys(probes):
        for candidate in _path_candidates(probe):
            root = _longest_existing_prefix(candidate)
            if root is None:
                continue
            if _is_container_drive_root(root):
                root = _descend_hint_path(root, probe)
            if _is_container_drive_root(root):
                continue
            key = str(root)
            if key in seen_roots:
                continue
            seen_roots.add(key)
            try:
                if root.is_dir():
                    score = _segment_set_score(root)
                    if score[0] >= 2:
                        return root.resolve()
                found = _find_segment_folder_under(root, max_depth=6)
                if found:
                    return found
            except OSError:
                continue

    for root in scoped_roots:
        key = str(root)
        if key in seen_roots:
            continue
        seen_roots.add(key)
        try:
            found = _find_segment_folder_under(root, max_depth=6)
            if found:
                return found
        except OSError:
            continue
    return None


def _resolve_existing_host_path(probe: str, *, strict: bool = False) -> Path | None:
    for candidate in _path_candidates(probe):
        try:
            if candidate.exists():
                return candidate.resolve()
            parent = candidate.parent
            tail = candidate.name
            if parent.exists() and parent.is_dir():
                child = _resolve_child_segment_folder(parent, tail)
                if child:
                    return child
                if strict:
                    if _segment_info(tail):
                        seg_file = parent / tail
                        if seg_file.is_file():
                            return seg_file.resolve()
                    continue
                found = _find_segment_folder_under(parent, max_depth=3)
                if found:
                    return found
        except OSError:
            continue
    return None


def _drive_mount_accessible(mount: Path) -> bool:
    """True when a container bind mount is present and readable."""
    try:
        if _is_stale_host_mount(mount):
            return False
        if not mount.is_dir():
            return False
        first = next(mount.iterdir(), None)
        if first is None and _is_host_drive_letter_mount(mount):
            return False
        return True
    except OSError:
        return False


def _decode_proc_mount_path(value: str) -> str:
    """Decode the small escape set used by /proc/* mount tables."""
    return (
        value.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )


def _mountinfo_has_mountpoint(text: str, mount_point: str) -> bool:
    """Return True when *mount_point* is an actual mount in /proc/self/mountinfo text."""
    wanted = mount_point.rstrip("/") or "/"
    for line in (text or "").splitlines():
        parts = line.split()
        # mountinfo field 5 is the mount point. Filesystem type is intentionally
        # ignored: Docker Desktop can expose Windows bind mounts via 9p/drvfs,
        # gRPC-FUSE, VirtioFS, or another backend.
        if len(parts) > 4 and _decode_proc_mount_path(parts[4]).rstrip("/") == wanted:
            return True
    return False


def _host_letter_has_container_mount(letter: str) -> bool:
    """True when /host/<letter> is an actual container mount, independent of fs type."""
    letter = (letter or "").strip().lower()
    if len(letter) != 1 or not letter.isalpha():
        return False
    mount_point = f"/host/{letter}"
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            if _mountinfo_has_mountpoint(fh.read(), mount_point):
                return True
    except OSError:
        pass

    # Fallback for unusual Linux/container builds without mountinfo.
    try:
        with open("/proc/mounts", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and _decode_proc_mount_path(parts[1]).rstrip("/") == mount_point:
                    return True
    except OSError:
        pass
    return False


def _host_letter_is_windows_drvfs(letter: str) -> bool:
    """Backward-compatible alias; mount detection is now filesystem-agnostic."""
    return _host_letter_has_container_mount(letter)


def _container_drive_mounts() -> dict[str, Path]:
    host_prefix = _host_mount_prefix()
    return {letter: host_prefix / letter for letter in string.ascii_lowercase}


def _accessible_drive_roots() -> list[Path]:
    """All drive roots currently readable inside the API/worker container."""
    roots: list[Path] = []
    seen: set[str] = set()
    for drive in _drive_catalog():
        if not drive.get("mounted"):
            continue
        for key in ("host_path", "container_path"):
            raw = drive.get(key) or ""
            if not raw:
                continue
            path = Path(raw)
            norm = str(path)
            if norm in seen:
                continue
            if _drive_mount_accessible(path):
                seen.add(norm)
                roots.append(path)
    for extra in (Path("/evidence"), _settings().host_evidence_root or ""):
        if extra:
            path = Path(extra)
            if path.is_dir():
                norm = str(path.resolve())
                if norm not in seen:
                    seen.add(norm)
                    roots.append(path.resolve())
    return roots


def _drive_catalog() -> list[dict]:
    settings = _settings()
    drive_map = settings.host_drive_map_dict
    if drive_map:
        return [
            {
                "key": key.lower(),
                "label": f"{key.upper()}:" if len(key) == 1 else key,
                "host_path": str(Path(host_path)),
                "container_path": str(Path(host_path)),
                "mounted": Path(host_path).exists(),
            }
            for key, host_path in drive_map.items()
        ]
    if _running_in_container():
        drives: list[dict] = []
        for letter, mount in _container_drive_mounts().items():
            accessible = _drive_mount_accessible(mount)
            stale = _is_stale_host_mount(mount) or (
                _host_letter_has_container_mount(letter) and not accessible
            )
            drives.append({
                "key": letter,
                "label": f"{letter.upper()}:",
                "host_path": str(mount) if accessible else "",
                "container_path": str(mount),
                "mounted": accessible,
                "bind_present": _safe_is_dir(mount),
                "stale": stale,
            })
        host_prefix = _host_mount_prefix()
        if _safe_is_dir(host_prefix):
            for dirname, label in {
                "volumes": "Volumes",
                "home": "/home",
                "mnt": "/mnt",
                "media": "/media",
                "users": "/Users",
            }.items():
                mount = host_prefix / dirname
                if _safe_is_dir(mount) and not _is_stale_host_mount(mount):
                    drives.append({
                        "key": dirname,
                        "label": label,
                        "host_path": str(mount),
                        "container_path": str(mount),
                        "mounted": True,
                    })
        for root in ("/evidence",):
            p = Path(root)
            if p.is_dir():
                drives.append({
                    "key": "evidence",
                    "label": "/evidence",
                    "host_path": str(p),
                    "container_path": str(p),
                    "mounted": True,
                })
        return drives
    if _is_windows():
        return [
            {
                "key": letter.lower(),
                "label": f"{letter}:",
                "host_path": str(Path(f"{letter}:\\")),
                "container_path": str(Path(f"{letter}:\\")),
                "mounted": Path(f"{letter}:\\").exists(),
                "bind_present": Path(f"{letter}:\\").exists(),
            }
            for letter in string.ascii_uppercase
        ]
    return list_drives_legacy_non_container()


def list_drives_legacy_non_container() -> list[dict]:
    drives: list[dict] = []
    if _is_macos():
        volumes = Path("/Volumes")
        if volumes.is_dir():
            for entry in sorted(volumes.iterdir(), key=lambda p: p.name.lower()):
                if entry.is_dir() and not entry.name.startswith("."):
                    drives.append({
                        "key": entry.name.lower().replace(" ", "_"),
                        "label": entry.name,
                        "host_path": str(entry),
                        "container_path": str(entry),
                        "mounted": True,
                    })
    else:
        for root in ("/mnt", "/media", "/home"):
            p = Path(root)
            if p.is_dir():
                drives.append({
                    "key": root.replace("/", "_").strip("_") or "root",
                    "label": root,
                    "host_path": str(p),
                    "container_path": str(p),
                    "mounted": True,
                })
    return drives


def list_drives() -> list[dict]:
    settings = _settings()
    catalog = _drive_catalog()
    if settings.host_evidence_root:
        p = Path(settings.host_evidence_root).resolve()
        if p.is_dir() and not any(d["host_path"] == str(p) for d in catalog):
            catalog.insert(0, {
                "key": "evidence",
                "label": "Evidence",
                "host_path": str(p),
                "container_path": str(p),
                "mounted": True,
            })
    return catalog


def _resolve_drive_base(drive_key: str) -> Path:
    key = drive_key.lower().strip().rstrip(":")
    if not key:
        raise ValueError("No drive specified")
    mapped = _settings().host_drive_map_dict.get(key)
    if mapped:
        p = Path(mapped)
        return p.resolve() if p.exists() else p
    for d in _drive_catalog():
        if d["key"] == key and d.get("host_path"):
            p = Path(d["host_path"])
            if p.exists():
                return p.resolve()
    if len(key) == 1 and key.isalpha():
        bases = _windows_drive_container_bases(key)
        for base in bases:
            if base.exists():
                return base
        if bases:
            return bases[0]
    if _is_windows() and len(key) <= 2:
        return Path(f"{key}:\\")
    raise ValueError(f"Unknown drive: {drive_key}")


def _is_absolute_host_path(raw: str) -> bool:
    text = (raw or "").strip()
    if not text:
        return False
    if WINDOWS_DRIVE_PATH_RE.match(text):
        return True
    if text.startswith("\\\\") or text.startswith("//"):
        return True
    if text.startswith("/") or text.startswith("\\"):
        return True
    return False


def _lookup_path_only(raw: str, *, job_id: str | None = None) -> Path | None:
    """Look up this exact path on the host. Never scans drives or remounts Docker."""
    text = (raw or "").strip()
    if not text:
        return None
    host_path: str | None = None
    try:
        from app.services.hostdrive_agent import lookup_exact_path
    except Exception:
        lookup_exact_path = None  # type: ignore[assignment]
    if lookup_exact_path:
        try:
            info = lookup_exact_path(text)
            if info and info.get("path"):
                host_path = str(info["path"])
        except Exception as exc:
            log.debug("host path lookup skipped: %s", exc)
    for probe in (host_path, text):
        if not probe:
            continue
        for candidate in _path_candidates(probe):
            try:
                if candidate.exists():
                    return candidate.resolve()
            except OSError:
                continue
    # Never robocopy / stage into data/uploads — register the source path in place.
    return None


def _path_usable(p: Path) -> bool:
    """True when Docker can stat this path (ENODEV / stale letter mounts are False)."""
    try:
        if p.is_file():
            return True
        if not _safe_is_dir(p):
            return False
        return not _is_stale_host_mount(p)
    except OSError:
        return False


def _heal_selected_host_path(probe: str) -> None:
    """Ask HostDrive to remount the selected office letter before failing resolve.

    Skip when we are not inside Docker, or when that letter is already a healthy
    /host/<letter> mount — remounting will not create a missing subfolder.
    """
    raw = (probe or "").strip()
    if not raw or not Path("/.dockerenv").exists():
        return
    try:
        from app.services.drive_mount_agent import ensure_path_mounted, path_is_readable

        # A /host/<letter> directory can exist as the parent of some other
        # folder while this worker still cannot read the selected export.
        # Letter presence is not enough — remount until the exact path is readable.
        if path_is_readable(raw):
            return
        ensure_path_mounted(raw, wait_sec=90.0)
    except Exception as exc:
        log.warning("ensure_path_mounted failed for %s: %s", raw, exc)


def resolve_host_path(
    raw: str | None,
    *,
    drive: str = "",
    browse_path: str = "",
    strict: bool = True,
    job_id: str | None = None,
) -> Path:
    settings = _settings()
    original_raw = raw.strip() if raw else ""
    if original_raw and is_placeholder_evidence_path(original_raw):
        raise ValueError(
            "That path is only an example. Choose the evidence folder on this computer so the files can upload."
        )
    if original_raw:
        mapped = resolve_staged_upload_raw(original_raw)
        if mapped is not None:
            return mapped
        try:
            from app.services.client_intake import is_staged_upload_path

            staged = Path(original_raw)
            if staged.exists() and is_staged_upload_path(staged):
                return staged.resolve()
        except Exception:
            pass
        candidate = _resolve_raw_path(original_raw, strict=strict)
    elif drive:
        base = _resolve_drive_base(drive)
        rel = browse_path.replace("\\", "/").strip("/")
        candidate = (base / rel.replace("/", os.sep)) if rel else base
        try:
            candidate = candidate.resolve()
        except OSError:
            pass
    elif settings.host_evidence_root:
        candidate = Path(settings.host_evidence_root).resolve()
    else:
        raise ValueError("No path specified")
    if not settings.host_evidence_enabled:
        raise ValueError("Host evidence access is disabled")
    if _path_usable(candidate):
        return candidate
    probe = original_raw or (f"{drive}:\\{browse_path}" if drive else browse_path)
    looked = _lookup_path_only(probe, job_id=job_id)
    if looked is not None and _path_usable(looked):
        return looked
    if probe:
        _heal_selected_host_path(probe)
        if original_raw:
            try:
                candidate = _resolve_raw_path(original_raw, strict=strict)
            except Exception:
                pass
        elif drive:
            try:
                base = _resolve_drive_base(drive)
                rel = browse_path.replace("\\", "/").strip("/")
                candidate = (base / rel.replace("/", os.sep)) if rel else base
            except Exception:
                pass
        if _path_usable(candidate):
            return candidate
        looked = _lookup_path_only(probe, job_id=job_id)
        if looked is not None and _path_usable(looked):
            return looked
    display = original_raw or browse_path or drive
    helper_sees = False
    if probe:
        try:
            from app.services.hostdrive_agent import lookup_exact_path

            info = lookup_exact_path(probe)
            helper_sees = bool(info and info.get("ok") and info.get("path"))
        except Exception:
            helper_sees = False
    if helper_sees:
        letter = None
        match = WINDOWS_DRIVE_PATH_RE.match((probe or "").strip())
        if match:
            letter = match.group(1).upper()
        loc = (letter or "?").lower()
        letter_root = _host_mount_prefix() / loc if letter else None
        if letter_root is not None and _drive_mount_accessible(letter_root):
            raise ValueError(
                f"Path not found inside Docker: {display}. "
                f"Drive {letter}: is mounted, but this worker cannot read that folder. "
                "HostDrive is refreshing the phone and disk workers — click Try again in a moment."
            )
        raise ValueError(
            f"Path not found inside Docker: {display}. "
            f"Drive {letter or '?'}: is visible on the office server but not mounted inside Docker "
            f"(missing /host/{loc}). HostDrive is refreshing that letter — click Try again if it just came online."
        )
    hint = _missing_windows_drive_mount_hint(display, candidate)
    if hint:
        raise ValueError(f"Path not found inside Docker: {display}. {hint}")
    raise ValueError(f"Path not found: {display}")


def _missing_windows_drive_mount_hint(raw: str, candidate: Path) -> str | None:
    """Clearer error when helper sees G: but Docker was never remounted with /host/g."""
    if not _running_in_container():
        return None
    letter: str | None = None
    match = WINDOWS_DRIVE_PATH_RE.match((raw or "").strip())
    if match:
        letter = match.group(1).lower()
    cand = str(candidate).replace("\\", "/").lower()
    m = re.match(r"^/host/([a-z])(?:/|$)", cand)
    if m:
        letter = m.group(1)
    if not letter:
        return None
    mount = _host_mount_prefix() / letter
    refresh_hint = (
        f"Click Refresh drive mounts, or run: "
        f"powershell -File scripts/generate-drive-mounts.ps1 -RequireDrive {letter.upper()} ; "
        f"docker compose -f docker-compose.yml -f docker-compose.drives.generated.yml "
        f"up -d --no-deps --force-recreate api worker-disk worker-mobile worker-report"
    )
    if not _drive_mount_accessible(mount):
        return (
            f"Drive {letter.upper()}: is visible on this PC but not mounted inside Docker "
            f"(missing /host/{letter}). {refresh_hint}"
        )
    # A plain /host/<letter> directory can exist in the image/VM even when Docker
    # never attached the Windows volume. Check for an exact mount point instead
    # of assuming Docker Desktop must use the legacy 9p/drvfs filesystem.
    if not _host_letter_has_container_mount(letter):
        return (
            f"Drive {letter.upper()}: has a /host/{letter} directory in Docker, but it is not an active bind mount of the Windows volume. "
            f"{refresh_hint}"
        )
    return None


def fingerprint_host_segment(path: Path) -> tuple[str, int]:
    stat = path.stat()
    if path.is_dir():
        digest = hashlib.sha256(f"hostdir:{path.resolve()}:{int(stat.st_mtime)}".encode()).hexdigest()
        return digest, 0
    size = stat.st_size
    if size > 32 * 1024 * 1024:
        digest = hashlib.sha256(f"host:{path.resolve()}:{size}:{int(stat.st_mtime)}".encode()).hexdigest()
        return digest, size
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest(), size


def _folder_segments(folder: Path) -> list[str]:
    names: list[str] = []
    try:
        for entry in folder.iterdir():
            if entry.is_file() and (_segment_info(entry.name) or is_mobile_segment_filename(entry.name)):
                names.append(entry.name)
    except OSError:
        pass
    return sorted(dict.fromkeys(names))


def _segment_files_under(folder: Path) -> list[Path]:
    """Find disk/mobile segments in *folder* and nested subfolders (client dumps)."""
    found: list[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(folder):
            dirnames[:] = [d for d in dirnames if d.lower() not in _LIST_SKIP_DIR_NAMES]
            for name in filenames:
                if name.startswith(".") or name.lower() in _LIST_SKIP_FILE_NAMES:
                    continue
                if _segment_info(name) or is_mobile_segment_filename(name):
                    found.append(Path(dirpath) / name)
    except OSError:
        pass
    return found


def _build_segment_set(folder: Path, filename: str) -> list[str]:
    info = _segment_info(filename)
    if not info:
        return [filename]
    if info.get("single"):
        return [filename]
    key = info["key"]
    parts: list[tuple[int, str]] = []
    try:
        for entry in folder.iterdir():
            if not entry.is_file():
                continue
            si = _segment_info(entry.name)
            if si and si.get("key") == key:
                parts.append((si["part"], entry.name))
    except OSError:
        pass
    parts.sort(key=lambda x: x[0])
    return [n for _, n in parts] if parts else [filename]


_ANDROID_BACKUP_MARKERS = ("backup.ab", "backup.adb", "data.ab")
_BROWSE_SKIP_DIR_NAMES = frozenset(
    {
        "$recycle.bin",
        "system volume information",
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "recovery",
        "boot",
        "documents and settings",
    }
)


def _dir_looks_like_android_backup(path: Path) -> bool:
    """Cheap marker check only — never full-scan directories (Recycle Bin, etc.)."""
    try:
        for marker in _ANDROID_BACKUP_MARKERS:
            if (path / marker).is_file():
                return True
    except OSError:
        return False
    return False


def _entry_dict(folder: Path, name: str) -> dict:
    full = folder / name
    try:
        st = full.stat()
        is_dir = full.is_dir()
        size = None if is_dir else st.st_size
    except OSError:
        is_dir = False
        size = None
    seg = _segment_info(name) if not is_dir else None
    segment_set = _build_segment_set(folder, name) if seg else []
    ios_backup = False
    android_backup = False
    if is_dir:
        if name.lower() not in _BROWSE_SKIP_DIR_NAMES:
            ios_backup = any((full / m).is_file() for m in IOS_BACKUP_MARKERS)
            android_backup = _dir_looks_like_android_backup(full)
    else:
        android_backup = Path(name).suffix.lower() in ANDROID_BACKUP_EXT
    return {
        "name": name,
        "kind": "dir" if is_dir else "file",
        "size_bytes": size,
        "selectable": bool(seg) or ios_backup or android_backup,
        "ios_backup": ios_backup,
        "android_backup": android_backup,
        "segment_base": seg["base"] if seg else None,
        "segment_part": seg["part"] if seg else None,
        "segment_set": segment_set,
        "segment_count": len(segment_set),
        "drive_key": None,
    }


def mount_info() -> dict:
    settings = _settings()
    configured = settings.host_evidence_enabled
    root = settings.host_evidence_root or ""
    drives = list_drives() if configured else []
    hint = (
        "Disk segments stay on your examiner drives — register paths only; "
        "the extracted disk is built in place with no image copy."
    )
    if not configured:
        hint = "Host evidence browsing is disabled (HOST_EVIDENCE_ENABLED=false)."
    elif _running_in_container():
        hint += " Provide the folder path — the server looks at that path only and does not require a Docker drive mount."
    return {
        "configured": configured,
        "host_root": root,
        "container_mount": root or None,
        "drives": drives,
        "hint": hint,
    }


def browse(
    *,
    drive: str = "",
    browse_path: str = "",
    host_path: str | None = None,
    source_type: str = "disk",
) -> dict:
    mi = mount_info()
    if not mi["configured"]:
        return {
            **mi,
            "host_evidence_path": "",
            "drive_root": "",
            "current_path": "",
            "display_path": "",
            "parent_path": None,
            "entries": [],
            "folder_segment_count": 0,
            "folder_segments": [],
            "error": "Host evidence is disabled",
            "mount_hint": mi["hint"],
        }
    try:
        if host_path:
            folder = resolve_host_path(host_path)
            if folder.is_file():
                folder = folder.parent
            drive_root = ""
            current_path = ""
            display = container_to_workstation_path(folder)
        elif drive and not browse_path:
            folder = _resolve_drive_base(drive)
            drive_root = drive.lower()
            current_path = ""
            display = container_to_workstation_path(folder)
        elif not drive and not browse_path and not host_path:
            entries = []
            for d in _drive_catalog():
                entries.append({
                    "name": d["label"],
                    "kind": "drive",
                    "size_bytes": None,
                    "selectable": bool(d.get("mounted")),
                    "ios_backup": False,
                    "android_backup": False,
                    "segment_base": None,
                    "segment_part": None,
                    "segment_set": [],
                    "segment_count": 0,
                    "drive_key": d["key"],
                    "mounted": bool(d.get("mounted")),
                    "stale": bool(d.get("stale")),
                })
            return {
                "configured": True,
                "host_evidence_path": mi["host_root"],
                "host_root": mi["host_root"],
                "drive_root": "",
                "current_path": "",
                "display_path": "This PC",
                "parent_path": None,
                "entries": entries,
                "folder_segment_count": 0,
                "folder_segments": [],
                "error": None,
                "mount_hint": mi["hint"],
                "drives": mi["drives"],
            }
        else:
            folder = resolve_host_path(None, drive=drive, browse_path=browse_path)
            drive_root = drive.lower()
            current_path = browse_path.replace("\\", "/").strip("/")
            display = container_to_workstation_path(folder)
    except (ValueError, OSError) as e:
        return {
            "configured": True,
            "host_evidence_path": mi["host_root"],
            "host_root": mi["host_root"],
            "drive_root": drive,
            "current_path": browse_path,
            "display_path": host_path or browse_path or "",
            "parent_path": None,
            "entries": [],
            "folder_segment_count": 0,
            "folder_segments": [],
            "error": str(e),
            "mount_hint": mi["hint"],
            "drives": mi["drives"],
        }

    if not folder.exists():
        return {
            "configured": True,
            "host_evidence_path": str(folder),
            "host_root": mi["host_root"],
            "drive_root": drive_root if "drive_root" in dir() else drive,
            "current_path": current_path if "current_path" in dir() else browse_path,
            "display_path": display if "display" in dir() else "",
            "parent_path": None,
            "entries": [],
            "folder_segment_count": 0,
            "folder_segments": [],
            "error": f"Path not found: {display if 'display' in dir() else folder}",
            "mount_hint": mi["hint"],
            "drives": mi["drives"],
        }

    if not folder.is_dir():
        return {
            "configured": True,
            "host_evidence_path": str(folder),
            "host_root": mi["host_root"],
            "drive_root": drive_root if "drive_root" in dir() else drive,
            "current_path": current_path if "current_path" in dir() else browse_path,
            "display_path": display if "display" in dir() else "",
            "parent_path": None,
            "entries": [],
            "folder_segment_count": 0,
            "folder_segments": [],
            "error": "Not a directory",
            "mount_hint": mi["hint"],
            "drives": mi["drives"],
        }

    entries = []
    try:
        with os.scandir(folder) as iterator:
            scanned = list(iterator)

        def _browse_sort_key(ent: os.DirEntry) -> tuple[int, str]:
            try:
                return (0 if ent.is_dir(follow_symlinks=False) else 1, ent.name.lower())
            except OSError:
                return (1, ent.name.lower())

        scanned.sort(key=_browse_sort_key)
        for ent in scanned:
            entries.append(_entry_dict(folder, ent.name))
    except OSError as e:
        return {
            "configured": True,
            "host_evidence_path": str(folder),
            "host_root": mi["host_root"],
            "drive_root": drive_root,
            "current_path": current_path,
            "display_path": display,
            "parent_path": _parent_path(current_path),
            "entries": [],
            "folder_segment_count": 0,
            "folder_segments": [],
            "error": str(e),
            "mount_hint": mi["hint"],
            "drives": mi["drives"],
        }

    folder_segments = _folder_segments(folder)
    return {
        "configured": True,
        "host_evidence_path": str(folder),
        "host_root": mi["host_root"],
        "drive_root": drive_root,
        "current_path": current_path,
        "display_path": display,
        "parent_path": _parent_path(current_path),
        "entries": entries,
        "folder_segment_count": len(folder_segments),
        "folder_segments": folder_segments,
        "error": None,
        "mount_hint": mi["hint"],
        "drives": mi["drives"],
    }


def _parent_path(current: str) -> str | None:
    parts = [p for p in current.replace("\\", "/").split("/") if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return ""
    return "/".join(parts[:-1])


def preview_folder(path: str | None = None, source_type: str = "disk") -> dict:
    mi = mount_info()
    resolved = None
    items: list[dict] = []
    error = None
    if path:
        try:
            folder = resolve_host_path(path)
            if folder.is_file():
                folder = folder.parent
            resolved = str(folder)
            if folder.is_dir():
                for entry in sorted(folder.iterdir(), key=lambda p: p.name.lower()):
                    if entry.is_file():
                        items.append({"name": entry.name, "size_bytes": entry.stat().st_size})
        except (ValueError, OSError) as e:
            error = str(e)
    ready = bool(items) and error is None
    if source_type == "disk" and resolved:
        segs = _folder_segments(Path(resolved))
        ready = len(segs) > 0
    elif source_type == "mobile" and resolved:
        ready = folder_has_mobile_segments(Path(resolved))
    return {
        "configured": mi["configured"],
        "container_mount": mi["container_mount"],
        "host_evidence_path": path or mi["host_root"],
        "expected_job_folder": "",
        "resolved_folder": resolved,
        "source_type": source_type,
        "items": items[:100],
        "item_count": len(items),
        "error": error,
        "ready_to_register": ready,
    }


_HINT_SEARCH_SKIP_DIRS = frozenset(
    {
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "$recycle.bin",
        "system volume information",
        "node_modules",
        ".git",
        "appdata",
        "recovery",
        "intel",
        "amd",
        "nvidia",
        "windowsapps",
        "winsxs",
        "msocache",
        "installer",
        "drivers",
        "boot",
        "perflogs",
        "config.msi",
    }
)


def _should_skip_hint_search_dir(name: str) -> bool:
    lower = name.lower()
    if lower.startswith("$") or lower.startswith("."):
        return True
    return lower in _HINT_SEARCH_SKIP_DIRS


def _prioritized_hint_search_roots() -> list[Path]:
    """Search likely evidence locations before scanning entire drive roots."""
    roots: list[Path] = []
    seen: set[str] = set()
    drive_roots = _accessible_drive_roots()
    for drive_root in drive_roots:
        for sub in (
            "all",
            "evidence",
            "forensic-images",
            "data",
            "forensics_data",
            "fotrensics_data",
            "forensic",
        ):
            probe = drive_root / sub
            if _drive_mount_accessible(probe):
                norm = str(probe)
                if norm not in seen:
                    seen.add(norm)
                    roots.append(probe)
    for drive_root in drive_roots:
        norm = str(drive_root)
        if norm not in seen:
            seen.add(norm)
            roots.append(drive_root)
    return roots


def _find_named_segment_folder(root: Path, name: str, *, max_depth: int = 12) -> Path | None:
    target = name.strip().lower()
    if not target:
        return None
    queue: list[tuple[Path, int]] = [(root, 0)]
    head = 0
    visited = 0
    max_visit = 8_000
    while head < len(queue) and visited < max_visit:
        current, depth = queue[head]
        head += 1
        visited += 1
        if depth > max_depth:
            continue
        try:
            with os.scandir(current) as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if _should_skip_hint_search_dir(entry.name):
                        continue
                    child = Path(entry.path)
                    if entry.name.lower() == target and _segment_set_score(child)[0] >= 2:
                        return child.resolve()
                    if depth < max_depth:
                        queue.append((child, depth + 1))
        except OSError:
            continue
    return None


def _find_folder_by_name_hint(folder_hint: str) -> dict:
    clean = folder_hint.strip().strip("\\/")
    if not clean:
        return {
            "path": None,
            "segment_count": 0,
            "error": "No folder name provided",
        }

    for variant in _path_typo_variants(clean):
        found = _resolve_existing_host_path(variant)
        if found is not None:
            seg_count = len(_folder_segments(found))
            if seg_count >= 1 or _segment_set_score(found)[0] >= 2:
                return {
                    "path": container_to_workstation_path(found),
                    "segment_count": seg_count,
                    "error": None,
                }

    for root in _accessible_drive_roots():
        for candidate in _hint_path_candidates(root, clean):
            try:
                if candidate.is_dir() and _segment_set_score(candidate)[0] >= 2:
                    return {
                        "path": container_to_workstation_path(candidate),
                        "segment_count": len(_folder_segments(candidate)),
                        "error": None,
                    }
            except OSError:
                continue

    leaf = Path(clean.replace("/", os.sep)).name
    if not leaf:
        return {
            "path": None,
            "segment_count": 0,
            "error": "No folder name provided",
        }

    for root in _prioritized_hint_search_roots():
        found = _find_named_segment_folder(root, leaf, max_depth=10)
        if found is not None:
            return {
                "path": container_to_workstation_path(found),
                "segment_count": len(_folder_segments(found)),
                "error": None,
            }

    return {
        "path": None,
        "segment_count": 0,
        "error": (
            f'Could not find folder "{leaf}" with disk segments (.E01, .E02, …). '
            "Choose the folder again so the files can upload."
        ),
    }


def find_folder_with_segment_files(
    filenames: list[str],
    folder_hint: str | None = None,
    relative_paths: list[str] | None = None,
    file_sizes: dict[str, int] | None = None,
) -> dict:
    names = _segment_filenames_only(filenames)
    abs_hint = (folder_hint or "").strip()
    if abs_hint and _is_absolute_host_path(abs_hint):
        try:
            folder = resolve_host_path(abs_hint, strict=True)
            if folder.is_file():
                folder = folder.parent
            if names:
                if _folder_contains_segment_names(folder, names):
                    return {
                        "path": container_to_workstation_path(folder),
                        "segment_count": len(names),
                        "error": None,
                    }
            elif _folder_segments(folder) or folder_has_mobile_segments(folder):
                return {
                    "path": container_to_workstation_path(folder),
                    "segment_count": len(_folder_segments(folder)),
                    "error": None,
                }
        except ValueError:
            pass
        return {
            "path": None,
            "segment_count": 0,
            "error": f"Path not found: {abs_hint}",
        }
    if not names:
        if folder_hint and folder_hint.strip():
            return _find_folder_by_name_hint(folder_hint)
        return {
            "path": None,
            "segment_count": 0,
            "error": "No disk or mobile segment files (.E01, .pas, .ufd, …) in the selection",
        }
    search_roots = _accessible_drive_roots()
    expected_sizes = {str(k).lower(): int(v) for k, v in (file_sizes or {}).items() if int(v) >= 0}

    def verified(folder: Path) -> bool:
        if not _folder_contains_segment_names(folder, names):
            return False
        if not expected_sizes:
            return True
        try:
            by_name = {entry.name.lower(): entry for entry in folder.iterdir() if entry.is_file()}
        except OSError:
            return False
        for name in names:
            expected = expected_sizes.get(name.lower())
            if expected is None:
                continue
            fp = by_name.get(name.lower())
            if fp is None:
                return False
            try:
                if fp.stat().st_size != expected:
                    return False
            except OSError:
                return False
        return True

    def success(folder: Path) -> dict:
        return {
            "path": container_to_workstation_path(folder),
            "segment_count": len(names),
            "error": None,
            "source_residency": "server_local",
            "verified_by": "filename_size" if expected_sizes else "filename",
        }

    hints: list[str] = []
    rel_hint = _relative_folder_hint(relative_paths)
    if rel_hint:
        hints.append(rel_hint.replace("/", os.sep))
    if folder_hint:
        clean = folder_hint.strip().strip("\\/")
        if clean and clean not in hints:
            hints.append(clean.replace("/", os.sep))

    for hint in hints:
        for root in search_roots:
            for candidate in _hint_path_candidates(root, hint):
                try:
                    if candidate.is_dir() and verified(candidate):
                        return success(candidate)
                except OSError:
                    continue
        base_name = Path(hint).name
        if base_name:
            for root in search_roots:
                found = _find_folder_by_segment_anchors(root, names, [base_name])
                if found and verified(found):
                    return success(found)

    for root in search_roots:
        try:
            if verified(root):
                return success(root)
        except OSError:
            continue

    anchors = names[:3]
    for root in search_roots:
        found = _find_folder_by_segment_anchors(root, names, anchors)
        if found and verified(found):
            return success(found)

    return {
        "path": None,
        "segment_count": 0,
        "error": (
            f"Could not find a folder containing {len(names)} selected segment file(s). "
            "Choose the folder again so the files can upload."
        ),
        "mount_hint": None,
    }


def _folder_regular_files(folder: Path, *, limit: int = 500) -> list[Path]:
    """Any regular files in the selected folder (in place — no copy)."""
    skip = frozenset({"thumbs.db", "desktop.ini", "autorun.inf"})
    out: list[Path] = []
    try:
        entries = list(folder.iterdir())
    except OSError:
        return []
    for entry in sorted(entries, key=lambda p: p.name.lower()):
        if len(out) >= limit:
            break
        name = entry.name
        if name.startswith(".") or name.startswith("$") or name.lower() in skip:
            continue
        try:
            if entry.is_file():
                out.append(entry)
        except OSError:
            continue
    return out


def _case_export_segments(folder: Path) -> list[Path]:
    try:
        from app.services.mobile_segments import case_export_segment_paths

        return case_export_segment_paths(folder)
    except Exception as exc:
        log.debug("case export lookup skipped for %s: %s", folder, exc)
        return []


def _case_export_dir(folder: Path) -> Path | None:
    try:
        from app.services.mobile_segments import locate_case_export_dir

        return locate_case_export_dir(folder)
    except Exception:
        return None


def _last_listing_counts(db: Session, job_id: str) -> dict:
    """Counts from the most recent completed List folder run (for error text)."""
    try:
        row = fetchone(
            db,
            """SELECT metadata FROM disk_build_logs
               WHERE job_id=:jid AND stage='folder_list'
                 AND metadata IS NOT NULL AND metadata->>'complete' = 'true'
               ORDER BY timestamp DESC LIMIT 1""",
            {"jid": job_id},
        )
    except Exception:
        row = None
    meta = (row or {}).get("metadata") if row else None
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except ValueError:
            meta = None
    if not isinstance(meta, dict):
        return {"count": 0, "segment_count": 0, "known": False}
    return {
        "count": int(meta.get("count") or 0),
        "segment_count": int(meta.get("segment_count") or 0),
        "known": True,
    }


def _collect_segment_files(
    folder: Path,
    selected_names: list[str] | None,
    source_type: str,
) -> list[Path]:
    if source_type in ("disk", "mobile"):
        if selected_names:
            names: set[str] = set()
            for n in selected_names:
                names.update(_build_segment_set(folder, n))
            found = [folder / n for n in sorted(names) if (folder / n).is_file()]
            if found:
                return found
            found = [folder / n for n in selected_names if (folder / n).is_file()]
            if found:
                return found
        # Case-layout run (02_Original_Extraction/<run>, 03_Working_Copy/<run>,
        # 05_Exports/<run>, or the case root): export_catalog.json is the
        # authority. The working copy is often an empty folder and the sealed
        # original is a junction Docker cannot walk — register the payload
        # shards + .pas/.ufd/.ufdx companions instead, whatever source_type says.
        case_paths = _case_export_segments(folder)
        if case_paths:
            return case_paths
        if source_type == "mobile":
            payload = list_payload_zip_archives(folder, [str(folder)])
            if payload:
                return payload
            live = live_mobile_collection_segments(folder)
            if live:
                return live
            packages = [folder / n for n in mobile_segments_in_folder(folder)]
            payload = [path for path in packages if mobile_package_has_payload(path)]
            if payload:
                return payload
            if packages:
                return packages
            if folder_is_live_mobile_collection(folder):
                return [folder]
            return _folder_regular_files(folder)
        names = _folder_segments(folder)
        if names:
            return [folder / n for n in names]
        try:
            from app.services.client_intake import is_staged_upload_path

            if is_staged_upload_path(folder):
                nested = _segment_files_under(folder)
                if nested:
                    return nested
        except Exception:
            pass
        return _folder_regular_files(folder)
    return [folder]


_LIST_SKIP_DIR_NAMES = frozenset(
    {
        "$recycle.bin",
        "system volume information",
        "recovery",
        "config.msi",
        # Live iPhone/Android trees. Segment register must use 05_Exports payload
        # zips — walking ios_image / AFC junctions hangs list-folder for hours.
        "ios_image",
        "ios_backup",
        "afc_media",
        "house_arrest",
        "readable_artifacts",
        "shared_storage",
        "adb_logical",
    }
)

_LIST_SKIP_FILE_NAMES = frozenset({"thumbs.db", "desktop.ini", "autorun.inf"})


def folder_lists_fast(folder: Path) -> bool:
    """True when List folder needs no deep walk (case-layout run or a small flat folder).

    Used by the API to decide inline vs background listing.
    """
    try:
        if _case_export_entries(folder):
            return True
        n_dirs = 0
        n_files = 0
        with os.scandir(folder) as it:
            for ent in it:
                if ent.name.startswith("$") or ent.name.lower() in _LIST_SKIP_DIR_NAMES:
                    continue
                if ent.is_dir(follow_symlinks=True):
                    n_dirs += 1
                else:
                    n_files += 1
                if n_dirs > 0 or n_files > 400:
                    return False
        return True
    except OSError:
        return False


def listing_complete(db: Session, job_id: str) -> bool:
    """True only after List folder finished writing its complete marker."""
    row = fetchone(
        db,
        """SELECT 1 AS ok FROM disk_build_logs
           WHERE job_id=:jid AND stage='folder_list'
             AND (
               (metadata IS NOT NULL AND metadata->>'complete' = 'true'
                  AND COALESCE((metadata->>'count')::int, 0) > 0)
               OR (
                 message LIKE 'Folder listing complete%'
                 AND message NOT LIKE 'Folder listing complete — 0 item%'
               )
             )
           LIMIT 1""",
        {"jid": job_id},
    )
    return bool(row)


def _list_folder_workers() -> int:
    try:
        from app.config import get_settings

        settings = get_settings()
        n = int(getattr(settings, "list_folder_workers", 0) or 0)
        if n <= 0:
            n = max(8, int(getattr(settings, "extract_disk_workers", 8) or 8) * 2)
        return max(8, min(n, 32))
    except Exception:
        return 16


def _list_folder_max_seconds() -> float:
    """Wall-clock cap for a deep listing (0 disables). Default 15 minutes."""
    try:
        from app.config import get_settings

        raw = getattr(get_settings(), "list_folder_max_seconds", None)
        if raw is None:
            raw = os.environ.get("LIST_FOLDER_MAX_SECONDS", "900")
        return max(0.0, float(raw or 0))
    except Exception:
        return 900.0


def _case_export_entries(folder: Path) -> list[dict]:
    """Shallow listing for a case-layout mobile run: export folder top level only.

    The sealed original (junctioned iOS backup, 100k+ files on a drvfs mount)
    must never be walked here — extract reads the 05_Exports payload shards.
    """
    try:
        from app.services.mobile_segments import case_export_payload

        info = case_export_payload(folder)
    except Exception:
        return []
    export_dir = info.get("export_dir")
    if export_dir is None or not (info.get("shards") or info.get("packages")):
        return []
    entries: list[dict] = []
    try:
        with os.scandir(export_dir) as it:
            for ent in it:
                name = ent.name
                if not name or name.startswith(".") or name.startswith("$"):
                    continue
                try:
                    if ent.is_dir(follow_symlinks=True):
                        entries.append({"name": name, "relative_path": name, "kind": "dir", "size_bytes": None})
                        continue
                    st = ent.stat(follow_symlinks=True)
                except OSError:
                    continue
                entries.append(
                    {"name": name, "relative_path": name, "kind": "file", "size_bytes": int(st.st_size)}
                )
    except OSError:
        return []
    entries.sort(key=lambda e: (e["kind"] != "file", e["name"].lower()))
    return entries


def _list_folder_max_entries() -> int:
    try:
        from app.config import get_settings

        return max(100, int(getattr(get_settings(), "list_folder_max_entries", 500_000) or 500_000))
    except Exception:
        return 500_000


def _scan_directory(
    dirpath: str,
    root: str,
    skip_dirs: frozenset[str],
    skip_files: frozenset[str],
    rel_prefix: str = "",
) -> tuple[list[dict], list[tuple[str, str]]]:
    """List one directory with a single scandir pass. Returns (rows, child_dirs).

    ``rel_prefix`` keeps case-relative paths when a child is a remapped
    Windows junction (``/host/e/ib/...``) whose real path is outside ``root``.
    """
    from app.services.dir_walk import entry_is_dir, resolve_openable_dir

    rows: list[dict] = []
    children: list[tuple[str, str]] = []
    prefix = root.rstrip("\\/")
    prefix_len = len(prefix)
    try:
        with os.scandir(dirpath) as iterator:
            for ent in iterator:
                name = ent.name
                if not name or name in (".", "..") or name.startswith("$"):
                    continue
                low = name.lower()
                try:
                    is_dir = entry_is_dir(ent)
                    st = ent.stat(follow_symlinks=not is_dir)
                except OSError:
                    continue
                rel = f"{rel_prefix}/{name}".strip("/") if rel_prefix else (
                    ent.path[prefix_len:].lstrip("\\/").replace("\\", "/")
                )
                if is_dir:
                    if low in skip_dirs:
                        continue
                    opened = resolve_openable_dir(Path(ent.path))
                    children.append((str(opened or ent.path), rel))
                    rows.append(
                        {"name": name, "relative_path": rel, "kind": "dir", "size_bytes": None}
                    )
                    continue
                if name.startswith(".") or low in skip_files:
                    continue
                rows.append(
                    {
                        "name": name,
                        "relative_path": rel,
                        "kind": "file",
                        "size_bytes": int(st.st_size),
                    }
                )
    except OSError:
        if os.path.abspath(dirpath) == os.path.abspath(root):
            raise
    return rows, children


def _walk_folder_entries(folder: Path) -> list[dict]:
    """Recursively list *folder* by scanning sibling directories in parallel."""
    from app.services.dir_walk import resolve_openable_dir
    from app.services.mobile_segments import list_payload_zip_archives

    case_entries = _case_export_entries(folder)
    if case_entries:
        return case_entries

    payload = list_payload_zip_archives(folder, [str(folder)])
    if payload:
        entries: list[dict] = []
        for archive in payload:
            try:
                st = archive.stat()
            except OSError:
                continue
            entries.append(
                {
                    "name": archive.name,
                    "relative_path": archive.name,
                    "kind": "file",
                    "size_bytes": int(st.st_size),
                }
            )
        if entries:
            return entries

    root = os.path.abspath(os.fspath(folder))
    opened_root = resolve_openable_dir(Path(root))
    if opened_root is None and not os.path.isdir(root):
        raise OSError(f"Not a directory: {root}")
    scan_root = str(opened_root or root)
    workers = _list_folder_workers()
    max_entries = _list_folder_max_entries()
    budget_sec = _list_folder_max_seconds()
    skip_dirs = _LIST_SKIP_DIR_NAMES
    skip_files = _LIST_SKIP_FILE_NAMES
    entries: list[dict] = []
    pending: list[tuple[str, str]] = [(scan_root, "")]
    truncated = False
    started = time.monotonic()

    workers = max(1, min(workers, 4))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="list-folder") as pool:
        inflight: dict = {}

        def _submit() -> None:
            while pending and len(inflight) < workers * 4:
                path, rel_prefix = pending.pop()
                inflight[pool.submit(_scan_directory, path, root, skip_dirs, skip_files, rel_prefix)] = True

        _submit()
        while inflight:
            done, _ = wait(inflight, return_when=FIRST_COMPLETED, timeout=5.0)
            if not truncated and budget_sec > 0 and time.monotonic() - started > budget_sec:
                # A bind-mounted phone tree can take hours to stat. The listing is
                # an examiner-facing preview — cap it and let Get segments run.
                truncated = True
                pending.clear()
                log.warning("list-folder budget of %ss reached under %s; listing truncated", budget_sec, root)
            for fut in done:
                inflight.pop(fut, None)
                try:
                    rows, children = fut.result()
                except Exception:
                    continue
                if truncated:
                    continue
                space = max_entries - len(entries)
                if space <= 0:
                    truncated = True
                    pending.clear()
                    continue
                if len(rows) > space:
                    entries.extend(rows[:space])
                    truncated = True
                    pending.clear()
                    continue
                entries.extend(rows)
                pending.extend(children)
            if not truncated:
                _submit()

    if truncated:
        entries.append(
            {
                "name": "…",
                "relative_path": "",
                "kind": "file",
                "size_bytes": None,
                "truncated": True,
            }
        )
    return entries


def _listing_log_rows(entries: list[dict]) -> tuple[list[dict], list[str]]:
    """Pack listing into few log lines (segments/dirs kept; other files grouped)."""
    segment_names: list[str] = []
    log_rows: list[dict] = []
    other_chunk: list[str] = []

    def flush_others() -> None:
        if not other_chunk:
            return
        log_rows.append(
            {
                "message": "  [FILES] " + ", ".join(other_chunk),
                "metadata": {"kind": "files", "count": len(other_chunk), "names": list(other_chunk)},
            }
        )
        other_chunk.clear()

    for entry in entries:
        if entry.get("truncated"):
            flush_others()
            log_rows.append(
                {
                    "message": "  [truncated] listing stopped at the configured entry cap",
                    "metadata": {"truncated": True},
                }
            )
            continue
        rel = str(entry.get("relative_path") or entry.get("name") or "")
        name = str(entry.get("name") or "")
        if entry.get("kind") == "dir":
            flush_others()
            log_rows.append(
                {
                    "message": f"  [DIR] {rel}",
                    "metadata": {"name": name, "relative_path": rel, "kind": "dir"},
                }
            )
            continue
        size = entry.get("size_bytes")
        size_label = "" if size is None else f" — {size:,} bytes"
        if _segment_info(name):
            flush_others()
            segment_names.append(name)
            log_rows.append(
                {
                    "message": f"  [SEG] {rel}{size_label}",
                    "metadata": {
                        "name": name,
                        "relative_path": rel,
                        "kind": "file",
                        "size_bytes": size,
                        "segment": True,
                    },
                }
            )
            continue
        other_chunk.append(rel)
        if len(other_chunk) >= 80:
            flush_others()
    flush_others()
    return log_rows, segment_names


def _log_folder_listing(db: Session, job_id: str, folder: Path) -> dict:
    """Write directory contents to extraction logs (stage=folder_list)."""
    display_folder = _listing_display_path(folder)
    workers = _list_folder_workers()
    write_disk_log(
        db,
        job_id,
        f"Listing folder contents in parallel ({workers} workers): {display_folder}",
        stage="folder_list",
        metadata={"path": display_folder, "workers": workers, "started": True},
    )
    db.commit()

    try:
        entries = _walk_folder_entries(folder)
    except OSError as exc:
        raise ValueError(f"Cannot list folder {display_folder}: {exc}") from exc

    try:
        from app.services.client_intake import is_staged_upload_path

        staged_dump = is_staged_upload_path(folder)
    except Exception:
        staged_dump = False
    if not entries and staged_dump:
        raise ValueError(
            "Client upload dump is empty. Wait until every image file from this computer "
            "has finished transferring to the forensic server, then Try again."
        )

    log_rows, segment_names = _listing_log_rows(entries)
    write_disk_logs_batch(db, job_id, log_rows, stage="folder_list", flush=False)
    write_disk_log(
        db,
        job_id,
        f"Folder listing complete — {len(entries)} item(s), {len(segment_names)} segment file(s) detected "
        f"({workers} parallel scanners)",
        stage="folder_list",
        metadata={
            "path": display_folder,
            "count": len(entries),
            "segment_count": len(segment_names),
            "segments": segment_names[:50],
            "complete": True,
            "workers": workers,
        },
    )
    db.commit()

    try:
        from app.services.pipeline_orchestrator import mark_list_folder_done

        mark_list_folder_done(db, job_id, path=display_folder, count=len(entries))
        db.commit()
    except Exception:
        pass

    persist_job_evidence_folder(db, job_id, display_folder)
    preview = [row for row in entries if row.get("kind") == "file" and _segment_info(str(row.get("name") or ""))]
    if len(preview) < 80:
        for row in entries:
            if row in preview:
                continue
            preview.append(row)
            if len(preview) >= 80:
                break
    return {
        "path": display_folder,
        "count": len(entries),
        "entries": preview,
        "segment_count": len(segment_names),
        "segments": segment_names,
        "workers": workers,
    }


def _commit_register_progress(db: Session) -> None:
    """Commit so API idle-in-transaction timeout cannot roll back registered files."""
    from app.db.sql_helpers import rollback_aborted_transaction

    try:
        db.commit()
    except Exception:
        rollback_aborted_transaction(db)


def evidence_folder_from_disk_source(ds: dict | None) -> str:
    if not isinstance(ds, dict):
        return ""
    if str(ds.get("intake") or "") == "browser_upload":
        for key in ("staging_container_path", "evidence_folder"):
            val = str(ds.get(key) or "").strip()
            if val:
                mapped = resolve_staged_upload_raw(val)
                return str(mapped) if mapped is not None else val
    for key in ("evidence_folder", "last_host_path"):
        val = str(ds.get(key) or "").strip()
        if val:
            mapped = resolve_staged_upload_raw(val)
            return str(mapped) if mapped is not None else val
    return ""


def persist_job_evidence_folder(db: Session, job_id: str, folder_path: str) -> None:
    """Remember the last selected evidence folder so Try again can remount and re-register."""
    from app.services.mobile_os import load_job_disk_source

    display = (folder_path or "").strip()
    if not display:
        return
    mapped = resolve_staged_upload_raw(display)
    if mapped is not None:
        display = str(mapped)
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
    ds = load_job_disk_source(row)
    if ds.get("evidence_folder") == display and ds.get("last_host_path") == display:
        _commit_register_progress(db)
        return
    ds["evidence_folder"] = display
    ds["last_host_path"] = display
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:job_id",
        {"ds": json.dumps(ds), "job_id": job_id},
    )
    _commit_register_progress(db)


def load_job_evidence_folder(db: Session, job_id: str) -> str:
    from app.services.mobile_os import load_job_disk_source

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
    found = evidence_folder_from_disk_source(load_job_disk_source(row))
    if found:
        return found
    ev = fetchone(
        db,
        """SELECT host_path FROM evidence_files
           WHERE job_id=:job_id AND coalesce(host_path,'') <> ''
           ORDER BY created_at DESC NULLS LAST LIMIT 1""",
        {"job_id": job_id},
    )
    host = str((ev or {}).get("host_path") or "").strip()
    if host:
        p = Path(host)
        return str(p.parent) if p.suffix else str(p)
    log_row = fetchone(
        db,
        """SELECT metadata FROM disk_build_logs
           WHERE job_id=:job_id AND stage='folder_list' AND metadata IS NOT NULL
           ORDER BY timestamp DESC LIMIT 1""",
        {"job_id": job_id},
    )
    meta = (log_row or {}).get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    if isinstance(meta, dict):
        path = str(meta.get("path") or "").strip()
        if path:
            return path
    return ""


def readable_segment_paths(paths: list[Path]) -> tuple[list[Path], list[str]]:
    readable: list[Path] = []
    vanished: list[str] = []
    for fp in paths:
        try:
            if fp.is_file() or fp.is_dir():
                readable.append(fp)
            else:
                vanished.append(fp.name)
        except OSError:
            vanished.append(fp.name)
    return readable, vanished


def reregister_job_evidence_from_saved_folder(
    db: Session,
    job_id: str,
    *,
    source_type: str = "disk",
) -> dict:
    """Re-register from the last saved folder when evidence_files is empty."""
    folder = load_job_evidence_folder(db, job_id)
    if not folder:
        return {"accepted": [], "recovered": False, "path": ""}
    result = register_segments(
        db,
        job_id,
        path=folder,
        source_type=source_type,
        skip_folder_list=True,
    )
    _commit_register_progress(db)
    return {**result, "recovered": True, "path": folder}


def list_folder_contents(
    db: Session,
    job_id: str,
    *,
    path: str | None = None,
    drive: str = "",
    browse_path: str = "",
) -> dict:
    """Resolve a host folder, log every entry to extraction logs, return the listing."""
    display_in = (path or drive or browse_path or "").strip()
    if display_in:
        write_disk_log(
            db,
            job_id,
            f"Opening folder for listing: {display_in}",
            stage="folder_list",
        )
        db.commit()

    folder = resolve_host_path(path, drive=drive, browse_path=browse_path, strict=True, job_id=job_id)
    if folder.is_file():
        folder = folder.parent
    return _log_folder_listing(db, job_id, folder)


def ensure_folder_listed(db: Session, job_id: str) -> dict | None:
    """Block later agents until List folder has a complete marker."""
    from app.services.mobile_os import load_job_disk_source

    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
    ds = load_job_disk_source(row)
    if is_client_upload_pending(ds):
        return None
    if listing_complete(db, job_id):
        return None
    folder = load_job_evidence_folder(db, job_id)
    if not folder:
        folder = str(ds.get("staging_container_path") or "").strip()
    if not folder:
        return None

    # Never walk a big tree on the caller's thread: the huddle/process endpoints
    # invoke this on every poll, and an inline multi-hour walk (repeated on every
    # poll because a 0-item listing never counts as "complete") froze the API.
    try:
        from app.services.folder_listing_jobs import is_running, start_background_listing

        if is_running(job_id):
            return None
        resolved = resolve_host_path(folder, strict=True, job_id=job_id)
        if resolved.is_file():
            resolved = resolved.parent
        if folder_lists_fast(resolved):
            return list_folder_contents(db, job_id, path=folder)
        schema = str(db.info.get("firm_schema") or "")
        if not schema:
            try:
                from app.db.tenant import get_tenant_context

                ctx = get_tenant_context()
                schema = str(getattr(ctx, "schema_name", "") or "")
            except Exception:
                schema = ""
        if schema:
            start_background_listing(schema_name=schema, job_id=job_id, path=folder)
            return None
    except ValueError:
        raise
    except Exception as exc:
        log.debug("background list-folder unavailable for job %s: %s", job_id, exc)
    return list_folder_contents(db, job_id, path=folder)


def register_segments(
    db: Session,
    job_id: str,
    *,
    path: str | None = None,
    drive: str = "",
    browse_path: str = "",
    selected_names: list[str] | None = None,
    source_type: str = "disk",
    skip_folder_list: bool = False,
) -> dict:
    display_in = (path or drive or browse_path or "").strip()
    if display_in:
        write_disk_log(
            db,
            job_id,
            f"Resolving evidence path: {display_in}",
            stage="evidence_register",
        )
        db.commit()
    folder = resolve_host_path(path, drive=drive, browse_path=browse_path, strict=True, job_id=job_id)
    if folder.is_file():
        folder = folder.parent

    # Step before Get segments: print every file in the folder to extraction logs.
    listing: dict | None = None
    if not skip_folder_list:
        listing = _log_folder_listing(db, job_id, folder)

    paths = _collect_segment_files(folder, selected_names, source_type)
    if not paths:
        try:
            from app.services.client_intake import is_staged_upload_path

            if is_staged_upload_path(folder):
                paths = _segment_files_under(folder)
        except Exception:
            pass
    if not paths:
        listed = listing or _last_listing_counts(db, job_id)
        try:
            from app.services.client_intake import is_staged_upload_path

            staged_dump = is_staged_upload_path(folder)
        except Exception:
            staged_dump = False
        if staged_dump:
            raise ValueError(
                "No registerable evidence in the client upload dump. "
                f"Folder listing found {listed.get('count', 0)} item(s) "
                f"({listed.get('segment_count', 0)} segment-like). "
                "Wait until every image file from this computer has finished transferring, then Try again."
            )
        shown = _listing_display_path(folder)
        export_dir = _case_export_dir(folder)
        if export_dir is not None:
            raise ValueError(
                f"No payload found for this extraction run. {shown} resolved to the export folder "
                f"{_listing_display_path(export_dir)}, but it holds no .part-NNNNN.zip shards, "
                "full ZIP, or .pas/.ufd/.ufdx packages yet. If the acquisition is still packaging, "
                "wait for 05_Exports to finish, then Try again."
            )
        counts = (
            f"Folder listing found {listed.get('count', 0)} item(s) "
            f"({listed.get('segment_count', 0)} segment-like). "
            if listed.get("known", True)
            else "The folder has not been listed yet. "
        )
        raise ValueError(
            f"No registerable evidence found at {shown}. {counts}"
            "Select the case run folder (05_Exports/<run> with export_catalog.json) or a folder "
            "containing .E01/.E02/.001, .pas/.ufd/.ufdx or payload .zip files."
        )

    display_folder = _listing_display_path(folder)
    persist_job_evidence_folder(db, job_id, display_folder)

    # Make the source-residency contract explicit. Host/server paths are processed
    # in place and must never be copied or deleted by client-upload cleanup.
    try:
        from app.services.client_intake import is_staged_upload_path
        from app.services.mobile_os import load_job_disk_source

        staged_source = is_staged_upload_path(folder)
        row_ds = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
        source_ds = dict(load_job_disk_source(row_ds))
        if staged_source:
            source_ds.update({
                "intake": "browser_upload",
                "source_origin": "client_browser",
                "transport_mode": "staged_upload",
                "transport": "staged_upload",
                "source_residency": "client_uploaded_to_server",
                "transfer_required": True,
                "download_required": True,
                "cleanup_policy": "delete_after_pipeline_success",
            })
        else:
            raw_display = str(display_folder or "")
            if raw_display.startswith("\\") or raw_display.startswith("//"):
                source_origin = "server_network"
            elif len(raw_display) >= 3 and raw_display[1:3] in (":\\", ":/"):
                source_origin = "server_attached_or_mapped"
            else:
                source_origin = "server_path"
            source_ds.update({
                "intake": "server_local",
                "source_origin": "server_accessible",
                "server_origin_detail": source_origin,
                "transport_mode": "zero_copy",
                "transport": "in_place",
                "source_residency": "server_local",
                "transfer_required": False,
                "download_required": False,
                "cleanup_policy": "never_delete_source",
                "staging_purged": False,
            })
            source_ds["source_type"] = "disk"
            for upload_key in (
                "upload_status", "upload_expected_files", "upload_received_files",
                "upload_received_bytes", "upload_parallelism",
            ):
                source_ds.pop(upload_key, None)
            for mobile_key in ("mobile_os", "owner_agent", "mobile_device", "mobile_platform"):
                source_ds.pop(mobile_key, None)
            source_ds.pop("staging_host_path", None)
            source_ds.pop("staging_container_path", None)
            source_ds.pop("staging_object_prefix", None)
        execute(
            db,
            "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:job_id",
            {"ds": json.dumps(source_ds), "job_id": job_id},
        )
        _commit_register_progress(db)
    except Exception as exc:
        log.debug("source residency metadata failed job=%s: %s", job_id, exc)

    readable, vanished = readable_segment_paths(paths)
    if not readable:
        raise ValueError(
            "The folder listed earlier is no longer readable from Docker. "
            f"Found {len(paths)} segment name(s) at {display_folder}"
            + (f" but these are missing: {', '.join(vanished[:8])}" if vanished else "")
            + ". If you attached a new drive, wait for it to remount, then Try again."
        )

    write_disk_log(
        db,
        job_id,
        f"Registering {len(readable)} segment(s) from {display_folder} — paths only, no copy",
        stage="evidence_register",
    )
    # Close the transaction before per-file I/O. The API idle-in-transaction
    # timeout is 60s; fingerprint/stat on a Docker bind mount can exceed that and
    # used to abort the whole registration so process_job saw zero evidence_files.
    _commit_register_progress(db)

    accepted = []
    group_id = str(uuid.uuid4())
    total = len(readable)
    from app.db.sql_helpers import rollback_aborted_transaction

    for idx, fp in enumerate(readable, start=1):
        try:
            sha256, size = fingerprint_host_segment(fp)
        except OSError as exc:
            write_disk_log(
                db,
                job_id,
                f"Could not read {fp.name}: {exc}",
                stage="evidence_register",
            )
            _commit_register_progress(db)
            continue
        seg = _segment_info(fp.name)
        try:
            rel = str(fp.relative_to(folder)).replace("\\", "/")
        except ValueError:
            rel = fp.name
        host = str(fp.resolve())
        try:
            existing = fetchone(
                db,
                "SELECT * FROM evidence_files WHERE job_id=:job_id AND host_path=:host_path",
                {"job_id": job_id, "host_path": host},
            )
            if existing:
                accepted.append(_evidence_row(existing))
                _commit_register_progress(db)
                continue
            row = fetchone(
                db,
                """INSERT INTO evidence_files(
                       job_id, group_id, relative_path, original_name, host_path, storage_uri,
                       sha256, status, size_bytes, source_kind, segment_part, segment_base)
                   VALUES (:job_id,:group_id,:rel,:orig,:host,:uri,:sha256,'registered',:size,'host',:part,:base)
                   RETURNING *""",
                {
                    "job_id": job_id,
                    "group_id": group_id,
                    "rel": rel,
                    "orig": fp.name,
                    "host": host,
                    "uri": f"file://{host}",
                    "sha256": sha256,
                    "size": size,
                    "part": seg["part"] if seg else None,
                    "base": seg["base"] if seg else None,
                },
            )
            if row:
                accepted.append(_evidence_row(row))
                write_disk_log(
                    db,
                    job_id,
                    f"Registered {fp.name} ({idx}/{total})",
                    stage="evidence_register",
                    metadata={"size_bytes": size, "progress_pct": round(idx * 100 / total)},
                )
            _commit_register_progress(db)
        except Exception as exc:
            rollback_aborted_transaction(db)
            log.warning("segment register failed job=%s file=%s: %s", job_id, fp.name, exc)
            write_disk_log(
                db,
                job_id,
                f"Retryable register error for {fp.name}: {exc}",
                stage="evidence_register",
            )
            _commit_register_progress(db)

    if not accepted:
        raise ValueError(
            "No disk segments registered. The folder was listed, but files could not "
            "be committed. If you attached a new drive, wait for it to remount, then Try again."
        )

    ev = fetchall(db, "SELECT original_name, status FROM evidence_files WHERE job_id=:job_id", {"job_id": job_id})
    sr = segment_readiness(ev)
    write_disk_log(
        db,
        job_id,
        f"Registration complete — {len(accepted)} segment(s); "
        f"{'ready to process' if sr.get('ready') else sr.get('message') or 'incomplete segment set'}",
        stage="evidence_register",
        metadata={"readiness": sr},
    )
    execute(
        db,
        "UPDATE jobs SET segment_readiness=CAST(:sr AS jsonb), status='registered', updated_at=NOW() WHERE id=:job_id",
        {"sr": json.dumps(sr), "job_id": job_id},
    )
    _commit_register_progress(db)

    job_row = fetchone(db, "SELECT type, disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
    from app.services.mobile_os import extract_mobile_meta, load_job_disk_source, merge_mobile_meta_into_disk_source

    prior_ds = load_job_disk_source(job_row)
    mobile_meta = extract_mobile_meta(prior_ds)
    job_type = str(job_row.get("type") or "").lower()
    explicit_mobile_type = job_type in ("mobile_extraction", "android_mobile", "ios_mobile", "ios_backup", "android_backup")
    # Stale mobile_os metadata must not turn a host_disk/E01 job into Android/iOS.
    is_mobile = source_type == "mobile" or explicit_mobile_type or (not job_type and bool(mobile_meta.get("mobile_os")))
    if is_mobile:
        from app.services.mobile_adapters import build_import_collection_summary
        from app.services.mobile_capability import evaluate_mobile_capability
        from app.services.mobile_os import mobile_os_to_axiom_platform

        names = [str(p.name) for p in paths]
        host_paths = [str(p) for p in paths]
        capability = evaluate_mobile_capability(
            mobile_os=str(mobile_meta.get("mobile_os") or ""),
            acquisition_mode=str(mobile_meta.get("acquisition_mode") or "import"),
            evidence_names=names,
            host_paths=host_paths,
        )
        summary = build_import_collection_summary(
            names=names,
            paths=host_paths,
            mobile_os=str(mobile_meta.get("mobile_os") or ""),
            capability=capability,
        )
        platform = mobile_os_to_axiom_platform(str(mobile_meta.get("mobile_os") or ""))
        if not platform and capability.get("inferred_platform"):
            platform = capability["inferred_platform"]
        acq_methods: list[str] = []
        acq_manifest = folder / "acquisition_manifest.json"
        if acq_manifest.is_file():
            try:
                import json as _json

                payload = _json.loads(acq_manifest.read_text(encoding="utf-8"))
                methods = payload.get("methods") or []
                if isinstance(methods, list):
                    acq_methods = [str(m) for m in methods]
                if payload.get("primary_method"):
                    summary = {**summary, "primary_method": payload.get("primary_method")}
                if payload.get("acquisition_mode"):
                    summary = {**summary, "provenance": "host_helper_live"}
            except Exception:
                pass

        # Document Phase 1: hash + manifest + .ufdx path graph for .pas/.ufd/.ufdx/.zip.
        evidence_manifest = None
        try:
            from app.services.mobile_forensic.cellebrite_ufed import (
                collect_mobile_payload_paths,
                parse_ufdx_extraction_paths,
            )
            from app.services.mobile_forensic.integrity import (
                build_evidence_manifest,
                hash_evidence_paths,
                load_intake_keys_from_disk_source,
                write_manifest_sidecar,
            )

            payload_graph = collect_mobile_payload_paths(folder)
            hash_targets = list(paths)
            for extra in payload_graph.get("dump_zips") or []:
                if extra not in hash_targets:
                    hash_targets.append(extra)
            for extra in payload_graph.get("ufdx_refs") or []:
                if extra not in hash_targets:
                    hash_targets.append(extra)
            hashed = hash_evidence_paths(hash_targets)
            ufdx_paths: list[str] = []
            for ufdx in payload_graph.get("ufdxs") or []:
                ufdx_paths.extend(parse_ufdx_extraction_paths(ufdx))
            evidence_manifest = build_evidence_manifest(
                job_id=job_id,
                source_paths=host_paths,
                hashed=hashed,
                mobile_os=str(mobile_meta.get("mobile_os") or ""),
                acquisition_mode="live_logical" if acq_methods else "import",
                formats=list(payload_graph.get("formats") or summary.get("formats") or []),
                adapter=str(summary.get("adapter") or ""),
                intake_keys=load_intake_keys_from_disk_source(prior_ds),
                device_info=payload_graph.get("device_info") or {},
                ufdx_paths=ufdx_paths,
            )
            write_manifest_sidecar(folder, evidence_manifest)
            summary = {
                **summary,
                "formats": evidence_manifest.get("formats"),
                "source_id": evidence_manifest.get("source_id"),
                "dump_zip_count": len(payload_graph.get("dump_zips") or []),
                "ufdx_ref_count": len(payload_graph.get("ufdx_refs") or []),
            }
        except Exception as exc:
            log.warning("mobile evidence manifest failed job=%s: %s", job_id, exc)

        update_meta = {
            **mobile_meta,
            "source_type": "mobile",
            "capability_label": capability.get("capability_label"),
            "capability_reasons": capability.get("reasons") or [],
            "permitted_actions": capability.get("permitted_actions") or [],
            "import_adapter": summary.get("adapter"),
            "collection_summary": summary,
            "os_mismatch_warning": capability.get("os_mismatch_warning"),
            "acquisition_mode": "live_logical" if acq_methods else "import",
            "acquisition_methods": acq_methods or mobile_meta.get("acquisition_methods") or [],
        }
        if evidence_manifest:
            update_meta["evidence_manifest"] = evidence_manifest
            update_meta["evidence_source_id"] = evidence_manifest.get("source_id")
        if platform:
            update_meta["axiom_platform"] = platform
            update_meta["evidence_platform"] = platform
        from app.services.mobile_platform_agents import detect_mobile_platform, persist_owner_on_disk_source

        detected = detect_mobile_platform(
            update_meta,
            mobile_meta,
            summary,
            names,
            host_paths,
            str(folder),
        )
        if detected:
            prior_os = str(mobile_meta.get("mobile_os") or "").lower()
            if prior_os in {"ios", "android"} and prior_os != detected:
                update_meta["os_mismatch_warning"] = (
                    f"Selected {prior_os} but the package looks like {detected}. "
                    f"{'iOS Agent' if detected == 'ios' else 'Android Agent'} will own extract and RAG."
                )
            from app.service_identity import job_type_platform

            typed = job_type_platform(job_type)
            if typed and typed != detected:
                corrected = "ios_mobile" if detected == "ios" else "android_mobile"
                execute(
                    db,
                    "UPDATE jobs SET type=:t, updated_at=NOW() WHERE id=:job_id",
                    {"t": corrected, "job_id": job_id},
                )
                job_type = corrected
                write_disk_log(
                    db,
                    job_id,
                    (
                        f"Evidence platform is {detected}; job type corrected from {typed} "
                        f"to {corrected} so the owning product heartbeats and extracts."
                    ),
                    stage="evidence_register",
                    level="warning",
                )
        update_meta = persist_owner_on_disk_source(update_meta, detected)
        merged = merge_mobile_meta_into_disk_source(prior_ds, update_meta)
        execute(
            db,
            "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:job_id",
            {"ds": json.dumps(merged), "job_id": job_id},
        )
        db.flush()
        write_disk_log(
            db,
            job_id,
            f"Mobile import package registered — OS={merged.get('mobile_os')} "
            f"capability={merged.get('capability_label')} adapter={summary.get('adapter')}"
            + (
                f" source={evidence_manifest.get('source_id')}"
                if evidence_manifest
                else ""
            ),
            stage="evidence_register",
            metadata={
                "axiom_platform": merged.get("axiom_platform"),
                "capability_label": merged.get("capability_label"),
                "import_adapter": summary.get("adapter"),
                "segment_hashes": [a.get("sha256") for a in accepted if a.get("sha256")],
                "source_id": (evidence_manifest or {}).get("source_id"),
                "formats": (evidence_manifest or {}).get("formats"),
            },
        )
        from app.services.artifact_selection_catalog import persist_job_axiom_platform

        platform = persist_job_axiom_platform(db, job_id)
        return {
            "accepted": accepted,
            "skipped": [],
            "readiness": sr,
            "message": None,
            "axiom_platform": platform,
            "capability": capability,
            "collection_summary": summary,
        }

    from app.services.artifact_selection_catalog import persist_job_axiom_platform

    platform = persist_job_axiom_platform(db, job_id)
    write_disk_log(
        db,
        job_id,
        f"Evidence platform detected — {platform} artifact catalog will be used",
        stage="evidence_register",
        metadata={"axiom_platform": platform},
    )
    return {"accepted": accepted, "skipped": [], "readiness": sr, "message": None, "axiom_platform": platform}


def mark_client_upload_progress(
    db: Session,
    job_id: str,
    *,
    expected_files: int | None = None,
    received_delta: int = 0,
    received_bytes_delta: int = 0,
    received_files: int | None = None,
) -> dict:
    """Record that browser files are still arriving. Do not list or register yet."""
    from app.services.client_intake import staging_locations
    from app.services.mobile_os import load_job_disk_source

    row = fetchone(
        db,
        "SELECT disk_source FROM jobs WHERE id=:job_id FOR UPDATE",
        {"job_id": job_id},
    ) or {}
    ds = dict(load_job_disk_source(row))
    locs = staging_locations(job_id)
    ds["intake"] = "browser_upload"
    ds["source_origin"] = "client_browser"
    ds["transport_mode"] = "staged_upload"
    ds["source_residency"] = "client_uploaded_to_server"
    ds["transfer_required"] = True
    ds["download_required"] = True
    ds["transport"] = "staged_upload"
    ds["cleanup_policy"] = "delete_after_pipeline_success"
    ds["upload_parallelism"] = 5
    ds["upload_status"] = "receiving"
    if expected_files is not None and expected_files > 0:
        ds["upload_expected_files"] = int(expected_files)
    if received_files is not None:
        ds["upload_received_files"] = max(0, int(received_files))
    else:
        ds["upload_received_files"] = int(ds.get("upload_received_files") or 0) + max(0, int(received_delta))
    ds["upload_received_bytes"] = int(ds.get("upload_received_bytes") or 0) + max(0, int(received_bytes_delta))
    ds["staging_host_path"] = locs["host_path"]
    ds["staging_container_path"] = locs["container_path"]
    ds["staging_object_prefix"] = locs["object_prefix"]
    ds["staging_purged"] = False
    execute(
        db,
        """UPDATE jobs
              SET disk_source=CAST(:ds AS jsonb),
                  status=CASE
                           WHEN status IN ('created','registered','pending','uploaded','awaiting_segments')
                           THEN 'awaiting_segments'
                           ELSE status
                         END,
                  updated_at=NOW()
            WHERE id=:job_id""",
        {"ds": json.dumps(ds), "job_id": job_id},
    )
    _commit_register_progress(db)
    return ds


def register_uploaded_intake(
    db: Session,
    job_id: str,
    *,
    staged_files: list[dict] | None = None,
    source_type: str = "disk",
) -> dict:
    """Register files a remote browser uploaded into DATA_ROOT/uploads."""
    from app.services.client_intake import count_staged_files, staging_locations, upload_root
    from app.services.mobile_os import load_job_disk_source

    folder = upload_root() / job_id / "intake"
    if not folder.is_dir():
        raise ValueError(
            "Upload staging folder is missing. Wait until every image file from this computer "
            "has finished transferring to the forensic server."
        )
    n_disk = count_staged_files(job_id)
    if n_disk <= 0:
        raise ValueError(
            "Client upload dump is empty. Wait until every image file from this computer "
            "has finished transferring to the forensic server, then Try again."
        )
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
    ds = dict(load_job_disk_source(row))
    expected = int(ds.get("upload_expected_files") or 0)
    received = int(ds.get("upload_received_files") or 0)
    if expected > 0 and (n_disk < expected or received < expected):
        raise ValueError(
            f"Client upload is still in progress ({min(n_disk, received)}/{expected} fully received file(s); "
            f"{n_disk} visible in staging). All other agents wait until every image file has arrived."
        )
    locs = staging_locations(job_id)
    ds["intake"] = "browser_upload"
    ds["source_origin"] = "client_browser"
    ds["transport_mode"] = "staged_upload"
    ds["source_residency"] = "client_uploaded_to_server"
    ds["transfer_required"] = True
    ds["download_required"] = True
    ds["transport"] = "staged_upload"
    ds["cleanup_policy"] = "delete_after_pipeline_success"
    ds["upload_parallelism"] = 5
    # Keep the global pipeline gate closed while the now-complete byte set is
    # listed, fingerprinted and registered. Only successful registration below
    # transitions to `complete`.
    ds["upload_status"] = "verifying"
    ds["upload_received_files"] = max(received, n_disk)
    ds["staging_host_path"] = locs["host_path"]
    ds["staging_container_path"] = locs["container_path"]
    ds["staging_object_prefix"] = locs["object_prefix"]
    ds["staging_purged"] = False
    ds["evidence_folder"] = str(folder)
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:job_id",
        {"ds": json.dumps(ds), "job_id": job_id},
    )
    _commit_register_progress(db)
    write_disk_log(
        db,
        job_id,
        f"Client bytes complete — {n_disk} file(s) staged at {locs['host_path']} "
        f"(container {locs['container_path']}). Verifying and registering the full set before releasing any later agent.",
        stage="evidence_register",
        metadata={"intake": "browser_upload", "count": n_disk, "upload_status": "verifying", **locs},
    )
    db.commit()
    result = register_segments(
        db,
        job_id,
        path=str(folder),
        source_type=source_type,
        skip_folder_list=False,
    )
    row = fetchone(db, "SELECT disk_source FROM jobs WHERE id=:job_id", {"job_id": job_id}) or {}
    ds = dict(load_job_disk_source(row))
    ds["intake"] = "browser_upload"
    ds["source_origin"] = "client_browser"
    ds["transport_mode"] = "staged_upload"
    ds["source_residency"] = "client_uploaded_to_server"
    ds["transfer_required"] = True
    ds["download_required"] = True
    ds["transport"] = "staged_upload"
    ds["cleanup_policy"] = "delete_after_pipeline_success"
    ds["upload_parallelism"] = 5
    ds["upload_status"] = "complete"
    ds["staging_host_path"] = locs["host_path"]
    ds["staging_container_path"] = locs["container_path"]
    ds["staging_object_prefix"] = locs["object_prefix"]
    ds["staging_purged"] = False
    ds["evidence_folder"] = str(folder)
    execute(
        db,
        "UPDATE jobs SET disk_source=CAST(:ds AS jsonb), status='registered', updated_at=NOW() WHERE id=:job_id",
        {"ds": json.dumps(ds), "job_id": job_id},
    )
    _commit_register_progress(db)
    try:
        from app.services.download_agent import signal_download_complete

        signal_download_complete(db, job_id, received_files=n_disk)
    except Exception as exc:
        log.warning("download_agent complete signal failed job=%s: %s", job_id, exc)
    return result


def _evidence_row(row: dict) -> dict:
    created = row["created_at"]
    return {
        "id": str(row["id"]),
        "job_id": str(row["job_id"]),
        "original_name": row["original_name"],
        "relative_path": row.get("relative_path"),
        "storage_uri": row.get("storage_uri"),
        "sha256": row.get("sha256"),
        "status": row["status"],
        "size_bytes": row.get("size_bytes"),
        "created_at": created.isoformat() if hasattr(created, "isoformat") else str(created),
    }


def is_disk_image_filename(name: str) -> bool:
    """True for E01/EWF/raw disk images — not UFED/mobile package extensions."""
    from app.disk_forensic.segments import is_disk_image_filename as _disk_only

    return bool(_disk_only(name) or SEGMENT_RE.match(name) or DISK_EXT_RE.search(name or ""))
