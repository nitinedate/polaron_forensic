"""Mobile forensic extraction segment detection (.pas, .ufd, .ufdx, archives)."""

from __future__ import annotations

import json
import os
import re
import zipfile
from pathlib import Path

# Mobile extraction companions — registered from host folder like E01 segments.
MOBILE_SEGMENT_EXTENSIONS = frozenset({".pas", ".ufd", ".ufdx", ".zip"})

MOBILE_SEGMENT_NAME_RE = re.compile(
    r"\.(?:pas(?:\d+)?|ufd|ufdx|zip)$",
    re.I,
)

# 28_01_2025Vivo.pas001 style
_PAS_PART_SUFFIX_RE = re.compile(r"^(?P<base>.+)\.pas(?P<part>\d+)$", re.I)
# 28_01_2025Vivo1.pas style (digit before .pas)
_PAS_INDEXED_RE = re.compile(r"^(?P<stem>.+?)(?P<idx>\d+)\.pas$", re.I)
# 28_01_2025Vivo.pas style
_PAS_SINGLE_RE = re.compile(r"^(?P<base>.+)\.pas$", re.I)
# run1.part-00000.zip payload shards
_PAYLOAD_PART_ZIP_RE = re.compile(r"^(?P<base>.+)\.part-(?P<idx>\d+)$", re.I)


def is_mobile_segment_filename(name: str) -> bool:
    if not name:
        return False
    if MOBILE_SEGMENT_NAME_RE.search(name):
        return True
    path = Path(name)
    if path.suffix.lower() in MOBILE_SEGMENT_EXTENSIONS:
        return True
    return _looks_like_zip_archive(name)


def _looks_like_zip_archive(name: str) -> bool:
    """Some mobile exports use extensionless zip archives (e.g. vivo_V2403)."""
    path = Path(name)
    if path.suffix.lower() == ".zip":
        return True
    if path.suffix:
        return False
    try:
        return path.is_file() and zipfile.is_zipfile(path)
    except OSError:
        return False


def mobile_segment_key(name: str) -> tuple[str, int, str] | None:
    """Return (set_key, part_number, format) for a mobile segment filename."""
    lower = name.lower()
    if lower.endswith(".ufd"):
        base = Path(name).stem
        return f"{base}.mobile", 1, "ufd"
    if lower.endswith(".ufdx"):
        base = Path(name).stem
        return f"{base}.mobile", 1, "ufdx"
    if lower.endswith(".zip") or (not Path(name).suffix and _looks_like_zip_archive(name)):
        stem = Path(name).stem or name
        part = _PAYLOAD_PART_ZIP_RE.match(stem)
        if part:
            return f"{part.group('base')}.mobile", int(part.group("idx")) + 1, "zip"
        return f"{stem}.mobile", 1, "zip"

    m = _PAS_PART_SUFFIX_RE.match(name)
    if m:
        return f"{m.group('base')}.pas", int(m.group("part")), "pas"
    m = _PAS_INDEXED_RE.match(name)
    if m:
        idx = int(m.group("idx"))
        # Mobile multi-part exports use small indices (Vivo1.pas); model numbers like V2403 must not match.
        if 1 <= idx <= 99:
            stem = m.group("stem")
            return f"{stem}.pas", idx + 1, "pas"
    m = _PAS_SINGLE_RE.match(name)
    if m:
        return f"{m.group('base')}.pas", 1, "pas"
    return None


_IOS_COLLECTION_MARKERS = frozenset(
    {"ios_image", "ios_backup", "afc_media", "house_arrest", "readable_artifacts"}
)
_ANDROID_COLLECTION_MARKERS = frozenset(
    {"shared_storage", "android_backup", "sdcard", "adb_pull"}
)


_PAYLOAD_HINTS = (
    "dump/",
    "02_original_extraction",
    "ios_image",
    "ios_backup",
    "afc_media",
    "house_arrest",
    "data/data",
    "shared_storage",
    "whatsapp",
    "readable_artifacts",
    "sdcard",
)
_PAYLOAD_MEMBER_PREFIXES = (
    "02_original_extraction/",
    "dump/",
)


def mobile_package_has_payload(path: Path) -> bool:
    """True for a UFED/Aetheris package that actually contains phone files (not a marker zip)."""
    try:
        if not path.is_file():
            return False
        name_l = path.name.lower()
        if ".part-" in name_l and path.suffix.lower() == ".zip":
            return path.stat().st_size > 0
        size = path.stat().st_size
    except OSError:
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()[:120]
    except (OSError, zipfile.BadZipFile):
        return path.suffix.lower() in {".pas", ".ufd", ".ufdx"} and size >= 1_048_576
    joined = " ".join(names).lower()
    if any(hint in joined for hint in _PAYLOAD_HINTS):
        return True
    if size < 1_048_576:
        return any(
            n.replace("\\", "/").lower().startswith(_PAYLOAD_MEMBER_PREFIXES)
            for n in names
        )
    return False


def zip_contains_extract_payload(path: Path) -> bool:
    """True when extract should read this zip instead of walking ORIGINAL_PATH."""
    if mobile_package_has_payload(path):
        return True
    try:
        if not path.is_file() or path.suffix.lower() not in {".zip", ".pas", ".ufd"}:
            return False
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist()[:120]:
                lower = name.replace("\\", "/").lower()
                if lower.startswith(_PAYLOAD_MEMBER_PREFIXES):
                    return True
    except (OSError, zipfile.BadZipFile):
        return False
    return False


def _unique_existing_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            if not path.is_file():
                continue
            key = str(path.resolve())
        except OSError:
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


_CASE_EXPORT_PARENTS = frozenset(
    {
        "02_original_extraction",
        "original",
        "03_working_copy",
        "working_copy",
        "05_exports",
        "05_export",
        "07_logs",
        "08_hashes",
    }
)


def export_dirs_near(path: Path) -> list[Path]:
    """Folders that may hold 05_Exports payload zips next to a live collection."""
    folder = path if path.is_dir() else path.parent
    found: list[Path] = [folder]
    try:
        parent = folder.parent
        grand = parent.parent
        if parent.name.lower() in _CASE_EXPORT_PARENTS:
            found.append(grand / "05_Exports" / folder.name)
            found.append(grand / "05_Exports")
            found.append(grand / "02_Original_Extraction" / folder.name)
        exports = folder / "05_Exports"
        if exports.is_dir():
            found.append(exports)
            for child in exports.iterdir():
                if child.is_dir():
                    found.append(child)
        if parent.name.lower() in {"05_exports", "05_export"}:
            found.append(folder)
        cursor = folder
        for _ in range(6):
            case_exports = cursor / "05_Exports"
            if cursor.name.upper().startswith("CASE-") or case_exports.is_dir():
                if case_exports.is_dir():
                    found.append(case_exports)
                    run_exports = case_exports / folder.name
                    if run_exports.is_dir():
                        found.append(run_exports)
                break
            nxt = cursor.parent
            if nxt == cursor:
                break
            cursor = nxt
    except OSError:
        pass
    uniq: list[Path] = []
    seen: set[str] = set()
    for item in found:
        try:
            key = str(item.resolve())
        except OSError:
            key = str(item)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(item)
    return uniq


# ---------------------------------------------------------------------------
# Case-layout export discovery (export_catalog.json is the authority)
# ---------------------------------------------------------------------------

_CASE_RUN_PARENTS = frozenset(
    {
        "02_original_extraction",
        "03_working_copy",
        "05_exports",
        "05_export",
        "06_reports",
        "07_logs",
        "08_hashes",
        "09_review",
    }
)
_EXPORT_CATALOG_NAME = "export_catalog.json"
_METADATA_PACKAGE_EXTS = (".pas", ".ufd", ".ufdx")


def _container_candidates(raw: str) -> list[Path]:
    """Windows/host path from a catalog -> paths that may exist inside Docker."""
    out: list[Path] = []
    text = (raw or "").strip()
    if not text:
        return out
    try:
        from app.services.dir_walk import rewrite_container_host_path

        rewritten = rewrite_container_host_path(text)
        if rewritten is not None:
            out.append(rewritten)
    except Exception:
        pass
    out.append(Path(text.replace("\\", "/") if os.sep == "/" else text))
    return out


def _existing(raw: str, *, fallback_dir: Path | None = None) -> Path | None:
    for cand in _container_candidates(raw):
        try:
            if cand.is_file():
                return cand
        except OSError:
            continue
    if fallback_dir is not None:
        name = Path((raw or "").replace("\\", "/")).name
        if name:
            try:
                cand = fallback_dir / name
                if cand.is_file():
                    return cand
            except OSError:
                pass
    return None


def export_catalog_candidates(export_dir: Path) -> list[Path]:
    """Where export_catalog.json may live: 07_Logs/<run> (V22) or beside the packages (legacy)."""
    out: list[Path] = []
    try:
        if export_dir.parent.name.lower() in {"05_exports", "05_export"}:
            out.append(export_dir.parent.parent / "07_Logs" / export_dir.name / _EXPORT_CATALOG_NAME)
        out.append(export_dir.parent / ".aetheris" / export_dir.name / _EXPORT_CATALOG_NAME)
    except Exception:
        pass
    out.append(export_dir / _EXPORT_CATALOG_NAME)
    return out


def read_export_catalog(export_dir: Path) -> dict | None:
    for cat in export_catalog_candidates(export_dir):
        try:
            if not cat.is_file() or cat.stat().st_size > 4 * 1024 * 1024:
                continue
            data = json.loads(cat.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            continue
    return None


def _dir_has_export_payload(folder: Path) -> bool:
    """True for a run export folder: catalog, shards, or the four-file layout (<run>.zip + .ufdx/.ufd/.pas)."""
    try:
        for cat in export_catalog_candidates(folder):
            if cat.is_file():
                return True
        run_l = folder.name.lower()
        exts_seen: set[str] = set()
        with os.scandir(folder) as it:
            for ent in it:
                if not ent.is_file(follow_symlinks=False):
                    continue
                low = ent.name.lower()
                if low.endswith(".zip") and ".part-" in low:
                    return True
                stem, dot, ext = low.rpartition(".")
                if dot and ext in {"zip", "ufd", "ufdx", "pas"} and (stem == run_l or ".part-" not in low):
                    exts_seen.add(ext)
        return "zip" in exts_seen and bool(exts_seen & {"ufdx", "ufd", "pas"})
    except OSError:
        return False


def _latest_run_dir(exports_root: Path, *, prefer_name: str = "") -> Path | None:
    """Newest run folder under 05_Exports that actually holds a payload."""
    try:
        if prefer_name:
            preferred = exports_root / prefer_name
            if preferred.is_dir() and _dir_has_export_payload(preferred):
                return preferred
        runs: list[tuple[float, Path]] = []
        with os.scandir(exports_root) as it:
            for ent in it:
                if not ent.is_dir(follow_symlinks=True):
                    continue
                run = Path(ent.path)
                if _dir_has_export_payload(run):
                    try:
                        mtime = ent.stat().st_mtime
                    except OSError:
                        mtime = 0.0
                    runs.append((mtime, run))
        runs.sort(key=lambda x: (x[0], x[1].name))
        return runs[-1][1] if runs else None
    except OSError:
        return None


def locate_case_export_dir(folder: Path) -> Path | None:
    """Find the 05_Exports/<run> folder that belongs to *folder*.

    Accepts the run folder itself, 05_Exports, a case root, or any sibling run
    folder (02_Original_Extraction/<run>, 03_Working_Copy/<run>, 07_Logs/<run>).
    """
    try:
        folder = Path(folder)
        if folder.is_file():
            folder = folder.parent
        if not folder.is_dir():
            return None
    except OSError:
        return None
    try:
        if _dir_has_export_payload(folder):
            return folder
        name_l = folder.name.lower()
        parent = folder.parent
        parent_l = parent.name.lower()
        # 05_Exports itself
        if name_l in {"05_exports", "05_export"}:
            return _latest_run_dir(folder)
        # <case>/<stage>/<run>
        if parent_l in _CASE_RUN_PARENTS:
            case_root = parent.parent
            for exports_name in ("05_Exports", "05_exports", "05_Export"):
                exports_root = case_root / exports_name
                if exports_root.is_dir():
                    hit = _latest_run_dir(exports_root, prefer_name=folder.name)
                    if hit is not None:
                        return hit
            return None
        # case root
        for exports_name in ("05_Exports", "05_exports", "05_Export"):
            exports_root = folder / exports_name
            if exports_root.is_dir():
                return _latest_run_dir(exports_root)
    except OSError:
        return None
    return None


def case_export_payload(folder: Path) -> dict:
    """Payload shards + companion packages for the export run related to *folder*.

    Returns ``{"export_dir", "catalog", "shards", "packages", "meta_zip"}``.
    ``shards`` are the ``.part-NNNNN.zip`` payload archives (or the single full
    zip when there are no shards); ``packages`` are the small .pas/.ufd/.ufdx
    companions. Never walks the phone tree.
    """
    empty = {"export_dir": None, "catalog": None, "shards": [], "packages": [], "meta_zip": None}
    export_dir = locate_case_export_dir(folder)
    if export_dir is None:
        return empty
    catalog = read_export_catalog(export_dir)
    shards: list[Path] = []
    packages: list[Path] = []
    meta_zip: Path | None = None

    if catalog:
        for raw in catalog.get("payload_shards") or []:
            hit = _existing(str(raw), fallback_dir=export_dir)
            if hit is not None:
                shards.append(hit)
        pkgs = catalog.get("packages") or {}
        if isinstance(pkgs, dict):
            for key, raw in pkgs.items():
                hit = _existing(str(raw), fallback_dir=export_dir)
                if hit is None:
                    continue
                if str(key).lower() == "zip":
                    meta_zip = hit
                else:
                    packages.append(hit)

    if not shards:
        try:
            found = [
                p for p in export_dir.iterdir()
                if p.is_file() and p.suffix.lower() == ".zip" and ".part-" in p.name.lower()
            ]
        except OSError:
            found = []
        shards = found
    if not packages:
        try:
            packages = [
                p for p in export_dir.iterdir()
                if p.is_file() and p.suffix.lower() in _METADATA_PACKAGE_EXTS
            ]
        except OSError:
            packages = []
    if meta_zip is None:
        try:
            for p in export_dir.iterdir():
                if p.is_file() and p.suffix.lower() == ".zip" and ".part-" not in p.name.lower():
                    meta_zip = p
                    break
        except OSError:
            pass

    def _shard_index(p: Path) -> int:
        m = _PAYLOAD_PART_ZIP_RE.match(p.stem)
        return int(m.group("idx")) if m else 10**9

    shards = sorted(_unique_existing_files(shards), key=_shard_index)
    packages = sorted(_unique_existing_files(packages), key=lambda p: p.name.lower())
    if not shards and meta_zip is not None:
        # No shard set — the single zip *is* the payload (small phones).
        if zip_contains_extract_payload(meta_zip):
            shards = [meta_zip]
    return {
        "export_dir": export_dir,
        "catalog": catalog,
        "shards": shards,
        "packages": packages,
        "meta_zip": meta_zip,
    }


def case_export_segment_paths(folder: Path) -> list[Path]:
    """Files to register for a case-layout mobile run.

    Payload shards are the evidence extract reads (zip-only enumeration, the
    sealed original is never walked). The .pas/.ufd/.ufdx companions are only
    registered when there is no shard set at all, so a metadata package never
    drags extract into a multi-hour walk of the junctioned phone tree.
    """
    info = case_export_payload(folder)
    if info["shards"]:
        return list(info["shards"])
    return list(info["packages"])


def list_payload_zip_archives(root: Path | None, segment_paths: list[str] | None = None) -> list[Path]:
    """Payload zips extract should read (part shards and inline 02_Original_Extraction zips)."""
    candidates: list[Path] = []
    bases: list[Path] = []
    if root is not None:
        bases.append(Path(root))
    for raw in segment_paths or []:
        bases.append(Path(raw))
    # Fast path: a case-layout run with export_catalog.json / .part-NNNNN.zip shards.
    for base in bases:
        try:
            info = case_export_payload(base)
        except Exception:
            info = None
        if info and info["shards"]:
            return list(info["shards"])
    seen_dirs: set[str] = set()
    for base in bases:
        for folder in export_dirs_near(base):
            try:
                key = str(folder.resolve())
            except OSError:
                key = str(folder)
            if key in seen_dirs or not folder.is_dir():
                continue
            seen_dirs.add(key)
            try:
                for entry in folder.iterdir():
                    if entry.is_file() and entry.suffix.lower() in {".zip", ".pas", ".ufd"}:
                        candidates.append(entry)
            except OSError:
                continue
        if base.is_file() and base.suffix.lower() in {".zip", ".pas", ".ufd"}:
            candidates.append(base)
            try:
                stem = base.stem
                part = _PAYLOAD_PART_ZIP_RE.match(stem)
                run = part.group("base") if part else stem
                candidates.extend(base.parent.glob(f"{run}.part-*.zip"))
            except OSError:
                pass
    payload = [p for p in _unique_existing_files(candidates) if zip_contains_extract_payload(p)]
    return payload


def live_mobile_collection_segments(folder: Path) -> list[Path]:
    """rag_new2 iOS path: register the backup folder, plus AFC/house_arrest. Skip rematerialize."""
    from app.services.dir_walk import resolve_openable_dir

    found: list[Path] = []

    def _open(path: Path) -> Path | None:
        return resolve_openable_dir(path)

    def _has_manifest(path: Path) -> bool:
        try:
            return (path / "Manifest.db").is_file() or (path / "Manifest.plist").is_file()
        except OSError:
            return False

    image_root = _open(folder / "ios_image") or _open(folder / "ios_backup")
    if image_root is not None:
        kids: list[Path] = []
        try:
            for child in image_root.iterdir():
                opened = _open(child)
                if opened is not None and _has_manifest(opened):
                    kids.append(opened)
        except OSError:
            kids = []
        found.extend(kids or [image_root])
    else:
        opened = _open(folder)
        if opened is not None and _has_manifest(opened):
            found.append(opened)
    for name in ("afc_media", "house_arrest", "shared_storage", "android_backup", "sdcard"):
        opened = _open(folder / name)
        if opened is not None and opened not in found:
            found.append(opened)
    return found


def folder_is_live_mobile_collection(folder: Path) -> bool:
    """True for an Advanced Logical / ADB pull tree (not a UFED .pas/.zip)."""
    try:
        names = {entry.name.lower() for entry in folder.iterdir()}
    except OSError:
        return False
    if names & _IOS_COLLECTION_MARKERS:
        return True
    if names & _ANDROID_COLLECTION_MARKERS:
        return True
    try:
        if (folder / "Manifest.db").is_file() or (folder / "Manifest.plist").is_file():
            return True
    except OSError:
        return False
    return False


def mobile_segments_in_folder(folder: Path) -> list[str]:
    names: list[str] = []
    try:
        for entry in folder.iterdir():
            if not entry.is_file():
                continue
            if is_mobile_segment_filename(entry.name):
                names.append(entry.name)
                continue
            if not entry.suffix:
                try:
                    if zipfile.is_zipfile(entry):
                        names.append(entry.name)
                except OSError:
                    pass
    except OSError:
        pass
    return sorted(names)


def folder_has_mobile_segments(folder: Path) -> bool:
    return bool(mobile_segments_in_folder(folder)) or folder_is_live_mobile_collection(folder)


def infer_mobile_platform_from_names(names: list[str]) -> str | None:
    """Infer Android vs iOS from segment filenames (.pas/.ufd/.ufdx/.zip)."""
    blob = " ".join(names).lower()
    if any(token in blob for token in ("vivo", "android", "samsung", "oppo", "xiaomi", "oneplus", "pixel", "huawei")):
        return "Android"
    if any(token in blob for token in ("iphone", "ios", "ipad", "apple", "ufdr")):
        return "iOS"
    if any(name.lower().endswith(ext) for name in names for ext in MOBILE_SEGMENT_EXTENSIONS):
        return "Android"
    return None


def infer_mobile_platform_from_paths(paths: list[str]) -> str | None:
    blob = " ".join(paths).lower()
    if any(token in blob for token in ("/mobile/", "\\mobile\\", "filesystem 01", "filesystem 02")):
        return "Android"
    if any(token in blob for token in ("iphone", "ios", "ipad", "apple")):
        return "iOS"
    if any(token in blob for token in ("vivo", "android", "samsung", "oppo", "xiaomi")):
        return "Android"
    return None


def is_mobile_evidence_format(fmt: str | None) -> bool:
    return (fmt or "").strip().lower() in {"pas", "ufd", "ufdx", "zip", "mobile", "backup"}


def infer_mobile_axiom_platform(
    *,
    evidence_names: list[str] | None = None,
    host_paths: list[str] | None = None,
    disk_format: str | None = None,
    case_type: str | None = None,
    examiner_mobile_os: str | None = None,
) -> str | None:
    from app.services.mobile_os import mobile_os_to_axiom_platform

    examiner_platform = mobile_os_to_axiom_platform(examiner_mobile_os)
    if examiner_platform:
        return examiner_platform

    case = (case_type or "").strip().lower()
    if "android" in case:
        return "Android"
    if "ios" in case or "iphone" in case:
        return "iOS"
    if "mobile" in case:
        # Generic mobile case without examiner OS — fall through to evidence inference.
        pass
    if is_mobile_evidence_format(disk_format):
        from_names = infer_mobile_platform_from_names(evidence_names or [])
        if from_names:
            return from_names
        from_paths = infer_mobile_platform_from_paths(host_paths or [])
        if from_paths:
            return from_paths
        return "Android"
    from_names = infer_mobile_platform_from_names(evidence_names or [])
    if from_names:
        return from_names
    from_paths = infer_mobile_platform_from_paths(host_paths or [])
    return from_paths
