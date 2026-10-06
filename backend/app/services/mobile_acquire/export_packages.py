"""Build portable evidence image packages after a sealed collection.

Creates examiner-facing containers under ``05_Exports/<run>/``:

* ``.zip``  — catalog + metadata; payload lives in ``*.part-NNNNN.zip`` shards
* ``*.part-NNNNN.zip`` — ZIP_STORED acquisition files under ``02_Original_Extraction/``
* ``.ufdx`` — XML case index (Aetheris schema)
* ``.ufd``  — thin ZIP unit descriptor (points at the payload zips)
* ``.pas``  — thin ZIP portable acquisition set (same payload model as .ufd)

Analysis extract/RAG reads **only those payload zips** — not the live sealed folder.
Pass ``--metadata-only`` to skip packing payload. Large phones are sharded so we
never hang on one ZIP64 DEFLATE of 80+ GiB.

These are **Aetheris portable packages**, not binary-compatible Cellebrite UFED
``.pas`` / ``.ufd`` files.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from xml.sax.saxutils import escape

from app.services.mobile_acquire.adb_tar_pull import iter_tree_files

# Export layout (V22): 05_Exports/<run>/ holds exactly four files —
#   <run>.zip   full ZIP64 payload (02_Original_Extraction/ + readable_artifacts/ + logs/hashes)
#   <run>.ufd / <run>.pas   thin sidecars (metadata + hash manifest)
#   <run>.ufdx  XML index
# Everything else (export_catalog.json, content_inventory.json, shard catalogs,
# FULL_ZIP_LOCATION.txt) goes to 07_Logs/<run>/. Payload sharding is opt-in
# (AETHERIS_EXPORT_SHARDS=1) for operators who need resumable multi-part output.
DEFAULT_FULL_ZIP_MAX_BYTES = 2 * 1024**3
SIDE_FILES_DIRNAME = "07_Logs"
_DEFAULT_PAYLOAD_SHARD_MIN_BYTES = 256 * 1024**2
_DEFAULT_PAYLOAD_SHARD_BYTES = 4 * 1024**3
_SKIP_ZIP_DIR_NAMES = {"readable_artifacts", "_package_marker"}
_SKIP_ZIP_HASH_BYTES = 2 * 1024**3
_SEALED_MARKERS = (
    "ios_image",
    "ios_backup",
    "afc_media",
    "house_arrest",
    "shared_storage",
    "android_backup",
)
_MAX_LOG_FILE_IN_META_ZIP = 2 * 1024 * 1024
_DEFAULT_EXPORT_RESERVE_BYTES = 1024**3
_TIGHT_EXPORT_MIN_FREE_RATIO = 0.70
_SAMPLE_BYTES_PER_FILE = 1024 * 1024
_SAMPLE_TOTAL_BYTES = 256 * 1024 * 1024


class ExportVolumeFullError(OSError):
    """Raised when free space drops below the configured live-write reserve."""


class ExportSpaceError(OSError):
    """Raised when no available volume can hold a complete evidence ZIP."""

    def __init__(self, *, payload_bytes: int, estimated_zip_bytes: int, best_free_bytes: int,
                 reserve_bytes: int, requested_dir: str, candidate_dir: str = "") -> None:
        self.payload_bytes = int(payload_bytes)
        self.estimated_zip_bytes = int(estimated_zip_bytes)
        self.best_free_bytes = int(best_free_bytes)
        self.reserve_bytes = int(reserve_bytes)
        self.requested_dir = requested_dir
        self.candidate_dir = candidate_dir or requested_dir
        need = self.estimated_zip_bytes + self.reserve_bytes
        shortfall = max(0, need - self.best_free_bytes)
        gib = 1024 ** 3
        super().__init__(
            "Not enough free space for the complete mobile evidence ZIP. "
            f"Acquired payload={self.payload_bytes / gib:.2f} GiB, "
            f"estimated ZIP={self.estimated_zip_bytes / gib:.2f} GiB, "
            f"free={self.best_free_bytes / gib:.2f} GiB, reserve={self.reserve_bytes / gib:.2f} GiB, "
            f"shortfall={shortfall / gib:.2f} GiB. "
            "Aetheris kept the sealed original on disk. Use a metadata-only package, or free space "
            "and pass --full / set AETHERIS_EXPORT_ROOT to retry a complete ZIP."
        )

    def as_dict(self) -> dict[str, Any]:
        need = self.estimated_zip_bytes + self.reserve_bytes
        return {
            "code": "mobile_export_insufficient_space",
            "payload_bytes": self.payload_bytes,
            "estimated_zip_bytes": self.estimated_zip_bytes,
            "free_bytes": self.best_free_bytes,
            "reserve_bytes": self.reserve_bytes,
            "shortfall_bytes": max(0, need - self.best_free_bytes),
            "requested_export_dir": self.requested_dir,
            "candidate_export_dir": self.candidate_dir,
        }


def is_sealed_mobile_original(original: Path) -> bool:
    root = Path(original)
    return any((root / name).exists() for name in _SEALED_MARKERS)


@dataclass
class ExportBundle:
    run_name: str
    export_dir: str
    packages: dict[str, str] = field(default_factory=dict)
    package_sha256: dict[str, str] = field(default_factory=dict)
    full_payload_in_zip: bool = False
    payload_shards: list[str] = field(default_factory=list)
    zip_export_dir: str = ""
    zip_storage_plan: dict[str, Any] = field(default_factory=dict)
    format_note: str = (
        "Aetheris portable packages (.zip/.ufdx/.ufd/.pas). Not native Cellebrite "
        "UFED binary containers — use folder import for PA when required."
    )
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_name": self.run_name,
            "export_dir": self.export_dir,
            "packages": self.packages,
            "package_sha256": self.package_sha256,
            "full_payload_in_zip": self.full_payload_in_zip,
            "payload_shards": list(self.payload_shards),
            "zip_export_dir": self.zip_export_dir or self.export_dir,
            "zip_storage_plan": self.zip_storage_plan,
            "format_note": self.format_note,
            "warnings": self.warnings,
        }


ProgressCb = Callable[[dict[str, Any]], None] | None


def _sha256_file(path: Path) -> str:
    try:
        if path.stat().st_size > _SKIP_ZIP_HASH_BYTES:
            return ""
    except OSError:
        return ""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_export_files(root: Path, *, follow_junctions: bool):
    yield from iter_tree_files(
        root,
        follow_junctions=follow_junctions,
        skip_dir_names=_SKIP_ZIP_DIR_NAMES,
    )


def _dir_bytes(root: Path, *, follow_junctions: bool = False) -> int:
    total = 0
    if not root.is_dir():
        return 0
    for full, _rel in _iter_export_files(root, follow_junctions=follow_junctions):
        try:
            total += os.path.getsize(full)
        except OSError:
            pass
    return total


def _dir_stats(root: Path, *, follow_junctions: bool = False) -> tuple[int, int]:
    count = 0
    total = 0
    if not root.is_dir():
        return 0, 0
    for full, _rel in _iter_export_files(root, follow_junctions=follow_junctions):
        try:
            total += os.path.getsize(full)
            count += 1
        except OSError:
            pass
    return count, total


def _free_bytes(path: Path) -> int:
    try:
        path.mkdir(parents=True, exist_ok=True)
        return int(shutil.disk_usage(path).free)
    except OSError:
        return -1


def _reserve_bytes() -> int:
    raw = (os.environ.get("AETHERIS_EXPORT_RESERVE_GB") or "1").strip()
    try:
        return max(256 * 1024**2, int(float(raw) * 1024**3))
    except (TypeError, ValueError):
        return _DEFAULT_EXPORT_RESERVE_BYTES


def _payload_shard_min_bytes() -> int:
    raw = (os.environ.get("AETHERIS_PAYLOAD_SHARD_MIN_BYTES") or "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except (TypeError, ValueError):
            pass
    return _DEFAULT_PAYLOAD_SHARD_MIN_BYTES


def _payload_shard_bytes() -> int:
    raw = (os.environ.get("AETHERIS_PAYLOAD_SHARD_BYTES") or "").strip()
    if raw:
        try:
            return max(1024 * 1024, int(raw))
        except (TypeError, ValueError):
            pass
    return _DEFAULT_PAYLOAD_SHARD_BYTES


def shards_enabled() -> bool:
    """Opt-in multi-part payload (.part-NNNNN.zip). Default is one full ZIP."""
    raw = str(os.environ.get("AETHERIS_EXPORT_SHARDS") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def side_files_dir(export_dir: Path, run_name: str, logs: Path | None = None) -> Path:
    """Where non-package files live so 05_Exports/<run> stays four files only.

    Prefers the case's 07_Logs/<run>; falls back to the run's log dir passed by
    the caller; last resort is a hidden ``.aetheris`` folder beside the export.
    """
    export_dir = Path(export_dir)
    candidates: list[Path] = []
    try:
        case_root = export_dir.parent.parent
        if export_dir.parent.name.lower() in {"05_exports", "05_export"}:
            candidates.append(case_root / SIDE_FILES_DIRNAME / run_name)
    except Exception:
        pass
    if logs:
        candidates.append(Path(logs))
    candidates.append(export_dir.parent / ".aetheris" / run_name)
    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            return cand
        except OSError:
            continue
    return export_dir


def find_readable_artifacts(original: Path, extra_roots: list[Path] | None = None) -> Path | None:
    """Materialised readable_artifacts tree to fold into the full ZIP."""
    roots = [Path(original) / "readable_artifacts"] + [Path(r) for r in (extra_roots or [])]
    for root in roots:
        try:
            if root.is_dir() and any(root.iterdir()):
                return root
        except OSError:
            continue
    return None


def payload_shard_catalog_complete(dest_dir: Path, catalog_dir: Path | None = None) -> bool:
    """True when a complete shard catalog exists and every shard is present in dest_dir."""
    catalog = Path(catalog_dir or dest_dir) / "payload_shards.json"
    if not catalog.is_file():
        catalog = Path(dest_dir) / "payload_shards.json"
    if not catalog.is_file():
        return False
    try:
        data = json.loads(catalog.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict) or not data.get("complete"):
        return False
    shards = data.get("shards") or []
    if not shards:
        return int(data.get("files") or 0) == 0
    return all((Path(dest_dir) / str(row.get("name") or "")).is_file() for row in shards if row.get("name"))


def _sample_deflate_ratio(root: Path) -> float:
    """Estimate fast-DEFLATE ratio without reading the whole acquisition.

    iOS backup payload files are hash-named, so filename extensions cannot tell us
    whether the data is JPEG/video/SQLite. Sampling file bytes is more reliable.
    The estimate is deliberately padded later; final writing also has a live
    free-space guard.
    """
    sampled = 0
    compressed = 0
    files = 0
    for full, _rel in _iter_export_files(root, follow_junctions=True):
        if sampled >= _SAMPLE_TOTAL_BYTES or files >= 512:
            break
        try:
            size = os.path.getsize(full)
            if size <= 0:
                continue
            take = min(_SAMPLE_BYTES_PER_FILE, size, _SAMPLE_TOTAL_BYTES - sampled)
            with open(full, "rb") as fh:
                data = fh.read(take)
            if not data:
                continue
            sampled += len(data)
            compressed += len(zlib.compress(data, 1))
            files += 1
        except OSError:
            continue
    if sampled <= 0:
        return 1.0
    ratio = compressed / sampled
    return max(0.45, min(1.02, ratio))


def _candidate_export_dirs(requested: Path, run_name: str) -> list[Path]:
    """Return requested/configured/Windows-volume export candidates in order."""
    out: list[Path] = [requested]
    configured = (os.environ.get("AETHERIS_EXPORT_ROOT") or "").strip()
    if configured:
        out.append(Path(configured) / run_name)
    if os.name == "nt":
        requested_drive = str(requested)[:2].upper()
        for letter in "DEFGHIJKLMNOPQRSTUVWXYZC":
            root = Path(f"{letter}:/")
            try:
                if not root.exists():
                    continue
            except OSError:
                continue
            candidate = root / "Aetheris_Mobile_Exports" / run_name
            if str(candidate)[:2].upper() == requested_drive:
                continue
            out.append(candidate)
    unique: list[Path] = []
    seen: set[str] = set()
    for item in out:
        key = os.path.normcase(os.path.abspath(str(item)))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _select_zip_destination(requested: Path, run_name: str, original: Path, payload_bytes: int) -> tuple[Path, bool, dict[str, Any]]:
    """Choose a volume and whether the payload should be DEFLATED.

    Prefer a fast stored ZIP when a volume can hold a second raw copy.  When the
    requested volume is only slightly short, use fast DEFLATE so a 85 GiB phone
    does not fail merely because the raw-copy precheck required 87+ GiB.
    """
    reserve = _reserve_bytes()
    candidates = _candidate_export_dirs(requested, run_name)
    free_map: list[tuple[Path, int]] = [(c, _free_bytes(c)) for c in candidates]
    raw_need = payload_bytes + reserve
    raw_fit = [(c, f) for c, f in free_map if f >= raw_need]
    if raw_fit:
        # Keep the requested case location when it fits; otherwise use the roomiest volume.
        chosen, free = raw_fit[0] if raw_fit[0][0] == requested else max(raw_fit, key=lambda x: x[1])
        return chosen, False, {
            "mode": "stored", "free_bytes": free, "reserve_bytes": reserve,
            "estimated_zip_bytes": payload_bytes, "sample_ratio": 1.0,
        }

    ratio = _sample_deflate_ratio(original)
    # Add 3% safety for central-directory/ratio variance. Never estimate larger than raw+1%.
    estimated = min(int(payload_bytes * 1.01), int(payload_bytes * min(1.0, ratio * 1.03)))
    compressed_need = estimated + reserve
    compressed_fit = [(c, f) for c, f in free_map if f >= compressed_need]
    if compressed_fit:
        chosen, free = compressed_fit[0] if compressed_fit[0][0] == requested else max(compressed_fit, key=lambda x: x[1])
        return chosen, True, {
            "mode": "deflate", "free_bytes": free, "reserve_bytes": reserve,
            "estimated_zip_bytes": estimated, "sample_ratio": ratio,
        }

    # If the estimate says no but a volume still has a plausible amount of free
    # space, do not gamble with evidence storage. Fail before hours of ZIP work.
    best_dir, best_free = max(free_map, key=lambda x: x[1]) if free_map else (requested, -1)
    if best_free < int(payload_bytes * _TIGHT_EXPORT_MIN_FREE_RATIO):
        estimated = max(estimated, int(payload_bytes * _TIGHT_EXPORT_MIN_FREE_RATIO))
    raise ExportSpaceError(
        payload_bytes=payload_bytes, estimated_zip_bytes=estimated,
        best_free_bytes=max(0, best_free), reserve_bytes=reserve,
        requested_dir=str(requested), candidate_dir=str(best_dir),
    )


def _assert_export_space(dest: Path, reserve_bytes: int) -> None:
    free = _free_bytes(dest.parent)
    if 0 <= free < reserve_bytes:
        raise ExportVolumeFullError(
            f"Export volume fell below safety reserve while writing ZIP: free={free} reserve={reserve_bytes}"
        )


def _write_file_index_jsonl(zf: zipfile.ZipFile, original: Path) -> int:
    count = 0
    with zf.open("file_index.jsonl", "w", force_zip64=True) as raw:
        for full, rel in _iter_export_files(original, follow_junctions=True):
            try:
                st = os.stat(full)
                row = {
                    "path": rel,
                    "size": st.st_size,
                    "mtime_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
                }
                raw.write((json.dumps(row, separators=(",", ":"), default=str) + "\n").encode("utf-8"))
                count += 1
            except OSError:
                continue
    return count


def _add_tree(
    zf: zipfile.ZipFile,
    root: Path,
    arc_prefix: str,
    *,
    compress: bool = False,
    progress: ProgressCb = None,
    progress_base_bytes: int = 0,
    progress_total_bytes: int = 0,
    reserve_bytes: int = 0,
    follow_junctions: bool = False,
) -> tuple[int, int]:
    count = 0
    written = 0
    if not root.is_dir():
        return 0, 0
    compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    last_emit = 0
    for full, rel in _iter_export_files(root, follow_junctions=follow_junctions):
        try:
            size = os.path.getsize(full)
            if reserve_bytes and count % 250 == 0:
                _assert_export_space(Path(zf.filename), reserve_bytes)
            zf.write(full, f"{arc_prefix}/{rel}", compress_type=compression)
            count += 1
            written += size
            if progress and (written - last_emit >= 64 * 1024 * 1024 or count % 500 == 0):
                done = progress_base_bytes + written
                phase_pct = round((done / progress_total_bytes) * 100, 1) if progress_total_bytes else None
                overall = round(90 + min(9.5, (phase_pct or 0) * 0.095), 1) if phase_pct is not None else 90
                progress({
                    "stage": "seal", "item": rel, "category": "Packaging",
                    "phase": "export_zip", "phase_progress_pct": phase_pct,
                    "progress_pct": overall, "export_bytes_done": done,
                    "export_bytes_total": progress_total_bytes, "export_files_done": count,
                })
                last_emit = written
        except ExportVolumeFullError:
            raise
        except OSError:
            continue
    return count, written


def _file_index(original: Path, limit: int | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not original.is_dir():
        return rows
    for full, rel in _iter_export_files(original, follow_junctions=True):
        try:
            st = os.stat(full)
            rows.append({
                "path": rel,
                "size": st.st_size,
                "mtime_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            })
        except OSError:
            continue
        if limit is not None and len(rows) >= limit:
            break
    return rows


def write_payload_shards(
    dest_dir: Path,
    *,
    original: Path,
    run_name: str,
    progress: ProgressCb = None,
    payload_bytes: int = 0,
    reserve_bytes: int = 0,
    shard_bytes: int | None = None,
    catalog_dir: Path | None = None,
) -> tuple[list[Path], dict[str, Any]]:
    """Write ZIP_STORED ``{run}.part-NNNNN.zip`` shards under dest_dir (opt-in).

    Each member is stored at ``02_Original_Extraction/<relative>``. Shards close
    as they fill so a killed writer still leaves complete parts on disk. The
    shard catalog is written to *catalog_dir* (07_Logs/<run>) when given.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    original = Path(original)
    limit = int(shard_bytes if shard_bytes is not None else _payload_shard_bytes())
    catalog_home = Path(catalog_dir) if catalog_dir else dest_dir
    catalog_path = catalog_home / "payload_shards.json"
    if payload_shard_catalog_complete(dest_dir, catalog_home):
        if not catalog_path.is_file():
            catalog_path = dest_dir / "payload_shards.json"
        data = json.loads(catalog_path.read_text(encoding="utf-8-sig"))
        paths = [dest_dir / str(row["name"]) for row in (data.get("shards") or []) if row.get("name")]
        return [p for p in paths if p.is_file()], data

    shards_meta: list[dict[str, Any]] = []
    paths: list[Path] = []
    shard_idx = 0
    zf: zipfile.ZipFile | None = None
    shard_path: Path | None = None
    shard_files = 0
    shard_stored = 0
    total_files = 0
    total_bytes = 0
    last_emit = 0

    def _close_shard() -> None:
        nonlocal zf, shard_path, shard_files, shard_stored, shard_idx
        if zf is None or shard_path is None:
            return
        zf.close()
        zf = None
        shards_meta.append({"name": shard_path.name, "files": shard_files, "bytes": shard_stored})
        paths.append(shard_path)
        shard_idx += 1
        shard_files = 0
        shard_stored = 0
        shard_path = None

    def _open_shard() -> None:
        nonlocal zf, shard_path, shard_files, shard_stored
        shard_path = dest_dir / f"{run_name}.part-{shard_idx:05d}.zip"
        if shard_path.exists():
            try:
                shard_path.unlink()
            except OSError:
                pass
        zf = zipfile.ZipFile(shard_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True)

    try:
        for full, rel in _iter_export_files(original, follow_junctions=True):
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if zf is not None and shard_stored > 0 and (shard_stored + size) > limit:
                _close_shard()
            if zf is None:
                _open_shard()
            if reserve_bytes and total_files % 250 == 0:
                _assert_export_space(dest_dir, reserve_bytes)
            assert zf is not None
            zf.write(full, f"02_Original_Extraction/{rel}", compress_type=zipfile.ZIP_STORED)
            shard_files += 1
            shard_stored += size
            total_files += 1
            total_bytes += size
            if progress and (total_bytes - last_emit >= 64 * 1024 * 1024 or total_files % 500 == 0):
                phase_pct = round((total_bytes / payload_bytes) * 100, 1) if payload_bytes else None
                overall = round(90 + min(9.5, (phase_pct or 0) * 0.095), 1) if phase_pct is not None else 90
                progress({
                    "stage": "seal", "item": rel, "category": "Packaging",
                    "phase": "export_zip", "phase_progress_pct": phase_pct,
                    "progress_pct": overall, "export_bytes_done": total_bytes,
                    "export_bytes_total": payload_bytes, "export_files_done": total_files,
                    "payload_shard": shard_path.name if shard_path else "",
                })
                last_emit = total_bytes
        _close_shard()
    except Exception:
        if zf is not None:
            try:
                zf.close()
            except Exception:
                pass
        raise

    catalog = {
        "complete": True,
        "format": "aetheris.payload_shards.v1",
        "run_name": run_name,
        "original": str(original),
        "files": total_files,
        "bytes": total_bytes,
        "shards": shards_meta,
    }
    catalog_path.write_text(json.dumps(catalog, indent=2, default=str), encoding="utf-8")
    return paths, catalog


def _write_main_zip(
    dest: Path,
    *,
    original: Path,
    logs: Path | None,
    hashes: Path | None,
    meta: dict[str, Any],
    include_payload: bool,
    progress: ProgressCb = None,
    payload_bytes: int = 0,
    compress_payload: bool = False,
    reserve_bytes: int = 0,
    shard_catalog: dict[str, Any] | None = None,
    readable: Path | None = None,
) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as zf:
        zf.writestr("aetheris_package.json", json.dumps(meta, indent=2, default=str))
        zf.writestr(
            "FORMAT.txt",
            (
                "Aetheris portable evidence package\n"
                f"format={meta.get('container_format')}\n"
                f"full_payload={include_payload}\n"
                "This is NOT a binary-compatible Cellebrite UFED .pas/.ufd file.\n"
                "Extract/RAG reads payload ZIP shards (02_Original_Extraction/), not the live folder.\n"
                "Sealed original folder (collection image):\n"
                f"  {original}\n"
            ),
        )
        zf.writestr("ORIGINAL_PATH.txt", str(original) + "\n")
        if shard_catalog:
            zf.writestr("SHARDS.json", json.dumps(shard_catalog, indent=2, default=str))
            zf.writestr("payload_shards.json", json.dumps(shard_catalog, indent=2, default=str))
        if include_payload:
            index_count = _write_file_index_jsonl(zf, original)
            zf.writestr(
                "file_index.json",
                json.dumps({
                    "complete": True,
                    "format": "jsonl",
                    "path": "file_index.jsonl",
                    "files": index_count,
                    "shards": bool(shard_catalog),
                }, indent=2),
            )
        else:
            zf.writestr(
                "file_index.json",
                json.dumps({
                    "skipped": True,
                    "reason": "metadata_only_sealed_image_on_disk",
                    "original": str(original),
                }, indent=2),
            )
        if logs and logs.is_dir() and include_payload:
            _add_tree(zf, logs, "07_Logs", compress=True)
        elif logs and logs.is_dir():
            for full, rel in iter_tree_files(logs):
                try:
                    if os.path.getsize(full) > _MAX_LOG_FILE_IN_META_ZIP:
                        continue
                    zf.write(full, f"07_Logs/{rel}", compress_type=zipfile.ZIP_DEFLATED)
                except OSError:
                    continue
        if hashes and hashes.is_dir():
            _add_tree(zf, hashes, "08_Hashes", compress=True)
        if include_payload and not shard_catalog:
            _add_tree(
                zf, original, "02_Original_Extraction", compress=compress_payload,
                progress=progress, progress_total_bytes=payload_bytes, reserve_bytes=reserve_bytes,
                follow_junctions=True,
            )
        if include_payload and readable is not None and readable.is_dir():
            # Human-readable DBs/media (WhatsApp, SMS, camera roll…) ride inside the
            # same ZIP so the package is self-contained — no readable_artifacts
            # folder is left beside it in 05_Exports.
            _add_tree(
                zf, readable, "readable_artifacts", compress=compress_payload,
                reserve_bytes=reserve_bytes, follow_junctions=True,
            )


def _write_thin_sidecar_zip(
    dest: Path,
    *,
    meta: dict[str, Any],
    hashes: Path | None,
) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("aetheris_package.json", json.dumps(meta, indent=2, default=str))
        zf.writestr(
            "FORMAT.txt",
            (
                "Aetheris thin portable unit (.ufd/.pas)\n"
                "Contains package metadata and hash manifest only.\n"
                "Authoritative payload remains the sealed case folder and/or the .zip.\n"
                "Not a native Cellebrite UFED binary container.\n"
            ),
        )
        if hashes and hashes.is_dir():
            for full, rel in iter_tree_files(hashes):
                try:
                    zf.write(full, f"08_Hashes/{rel}")
                except OSError:
                    continue


def _write_ufdx(
    dest: Path,
    *,
    run_name: str,
    case_id: str,
    evidence_id: str,
    method: str,
    device: dict[str, Any],
    packages: dict[str, str],
    original: Path,
    inventory: dict[str, Any] | None,
    created_utc: str,
) -> None:
    device_label = escape(str(device.get("device_label") or device.get("model") or "device"))
    os_family = escape(str(device.get("os_family") or ""))
    serial = escape(str(device.get("serial") or device.get("udid") or ""))
    inv_summary = escape(str((inventory or {}).get("summary") or ""))
    pkg_xml = "\n".join(
        f'    <Package extension="{escape(ext)}" path="{escape(path)}" />'
        for ext, path in packages.items()
    )
    counts = (inventory or {}).get("counts") or {}
    count_xml = "\n".join(
        f'    <Count category="{escape(str(k))}" value="{int(v)}" />'
        for k, v in counts.items()
    )
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<AetherisEvidenceIndex version="1.0" schema="aetheris.ufdx.v1">
  <Case id="{escape(case_id)}" evidence_id="{escape(evidence_id)}" />
  <Extraction run_name="{escape(run_name)}" method="{escape(method)}" created_utc="{escape(created_utc)}" />
  <Device os_family="{os_family}" label="{device_label}" serial="{serial}" />
  <Original path="{escape(str(original))}" />
  <Inventory summary="{inv_summary}">
{count_xml}
  </Inventory>
  <Packages>
{pkg_xml}
  </Packages>
  <Notes>
    Aetheris UFDX index. Not a native Cellebrite UFED project file.
    Authoritative image = sealed Original folder. Portable transfer = .zip.
  </Notes>
</AetherisEvidenceIndex>
"""
    dest.write_text(body, encoding="utf-8")


def build_export_packages(
    *,
    run_name: str,
    export_dir: Path,
    original: Path,
    logs: Path | None = None,
    hashes: Path | None = None,
    case_id: str = "",
    evidence_id: str = "",
    method: str = "",
    device: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    progress: ProgressCb = None,
    full_payload: bool | None = None,
    full_zip_max_bytes: int = DEFAULT_FULL_ZIP_MAX_BYTES,
    readable: Path | None = None,
    use_shards: bool | None = None,
) -> ExportBundle:
    """Write exactly .zip / .ufdx / .ufd / .pas under export_dir.

    Default packs the whole acquisition (plus readable_artifacts) into one
    ZIP64 ``<run>.zip``. Sidecar metadata (export_catalog.json, shard catalogs,
    FULL_ZIP_LOCATION.txt) is written to 07_Logs/<run>, never next to the
    packages. Pass full_payload=False for a metadata pointer package, or
    use_shards=True / AETHERIS_EXPORT_SHARDS=1 for multi-part output.
    """
    requested_export_dir = Path(export_dir)
    requested_export_dir.mkdir(parents=True, exist_ok=True)
    export_dir = requested_export_dir
    original = Path(original)
    side_dir = side_files_dir(requested_export_dir, run_name, Path(logs) if logs else None)
    shard_mode = shards_enabled() if use_shards is None else bool(use_shards)
    if readable is None:
        readable = find_readable_artifacts(original)
    created = datetime.now(timezone.utc).isoformat()
    device = device or {}
    ios_sealed = is_sealed_mobile_original(original)
    include_payload = True if full_payload is None else bool(full_payload)
    zip_dir = export_dir
    compress_payload = False
    use_shards = False
    shard_catalog: dict[str, Any] | None = None
    shard_paths: list[Path] = []
    storage_plan: dict[str, Any] = {
        "mode": "metadata_only", "estimated_zip_bytes": 0,
        "reserve_bytes": _reserve_bytes(), "free_bytes": _free_bytes(export_dir),
    }
    space_fallback_note = ""
    payload_bytes = 0
    if include_payload:
        payload_bytes = _dir_bytes(original, follow_junctions=True)
        if readable is not None:
            payload_bytes += _dir_bytes(readable, follow_junctions=True)
        use_shards = shard_mode and payload_bytes >= _payload_shard_min_bytes()
        try:
            zip_dir, compress_payload, storage_plan = _select_zip_destination(
                requested_export_dir, run_name, original, payload_bytes
            )
            zip_dir.mkdir(parents=True, exist_ok=True)
            if use_shards:
                if storage_plan.get("mode") not in ("stored", "deflate"):
                    raise ExportSpaceError(
                        payload_bytes=payload_bytes,
                        estimated_zip_bytes=payload_bytes,
                        best_free_bytes=int(storage_plan.get("free_bytes") or 0),
                        reserve_bytes=int(storage_plan.get("reserve_bytes") or 0),
                        requested_dir=str(requested_export_dir),
                        candidate_dir=str(zip_dir),
                    )
                compress_payload = False
                storage_plan = {**storage_plan, "mode": "stored_shards"}
        except ExportSpaceError as exc:
            if not ios_sealed:
                raise
            include_payload = False
            use_shards = False
            space_fallback_note = (
                "Not enough free space for payload ZIP shards; wrote a metadata "
                f"package and left the sealed original on disk. {exc}"
            )
    else:
        totals = (inventory or {}).get("totals") or {}
        try:
            payload_bytes = int(totals.get("bytes") or 0)
        except (TypeError, ValueError):
            payload_bytes = 0

    bundle = ExportBundle(run_name=run_name, export_dir=str(requested_export_dir))
    bundle.full_payload_in_zip = include_payload
    bundle.zip_export_dir = str(zip_dir)
    bundle.zip_storage_plan = dict(storage_plan)
    bundle.warnings.append(
        "Exported .pas/.ufd/.ufdx are Aetheris portable packages (ZIP/XML), not "
        "native Cellebrite UFED binary containers."
    )
    if include_payload:
        bundle.warnings.append(
            "Analysis extract reads the payload ZIP under 05_Exports; the live "
            "sealed folder is not walked when that zip exists."
        )
    else:
        bundle.warnings.append(
            space_fallback_note
            or "Metadata-only ZIP; pass --full to pack payload shards for zip-only extract."
        )

    base_meta = {
        "product": "Aetheris",
        "run_name": run_name,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "method": method,
        "device": device,
        "created_utc": created,
        "original_path": str(original),
        "original_bytes": payload_bytes,
        "full_payload_in_zip": include_payload,
        "payload_sharded": use_shards,
        "requested_export_dir": str(requested_export_dir),
        "zip_export_dir": str(zip_dir),
        "zip_storage_plan": storage_plan,
        "side_files_dir": str(side_dir),
        "readable_artifacts_in_zip": bool(readable is not None and include_payload),
        "inventory": inventory or {},
        "compatible_with": [
            "ZIP tools",
            "Folder import of ios_backup / afc_media / shared_storage / android_backup",
        ],
        "not_compatible_with": [
            "Native Cellebrite UFED .pas/.ufd binary open in Physical Analyzer",
        ],
    }

    # Primary .zip
    if progress:
        try:
            progress({"stage": "export", "item": "package.zip", "run_name": run_name})
        except Exception:
            pass
    zip_path = zip_dir / f"{run_name}.zip"
    zip_meta = dict(base_meta)
    zip_meta["container_format"] = "aetheris.zip.v1"
    zip_meta["extension"] = "zip"
    try:
        if use_shards and include_payload:
            if progress:
                progress({"stage": "seal", "item": "payload_shards", "category": "Packaging", "phase": "export_zip"})
            shard_paths, shard_catalog = write_payload_shards(
                zip_dir,
                original=original,
                run_name=run_name,
                progress=progress,
                payload_bytes=payload_bytes,
                reserve_bytes=int(storage_plan.get("reserve_bytes") or 0),
                catalog_dir=side_dir,
            )
            bundle.payload_shards = [str(p) for p in shard_paths]
            zip_meta["payload_shards"] = [p.name for p in shard_paths]
        _write_main_zip(
            zip_path,
            original=original,
            logs=Path(logs) if logs else None,
            hashes=Path(hashes) if hashes else None,
            meta=zip_meta,
            include_payload=include_payload,
            progress=progress if not use_shards else None,
            payload_bytes=payload_bytes,
            compress_payload=compress_payload,
            reserve_bytes=int(storage_plan.get("reserve_bytes") or 0),
            shard_catalog=shard_catalog if use_shards else None,
            readable=readable,
        )
        if include_payload:
            expected_files, expected_bytes = _dir_stats(original, follow_junctions=True)
            archived_files = 0
            archived_bytes = 0
            if use_shards:
                for shard in shard_paths:
                    with zipfile.ZipFile(shard, "r", allowZip64=True) as verify_zip:
                        members = [
                            i for i in verify_zip.infolist()
                            if i.filename.replace("\\", "/").startswith("02_Original_Extraction/") and not i.is_dir()
                        ]
                        archived_files += len(members)
                        archived_bytes += sum(int(i.file_size) for i in members)
            else:
                with zipfile.ZipFile(zip_path, "r", allowZip64=True) as verify_zip:
                    members = [
                        i for i in verify_zip.infolist()
                        if i.filename.replace("\\", "/").startswith("02_Original_Extraction/") and not i.is_dir()
                    ]
                    archived_files = len(members)
                    archived_bytes = sum(int(i.file_size) for i in members)
            if archived_files != expected_files or archived_bytes != expected_bytes:
                raise IOError(
                    f"ZIP payload verification failed files={archived_files}/{expected_files} "
                    f"bytes={archived_bytes}/{expected_bytes}"
                )
        if progress:
            progress({"stage": "seal", "item": "hashing_zip", "category": "Verifying", "phase": "zip_hash", "progress_pct": 99.6})
        bundle.packages["zip"] = str(zip_path)
        bundle.package_sha256["zip"] = _sha256_file(zip_path)
        if zip_dir != requested_export_dir:
            bundle.warnings.append(
                f"Full evidence ZIP was written to alternate volume {zip_dir} because the case export volume did not have enough free space."
            )
            (side_dir / "FULL_ZIP_LOCATION.txt").write_text(
                str(zip_path) + "\n", encoding="utf-8"
            )
    except Exception as exc:
        try:
            if zip_path.exists():
                zip_path.unlink()
        except OSError:
            pass
        if include_payload:
            raise
        bundle.warnings.append(f"Failed to write .zip package: {exc}")

    # Thin .ufd / .pas sidecars (not full payload duplicates)
    for ext, fmt in (("ufd", "aetheris.ufd.portable.v1"), ("pas", "aetheris.pas.portable.v1")):
        if progress:
            try:
                progress({"stage": "export", "item": f"package.{ext}", "run_name": run_name})
            except Exception:
                pass
        dest = export_dir / f"{run_name}.{ext}"
        meta = dict(base_meta)
        meta["container_format"] = fmt
        meta["extension"] = ext
        meta["primary_zip"] = bundle.packages.get("zip")
        try:
            _write_thin_sidecar_zip(dest, meta=meta, hashes=Path(hashes) if hashes else None)
            bundle.packages[ext] = str(dest)
            bundle.package_sha256[ext] = _sha256_file(dest)
        except Exception as exc:
            bundle.warnings.append(f"Failed to write .{ext} package: {exc}")

    # UFDX XML index
    try:
        if progress:
            try:
                progress({"stage": "export", "item": "package.ufdx", "run_name": run_name})
            except Exception:
                pass
        ufdx_path = export_dir / f"{run_name}.ufdx"
        _write_ufdx(
            ufdx_path,
            run_name=run_name,
            case_id=case_id,
            evidence_id=evidence_id,
            method=method,
            device=device,
            packages=bundle.packages,
            original=original,
            inventory=inventory,
            created_utc=created,
        )
        bundle.packages["ufdx"] = str(ufdx_path)
        bundle.package_sha256["ufdx"] = _sha256_file(ufdx_path)
    except Exception as exc:
        bundle.warnings.append(f"Failed to write .ufdx index: {exc}")

    catalog = side_dir / "export_catalog.json"
    catalog_payload = bundle.as_dict()
    catalog_payload["zip_storage_plan"] = storage_plan
    catalog_payload["side_files_dir"] = str(side_dir)
    catalog.write_text(json.dumps(catalog_payload, indent=2), encoding="utf-8")
    # Older runs left json/marker files beside the packages — clean them so the
    # export folder is exactly the four package files.
    for stale in ("export_catalog.json", "payload_shards.json", "FULL_ZIP_LOCATION.txt", "content_inventory.json"):
        stale_path = requested_export_dir / stale
        try:
            if stale_path.is_file() and stale_path != catalog:
                if not (side_dir / stale).exists():
                    shutil.move(str(stale_path), str(side_dir / stale))
                else:
                    stale_path.unlink()
        except OSError:
            pass
    return bundle
