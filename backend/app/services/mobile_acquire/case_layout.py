"""Case workspace layout and extraction naming — Architecture §4.2 and §8.1.

Two rules drive everything in this module:

  §8.1  "Never overwrite an earlier extraction with a later extraction. Each run
         must have its own immutable identity and audit trail."

  §12   Original extraction is immutable/read-only; analysis happens on a
         verified working copy.

So an acquisition NEVER writes into an existing run directory. `new_run` mints a
run id, refuses to reuse one, and the finaliser flips the original tree to
read-only. Everything downstream (RAG indexing, parsing) is pointed at the
working copy, never at 02_Original_Extraction.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# §4.2 recommended case folder structure.
CASE_SUBDIRS: tuple[str, ...] = (
    "01_Authority",
    "02_Original_Extraction",
    "03_Working_Copy",
    "04_PA_Case",
    "05_Exports",
    "06_Reports",
    "07_Logs",
    "08_Hashes",
    "09_Review",
    "10_Disclosure",
)

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _slug(value: str, *, default: str = "UNKNOWN") -> str:
    cleaned = _SAFE.sub("-", (value or "").strip()).strip("-")
    return (cleaned or default).upper()


def utc_stamp(when: datetime | None = None) -> str:
    return (when or datetime.now(timezone.utc)).strftime("%Y%m%d_%H%M%S")


def build_run_name(
    *,
    case_id: str,
    evidence_id: str,
    device_label: str,
    method: str,
    when: datetime | None = None,
) -> str:
    """CASE-2026-001_E01_PHONE01_LOGICAL_20260725_103000  (§8.1)."""
    return "_".join((
        _slug(case_id, default="CASE-UNKNOWN"),
        _slug(evidence_id, default="E00"),
        _slug(device_label, default="DEVICE00"),
        _slug(method, default="UNSPECIFIED"),
        utc_stamp(when),
    ))


@dataclass(frozen=True)
class RunPaths:
    """Every path a single acquisition run may touch."""

    case_root: Path
    run_name: str
    original: Path          # immutable master — written once, then read-only
    working: Path           # verified copy for analysis
    logs: Path
    hashes: Path
    exports: Path
    reports: Path
    authority: Path

    def as_dict(self) -> dict[str, str]:
        return {
            "case_root": str(self.case_root),
            "run_name": self.run_name,
            "original": str(self.original),
            "working": str(self.working),
            "logs": str(self.logs),
            "hashes": str(self.hashes),
            "exports": str(self.exports),
            "reports": str(self.reports),
            "authority": str(self.authority),
        }


def ensure_case(case_root: str | os.PathLike[str], case_id: str) -> Path:
    """Create (idempotently) the §4.2 folder skeleton for a case."""
    root = Path(case_root) / _slug(case_id, default="CASE-UNKNOWN")
    for sub in CASE_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root


def new_run(
    *,
    case_root: str | os.PathLike[str],
    case_id: str,
    evidence_id: str,
    device_label: str,
    method: str,
    when: datetime | None = None,
) -> RunPaths:
    """Allocate an immutable run directory. Raises if the run name already exists."""
    root = ensure_case(case_root, case_id)
    run_name = build_run_name(
        case_id=case_id,
        evidence_id=evidence_id,
        device_label=device_label,
        method=method,
        when=when,
    )

    original = root / "02_Original_Extraction" / run_name
    if original.exists():
        # §8.1 — an existing run is evidence. Never write into it again.
        raise FileExistsError(
            f"Extraction run '{run_name}' already exists. A new run must be started; "
            "an existing original extraction is immutable."
        )

    paths = RunPaths(
        case_root=root,
        run_name=run_name,
        original=original,
        working=root / "03_Working_Copy" / run_name,
        logs=root / "07_Logs" / run_name,
        hashes=root / "08_Hashes" / run_name,
        exports=root / "05_Exports" / run_name,
        reports=root / "06_Reports" / run_name,
        authority=root / "01_Authority",
    )
    for p in (paths.original, paths.working, paths.logs, paths.hashes,
              paths.exports, paths.reports):
        p.mkdir(parents=True, exist_ok=True)
    return paths


def seal_original(original: Path) -> dict[str, int]:
    """Flip the original extraction tree to read-only (§12 immutability control).

    Best-effort by design: on a share that does not honour chmod we still record
    what we attempted so the limitation is reportable rather than silent.
    """
    changed = 0
    failed = 0
    ro_file = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    ro_dir = ro_file | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

    for path in sorted(Path(original).rglob("*"), reverse=True):
        try:
            path.chmod(ro_dir if path.is_dir() else ro_file)
            changed += 1
        except OSError:
            failed += 1
    try:
        Path(original).chmod(ro_dir)
        changed += 1
    except OSError:
        failed += 1
    return {"sealed": changed, "unsealed": failed}


@dataclass
class EvidencePackage:
    """§8 — a collection is an evidence PACKAGE, not a single file."""

    run_name: str
    extraction_data: list[str] = field(default_factory=list)
    device_metadata: dict = field(default_factory=dict)
    collection_log: str | None = None
    collection_summary: str | None = None
    hash_manifest: str | None = None
    examiner_notes: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    content_inventory: dict = field(default_factory=dict)
    export_packages: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "run_name": self.run_name,
            "extraction_data": self.extraction_data,
            "device_metadata": self.device_metadata,
            "collection_log": self.collection_log,
            "collection_summary": self.collection_summary,
            "hash_manifest": self.hash_manifest,
            "examiner_notes": self.examiner_notes,
            "warnings": self.warnings,
            "errors": self.errors,
            "content_inventory": self.content_inventory,
            "export_packages": self.export_packages,
            "complete": bool(self.extraction_data and self.hash_manifest),
        }
