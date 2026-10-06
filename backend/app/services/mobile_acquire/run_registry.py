"""In-flight acquisition registry — progress, cancellation and recovery.

A full-filesystem collection can run for hours. The examiner must be able to
close the tab, lose the network, or reload the page without orphaning the run or
losing the outcome. That requires three things this module provides:

  * the collection executes on a background worker, not in the request;
  * progress is published to a shared snapshot that any number of SSE readers
    can poll independently;
  * the outcome is durable on disk, so a run can be recovered even after the API
    process restarts.

Durability note: the live registry is per-process. In a multi-worker deployment
an SSE reader may land on a worker that is not running the collection. `recover`
handles that by reading the collection summary the orchestrator writes into the
case folder — a completed run is therefore always retrievable, and only *live
progress* for a run owned by another worker is unavailable. Deployments that
need cross-worker live progress should run acquisition on a single dedicated
worker, which is also the correct topology for hardware-attached collection: the
device is physically cabled to one machine.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.services.mobile_acquire.orchestrator import (
    AcquisitionRequest,
    AcquisitionResult,
    CollectionOrchestrator,
    DeviceDetector,
)

# Terminal states. Anything else means the worker still holds the device.
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _export_dir_candidates(export_dir: str | None) -> list[Path]:
    raw = (export_dir or "").strip()
    if not raw:
        return []
    out: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        key = str(p).replace("\\", "/").lower()
        if key and key not in seen:
            seen.add(key)
            out.append(p)

    _add(Path(raw))
    mapped = _windows_drive_to_host_mount(raw)
    if mapped is not None:
        _add(mapped)
    norm = raw.replace("\\", "/")
    marker = "/evidence/"
    low = norm.lower()
    idx = low.find(marker)
    if idx >= 0:
        _add(Path("/evidence") / norm[idx + len(marker) :])
    if "evidence/cases" in low:
        rel = norm[low.find("evidence/cases") + len("evidence/cases") :].lstrip("/")
        _add(Path("/evidence/cases") / rel)
    return out


def _read_json(path: Path) -> Any:
    """Load JSON written on Windows (BOM) or Linux."""
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _result_file_count(data: dict[str, Any] | None) -> int:
    """Best file count from a collection result / summary (never walk the tree)."""
    if not isinstance(data, dict):
        return 0
    rec = data.get("acquisition_record") if isinstance(data.get("acquisition_record"), dict) else {}
    pkg = data.get("evidence_package") if isinstance(data.get("evidence_package"), dict) else {}
    inv = data.get("content_inventory") if isinstance(data.get("content_inventory"), dict) else {}
    if not inv and isinstance(pkg.get("content_inventory"), dict):
        inv = pkg["content_inventory"]
    totals = inv.get("totals") if isinstance(inv.get("totals"), dict) else {}
    counts = inv.get("counts") if isinstance(inv.get("counts"), dict) else {}
    for raw in (
        pkg.get("file_count"),
        rec.get("file_count"),
        rec.get("files_seen"),
        totals.get("files"),
        counts.get("files"),
        counts.get("total"),
        counts.get("file_count"),
        data.get("file_count"),
        data.get("files_seen"),
    ):
        try:
            value = int(raw or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def _result_output_size(data: dict[str, Any] | None) -> int:
    if not isinstance(data, dict):
        return 0
    rec = data.get("acquisition_record") if isinstance(data.get("acquisition_record"), dict) else {}
    inv = data.get("content_inventory") if isinstance(data.get("content_inventory"), dict) else {}
    totals = inv.get("totals") if isinstance(inv.get("totals"), dict) else {}
    for raw in (rec.get("output_size"), totals.get("bytes"), data.get("total_bytes"), data.get("output_size")):
        try:
            value = int(raw or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def _path_exists_here_or_host(path: str | None) -> bool:
    raw = str(path or "").strip()
    if not raw:
        return False
    candidate = Path(raw)
    if candidate.exists():
        return True
    mapped = _windows_drive_to_host_mount(raw)
    return bool(mapped and mapped.exists())


def _adapter_for_recovered(data: dict[str, Any] | None, run_name: str, case_id: str) -> str:
    blob = data if isinstance(data, dict) else {}
    explicit = str(blob.get("adapter") or "").strip()
    if explicit in ("android_adb", "android_mtp", "ios_lockdown"):
        return explicit
    family = ""
    for node in (blob.get("device"), blob.get("device_profile")):
        if isinstance(node, dict):
            family = str(node.get("os_family") or node.get("platform") or "").lower()
            if family:
                break
    hay = f"{family} {run_name} {case_id} {explicit}".lower()
    if any(token in hay for token in ("android", "oppo", "samsung", "pixel", "xiaomi", "oneplus", "adb", "mtp")):
        return "android_adb" if "mtp" not in hay else "android_mtp"
    if any(token in hay for token in ("ios", "iphone", "ipad", "apple")):
        return "ios_lockdown"
    return explicit or "ios_lockdown"


def _recover_from_helper(case_id: str) -> dict[str, Any] | None:
    """When the case folder was lost after a 502, reuse the host helper result."""
    needle = (case_id or "").strip().lower()
    if not needle:
        return None
    try:
        from app.services.mobile_acquire import host_bridge

        jobs = host_bridge.fetch_helper_jobs()
    except Exception:
        return None
    for job in jobs:
        if not isinstance(job, dict):
            continue
        cid = str(job.get("case_id") or "").strip().lower()
        rname = str(job.get("run_name") or "").strip().lower()
        jid = str(job.get("job_id") or "").strip()
        if not jid:
            continue
        if needle not in (cid, rname) and needle not in cid and needle not in rname:
            continue
        try:
            detail = host_bridge.fetch_helper_job(jid)
        except Exception:
            continue
        result = detail.get("result") if isinstance(detail, dict) else None
        if not isinstance(result, dict):
            continue
        if _result_file_count(result) <= 0 and not result.get("ok"):
            continue
        out = _normalize_result(result)
        warnings = list(out.get("warnings") or [])
        original = str((out.get("paths") or {}).get("original") or "")
        if original and not _path_exists_here_or_host(original):
            warnings.append(
                "Host helper still has this collection result, but the sealed original "
                "folder is missing from the case directory. Re-acquire the handset to "
                "restore files; counts below are from the finished helper result."
            )
            out["warnings"] = warnings
        return out
    return None


def _export_packages_from_dir(export_dir: str | None) -> dict[str, Any]:
    """Read 05_Exports/export_catalog.json (or glob *.zip/*.ufd/*.pas/*.ufdx)."""
    for root in _export_dir_candidates(export_dir):
        if not root.is_dir():
            continue
        catalog = root / "export_catalog.json"
        try:
            from app.services.mobile_segments import export_catalog_candidates

            for cand in export_catalog_candidates(root):
                if cand.is_file():
                    catalog = cand
                    break
        except Exception:
            pass
        if catalog.is_file():
            try:
                data = _read_json(catalog)
            except (OSError, json.JSONDecodeError):
                data = None
            if isinstance(data, dict) and isinstance(data.get("packages"), dict) and data["packages"]:
                data.setdefault("ok", True)
                return data
        packages: dict[str, str] = {}
        for ext in ("zip", "ufdx", "ufd", "pas"):
            hits = sorted(root.glob(f"*.{ext}"))
            if hits:
                packages[ext] = str(hits[0])
        if packages:
            return {"ok": True, "packages": packages, "export_dir": str(root)}
    return {}


def _windows_drive_to_host_mount(path: str) -> Path | None:
    """Map ``E:/foo`` / ``E:\\foo`` → ``/host/e/foo`` for Docker bind mounts."""
    cr = (path or "").strip().replace("\\", "/")
    if len(cr) >= 2 and cr[1] == ":" and cr[0].isalpha():
        letter = cr[0].lower()
        rest = cr[2:].lstrip("/")
        return Path("/host") / letter / rest if rest else Path("/host") / letter
    return None


def _known_evidence_case_roots() -> list[Path]:
    """Windows + Docker mounts that may hold sealed collections (E: project tree or F: evidence)."""
    out: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        key = str(p).replace("\\", "/").lower()
        if key and key not in seen:
            seen.add(key)
            out.append(p)

    for letter in ("e", "f", "d", "c"):
        _add(Path(f"{letter.upper()}:/evidence/cases"))
        _add(Path(f"/host/{letter}/evidence/cases"))
        _add(Path(f"{letter.upper()}:/projects/aetheris_project/evidence/cases"))
        _add(Path(f"/host/{letter}/projects/aetheris_project/evidence/cases"))
    _add(Path(r"E:\rag_new2\evidence\cases"))
    _add(Path("/host/e/rag_new2/evidence/cases"))
    _add(Path("/evidence/cases"))
    return out


def _case_root_candidates(case_root: str) -> list[Path]:
    """Paths that may resolve to the case-root directory from inside the API container."""
    cr = (case_root or "").strip().replace("\\", "/")
    out: list[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        key = str(p).replace("\\", "/").lower()
        if key and key not in seen:
            seen.add(key)
            out.append(p)

    mapped = _windows_drive_to_host_mount(cr)
    if mapped is not None:
        _add(mapped)
    if cr.startswith("/evidence"):
        rel = cr[len("/evidence") :].lstrip("/")
        _add(Path("/host/e/rag_new2/evidence") / rel)
        _add(Path("E:/rag_new2/evidence") / rel)
        _add(Path("/host/e/projects/aetheris_project/evidence") / rel)
        _add(Path("E:/projects/aetheris_project/evidence") / rel)
        for letter in ("e", "f", "d", "c"):
            _add(Path(f"/host/{letter}/evidence") / rel)
            _add(Path(f"{letter.upper()}:/evidence") / rel)
        _add(Path("/evidence") / rel)
    if cr.startswith("/host/"):
        _add(Path(cr))
    _add(Path(case_root))
    return out


def _recover_summary_from_disk(case_root: str, case_id: str) -> dict[str, Any] | None:
    """If the host bridge times out after evidence landed, rebuild a result from disk."""
    roots: list[Path] = []
    for base in _case_root_candidates(case_root):
        roots.append(base / case_id)
    for base in _known_evidence_case_roots():
        roots.append(base / case_id)

    # UFED-aligned layout uses 07_Logs; older paths used 03_Logs_and_Hashes.
    log_dir_names = ("07_Logs", "03_Logs_and_Hashes")

    summary_path: Path | None = None
    for root in roots:
        for log_name in log_dir_names:
            logs = root / log_name
            if not logs.is_dir():
                continue
            candidates = sorted(
                logs.rglob("collection_summary.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                summary_path = candidates[0]
                break
        if summary_path is not None:
            break
    if summary_path is None:
        # Fall back: newest original extraction folder alone.
        for root in roots:
            orig = root / "02_Original_Extraction"
            if not orig.is_dir():
                continue
            runs = sorted(
                [p for p in orig.iterdir() if p.is_dir()],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if not runs:
                continue
            run_dir = runs[0]
            # Never rglob the original here — junctions / 100k+ mobile files
            # make recover 502 and the UI applies a 0-file stub.
            if not run_dir.is_dir():
                continue
            return {
                "ok": True,
                "run_name": run_dir.name,
                "stage_reached": "complete",
                "paths": {
                    "case_root": str(root),
                    "run_name": run_dir.name,
                    "original": str(run_dir),
                    "logs": str(root / "07_Logs" / run_dir.name),
                    "hashes": str(root / "08_Hashes" / run_dir.name),
                    "exports": str(root / "05_Exports" / run_dir.name),
                },
                "acquisition_record": {"output_size": 0},
                "evidence_package": {
                    "run_name": run_dir.name,
                    "extraction_data": [],
                    "complete": True,
                },
                "warnings": [
                    "Host helper response was lost; result recovered from the sealed "
                    f"original extraction folder {run_dir.name}."
                ],
                "errors": [],
                "limitations": [],
            }
        return None

    try:
        summary = _read_json(summary_path)
    except Exception:
        return None
    if not isinstance(summary, dict):
        return None
    paths = dict(summary.get("paths") or {})
    if not paths.get("original"):
        # Infer from summary location: .../07_Logs/<run>/collection_summary.json
        run_logs = summary_path.parent
        run_name = summary.get("run_name") or run_logs.name
        parent = run_logs.parent.name
        case = (
            run_logs.parent.parent
            if parent in ("07_Logs", "03_Logs_and_Hashes")
            else run_logs.parent
        )
        paths.setdefault("case_root", str(case))
        paths.setdefault("run_name", str(run_name))
        paths.setdefault("logs", str(run_logs))
        paths.setdefault("original", str(case / "02_Original_Extraction" / run_name))
        paths.setdefault("exports", str(case / "05_Exports" / run_name))
        hash_dir = case / "08_Hashes" / run_name
        paths.setdefault("hashes", str(hash_dir if hash_dir.is_dir() else run_logs))
    export_packages = summary.get("export_packages") or {}
    rec_in = summary.get("acquisition_record") if isinstance(summary.get("acquisition_record"), dict) else {}
    file_n = _result_file_count(summary)
    total_b = _result_output_size(summary)
    rec = dict(rec_in)
    rec["output_size"] = total_b
    rec["file_count"] = file_n
    pkg = summary.get("evidence_package") if isinstance(summary.get("evidence_package"), dict) else {}
    pkg = dict(pkg)
    pkg.setdefault("run_name", summary.get("run_name") or "")
    pkg.setdefault("extraction_data", [])
    pkg["file_count"] = file_n
    pkg["complete"] = bool(summary.get("ok")) or file_n > 0
    pkg.setdefault("collection_summary", str(summary_path))
    if summary.get("content_inventory"):
        pkg["content_inventory"] = summary.get("content_inventory")
    if summary.get("export_packages"):
        pkg["export_packages"] = summary.get("export_packages")
    method_decision = summary.get("method_decision") or {}
    if not method_decision and file_n > 0:
        method_decision = {
            "selected": "logical",
            "considered": ["logical", "advanced_logical"],
            "rejected": {},
            "rationale": "Recovered logical shared-storage collection.",
            "deeper_available": ["full_file_system"],
        }
    raw_errors = summary.get("errors")
    if isinstance(raw_errors, list):
        errors_out = [str(x) for x in raw_errors if x]
    else:
        errors_out = []
    return {
        "ok": True if (file_n > 0 or summary.get("ok")) else False,
        "run_name": summary.get("run_name") or paths.get("run_name") or "",
        "stage_reached": "complete" if file_n > 0 or summary.get("ok") else "failed",
        "paths": paths,
        "device_profile": summary.get("device") or {},
        "method_decision": method_decision,
        "coverage_statement": summary.get("coverage_statement") or {},
        "validation": summary.get("validation") or {},
        "limitations": list(summary.get("limitations") or []),
        "warnings": list(summary.get("warnings") or []) + [
            "Host helper response was incomplete; result recovered from collection_summary.json."
        ],
        "errors": errors_out,
        "acquisition_record": rec,
        "verification": summary.get("verification") or {},
        "content_inventory": summary.get("content_inventory") or {},
        "export_packages": export_packages or summary.get("export_packages") or {},
        "evidence_package": pkg,
        "audit": summary.get("audit") or {},
        "chain_of_custody": summary.get("chain_of_custody") or [],
    }


def _normalize_result(raw: dict[str, Any] | None, *, error: str | None = None) -> dict[str, Any]:
    """Guarantee the UI-facing result shape even when host/exception paths are sparse."""
    data = dict(raw or {})
    errors = []
    raw_errors = data.get("errors")
    if isinstance(raw_errors, list):
        errors = [str(x) for x in raw_errors if x]
    if error and error not in errors:
        errors.insert(0, error)
    bogus = {"acquisition_record", "errors", "ok", "run_name"}
    if data.get("error"):
        err_s = str(data["error"]).strip()
        if err_s and err_s not in bogus and err_s not in errors:
            errors.insert(0, err_s)
    data.setdefault("ok", False)
    data.setdefault("run_name", "")
    data.setdefault("stage_reached", "failed")
    data.setdefault("paths", {})
    data.setdefault("device_profile", {})
    data.setdefault("capability", {})
    data.setdefault(
        "method_decision",
        {
            "selected": None,
            "considered": [],
            "rejected": {},
            "rationale": "Method selection was not recorded for this run.",
            "deeper_available": [],
        },
    )
    if not isinstance(data.get("method_decision"), dict):
        data["method_decision"] = {
            "selected": None,
            "considered": [],
            "rejected": {},
            "rationale": "Method selection was not recorded for this run.",
            "deeper_available": [],
        }
    data["method_decision"].setdefault("selected", None)
    data["method_decision"].setdefault("considered", [])
    data["method_decision"].setdefault("rejected", {})
    data["method_decision"].setdefault(
        "rationale", "Method selection was not recorded for this run."
    )
    data["method_decision"].setdefault("deeper_available", [])
    data.setdefault("preparation_steps", [])
    data.setdefault(
        "evidence_package",
        {
            "run_name": data.get("run_name") or "",
            "extraction_data": [],
            "collection_log": None,
            "collection_summary": None,
            "hash_manifest": None,
            "complete": False,
        },
    )
    data.setdefault("acquisition_record", {"output_size": 0, "missing_fields": []})
    data.setdefault("verification", {"ok": False, "verified": 0})
    data.setdefault("coverage_statement", {})
    data.setdefault("limitations", [])
    data.setdefault("warnings", [])
    data["errors"] = errors
    data.setdefault("audit", {"path": "", "event_count": 0, "by_severity": {}})
    data.setdefault("chain_of_custody", [])
    data.setdefault("content_inventory", {})
    data.setdefault("export_packages", {"ok": False, "packages": {}, "warnings": []})
    # Promote nested package fields when host returns a sparse top-level result.
    pkg = data.get("evidence_package") if isinstance(data.get("evidence_package"), dict) else {}
    if not data.get("content_inventory") and isinstance(pkg.get("content_inventory"), dict):
        data["content_inventory"] = pkg["content_inventory"]
    if (
        not (data.get("export_packages") or {}).get("packages")
        and isinstance(pkg.get("export_packages"), dict)
    ):
        data["export_packages"] = pkg["export_packages"]
    paths = data.get("paths") if isinstance(data.get("paths"), dict) else {}
    if not (data.get("export_packages") or {}).get("packages"):
        disk_pkg = _export_packages_from_dir(paths.get("exports"))
        if disk_pkg.get("packages"):
            data["export_packages"] = disk_pkg
            if isinstance(pkg, dict):
                pkg["export_packages"] = disk_pkg
                data["evidence_package"] = pkg
    exports = (data.get("export_packages") or {}).get("packages") or {}
    if isinstance(exports, dict):
        for ext, path in exports.items():
            paths.setdefault(f"export_{ext}", path)
    data["paths"] = paths
    files = _result_file_count(data)
    size = _result_output_size(data)
    rec = data.get("acquisition_record") if isinstance(data.get("acquisition_record"), dict) else {}
    if files > 0:
        data["ok"] = True
        if str(data.get("stage_reached") or "").lower() in ("", "failed", "acquire", "error", "removed"):
            data["stage_reached"] = "complete"
        if isinstance(pkg, dict):
            if int(pkg.get("file_count") or 0) <= 0:
                pkg["file_count"] = files
            pkg["complete"] = True
            data["evidence_package"] = pkg
        if isinstance(rec, dict):
            if int(rec.get("file_count") or 0) <= 0:
                rec["file_count"] = files
            if size > 0 and int(rec.get("output_size") or 0) <= 0:
                rec["output_size"] = size
            data["acquisition_record"] = rec
    return data


@dataclass
class ProgressSnapshot:
    """What the UI needs to render a progress banner, and nothing more."""

    stage: str = "queued"
    item: str = ""
    detail: str = ""
    category: str = ""
    bytes_done: int = 0
    bytes_total: int | None = None
    files_seen: int = 0
    output_path: str = ""
    media_path: str = ""
    case_path: str = ""
    progress_floor: int = 0
    updated_utc: str = field(default_factory=_now)

    def as_dict(self) -> dict[str, Any]:
        from app.services.mobile_acquire.progress_labels import estimate_acquisition_progress_pct

        pct, mode = estimate_acquisition_progress_pct(
            stage=self.stage,
            item=self.item,
            bytes_done=self.bytes_done,
            bytes_total=self.bytes_total,
            files_seen=self.files_seen,
        )
        if self.stage not in ("complete", "completed", "done", "failed"):
            pct = max(pct, min(99, int(self.progress_floor or 0)))
        return {
            "stage": self.stage,
            "item": self.item,
            "detail": self.detail,
            "category": self.category,
            "bytes_done": self.bytes_done,
            "bytes_total": self.bytes_total,
            "progress_pct": pct,
            "progress_mode": mode,
            "files_seen": self.files_seen,
            "output_path": self.output_path,
            "media_path": self.media_path,
            "case_path": self.case_path,
            "updated_utc": self.updated_utc,
        }


@dataclass
class AcquisitionRun:
    run_id: str
    case_id: str
    evidence_id: str
    adapter: str
    device_id: str
    examiner: str
    status: str = "queued"          # queued | running | completed | failed | cancelled
    run_name: str = ""
    started_utc: str = field(default_factory=_now)
    ended_utc: str | None = None
    progress: ProgressSnapshot = field(default_factory=ProgressSnapshot)
    result: dict[str, Any] | None = None
    error: str | None = None
    host_job_id: str = ""
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def request_cancel(self) -> None:
        self._cancel.set()

    def summary(self) -> dict[str, Any]:
        """Lightweight view for lists and SSE frames."""
        return {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "adapter": self.adapter,
            "device_id": self.device_id,
            "examiner": self.examiner,
            "status": self.status,
            "started_utc": self.started_utc,
            "ended_utc": self.ended_utc,
            "cancel_requested": self.cancelled,
            "progress": self.progress.as_dict(),
            "error": self.error,
            "host_job_id": self.host_job_id or "",
        }

    def detail(self) -> dict[str, Any]:
        """Full view, including the acquisition result once available."""
        return {**self.summary(), "result": self.result}


class AcquisitionRegistry:
    """Owns every acquisition this process has started."""

    def __init__(self) -> None:
        self._runs: dict[str, AcquisitionRun] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.RLock()

    # ---------------- lifecycle ----------------

    def start(
        self,
        request: AcquisitionRequest,
        *,
        detector: DeviceDetector | None = None,
    ) -> AcquisitionRun:
        """Queue a collection and return immediately.

        One device, one *in-flight* USB collection: a second live acquire against
        a device already being acquired is refused, because two processes
        competing for the same USB endpoint corrupts both extractions.

        Sequential jobs on the same handset are allowed. A finished, failed, or
        abandoned run (worker thread already dead) does not block a new
        collection or a forensic import of that device.
        """
        with self._lock:
            self._reap_abandoned_runs_locked()
            for existing in self._runs.values():
                if existing.status not in TERMINAL_STATES and \
                        existing.device_id == request.device_id:
                    raise RuntimeError(
                        f"Device {request.device_id} is already being acquired by run "
                        f"{existing.run_id} ({existing.status}). Wait for it to finish or "
                        "cancel it before starting another collection."
                    )

            run = AcquisitionRun(
                run_id=uuid.uuid4().hex[:16],
                case_id=request.case_id,
                evidence_id=request.evidence_id,
                adapter=request.adapter_name,
                device_id=request.device_id,
                examiner=request.examiner,
            )
            self._runs[run.run_id] = run

        thread = threading.Thread(
            target=self._execute,
            args=(run, request, detector),
            name=f"acquire-{run.run_id}",
            daemon=True,
        )
        with self._lock:
            self._threads[run.run_id] = thread
        thread.start()
        return run

    def _reap_abandoned_runs_locked(self) -> None:
        """Free devices whose worker died without reaching a terminal state.

        Callers must hold ``self._lock``. A stuck ``running`` row would otherwise
        block every later acquire and forensic job on the same UDID forever.
        """
        for run in self._runs.values():
            if run.status in TERMINAL_STATES:
                continue
            thread = self._threads.get(run.run_id)
            if thread is not None and not thread.is_alive():
                run.status = "failed"
                run.error = run.error or (
                    "Acquisition worker exited without a result. The device is free "
                    "for a new collection or a forensic job."
                )
                run.ended_utc = _now()

    def _execute(
        self,
        run: AcquisitionRun,
        request: AcquisitionRequest,
        detector: DeviceDetector | None,
    ) -> None:
        run.status = "running"
        run.progress = ProgressSnapshot(stage="starting")

        from app.services.mobile_acquire.progress_labels import enrich_progress_event

        def _map_case_root_for_poll(case_root: str) -> Path:
            for c in _case_root_candidates(case_root):
                try:
                    if c.exists() or c.parent.exists():
                        return c
                except OSError:
                    continue
            mapped = _windows_drive_to_host_mount(case_root)
            return mapped if mapped is not None else Path(case_root)

        host_case_root = str(request.case_root)
        host_cr = host_case_root.replace("\\", "/")
        if host_cr.startswith("/evidence"):
            rel = host_cr[len("/evidence"):].lstrip("/")
            host_case_root = str(Path(r"E:\rag_new2\evidence") / Path(rel))
        elif _windows_drive_to_host_mount(host_case_root) is not None:
            # Keep Windows drive form for enrich_progress_event display paths;
            # polling uses _map_case_root_for_poll → /host/<drive>/...
            pass

        def on_progress(event: dict[str, Any]) -> None:
            enriched = enrich_progress_event(
                event,
                case_root=host_case_root,
                case_id=request.case_id,
            )
            prev = run.progress
            # Prefer max bytes so directory-watch updates never go backwards.
            bytes_done = max(
                int(enriched.get("bytes_done") or 0),
                int(prev.bytes_done or 0),
            )
            files_seen = int(enriched.get("files_seen") or 0)
            if not files_seen:
                files_seen = prev.files_seen + (1 if enriched.get("item") and enriched.get("item") != prev.item else 0)
            files_seen = max(files_seen, prev.files_seen)
            snapshot = ProgressSnapshot(
                stage=str(enriched.get("stage") or prev.stage),
                item=str(enriched.get("item") or prev.item or ""),
                detail=str(enriched.get("detail") or prev.detail),
                category=str(enriched.get("category") or prev.category),
                bytes_done=bytes_done,
                bytes_total=(
                    enriched.get("bytes_total")
                    if enriched.get("bytes_total") is not None
                    else prev.bytes_total
                ),
                files_seen=files_seen,
                output_path=str(enriched.get("output_path") or prev.output_path),
                media_path=str(enriched.get("media_path") or prev.media_path),
                case_path=str(enriched.get("case_path") or prev.case_path),
                progress_floor=int(prev.as_dict().get("progress_pct") or 0),
                updated_utc=_now(),
            )
            if not run.run_name and enriched.get("run_name"):
                run.run_name = str(enriched["run_name"])
            run.progress = snapshot

        try:
            from app.services.mobile_acquire import host_bridge

            use_host = False
            adapter = (detector or DeviceDetector()).adapter_by_name(request.adapter_name)
            if adapter is None or not adapter.tool_available():
                use_host = host_bridge.helper_reachable()

            if use_host and request.adapter_name in (
                "android_adb", "android_mtp", "ios_lockdown",
            ):
                progress_name = f".acq_progress_{run.run_id}.json"
                progress_host = str(Path(host_case_root) / progress_name)
                progress_poll = _map_case_root_for_poll(request.case_root) / progress_name
                for folder in (Path(host_case_root), progress_poll.parent):
                    try:
                        folder.mkdir(parents=True, exist_ok=True)
                    except OSError:
                        pass

                on_progress({
                    "stage": "acquire",
                    "item": "host_usb_bridge",
                    "bytes_done": 0,
                })

                stop_poll = threading.Event()

                def _poll_host_progress() -> None:
                    while not stop_poll.wait(0.75):
                        data: dict[str, Any] | None = None
                        for candidate in (progress_poll, Path(progress_host)):
                            try:
                                if not candidate.is_file():
                                    continue
                                parsed = _read_json(candidate)
                                if isinstance(parsed, dict) and (
                                    parsed.get("item") or parsed.get("detail")
                                ):
                                    data = parsed
                                    break
                            except Exception:
                                continue
                        # Do not rglob the original here. Walking 100k+ files / junctions
                        # blocks the API (502) while the host helper already publishes counts.
                        try:
                            event = dict(data or {})
                            event.setdefault("stage", "acquire")
                            if event.get("item") or event.get("bytes_done") or event.get("files_seen"):
                                on_progress(event)
                        except Exception:
                            if data:
                                on_progress(data)

                poller = threading.Thread(
                    target=_poll_host_progress,
                    name=f"acq-progress-{run.run_id}",
                    daemon=True,
                )
                poller.start()
                payload = {
                    "case_id": request.case_id,
                    "evidence_id": request.evidence_id,
                    "examiner": request.examiner,
                    "legal_authority": request.legal_authority,
                    "case_root": request.case_root,
                    "adapter": request.adapter_name,
                    "device_id": request.device_id,
                    "objective_methods": [m.value for m in request.objective_methods],
                    "authorized_methods": [m.value for m in request.authorized_methods],
                    "method_override": (
                        request.examiner_method_override.value
                        if request.examiner_method_override else None
                    ),
                    "cable_adapter_asset_id": request.cable_adapter_asset_id,
                    "license_endpoint_id": request.license_endpoint_id,
                    "backup_password": request.backup_password,
                    "examiner_notes": request.examiner_notes,
                    "device_condition": request.device_condition,
                    "network_isolated": request.network_isolated,
                    "create_working_copy": request.create_working_copy,
                    "cloud_mailboxes": list(request.cloud_mailboxes or []),
                    "progress_file": progress_host,
                }
                try:
                    host_result = host_bridge.host_run_acquire(
                        payload,
                        should_cancel=run._cancel.is_set,
                        on_job=lambda job_id: setattr(run, "host_job_id", str(job_id or "")),
                    ) or {}
                finally:
                    stop_poll.set()
                    poller.join(timeout=2.0)
                    for candidate in (progress_poll, Path(progress_host)):
                        try:
                            candidate.unlink(missing_ok=True)
                        except TypeError:
                            try:
                                if candidate.exists():
                                    candidate.unlink()
                            except OSError:
                                pass
                        except OSError:
                            pass

                # Slim host responses (or progress-file short-circuit) often omit
                # sealed paths — always recover from disk when original is missing.
                paths_preview = (
                    (host_result.get("paths") or {})
                    if isinstance(host_result, dict)
                    else {}
                )
                if not host_result or not paths_preview.get("original"):
                    recovered = _recover_summary_from_disk(
                        request.case_root, request.case_id
                    )
                    if recovered:
                        warnings = list(
                            (host_result or {}).get("warnings") or []
                        ) + list(recovered.get("warnings") or [])
                        # Prefer disk paths/packages; keep any host-side warnings.
                        merged = dict(recovered)
                        if host_result.get("run_name") and not merged.get("run_name"):
                            merged["run_name"] = host_result["run_name"]
                        merged["warnings"] = warnings
                        host_result = merged

                run.run_name = str(host_result.get("run_name") or run.run_name)
                run.result = _normalize_result(
                    host_result if isinstance(host_result, dict) else None,
                    error=None if host_result.get("ok") else (
                        str(host_result.get("error") or "") or None
                    ),
                )
                # If evidence packages exist on disk, treat as completed-with-warnings.
                paths = (run.result or {}).get("paths") or {}
                original = str(paths.get("original") or run.progress.output_path)
                export_pkgs = ((run.result or {}).get("export_packages") or {}).get("packages") or {}

                def _dir_has_files(path_str: str) -> bool:
                    candidates = [Path(path_str)]
                    norm = path_str.replace("\\", "/")
                    # Host Windows path → Docker bind mounts commonly used here.
                    if norm.lower().startswith("e:/rag_new2/"):
                        rel = norm[len("e:/rag_new2/"):]
                        candidates.append(Path("/host/e/rag_new2") / rel)
                        candidates.append(Path("/") / rel)  # e.g. /evidence/...
                    if "/evidence/" in norm:
                        idx = norm.lower().find("/evidence/")
                        candidates.append(Path("/evidence") / norm[idx + len("/evidence/"):].lstrip("/"))
                        candidates.append(Path("/host/e/rag_new2/evidence") / norm[idx + len("/evidence/"):].lstrip("/"))
                    for cand in candidates:
                        try:
                            if cand.is_dir() and any(cand.rglob("*")):
                                return True
                        except OSError:
                            continue
                    return False

                if not run.result.get("ok") and (
                    export_pkgs or (original and _dir_has_files(original))
                ):
                    run.result["ok"] = True
                    run.result["stage_reached"] = "complete"
                    warn = (
                        "Host reported failure, but sealed original / exports "
                        "were found on disk — treating run as completed with warnings."
                    )
                    if warn not in (run.result.get("warnings") or []):
                        run.result.setdefault("warnings", []).append(warn)
                media = ""
                if original:
                    media = str(Path(original) / "afc_media" / "DCIM")
                if run.cancelled:
                    run.status = "cancelled"
                elif run.result.get("ok"):
                    run.status = "completed"
                else:
                    run.status = "failed"
                    errs = run.result.get("errors") or []
                    run.error = (
                        "; ".join(str(e) for e in errs[:3])
                        or "Host acquisition failed"
                    )
                run.progress = ProgressSnapshot(
                    stage=str(run.result.get("stage_reached") or run.progress.stage),
                    item=run.progress.item or "complete",
                    detail=run.progress.detail or "Collection finished — evidence package sealed.",
                    category=run.progress.category or "Complete",
                    bytes_done=run.progress.bytes_done,
                    files_seen=run.progress.files_seen,
                    output_path=original,
                    media_path=media or run.progress.media_path,
                    case_path=str(paths.get("case_root") or run.progress.case_path),
                    updated_utc=_now(),
                )
            else:
                orchestrator = CollectionOrchestrator(
                    detector or DeviceDetector(),
                    progress=on_progress,
                    cancel=run._cancel.is_set,
                )
                result: AcquisitionResult = orchestrator.run(request)
                run.run_name = result.run_name or run.run_name
                run.result = _normalize_result(result.as_dict())
                if run.cancelled:
                    run.status = "cancelled"
                elif result.ok:
                    run.status = "completed"
                else:
                    run.status = "failed"
                    run.error = "; ".join(result.errors[:3]) or "Acquisition reported errors."
                paths = (run.result or {}).get("paths") or {}
                original = str(paths.get("original") or run.progress.output_path)
                run.progress = ProgressSnapshot(
                    stage=result.stage_reached,
                    item=run.progress.item,
                    detail=run.progress.detail or "Collection finished.",
                    category=run.progress.category or "Complete",
                    bytes_done=run.progress.bytes_done,
                    files_seen=run.progress.files_seen,
                    output_path=original,
                    media_path=(
                        str(Path(original) / "afc_media" / "DCIM")
                        if original else run.progress.media_path
                    ),
                    case_path=str(paths.get("case_root") or run.progress.case_path),
                    updated_utc=_now(),
                )
        except Exception as exc:  # worker must never die silently
            run.status = "failed"
            run.error = str(exc)
            run.result = _normalize_result(
                {
                    "ok": False,
                    "stage_reached": run.progress.stage,
                    "limitations": [
                        "The acquisition process terminated unexpectedly. No conclusion may be "
                        "drawn about the contents of the device from this run."
                    ],
                },
                error=str(exc),
            )
        finally:
            run.ended_utc = _now()
            self._persist_status(run, request)

    def _persist_status(self, run: AcquisitionRun, request: AcquisitionRequest) -> None:
        """Write a pointer file so the run is recoverable after a restart."""
        try:
            paths = (run.result or {}).get("paths") or {}
            logs = paths.get("logs")
            if not logs:
                return
            target = Path(logs) / "run_status.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(run.summary(), indent=2), encoding="utf-8")
        except Exception:
            # Persistence is a convenience; the collection summary written by the
            # orchestrator remains the authoritative record.
            pass

    # ---------------- queries ----------------

    def get(self, run_id: str) -> AcquisitionRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def list(self, *, include_finished: bool = True) -> list[dict[str, Any]]:
        with self._lock:
            runs = list(self._runs.values())
        if not include_finished:
            runs = [r for r in runs if r.status not in TERMINAL_STATES]
        return [r.summary() for r in sorted(runs, key=lambda r: r.started_utc, reverse=True)]

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._runs.values() if r.status not in TERMINAL_STATES)

    def cancel(self, run_id: str) -> bool:
        """Stop the collection immediately.

        Host USB acquires run in a separate Windows process (idevicebackup2 /
        pymobiledevice3). Setting a flag alone would wait for that backup to
        finish — hours. Kill the host process tree now and seal whatever is
        already on disk as an interrupted extraction.
        """
        run = self.get(run_id)
        if run is None or run.status in TERMINAL_STATES:
            return False
        run.request_cancel()
        try:
            from app.services.mobile_acquire import host_bridge

            progress = ""
            if run.progress and run.progress.case_path:
                progress = str(Path(run.progress.case_path) / f".acq_progress_{run.run_id}.json")
            host_bridge.host_cancel_job(run.host_job_id, progress)
        except Exception:
            pass
        return True

    def recover_recent(self, case_root: str = "/evidence/cases") -> list[dict[str, Any]]:
        """Find the newest sealed collection under case_root and rehydrate it.

        Used when the UI reloads after a successful acquire whose in-memory run
        was lost (API restart / large host result never delivered).
        """
        bases = _case_root_candidates(case_root)
        bases.extend(_known_evidence_case_roots())

        newest: tuple[float, str, str] | None = None  # mtime, case_root_path, case_id
        for base in bases:
            try:
                if not base.is_dir():
                    continue
            except OSError:
                continue
            try:
                children = list(base.iterdir())
            except OSError:
                continue
            for child in children:
                if not child.is_dir() or child.name.startswith("."):
                    continue
                for log_name in ("07_Logs", "03_Logs_and_Hashes"):
                    logs = child / log_name
                    if not logs.is_dir():
                        continue
                    try:
                        summaries = list(logs.glob("*/collection_summary.json"))
                    except OSError:
                        continue
                    for summary in summaries:
                        try:
                            mtime = summary.stat().st_mtime
                        except OSError:
                            continue
                        if newest is None or mtime > newest[0]:
                            newest = (mtime, str(base), child.name)

        if newest is None:
            return []
        _, root_path, case_id = newest
        return self.recover(root_path, case_id)

    def recover(self, case_root: str, case_id: str) -> list[dict[str, Any]]:
        """Rebuild finished runs from the case folder after an API restart / lost SSE.

        Rehydrates into the in-memory registry so ``getRun`` / Complete UI work
        without starting a new collection.
        """
        full = _recover_summary_from_disk(case_root, case_id)
        roots: list[Path] = []
        for base in _case_root_candidates(case_root):
            roots.append(base / case_id)
        for base in _known_evidence_case_roots():
            roots.append(base / case_id)

        log_dirs: list[Path] = []
        seen_logs: set[str] = set()
        for root in roots:
            for name in ("07_Logs", "03_Logs_and_Hashes"):
                logs_root = root / name
                key = str(logs_root).replace("\\", "/").lower()
                if key in seen_logs or not logs_root.is_dir():
                    continue
                seen_logs.add(key)
                log_dirs.append(logs_root)

        recovered: list[dict[str, Any]] = []
        for logs_root in log_dirs:
            for status_file in sorted(logs_root.glob("*/run_status.json")):
                try:
                    recovered.append({**_read_json(status_file), "recovered": True})
                except Exception:
                    continue
            for summary_file in sorted(logs_root.glob("*/collection_summary.json")):
                run_dir = summary_file.parent.name
                if any(r.get("run_name") == run_dir for r in recovered):
                    continue
                try:
                    data = _read_json(summary_file)
                    result = full if full and (
                        str(full.get("run_name") or "") == run_dir
                        or not any(
                            r.get("run_name") == str(full.get("run_name") or "")
                            for r in recovered
                        )
                    ) else None
                    if result is None:
                        # Build a minimal result from this summary alone.
                        result = _recover_summary_from_disk(case_root, case_id)
                        if result and str(result.get("run_name") or "") not in ("", run_dir):
                            # Wrong run — wrap this summary instead of cross-polluting.
                            result = None
                    if result is None:
                        paths = dict(data.get("paths") or {})
                        paths.setdefault("run_name", run_dir)
                        paths.setdefault("logs", str(summary_file.parent))
                        result = _normalize_result(
                            {
                                "ok": True if _result_file_count(data) > 0 or not bool(data.get("errors")) else False,
                                "run_name": data.get("run_name", run_dir),
                                "stage_reached": "complete",
                                "paths": paths,
                                "device_profile": data.get("device") or {},
                                "method_decision": data.get("method_decision") or {},
                                "acquisition_record": data.get("acquisition_record")
                                if isinstance(data.get("acquisition_record"), dict)
                                else {"output_size": data.get("total_bytes") or 0},
                                "export_packages": data.get("export_packages") or {},
                                "evidence_package": data.get("evidence_package")
                                or {
                                    "run_name": data.get("run_name", run_dir),
                                    "extraction_data": [],
                                    "collection_summary": str(summary_file),
                                    "complete": True,
                                    "content_inventory": data.get("content_inventory") or {},
                                    "export_packages": data.get("export_packages") or {},
                                },
                                "content_inventory": data.get("content_inventory") or {},
                                "warnings": list(data.get("warnings") or []),
                                "errors": list(data.get("errors") or []),
                                "limitations": list(data.get("limitations") or []),
                            }
                        )
                    else:
                        result = _normalize_result(result)

                    recovered.append({
                        "run_id": "",
                        "run_name": data.get("run_name", run_dir),
                        "case_id": data.get("case_id", case_id),
                        "evidence_id": data.get("evidence_id", ""),
                        "examiner": data.get("examiner", ""),
                        "adapter": _adapter_for_recovered(data, str(data.get("run_name") or run_dir), case_id),
                        "device_id": (
                            (data.get("device") or {}).get("udid")
                            or (data.get("device") or {}).get("serial")
                            or ""
                        ),
                        "status": "completed" if (
                            _result_file_count(result) > 0 or result.get("ok")
                        ) else "failed",
                        "started_utc": data.get("started_utc"),
                        "ended_utc": data.get("ended_utc"),
                        "progress": {
                            "stage": "complete",
                            "item": "complete",
                            "detail": "Collection finished (recovered from disk)",
                            "category": "Complete",
                            "bytes_done": int(
                                (result.get("acquisition_record") or {}).get("output_size")
                                or data.get("total_bytes")
                                or 0
                            ),
                            "files_seen": _result_file_count(result) or int(data.get("file_count") or 0),
                            "progress_pct": 100,
                        },
                        "error": "; ".join((data.get("errors") or [])[:3]) or None,
                        "result": result,
                        "recovered": True,
                    })
                except Exception:
                    continue

        # If only the disk-full recovery path found evidence (no log scan hits).
        if not recovered and full:
            recovered.append({
                "run_id": "",
                "run_name": full.get("run_name") or "",
                "case_id": case_id,
                "evidence_id": "",
                "examiner": "",
                "adapter": _adapter_for_recovered(full, str(full.get("run_name") or ""), case_id),
                "device_id": "",
                "status": "completed" if full.get("ok") else "failed",
                "started_utc": None,
                "ended_utc": None,
                "progress": {
                    "stage": "complete",
                    "item": "complete",
                    "detail": "Collection finished (recovered from disk)",
                    "category": "Complete",
                    "bytes_done": int(
                        (full.get("acquisition_record") or {}).get("output_size") or 0
                    ),
                    "progress_pct": 100,
                },
                "error": None,
                "result": _normalize_result(full),
                "recovered": True,
            })

        helper_result = _recover_from_helper(case_id)
        if helper_result:
            helper_files = _result_file_count(helper_result)
            sparse = (not recovered) or all(
                _result_file_count(item.get("result") if isinstance(item.get("result"), dict) else {}) <= 0
                for item in recovered
            )
            if helper_files > 0 and sparse:
                recovered = [{
                    "run_id": "",
                    "run_name": helper_result.get("run_name") or "",
                    "case_id": case_id,
                    "evidence_id": "",
                    "examiner": "",
                    "adapter": _adapter_for_recovered(
                        helper_result, str(helper_result.get("run_name") or ""), case_id
                    ),
                    "device_id": "",
                    "status": "completed",
                    "started_utc": None,
                    "ended_utc": None,
                    "progress": {
                        "stage": "complete",
                        "item": "complete",
                        "detail": "Collection finished (recovered from host helper)",
                        "category": "Complete",
                        "bytes_done": _result_output_size(helper_result),
                        "files_seen": helper_files,
                        "progress_pct": 100,
                    },
                    "error": None,
                    "result": helper_result,
                    "recovered": True,
                }]
            elif recovered and helper_files > 0:
                for item in recovered:
                    current = item.get("result") if isinstance(item.get("result"), dict) else {}
                    if _result_file_count(current) <= 0:
                        item["result"] = helper_result
                        item["status"] = "completed"

        # Rehydrate into the registry so the Complete step can call getRun.
        out: list[dict[str, Any]] = []
        with self._lock:
            for item in recovered:
                run_name = str(item.get("run_name") or "")
                existing = next(
                    (
                        r
                        for r in self._runs.values()
                        if r.run_name == run_name and run_name
                    ),
                    None,
                )
                if existing is not None:
                    if existing.result is None and item.get("result"):
                        existing.result = item["result"]
                        existing.status = str(item.get("status") or existing.status)
                        existing.ended_utc = existing.ended_utc or _now()
                        existing.progress = ProgressSnapshot(
                            stage="complete",
                            item="complete",
                            detail="Collection finished (recovered from disk)",
                            category="Complete",
                            bytes_done=int(
                                ((item.get("progress") or {}).get("bytes_done")) or 0
                            ),
                            files_seen=int(
                                ((item.get("progress") or {}).get("files_seen")) or 0
                            ),
                            updated_utc=_now(),
                        )
                    out.append({**existing.detail(), "recovered": True})
                    continue

                run_id = str(item.get("run_id") or "").strip() or uuid.uuid4().hex[:16]
                run = AcquisitionRun(
                    run_id=run_id,
                    case_id=str(item.get("case_id") or case_id),
                    evidence_id=str(item.get("evidence_id") or ""),
                    adapter=str(item.get("adapter") or "ios_lockdown"),
                    device_id=str(item.get("device_id") or ""),
                    examiner=str(item.get("examiner") or ""),
                    status=str(item.get("status") or "completed"),
                    run_name=run_name,
                    started_utc=str(item.get("started_utc") or _now()),
                    ended_utc=str(item.get("ended_utc") or _now()),
                    progress=ProgressSnapshot(
                        stage="complete",
                        item="complete",
                        detail="Collection finished (recovered from disk)",
                        category="Complete",
                        bytes_done=int(
                            ((item.get("progress") or {}).get("bytes_done")) or 0
                        ),
                        files_seen=int(
                            ((item.get("progress") or {}).get("files_seen")) or 0
                        ),
                        updated_utc=_now(),
                    ),
                    result=item.get("result")
                    if isinstance(item.get("result"), dict)
                    else None,
                    error=item.get("error"),
                )
                self._runs[run.run_id] = run
                out.append({**run.detail(), "recovered": True})
        return out

    def prune(self, keep_last: int = 50) -> int:
        """Drop the oldest terminal runs so a long-lived process does not grow forever."""
        with self._lock:
            finished = sorted(
                (r for r in self._runs.values() if r.status in TERMINAL_STATES),
                key=lambda r: r.ended_utc or r.started_utc,
            )
            excess = max(len(finished) - keep_last, 0)
            for run in finished[:excess]:
                self._runs.pop(run.run_id, None)
                self._threads.pop(run.run_id, None)
            return excess


# Process-wide singleton. Acquisition is hardware-bound to this machine, so a
# single registry per API process is the right scope.
REGISTRY = AcquisitionRegistry()


def get_registry() -> AcquisitionRegistry:
    return REGISTRY
