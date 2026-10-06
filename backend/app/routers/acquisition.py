"""Mobile acquisition API — Device Wizard backend (Architecture §3.1, §7).

Endpoint flow mirrors the examiner's screen sequence:

    GET  /api/acquisition/adapters          which access technologies are usable here
    GET  /api/acquisition/devices           §7.1  device detector
    POST /api/acquisition/preview           §7.2-4 profile, capability, prep steps
    POST /api/acquisition/start             §7.5-10 full collection run
    POST /api/acquisition/verify            §12   re-verify a stored extraction
    GET  /api/acquisition/methods           §6    method reference for the UI

`preview` is deliberately separate from `start`: §7 requires the examiner to see
the resolved capability, the cable/preparation instructions and the coverage
limitations of each method BEFORE a collection begins. Collapsing the two would
mean the examiner authorises a method without seeing what it does not cover.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.deps import CurrentUser, firm_db, require_firm_permission
from app.services.mobile_acquire import (
    AcquisitionRequest,
    CollectionMethod,
    CollectionOrchestrator,
    DeviceDetector,
    IntegrityManifest,
    METHOD_PROFILES,
    coverage_statement,
    verify_against_manifest,
)
from app.services.mobile_acquire.entitlements import load_profile
from app.services.mobile_acquire.orchestrator import TOOL_VERSION
from app.services.mobile_acquire import host_bridge
from app.services.mobile_acquire.run_registry import TERMINAL_STATES, get_registry
from app.service_identity import mobile_service_platform
from app.services.mobile_platform_agents import detect_mobile_platform
from app.services.mobile_acquire.validation import (
    ACCEPTANCE_AREAS,
    CRITICAL_DEVICE_FAMILIES,
    ToolVersionLedger,
)

router = APIRouter(prefix="/api/acquisition", tags=["acquisition"])


def _required_mobile_platform() -> str | None:
    return mobile_service_platform()


def _platform_allowed(*hints: Any) -> bool:
    required = _required_mobile_platform()
    if not required:
        return True
    detected = detect_mobile_platform(*hints)
    return detected == required


def _assert_platform(*hints: Any) -> None:
    required = _required_mobile_platform()
    if not required:
        return
    detected = detect_mobile_platform(*hints)
    if detected != required:
        got = detected or "unknown"
        raise HTTPException(
            status_code=403,
            detail=(
                f"This is the {required.title()} mobile backend. "
                f"The selected device/adapter is {got}; use the matching mobile backend."
            ),
        )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PreviewRequest(BaseModel):
    adapter: str
    device_id: str


class StartRequest(BaseModel):
    adapter: str
    device_id: str
    case_id: str
    evidence_id: str
    legal_authority: str
    case_root: str

    objective_methods: list[str] = Field(default_factory=list)
    authorized_methods: list[str] = Field(default_factory=list)
    method_override: str | None = None

    cable_adapter_asset_id: str = ""
    license_endpoint_id: str = ""
    backup_password: str | None = None
    examiner_notes: str = ""
    device_condition: str = ""
    network_isolated: bool | None = None
    create_working_copy: bool = True
    cloud_mailboxes: list[dict[str, Any]] = Field(default_factory=list)


class ValidationRecordRequest(BaseModel):
    device_family: str
    passed: bool
    approver: str = ""
    notes: str = ""
    tool_version: str | None = None


class VerifyRequest(BaseModel):
    extraction_path: str
    manifest_path: str


class RemoveRunRequest(BaseModel):
    run_name: str = ""
    case_id: str = ""
    progress_file: str = ""
    paths: dict[str, Any] = Field(default_factory=dict)


def _methods(values: list[str]) -> list[CollectionMethod]:
    out: list[CollectionMethod] = []
    for value in values or []:
        try:
            out.append(CollectionMethod(value.strip().lower()))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown collection method '{value}'. Valid values: "
                       + ", ".join(m.value for m in CollectionMethod),
            )
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/adapters")
def list_adapters(
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """Which device-access technologies this workstation can actually use.

    Reported honestly: an adapter whose external tooling is missing is listed as
    unavailable with the reason, so a device that cannot be seen is never
    mistaken for a device that is not connected.

    When the API runs in Docker (no USB), availability is merged from the
    examiner host drive helper on port 9876.
    """
    from app.services.mobile_acquire import host_bridge

    detector = DeviceDetector()
    adapters = []
    for adapter in detector.adapters:
        try:
            available = adapter.tool_available()
            reason = "" if available else (
                "Required external tooling is not installed in this process "
                "(typical for Docker API). Host helper will be used when available."
            )
        except Exception as exc:
            available, reason = False, str(exc)
        adapters.append({
            "name": adapter.name,
            "os_family": adapter.os_family,
            "available": available,
            "reason": reason,
        })
    helper_ok = host_bridge.helper_reachable()
    host = host_bridge.fetch_host_adapters() if helper_ok else []
    merged = host_bridge.merge_adapters(adapters, host)
    required = _required_mobile_platform()
    if required:
        merged = [a for a in merged if _platform_allowed(a)]
    return {
        "adapters": merged,
        "host_helper": {
            "url": host_bridge.helper_base_url(),
            "reachable": helper_ok,
            "hint": (
                None if helper_ok else
                "Host drive helper on port 9876 is offline or not answering "
                "(often blocked by an old single-threaded acquire). On the examiner PC run: "
                "powershell -ExecutionPolicy Bypass -File scripts\\ensure-host-drive-helper.ps1"
            ),
        },
    }


@router.get("/methods")
def list_methods(
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """§6 method reference, including the mandatory coverage caveat per method."""
    return {
        "methods": [
            {
                "method": method.value,
                **coverage_statement(method),
                "intrusiveness_rank": rank,
            }
            for rank, method in enumerate(
                sorted(METHOD_PROFILES, key=lambda m: m.value), start=1)
        ],
        "selection_principle": (
            "Select the least intrusive method that is sufficient for the authorised "
            "objective, while preserving the option to perform a deeper method when "
            "legally authorised and technically necessary. Never assume that a "
            "particular device supports physical or full-file-system acquisition."
        ),
    }


@router.get("/devices")
def detect_devices(
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """§7 step 1 — device detector (local tools, else examiner host USB bridge)."""
    from app.services.mobile_acquire import host_bridge

    detector = DeviceDetector()
    devices, warnings = detector.scan()
    # Docker has no USB. Adapter "tooling missing" is expected and must not
    # drown the examiner UI — phones are detected on the Windows host helper.
    warnings = [
        w for w in warnings
        if "external tooling is not installed" not in w
        and "Devices of this type will not be detected" not in w
    ]
    out = [d.as_dict() for d in devices]
    helper_ok = host_bridge.helper_reachable()
    host_adapters: list[dict[str, Any]] = []
    local_adapters: list[dict[str, Any]] = []
    for adapter in detector.adapters:
        try:
            available = adapter.tool_available()
        except Exception:
            available = False
        local_adapters.append({
            "name": adapter.name,
            "os_family": adapter.os_family,
            "available": available,
            "reason": "",
        })

    # Docker API rarely sees USB — merge host helper detection.
    if helper_ok:
        host_adapters = host_bridge.fetch_host_adapters()
        host_ready = {a["name"] for a in host_adapters if a.get("available")}
        # Drop container-local "tooling missing" noise when the examiner host has the adapter.
        warnings = [
            w for w in warnings
            if not any(
                f"Adapter '{name}' is unavailable" in w for name in host_ready
            )
        ]
        host_devices, host_warnings = host_bridge.fetch_host_devices()
        warnings = list(warnings) + list(host_warnings)
        seen = {(d.get("adapter"), d.get("device_id")) for d in out}
        for hd in host_devices:
            key = (hd.get("adapter"), hd.get("device_id"))
            if key not in seen and hd.get("device_id"):
                out.append(hd)
                seen.add(key)
    elif not out:
        warnings = list(warnings) + [
            "No USB tools in the API container and host drive helper is offline. "
            "On the examiner PC run: scripts\\ensure-host-drive-helper.ps1 — then click Scan again."
        ]

    required = _required_mobile_platform()
    merged_adapters = host_bridge.merge_adapters(local_adapters, host_adapters)
    if required:
        out = [d for d in out if _platform_allowed(d)]
        merged_adapters = [a for a in merged_adapters if _platform_allowed(a)]
    return {
        "devices": out,
        "warnings": warnings,
        "device_count": len(out),
        "host_helper_reachable": helper_ok,
        "mobile_platform": required,
        "adapters": merged_adapters,
    }


@router.post("/preview")
def preview_device(
    payload: PreviewRequest,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """§7 steps 2-4 — identify, resolve capability, show preparation instructions."""
    from app.services.mobile_acquire import host_bridge

    _assert_platform({"adapter": payload.adapter, "device_id": payload.device_id})
    detector = DeviceDetector()
    adapter = detector.adapter_by_name(payload.adapter)
    if adapter is not None:
        _assert_platform({"adapter": payload.adapter, "os_family": getattr(adapter, "os_family", "")})
    if adapter is not None and adapter.tool_available():
        orchestrator = CollectionOrchestrator(detector)
        preview = orchestrator.preview(payload.adapter, payload.device_id)
        if not preview.get("ok"):
            raise HTTPException(status_code=400, detail=preview.get("error", "Preview failed."))
        return preview

    if host_bridge.helper_reachable():
        host_preview = host_bridge.host_preview(payload.adapter, payload.device_id)
        if host_preview and host_preview.get("ok"):
            return host_preview
        detail = (host_preview or {}).get("error") or "Host preview failed."
        raise HTTPException(status_code=400, detail=detail)

    raise HTTPException(
        status_code=503,
        detail=(
            "USB acquisition tools are not available inside Docker. Start the host drive "
            "helper (port 9876) on the examiner PC, plug in the phone, then retry."
        ),
    )


@router.post("/start")
def start_acquisition(
    payload: StartRequest,
    db: Session = Depends(firm_db),
    user: CurrentUser = Depends(require_firm_permission("forensic.job.create")),
) -> dict[str, Any]:
    """Architecture section 7 steps 5-10 — queue the full collection run.

    Returns immediately with a run id. A full-filesystem collection can run for
    hours; holding the HTTP request open for that long means a dropped
    connection orphans the collection and the examiner never sees the outcome
    even though the evidence was sealed correctly. Progress is streamed from
    /runs/{run_id}/stream and the result is durable in the case folder.
    """
    _assert_platform({"adapter": payload.adapter, "device_id": payload.device_id})
    if not payload.legal_authority.strip():
        raise HTTPException(
            status_code=400,
            detail="Legal authority is required before any collection may begin (section 14).",
        )

    override = _methods([payload.method_override])[0] if payload.method_override else None

    request = AcquisitionRequest(
        case_id=payload.case_id,
        evidence_id=payload.evidence_id,
        examiner=getattr(user, "email", None) or getattr(user, "id", "unknown"),
        legal_authority=payload.legal_authority,
        case_root=payload.case_root,
        adapter_name=payload.adapter,
        device_id=payload.device_id,
        objective_methods=_methods(payload.objective_methods),
        authorized_methods=_methods(payload.authorized_methods),
        examiner_method_override=override,
        cable_adapter_asset_id=payload.cable_adapter_asset_id,
        license_endpoint_id=payload.license_endpoint_id,
        backup_password=payload.backup_password,
        examiner_notes=payload.examiner_notes,
        device_condition=payload.device_condition,
        network_isolated=payload.network_isolated,
        create_working_copy=payload.create_working_copy,
        cloud_mailboxes=list(payload.cloud_mailboxes or []),
    )

    try:
        run = get_registry().start(request)
    except RuntimeError as exc:
        # Device already being acquired — a conflict, not a server fault.
        raise HTTPException(status_code=409, detail=str(exc))
    return run.summary()


def _merge_host_helper_runs(
    runs: list[dict[str, Any]],
    *,
    active_only: bool,
) -> list[dict[str, Any]]:
    """Surface USB collections that live in the host helper, not this API process.

    Browser refresh used to ask this endpoint for active runs, get an empty
    list (host jobs are not in the in-memory registry), then fall through to
    the last finished Docker run and freeze the wizard on Complete.
    """
    seen: set[str] = set()
    for run in runs:
        rid = str(run.get("run_id") or "")
        hid = str(run.get("host_job_id") or "")
        if rid:
            seen.add(rid)
        if hid:
            seen.add(hid)
    helper_runs: list[dict[str, Any]] = []
    try:
        for job in host_bridge.fetch_helper_jobs():
            if not _platform_allowed(job):
                continue
            jid = str(job.get("job_id") or "")
            if not jid or jid in seen:
                continue
            status = str(job.get("status") or "").lower()
            if active_only and status not in ("", "running", "queued"):
                continue
            helper_runs.append(host_bridge.helper_job_as_run(job))
            seen.add(jid)
    except Exception:
        pass
    return helper_runs + runs


@router.get("/runs")
def list_runs(
    active_only: bool = Query(False),
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """Every acquisition this workstation has started, including host-helper USB jobs."""
    registry = get_registry()
    runs = _merge_host_helper_runs(
        registry.list(include_finished=not active_only),
        active_only=active_only,
    )
    active_count = sum(1 for r in runs if r.get("status") not in TERMINAL_STATES)
    return {
        "runs": runs,
        "active_count": active_count,
    }


@router.get("/runs/recover")
def recover_runs(
    case_root: str = Query(...),
    case_id: str = Query(...),
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """Rebuild run history from the case folder after an API restart."""
    return {"runs": get_registry().recover(case_root, case_id)}


@router.get("/runs/recover-recent")
def recover_recent_runs(
    case_root: str = Query("/evidence/cases"),
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """Rehydrate the newest sealed collection when the in-memory run was lost."""
    return {"runs": get_registry().recover_recent(case_root)}


@router.get("/runs/{run_id}")
def get_run(
    run_id: str,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    run = get_registry().get(run_id)
    if run is not None:
        return run.detail()
    if host_bridge.is_host_job_id(run_id):
        job = host_bridge.fetch_helper_job(run_id)
        if job is not None:
            return host_bridge.helper_job_as_run(job, detail=True)
    raise HTTPException(status_code=404, detail="Acquisition run not found.")


@router.post("/runs/{run_id}/cancel")
def cancel_run(
    run_id: str,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.create")),
) -> dict[str, Any]:
    """Stop the collection immediately and keep whatever is already on disk."""
    registry = get_registry()
    run = registry.get(run_id)
    if run is None and host_bridge.is_host_job_id(run_id):
        res = host_bridge.host_cancel_job(run_id)
        accepted = bool(res and res.get("ok"))
        return {
            "accepted": accepted,
            "status": "cancelling" if accepted else "unknown",
            "message": (
                "Collection is stopping now. Files already written stay in the case folder "
                "as an interrupted extraction."
                if accepted else
                str((res or {}).get("error") or "Host collection could not be stopped.")
            ),
        }
    if run is None:
        raise HTTPException(status_code=404, detail="Acquisition run not found.")
    accepted = registry.cancel(run_id)
    return {
        "accepted": accepted,
        "status": "cancelling" if accepted else run.status,
        "message": (
            "Collection is stopping now. Files already written stay in the case folder "
            "as an interrupted extraction."
            if accepted else
            f"Run is already {run.status}; nothing to cancel."
        ),
    }


@router.post("/runs/{run_id}/remove")
def remove_run(
    run_id: str,
    body: RemoveRunRequest | None = None,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.create")),
) -> dict[str, Any]:
    """Stop the collection and delete this run's extracted files from the case."""
    import shutil
    from pathlib import Path

    payload = body or RemoveRunRequest()
    registry = get_registry()
    run = registry.get(run_id)
    paths: dict[str, Any] = dict(payload.paths or {})
    run_name = (payload.run_name or "").strip()
    case_id = (payload.case_id or "").strip()
    host_id = run_id
    if run is not None:
        run.request_cancel()
        run_name = run.run_name or run_name
        case_id = run.case_id or case_id
        host_id = run.host_job_id or run_id
        if isinstance(run.result, dict):
            raw = run.result.get("paths")
            if isinstance(raw, dict):
                for key, value in raw.items():
                    paths.setdefault(str(key), value)
        if run.progress:
            if run.progress.output_path:
                paths.setdefault("original", run.progress.output_path)
            if run.progress.case_path:
                paths.setdefault("case_root", run.progress.case_path)
        run.status = "cancelled"
        run.error = "removed_by_examiner"
        run.result = {
            "ok": False,
            "run_name": run_name,
            "stage_reached": "removed",
            "errors": ["Collection stopped and this run's files were removed"],
            "paths": {},
        }
    elif not host_bridge.is_host_job_id(run_id):
        raise HTTPException(status_code=404, detail="Acquisition run not found.")
    res = None
    if host_bridge.is_host_job_id(host_id) or host_bridge.is_host_job_id(run_id):
        res = host_bridge.host_remove_job(
            host_id if host_bridge.is_host_job_id(host_id) else run_id,
            run_name=run_name,
            case_id=case_id,
            progress_file=payload.progress_file,
            paths=paths or None,
        )
    protected_prefixes = ("CASE-", "02_", "03_", "05_", "07_", "08_")
    for key in ("original", "working", "logs", "hashes", "exports"):
        p = paths.get(key)
        if not p:
            continue
        try:
            target = Path(str(p))
            if not target.is_dir():
                continue
            if target.name.startswith(protected_prefixes):
                continue
            if run_name and run_name not in str(target):
                continue
            shutil.rmtree(target, ignore_errors=True)
        except Exception:
            pass
    accepted = bool((res and res.get("ok")) or run is not None)
    return {
        "accepted": accepted,
        "status": "removed",
        "removed": (res or {}).get("removed") or [],
        "message": (
            (res or {}).get("message")
            or "Collection stopped and this run's files were removed."
        ),
    }


@router.get("/runs/{run_id}/stream")
async def stream_run(
    run_id: str,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> StreamingResponse:
    """Server-sent progress for a running acquisition.

    Any number of readers may attach and detach freely; the stream is a view of
    the shared snapshot, never the owner of the collection. Closing this stream
    does NOT stop the acquisition.
    """
    registry = get_registry()
    if registry.get(run_id) is None and not (
        host_bridge.is_host_job_id(run_id) and host_bridge.fetch_helper_job(run_id)
    ):
        raise HTTPException(status_code=404, detail="Acquisition run not found.")

    async def event_gen() -> AsyncIterator[str]:
        last_payload: str | None = None
        idle_ticks = 0
        while True:
            run = registry.get(run_id)
            mapped: dict[str, Any] | None = None
            if run is None:
                job = (
                    host_bridge.fetch_helper_job(run_id)
                    if host_bridge.is_host_job_id(run_id)
                    else None
                )
                if job is None:
                    yield f"event: error\ndata: {json.dumps({'message': 'Run disappeared.'})}\n\n"
                    return
                mapped = host_bridge.helper_job_as_run(job, detail=True)
                payload = json.dumps({k: v for k, v in mapped.items() if k != "result"})
            else:
                payload = json.dumps(run.summary())

            if payload != last_payload:
                yield f"event: progress\ndata: {payload}\n\n"
                last_payload = payload
                idle_ticks = 0
            else:
                idle_ticks += 1
                # Heartbeat every ~15s. Without it, proxies close an idle
                # connection during the long quiet stretches of a big pull and
                # the examiner sees the run as dead while it is still running.
                if idle_ticks >= 15:
                    yield ": keep-alive\n\n"
                    idle_ticks = 0

            if mapped is not None:
                if mapped.get("status") in TERMINAL_STATES:
                    yield f"event: done\ndata: {json.dumps(mapped)}\n\n"
                    return
            elif run is not None and run.status in TERMINAL_STATES:
                yield f"event: done\ndata: {json.dumps(run.detail())}\n\n"
                return

            await asyncio.sleep(1)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _ledger() -> ToolVersionLedger | None:
    path = os.environ.get("FORENSIC_VALIDATION_LEDGER")
    if not path:
        return None
    try:
        return ToolVersionLedger(path)
    except Exception:
        return None


@router.get("/licence")
def licence_status(
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """Architecture section 3.3 — what this endpoint is licensed and equipped to do.

    Distinguishes a licensing gap (procurement can fix it) from a capability the
    platform does not implement at all. Neither may be reported as an absence of
    evidence on the device.
    """
    profile = load_profile()
    return {"tool_version": TOOL_VERSION, "licence": profile.as_dict()}


@router.get("/validation")
def validation_status(
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """Architecture section 15/22 — production readiness of the current build."""
    ledger = _ledger()
    if ledger is None:
        return {
            "tool_version": TOOL_VERSION,
            "configured": False,
            "production_ready": False,
            "message": (
                "No validation ledger is configured (FORENSIC_VALIDATION_LEDGER). "
                "Acceptance testing against a known-device corpus cannot be evidenced. "
                "Complete section 22 acceptance testing before casework."
            ),
            "acceptance_areas": ACCEPTANCE_AREAS,
            "critical_device_families": list(CRITICAL_DEVICE_FAMILIES),
        }
    status = ledger.status(TOOL_VERSION)
    return {
        **status,
        "configured": True,
        "acceptance_areas": ACCEPTANCE_AREAS,
        "version_drift": ledger.drift_from(TOOL_VERSION),
        "versions_seen": ledger.versions_seen(),
    }


@router.post("/validation/record")
def record_validation(
    payload: ValidationRecordRequest,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.create")),
) -> dict[str, Any]:
    """Record an acceptance area validated outside the automated harness.

    Peer review, network controls, analysis import and report generation cannot
    be self-certified by the tool. They are attested here by a named examiner so
    the ledger reflects the whole of section 22, not just the automatable part.
    """
    ledger = _ledger()
    if ledger is None:
        raise HTTPException(
            status_code=400,
            detail="No validation ledger configured (FORENSIC_VALIDATION_LEDGER).",
        )
    if payload.device_family not in CRITICAL_DEVICE_FAMILIES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown device family. Expected one of: "
                   + ", ".join(CRITICAL_DEVICE_FAMILIES),
        )
    record = ledger.record_manual(
        tool_version=payload.tool_version or TOOL_VERSION,
        device_family=payload.device_family,
        examiner=getattr(user, "email", None) or getattr(user, "id", "unknown"),
        passed=payload.passed,
        approver=payload.approver,
        notes=payload.notes,
    )
    return {"recorded": record.as_dict(), "status": ledger.status(TOOL_VERSION)}


@router.post("/verify")
def verify_extraction(
    payload: VerifyRequest,
    user: CurrentUser = Depends(require_firm_permission("forensic.job.read")),
) -> dict[str, Any]:
    """§12 — re-verify a stored extraction against its manifest."""
    import json
    from pathlib import Path

    manifest_file = Path(payload.manifest_path)
    if not manifest_file.is_file():
        raise HTTPException(status_code=404, detail="Manifest not found.")
    extraction = Path(payload.extraction_path)
    if not extraction.is_dir():
        raise HTTPException(status_code=404, detail="Extraction directory not found.")

    data = json.loads(manifest_file.read_text())
    manifest = IntegrityManifest(
        run_name=data.get("run_name", ""),
        created_utc=data.get("created_utc", ""),
        algorithms=tuple(data.get("algorithms") or ()),
    )
    result = verify_against_manifest(extraction, data)
    return {
        "run_name": manifest.run_name,
        "manifest_created_utc": manifest.created_utc,
        **result.as_dict(),
        "interpretation": (
            "Verified: the extraction is byte-identical to the state recorded at "
            "acquisition."
            if result.ok else
            "FAILED: the extraction no longer matches its acquisition-time hashes. "
            "Do not analyse this copy. Restore from the immutable original and "
            "record the discrepancy."
        ),
    }
