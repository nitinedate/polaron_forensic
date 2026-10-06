"""Host CLI for live mobile acquisition — UFED §7 orchestrator on the examiner PC.

USB devices are visible only on the workstation. Docker API/workers must not be
the sole acquire path. The host drive helper prefers this module:

    python -m app.services.mobile_acquire.cli --job-id <id> --device-id <serial> ...

Stdout is a single JSON object compatible with ``Invoke-MobileAcquire`` /
``POST /acquire`` consumers (HostEvidencePanel).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


def _default_case_root(job_id: str, output_root: str | None) -> Path:
    if output_root:
        root = Path(output_root)
    else:
        env = (os.environ.get("MOBILE_ACQUISITION_ROOT") or "").strip()
        if env:
            root = Path(env)
        else:
            for letter in ("D", "E", "C"):
                drive = Path(f"{letter}:/")
                if drive.exists():
                    root = drive / "forensic-mobile-acquisitions"
                    break
            else:
                root = Path.home() / "forensic-mobile-acquisitions"
    return root / "cases" / job_id


def _pick_adapter(os_hint: str, device_id: str, detector) -> tuple[str, str] | None:
    """Return (adapter_name, device_id) for the best matching connected device."""
    from app.services.mobile_acquire.methods import CollectionMethod  # noqa: F401

    devices, _warnings = detector.scan()
    hint = (os_hint or "").strip().lower()
    preferred_family = "android" if hint == "android" else "ios" if hint == "ios" else ""

    if device_id:
        for d in devices:
            if d.device_id == device_id or device_id in (d.device_id or ""):
                return d.adapter_name, d.device_id
        low = device_id.lower()
        if preferred_family != "ios" and (
            low.startswith("usb\\") or low.startswith("shell:") or "vid_" in low
        ):
            return "android_mtp", device_id
    if not devices:
        return None
    if preferred_family:
        for d in devices:
            if (d.os_family or "").lower() == preferred_family:
                return d.adapter_name, d.device_id
    d0 = devices[0]
    return d0.adapter_name, d0.device_id


def run_acquire(args: argparse.Namespace) -> dict[str, Any]:
    from app.services.mobile_acquire import (
        AcquisitionRequest,
        CollectionMethod,
        CollectionOrchestrator,
        DeviceDetector,
    )

    job_id = (args.job_id or "").strip()
    if not job_id:
        return {"ok": False, "error": "job_id is required"}

    detector = DeviceDetector()
    picked = _pick_adapter(args.os_hint or "", args.device_id or "", detector)
    if not picked:
        return {
            "ok": False,
            "error": "No connected mobile device detected (adb / MTP / usbmux).",
            "engine": "python_orchestrator",
        }
    adapter_name, device_id = picked
    case_root = _default_case_root(job_id, args.output_root)
    case_root.mkdir(parents=True, exist_ok=True)

    method_override = None
    if args.method:
        try:
            method_override = CollectionMethod(args.method.strip().lower())
        except ValueError:
            return {"ok": False, "error": f"Unknown method '{args.method}'"}

    orch = CollectionOrchestrator(detector)
    result = orch.run(
        AcquisitionRequest(
            case_id=args.case_id or f"JOB-{job_id[:8]}",
            evidence_id=args.evidence_id or "E01",
            examiner=args.examiner or "host-acquire",
            legal_authority=args.legal_authority or f"Job {job_id} live acquisition",
            case_root=str(case_root),
            adapter_name=adapter_name,
            device_id=device_id,
            examiner_method_override=method_override,
            cable_adapter_asset_id=args.cable or "",
            backup_password=args.backup_password,
            network_isolated=True if args.network_isolated else None,
            create_working_copy=True,
            examiner_notes=f"Host CLI acquire for job {job_id}",
        )
    )

    working = (result.paths or {}).get("working") or (result.paths or {}).get("original")
    original = (result.paths or {}).get("original")
    package = result.package or {}
    files = package.get("extraction_data") or []
    method = (result.method_decision or {}).get("selected") or "none"

    return {
        "ok": bool(result.ok),
        "engine": "python_orchestrator",
        "run_name": result.run_name,
        "adapter": adapter_name,
        "device_id": device_id,
        "primary_method": method,
        "methods": [method] if method and method != "none" else [],
        "output_path": working or original,
        "original_path": original,
        "working_path": working,
        "backup_path": working if method in ("backup", "advanced_logical") else None,
        "files_copied": len(files),
        "message": (
            f"UFED-aligned package sealed ({method}, {len(files)} files)."
            if result.ok
            else (result.errors[0] if result.errors else "Acquisition failed")
        ),
        "warnings": list(result.warnings or []) + list(result.limitations or [])[:5],
        "errors": list(result.errors or []),
        "paths": result.paths,
        "stage_reached": result.stage_reached,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UFED-aligned live mobile acquisition (host)")
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--device-id", default="")
    parser.add_argument("--device-name", default="")
    parser.add_argument("--os-hint", default="other")
    parser.add_argument("--output-root", default="")
    parser.add_argument("--case-id", default="")
    parser.add_argument("--evidence-id", default="E01")
    parser.add_argument("--examiner", default="host-acquire")
    parser.add_argument("--legal-authority", default="")
    parser.add_argument("--method", default="", help="Optional CollectionMethod override")
    parser.add_argument("--cable", default="")
    parser.add_argument("--backup-password", default=None)
    parser.add_argument("--network-isolated", action="store_true")
    args = parser.parse_args(argv)

    try:
        payload = run_acquire(args)
    except Exception as exc:
        payload = {"ok": False, "error": str(exc), "engine": "python_orchestrator"}
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
