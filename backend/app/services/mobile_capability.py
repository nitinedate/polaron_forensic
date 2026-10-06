"""Mobile capability decision engine (Architecture v2.1 §25)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.services.mobile_os import MOBILE_OS_OTHER, normalize_mobile_os
from app.services.mobile_segments import (
    folder_has_mobile_segments,
    infer_mobile_platform_from_names,
    infer_mobile_platform_from_paths,
    is_mobile_segment_filename,
    mobile_segment_key,
)

CAPABILITY_LABELS = frozenset({
    "SUPPORTED_DIRECT_LOGICAL",
    "SUPPORTED_BACKUP",
    "SUPPORTED_IMPORT",
    "SUPPORTED_REMOVABLE_MEDIA",
    "SUPPORTED_ROOTED_FILESYSTEM",
    "DEVICE_UNLOCK_REQUIRED",
    "EXTERNAL_TOOL_REQUIRED",
    "CUSTOM_ENGINEERING_REQUIRED",
    "VALIDATION_PENDING",
    "UNSUPPORTED_DIRECT_ACQUISITION",
})


def detect_import_formats(names: list[str]) -> list[str]:
    formats: list[str] = []
    seen: set[str] = set()
    for name in names or []:
        key = mobile_segment_key(name)
        fmt = key[2] if key else None
        if not fmt and is_mobile_segment_filename(name):
            fmt = Path(name).suffix.lower().lstrip(".") or "zip"
        if fmt and fmt not in seen:
            seen.add(fmt)
            formats.append(fmt)
    return formats


def evaluate_mobile_capability(
    *,
    mobile_os: str | None,
    acquisition_mode: str = "import",
    detected_formats: list[str] | None = None,
    evidence_names: list[str] | None = None,
    host_paths: list[str] | None = None,
    folder_path: str | None = None,
    live_device: bool = False,
) -> dict[str, Any]:
    """Return capability label, permitted actions, and examiner-facing reasons."""
    os_id = normalize_mobile_os(mobile_os) or MOBILE_OS_OTHER
    mode = (acquisition_mode or "import").strip().lower()
    formats = list(detected_formats or [])
    if not formats and evidence_names:
        formats = detect_import_formats(evidence_names)

    if folder_path and not formats:
        folder = Path(folder_path)
        if folder.is_dir() and folder_has_mobile_segments(folder):
            from app.services.mobile_segments import mobile_segments_in_folder

            formats = detect_import_formats(mobile_segments_in_folder(folder))

    reasons: list[str] = []
    permitted: list[str] = []

    if live_device:
        # Live acquisition is implemented by app.services.mobile_acquire. Delegate
        # to the real capability model instead of returning a blanket refusal: a
        # connected, authorised handset IS acquirable, and where it is not, the
        # reason must be specific enough for the examiner to act on.
        from app.services.mobile_acquire import CollectionOrchestrator, DeviceDetector

        detector = DeviceDetector()
        try:
            devices, detect_warnings = detector.scan()
        except Exception as exc:  # defensive: never let detection kill the request
            devices, detect_warnings = [], [f"Device detection failed: {exc}"]
        reasons.extend(detect_warnings)

        candidates = [d for d in devices
                      if not os_id or os_id == MOBILE_OS_OTHER or os_id == d.os_family]
        if not candidates:
            reasons.append(
                "No device is currently visible to an available acquisition adapter. "
                "Connect the validated data cable, authorise this workstation on the "
                "device, and re-scan."
            )
            return {
                "capability_label": "DEVICE_UNLOCK_REQUIRED",
                "permitted_actions": ["detect", "import"],
                "reasons": reasons,
                "detected_formats": formats,
                "mobile_os": os_id,
                "acquisition_mode": "acquire",
                "detected_devices": [],
            }

        orchestrator = CollectionOrchestrator(detector)
        device = candidates[0]
        preview = orchestrator.preview(device.adapter_name, device.device_id)
        if not preview.get("ok"):
            reasons.append(preview.get("error", "Device preview failed."))
            return {
                "capability_label": "VALIDATION_PENDING",
                "permitted_actions": ["detect", "import"],
                "reasons": reasons,
                "detected_formats": formats,
                "mobile_os": os_id,
                "acquisition_mode": "acquire",
                "detected_devices": [d.as_dict() for d in candidates],
            }

        capability = preview["capability"]
        reasons.extend(capability.get("warnings") or [])
        supported = capability.get("supported_methods") or []
        return {
            "capability_label": capability.get("capability_label", "VALIDATION_PENDING"),
            "permitted_actions": (["acquire", "import"] if supported else ["import"]),
            "reasons": reasons,
            "detected_formats": formats,
            "mobile_os": os_id or device.os_family,
            "acquisition_mode": "acquire",
            "detected_devices": [d.as_dict() for d in candidates],
            "supported_methods": supported,
            "blocked_methods": capability.get("blocked_methods") or {},
            "preparation_steps": preview.get("preparation_steps") or [],
            "device_profile": preview.get("device_profile") or {},
            "method_profiles": preview.get("method_profiles") or {},
        }

    if mode not in ("import", "acquire"):
        reasons.append(f"Acquisition mode '{mode}' is not recognised; the import workflow is used.")
        return {
            "capability_label": "UNSUPPORTED_DIRECT_ACQUISITION",
            "permitted_actions": ["import"],
            "reasons": reasons,
            "detected_formats": formats,
            "mobile_os": os_id,
            "acquisition_mode": "import",
        }

    if formats:
        permitted.append("import")
        reasons.append(f"Known mobile export format(s) detected: {', '.join(formats)}.")
        label = "SUPPORTED_IMPORT"
    else:
        # Allow process path to proceed after register; empty until folder selected.
        permitted.append("import")
        reasons.append("Import workflow available for .pas / .ufd / .ufdx / .zip and backup packages.")
        label = "SUPPORTED_IMPORT"

    inferred = None
    if evidence_names:
        inferred = infer_mobile_platform_from_names(evidence_names)
    if not inferred and host_paths:
        inferred = infer_mobile_platform_from_paths(host_paths)

    mismatch = None
    if inferred and os_id in ("android", "ios"):
        expected = "Android" if os_id == "android" else "iOS"
        if inferred != expected:
            mismatch = (
                f"Examiner selected {expected}, but filenames/paths suggest {inferred}. "
                "Examiner selection will be used."
            )
            reasons.append(mismatch)

    if os_id == MOBILE_OS_OTHER:
        reasons.append("OS marked Other/Unknown — platform inference may fill AXIOM catalog later.")

    return {
        "capability_label": label,
        "permitted_actions": permitted,
        "reasons": reasons,
        "detected_formats": formats,
        "mobile_os": os_id,
        "acquisition_mode": "import",
        "os_mismatch_warning": mismatch,
        "inferred_platform": inferred,
    }


def can_start_acquisition(capability: dict[str, Any] | None) -> bool:
    """True when a live collection may begin against the connected device."""
    if not capability:
        return False
    actions = set(capability.get("permitted_actions") or [])
    return "acquire" in actions and bool(capability.get("supported_methods"))


def can_start_import(capability: dict[str, Any] | None) -> bool:
    if not capability:
        return False
    label = str(capability.get("capability_label") or "")
    actions = set(capability.get("permitted_actions") or [])
    return label == "SUPPORTED_IMPORT" and "import" in actions
