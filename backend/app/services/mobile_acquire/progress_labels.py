"""Human-readable acquisition progress labels for the Device Wizard UI."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

# Pipeline stage → [lo, hi] percent bands when bytes_total is unknown.
_STAGE_BANDS: dict[str, tuple[int, int]] = {
    "queued": (0, 2),
    "starting": (1, 5),
    "identify": (5, 8),
    "capability": (6, 9),
    "initialize": (8, 10),
    "preflight": (9, 12),
    "acquire": (12, 78),
    "integrity": (78, 86),
    "hashing": (82, 92),
    "working_copy": (90, 95),
    "export": (94, 98),
    "summary": (97, 99),
    "complete": (100, 100),
    "failed": (100, 100),
}

# Within the acquire band, map known item tokens to sub-ranges (fractions of the band).
_ACQUIRE_ITEM_BANDS: list[tuple[str, float, float]] = [
    ("host_usb_bridge", 0.00, 0.04),
    ("preparing", 0.00, 0.04),
    ("starting", 0.00, 0.04),
    ("device_state", 0.04, 0.12),
    ("crash", 0.10, 0.16),
    ("afc", 0.14, 0.42),
    ("dcim", 0.18, 0.40),
    ("photodata", 0.20, 0.38),
    ("whatsapp", 0.35, 0.48),
    ("telegram", 0.35, 0.48),
    ("shared_storage", 0.38, 0.52),
    ("ios_backup", 0.42, 0.92),
    ("android_backup", 0.42, 0.92),
    ("backup", 0.42, 0.92),
    ("collecting", 0.20, 0.70),
]


def _byte_fraction(bytes_done: int) -> float:
    """0..~0.95 curve from collected bytes when no total is known.

    Tuned so early megabytes barely move the bar, while multi-GB phone
    pulls visibly advance during the long backup/AFC phases.
    """
    done = max(0, int(bytes_done or 0))
    if done <= 0:
        return 0.0
    mb = done / (1024 * 1024)
    # ~1 GB ≈ 0.08, ~8 GB ≈ 0.49, ~20 GB ≈ 0.81, asymptote 0.95
    return min(0.95, 1.0 - math.exp(-mb / 12000.0))


def _acquire_item_fraction(item: str) -> tuple[float, float]:
    low = (item or "").strip().lower().replace("\\", "/")
    for token, start, end in _ACQUIRE_ITEM_BANDS:
        if token in low:
            return start, end
    return 0.15, 0.75


def estimate_acquisition_progress_pct(
    *,
    stage: str,
    item: str = "",
    bytes_done: int = 0,
    bytes_total: int | None = None,
    files_seen: int = 0,
) -> tuple[int, str]:
    """Return (percent, mode) for the mobile collection progress bar.

    mode is ``bytes`` when the adapter reported a real total, otherwise
    ``estimated`` from pipeline stage + collected volume so the bar moves
    during unbounded iOS/Android pulls.
    """
    stage_l = (stage or "starting").strip().lower()
    if stage_l in ("complete", "completed", "done"):
        return 100, "bytes" if bytes_total else "estimated"
    if stage_l == "failed":
        return 100, "estimated"

    if bytes_total and int(bytes_total) > 0:
        pct = min(99, max(1, int(100 * max(0, int(bytes_done or 0)) / int(bytes_total))))
        return pct, "bytes"

    lo, hi = _STAGE_BANDS.get(stage_l, (10, 70))
    if lo >= 100:
        return 100, "estimated"

    span = max(1, hi - lo)
    byte_f = _byte_fraction(bytes_done)
    if stage_l == "acquire":
        item_lo, item_hi = _acquire_item_fraction(item)
        # Stay inside the item sub-band; bytes fill from item_lo → item_hi.
        frac = item_lo + (item_hi - item_lo) * byte_f
        if files_seen > 0 and frac < item_lo + 0.02:
            frac = item_lo + 0.02
    else:
        frac = min(0.9, 0.15 + 0.75 * byte_f)

    pct = int(lo + span * frac)
    return min(99, max(lo, pct)), "estimated"


def describe_progress_item(item: str) -> dict[str, str]:
    """Map adapter progress tokens to examiner-facing fetch descriptions."""
    raw = (item or "").strip()
    low = raw.lower().replace("\\", "/")

    if not raw or raw in {"host_usb_bridge", "preparing", "starting"}:
        return {
            "category": "Preparing",
            "detail": "Starting host USB collection and preparing the evidence package…",
        }
    if low.startswith("device_state") or "/device_state" in low:
        return {
            "category": "Device state",
            "detail": f"Capturing live device state / databases — {raw}",
        }
    if "crash" in low:
        return {
            "category": "Diagnostics",
            "detail": "Collecting crash reports and diagnostic logs…",
        }
    if "ios_backup/unlock" in low or "unlock_required" in low:
        return {
            "category": "Unlock required",
            "detail": (
                "Unlock the iPhone, enter the passcode, and keep the screen on — "
                "iTunes/Finder backup cannot start while the device is locked."
            ),
        }
    if "ios_backup/attempt" in low:
        return {
            "category": "iOS backup",
            "detail": (
                "Fetching iTunes/Finder backup (SMS/iMessage, WhatsApp app data, photos domains). "
                "If prompted on the phone, enter the passcode and stay unlocked."
            ),
        }
    if "ios_backup" in low or low.endswith("backup") and "android" not in low:
        return {
            "category": "iOS backup",
            "detail": (
                "Fetching iTunes/Finder backup (SMS/iMessage, WhatsApp app data, "
                "photos domains, call history where backup type allows)…"
            ),
        }
    if "android_backup" in low or low.endswith(".ab"):
        return {
            "category": "Android backup",
            "detail": "Fetching Android backup agent payload (apps that allow backup)…",
        }
    if "afc" in low and "dcim" in low:
        return {
            "category": "Photos & video",
            "detail": "Fetching Camera Roll / DCIM over AFC (photos, videos, live photos)…",
        }
    if "afc" in low and "photodata" in low:
        return {
            "category": "Photo library",
            "detail": "Fetching PhotoData library databases and thumbnails over AFC…",
        }
    if "afc" in low and "download" in low:
        return {
            "category": "Downloads",
            "detail": "Fetching Downloads folder over AFC…",
        }
    if "afc" in low:
        return {
            "category": "iOS media",
            "detail": f"Fetching media partition over AFC — {raw}",
        }
    if "whatsapp" in low:
        return {
            "category": "WhatsApp media",
            "detail": f"Fetching WhatsApp shared media / folders — {raw}",
        }
    if "telegram" in low:
        return {
            "category": "Telegram media",
            "detail": f"Fetching Telegram shared media — {raw}",
        }
    if any(x in low for x in ("/dcim", "dcim", "/pictures", "pictures", "/movies", "movies", "/video")):
        return {
            "category": "Photos & video",
            "detail": f"Fetching gallery / camera media — {raw}",
        }
    if any(x in low for x in ("download", "document", "/music", "audio", "recording", "podcast")):
        return {
            "category": "Files & audio",
            "detail": f"Fetching downloads / documents / audio — {raw}",
        }
    if "shared_storage" in low or low.startswith("/sdcard"):
        return {
            "category": "Shared storage",
            "detail": f"Fetching Android shared storage — {raw}",
        }
    if low.startswith("hash") or "manifest" in low:
        return {
            "category": "Integrity",
            "detail": f"Hashing sealed evidence — {raw}",
        }
    if "working" in low or "copy" in low:
        return {
            "category": "Working copy",
            "detail": f"Creating verified working copy — {raw}",
        }
    if "export" in low or "package." in low:
        return {
            "category": "Export",
            "detail": f"Building portable evidence image (.zip/.ufdx/.ufd/.pas) — {raw}",
        }
    return {
        "category": "Collecting",
        "detail": f"Fetching — {raw}",
    }


def enrich_progress_event(event: dict[str, Any], *, case_root: str = "", case_id: str = "") -> dict[str, Any]:
    """Attach detail/category and best-known storage paths to a progress event."""
    out = dict(event)
    labels = describe_progress_item(str(out.get("item") or ""))
    out.setdefault("category", labels["category"])
    out.setdefault("detail", labels["detail"])

    run_name = str(out.get("run_name") or "")
    root = Path(case_root) if case_root else None
    if root and case_id:
        case_dir = root / case_id
        out.setdefault("case_path", str(case_dir))
        if run_name:
            original = case_dir / "02_Original_Extraction" / run_name
            out["output_path"] = str(original)
            # Best-effort media locations examiners look for first.
            item = str(out.get("item") or "").lower()
            if "afc" in item or "dcim" in item or "photo" in item:
                out["media_path"] = str(original / "afc_media" / "DCIM")
            elif "whatsapp" in item or "sdcard" in item or "shared" in item:
                out["media_path"] = str(original / "shared_storage")
            elif "ios_backup" in item:
                out["media_path"] = str(original / "ios_backup")
            else:
                out.setdefault("media_path", str(original))
        else:
            out.setdefault(
                "output_path",
                str(case_dir / "02_Original_Extraction"),
            )
            out.setdefault("media_path", str(case_dir / "02_Original_Extraction"))
    return out
