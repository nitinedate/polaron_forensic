"""Build portable .zip/.ufdx/.ufd/.pas packages from an existing sealed extraction.

Usage (on examiner host, from backend/ with PYTHONPATH set):

  python -m app.services.mobile_acquire.export_cli ^
    --original "E:\\rag_new2\\evidence\\cases\\CASE-...\\02_Original_Extraction\\RUN" ^
    --exports  "E:\\rag_new2\\evidence\\cases\\CASE-...\\05_Exports\\RUN"

Default writes exactly four files under 05_Exports/<run>: <run>.zip (full ZIP64
payload incl. readable_artifacts), <run>.ufd, <run>.pas, <run>.ufdx. Sidecar
JSON (content_inventory.json, export_catalog.json) goes to 07_Logs/<run>.
Pass --metadata-only to skip packing the acquisition, --shards for
multi-part .part-NNNNN.zip output.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.services.mobile_acquire.content_inventory import inventory_extraction
from app.services.mobile_acquire.export_packages import (
    ExportSpaceError,
    build_export_packages,
    side_files_dir,
)


def slim_inventory(inv: dict) -> dict:
    manifest = inv.get("ios_manifest") or {}
    return {
        "ok": inv.get("ok"),
        "ios_backup_complete": inv.get("ios_backup_complete"),
        "counts": inv.get("counts") or {},
        "totals": inv.get("totals") or {},
        "summary": inv.get("summary"),
        "gaps": inv.get("gaps") or [],
        "ios_manifest": {
            "ios_backup_complete": manifest.get("ios_backup_complete"),
            "camera_media_files": manifest.get("camera_media_files"),
            "whatsapp_media_files": manifest.get("whatsapp_media_files"),
            "whatsapp_db_paths": manifest.get("whatsapp_db_paths") or [],
        },
    }


def _merge_progress(path: str, extra: dict) -> None:
    if not path:
        return
    prev: dict = {}
    try:
        prev = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        if not isinstance(prev, dict):
            prev = {}
    except Exception:
        prev = {}
    prev.update(extra)
    prev.setdefault("stage", "seal")
    prev.setdefault("item", "export_packages")
    prev.setdefault("category", "Sealing")
    # Do not force every export event to 100%. Packaging reports 90..99.6 and
    # only the explicit complete event is allowed to reach 100.
    if str(prev.get("stage") or "").lower() == "complete":
        prev["progress_pct"] = 100
    elif "progress_pct" not in prev:
        prev["progress_pct"] = 90
    Path(path).write_text(json.dumps(prev, separators=(",", ":")), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export portable evidence packages")
    parser.add_argument("--original", required=True, help="02_Original_Extraction/<run> path")
    parser.add_argument("--exports", required=True, help="05_Exports/<run> output path")
    parser.add_argument("--case-id", default="")
    parser.add_argument("--evidence-id", default="")
    parser.add_argument("--method", default="advanced_logical")
    parser.add_argument("--logs", default="")
    parser.add_argument("--hashes", default="")
    parser.add_argument("--progress-file", default="")
    parser.add_argument("--full", action="store_true", help="Pack payload ZIP shards (default)")
    parser.add_argument("--metadata-only", action="store_true", help="Skip payload; write a metadata pointer ZIP only")
    parser.add_argument("--shards", action="store_true", help="Multi-part .part-NNNNN.zip output instead of one full ZIP")
    args = parser.parse_args(argv)

    original = Path(args.original)
    exports = Path(args.exports)
    if not original.is_dir():
        print(json.dumps({"ok": False, "error": f"original not found: {original}"}))
        return 1

    want_full = not bool(args.metadata_only)
    _merge_progress(args.progress_file, {
        "detail": (
            "Writing full evidence ZIP (.zip/.ufd/.pas/.ufdx) for zip-only extract/RAG"
            if want_full else
            "Writing portable metadata packages; sealed image stays in Original"
        ),
        "stage": "seal",
        "item": "export_packages",
        "progress_pct": 90,
        "phase": "export_zip",
        "phase_progress_pct": 0,
    })

    inventory = None
    side_dir = side_files_dir(exports, original.name, Path(args.logs) if args.logs else None)
    inv_path = side_dir / "content_inventory.json"
    legacy_inv = exports / "content_inventory.json"
    if not inv_path.is_file() and legacy_inv.is_file():
        try:
            legacy_inv.replace(inv_path)
        except OSError:
            inv_path = legacy_inv
    if inv_path.is_file():
        try:
            loaded = json.loads(inv_path.read_text(encoding="utf-8-sig"))
            if isinstance(loaded, dict) and loaded.get("ok") is not False:
                inventory = loaded
        except Exception:
            inventory = None
    if inventory is None:
        inventory = inventory_extraction(original)
        try:
            inv_path.write_text(json.dumps(inventory, indent=2, default=str), encoding="utf-8")
        except OSError:
            pass
    try:
        bundle = build_export_packages(
            run_name=original.name,
            export_dir=exports,
            original=original,
            logs=Path(args.logs) if args.logs else None,
            hashes=Path(args.hashes) if args.hashes else None,
            case_id=args.case_id or original.parent.parent.name,
            evidence_id=args.evidence_id,
            method=args.method,
            device={},
            inventory=slim_inventory(inventory),
            full_payload=False if args.metadata_only else True,
            use_shards=True if args.shards else None,
            progress=(lambda event: _merge_progress(args.progress_file, event)) if args.progress_file else None,
        )
    except ExportSpaceError as exc:
        detail = exc.as_dict()
        detail["message"] = str(exc)
        _merge_progress(args.progress_file, {
            "stage": "error",
            "category": "Storage required",
            "item": "export_space",
            "detail": str(exc),
            "progress_pct": 90,
            "storage": detail,
        })
        print(json.dumps({"ok": False, "error": str(exc), "error_code": detail["code"], "storage": detail}, separators=(",", ":")))
        return 3
    except OSError as exc:
        _merge_progress(args.progress_file, {
            "stage": "error", "category": "Export failed", "item": "export_packages",
            "detail": str(exc), "progress_pct": 90,
        })
        print(json.dumps({"ok": False, "error": str(exc), "error_code": "mobile_export_io_error"}, separators=(",", ":")))
        return 4
    except Exception as exc:
        _merge_progress(args.progress_file, {
            "stage": "error", "category": "Export failed", "item": "export_packages",
            "detail": str(exc), "progress_pct": 90,
        })
        print(json.dumps({"ok": False, "error": str(exc), "error_code": "mobile_export_failed"}, separators=(",", ":")))
        return 5

    _merge_progress(args.progress_file, {
        "detail": "Evidence packages written. Sealed original remains the image.",
        "stage": "complete",
        "category": "Complete",
        "progress_pct": 100,
    })
    print(json.dumps({"ok": True, "inventory": slim_inventory(inventory), "export": bundle.as_dict()}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
