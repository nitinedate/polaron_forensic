#!/usr/bin/env python3
"""iOS-only: unpack hashed iTunes backup files into examiner-readable artifacts.

Android must not import or call this module. Looks under ios_image/ and
ios_backup/ for Manifest.db, then copies ChatStorage / SMS / catalogued
app DBs to readable_artifacts/.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialise iOS backup hashes (iosagent only)")
    parser.add_argument("--original", required=True)
    parser.add_argument("--exports", default="")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent.parent
    backend = here / "backend"
    if str(backend) not in sys.path:
        sys.path.insert(0, str(backend))

    from app.services.mobile_acquire.ios_readable import materialize_ios_readable_artifacts

    original = Path(args.original)
    if not original.is_dir():
        print(json.dumps({"ok": False, "error": f"original not found: {original}", "agent": "iosagent"}))
        return 1

    out = materialize_ios_readable_artifacts(original)
    extra = None
    if args.exports:
        extra = materialize_ios_readable_artifacts(original, dest_root=Path(args.exports) / "readable_artifacts")

    def _slim(payload: dict | None) -> dict:
        if not payload:
            return {}
        return {
            "ok": payload.get("ok"),
            "copied": len(payload.get("copied") or []),
            "deleted_whatsapp_messages": payload.get("deleted_whatsapp_messages"),
            "deleted_whatsapp_media": payload.get("deleted_whatsapp_media"),
            "whatsapp_media_live": payload.get("whatsapp_media_live"),
            "camera_media": payload.get("camera_media"),
            "readable_root": payload.get("readable_root"),
        }

    print(json.dumps({
        "ok": bool(out.get("ok")),
        "agent": "iosagent",
        "original": _slim(out),
        "exports": _slim(extra) if extra else None,
    }))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
