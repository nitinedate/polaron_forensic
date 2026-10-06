#!/usr/bin/env python3
"""Android-only: copy trash, DCIM, and WhatsApp media into readable_artifacts.

iOS must not import or call this module. ChatStorage / AFC stay on the iOS agent.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialise Android trash/WhatsApp (androidagent only)")
    parser.add_argument("--original", required=True)
    parser.add_argument("--exports", default="")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent.parent
    backend = here / "backend"
    if str(backend) not in sys.path:
        sys.path.insert(0, str(backend))

    from app.services.mobile_acquire.android_readable import materialize_android_readable_artifacts

    original = Path(args.original)
    if not original.is_dir():
        print(json.dumps({"ok": False, "error": f"original not found: {original}", "agent": "androidagent"}))
        return 1

    out = materialize_android_readable_artifacts(original)
    extra = None
    if args.exports:
        extra = materialize_android_readable_artifacts(
            original, dest_root=Path(args.exports) / "readable_artifacts"
        )
    def _slim(payload: dict | None) -> dict:
        if not payload:
            return {}
        return {
            "ok": payload.get("ok"),
            "copied": len(payload.get("copied") or []),
            "trashed": payload.get("trashed"),
            "whatsapp_media": payload.get("whatsapp_media"),
            "whatsapp_decrypted_backups": payload.get("whatsapp_decrypted_backups"),
            "whatsapp_decryption_state": payload.get("whatsapp_decryption_state"),
            "limitations": payload.get("limitations") or [],
            "readable_root": payload.get("readable_root"),
        }

    print(json.dumps({
        "ok": bool(out.get("ok")),
        "agent": "androidagent",
        "original": _slim(out),
        "exports": _slim(extra) if extra else None,
    }))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
