#!/usr/bin/env python3
"""CLI for the host drive helper: list iOS devices on Apple usbmux."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

try:
    from app.services.mobile_acquire.ios_usbmux import as_json

    print(as_json())
except Exception as exc:
    print(json.dumps({"ok": False, "devices": [], "count": 0, "error": str(exc)}))
    raise SystemExit(1)
