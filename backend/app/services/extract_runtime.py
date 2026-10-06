"""Runtime extract overrides — read by extract workers each progress tick."""

from __future__ import annotations

import json
from pathlib import Path

# Mounted at /app/data in worker-disk
OVERRIDE_PATH = Path("/app/data/extract_runtime_override.json")


def load_extract_overrides() -> dict:
    try:
        if OVERRIDE_PATH.is_file():
            data = json.loads(OVERRIDE_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def write_extract_overrides(**kwargs) -> None:
    OVERRIDE_PATH.parent.mkdir(parents=True, exist_ok=True)
    cur = load_extract_overrides()
    cur.update({k: v for k, v in kwargs.items() if v is not None})
    OVERRIDE_PATH.write_text(json.dumps(cur, indent=2), encoding="utf-8")
