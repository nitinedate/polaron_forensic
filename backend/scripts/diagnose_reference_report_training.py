#!/usr/bin/env python3
"""Print the five-report exemplar mapping used by the Report Agent."""
from __future__ import annotations

import json
from pathlib import Path
import sys

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.services.report_reference_kb import (
    load_reference_corpus,
    reference_corpus_fingerprint,
    reference_corpus_summary,
    validate_reference_corpus,
)


def main() -> int:
    errors = validate_reference_corpus()
    data = load_reference_corpus()
    print("Reference forensic report corpus")
    print("fingerprint:", reference_corpus_fingerprint())
    print("summary:", json.dumps(reference_corpus_summary(), indent=2))
    if errors:
        print("errors:")
        for item in errors:
            print(" -", item)
        return 2
    print("objective patterns:")
    for pattern in data.get("objective_patterns") or []:
        print(f" - {pattern.get('id')}: {pattern.get('canonical_title')}")
        print("   KB reports:", ", ".join(pattern.get("kb_report_ids") or []))
        print("   Annexure:", ", ".join(pattern.get("annexure_kinds") or []) or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
