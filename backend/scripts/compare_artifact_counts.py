#!/usr/bin/env python3
"""Compare app artifact xlsx export vs reference AXIOM PDF report counts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import openpyxl

from app.services.axiom_report_reconciliation import build_report_reconciliation


def norm_name(value: str | None) -> str:
    text = re.sub(r"\s+", " ", (value or "").strip().lower())
    text = text.replace("&", "and").replace("—", "-").replace("–", "-")
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def load_xlsx(path: Path) -> dict[str, dict]:
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    header = rows[0]
    idx = {str(h).strip().lower(): i for i, h in enumerate(header) if h}
    out: dict[str, dict] = {}
    for row in rows[1:]:
        artifact = row[idx.get("artifact", 1)]
        if not artifact:
            continue
        count = row[idx.get("count", 2)]
        in_scope = row[idx.get("in scope", 3)] if "in scope" in idx else None
        key = norm_name(str(artifact))
        out[key] = {
            "group": row[idx.get("group", 0)],
            "artifact": str(artifact),
            "count": int(count or 0),
            "in_scope": str(in_scope or "").strip().lower() == "yes",
            "norm": key,
        }
    return out


def compare(xlsx_path: Path) -> int:
    app = load_xlsx(xlsx_path)
    report = build_report_reconciliation(app)

    matches = [r for r in report if r["status"] == "match"]
    near = [r for r in report if r["status"] == "near_match"]
    gaps = [r for r in report if r["status"] == "gap"]
    missing = [r for r in report if r["status"] == "missing_in_app"]

    print(f"Report section B artifacts: {len(report)}")
    print(f"Exact matches: {len(matches)}")
    print(f"Near matches (within ~5%): {len(near)}")
    print(f"Gaps: {len(gaps)}")
    print(f"Missing in app export: {len(missing)}")
    print()

    if gaps or near:
        print("=== PDF vs APP (section B) ===")
        print(f"{'Artifact':32} {'PDF':>8} {'App':>8} {'Delta':>8}  Status")
        print("-" * 72)
        for row in sorted(gaps + near, key=lambda r: abs(int(r.get("delta") or 0)), reverse=True):
            app_c = row.get("app_count")
            app_s = "" if app_c is None else str(app_c)
            delta = row.get("delta")
            delta_s = "" if delta is None else f"{int(delta):+d}"
            print(f"{row['artifact']:32} {row['pdf_count']:8d} {app_s:>8} {delta_s:>8}  {row['status']}")
            if row.get("reason"):
                print(f"  reason: {row['reason']}")
        print()

    if matches:
        print("=== EXACT MATCHES ===")
        for row in matches:
            print(f"  {row['artifact']}: {row['pdf_count']}")
        print()

    if missing:
        print("=== NOT FOUND IN XLSX ===")
        for row in missing:
            print(f"  {row['artifact']} (PDF={row['pdf_count']})")
        print()

    return 0 if not gaps and not missing else 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: compare_artifact_counts.py <artifacts.xlsx>")
        raise SystemExit(1)
    raise SystemExit(compare(Path(sys.argv[1])))
