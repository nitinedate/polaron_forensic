"""Re-persist AXIOM artifact counts to job_axiom_artifact_results (updates Excel export).

Usage (inside api container):
  python /app/scripts/persist_collector_counts.py d0996306-8429-420a-8303-a19357488596 --report-only
  python /app/scripts/persist_collector_counts.py d0996306-8429-420a-8303-a19357488596 --full

From PowerShell on host:
  docker compose exec api python /app/scripts/persist_collector_counts.py d0996306-8429-420a-8303-a19357488596 --report-only
"""
from __future__ import annotations

import argparse
import sys

from app.db.session import SessionLocal, apply_firm_search_path
from app.services.axiom_artifact_runner import persist_collector_counts


def _progress(msg: str, current: int, total: int) -> None:
    print(f"[{current}/{total}] {msg}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Persist AXIOM-aligned artifact counts for a job")
    parser.add_argument("job_id", help="Job UUID")
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Update only PDF section B report-template artifacts (~32, ~2–5 min)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Update entire Windows catalog (~634 artifacts, 15–30+ min on large disks)",
    )
    parser.add_argument("--firm", default="firm_aetheris", help="Firm schema (default: firm_aetheris)")
    args = parser.parse_args()

    report_only = args.report_only or not args.full
    mode = "report-template (Section B)" if report_only else "full catalog"
    print(f"Job: {args.job_id}")
    print(f"Mode: {mode}")
    print(f"Firm: {args.firm}")
    print(flush=True)

    with SessionLocal() as db:
        apply_firm_search_path(db, args.firm)
        counts = persist_collector_counts(
            db,
            args.job_id,
            report_only=report_only,
            progress_cb=_progress,
        )
        db.commit()
        nonzero = sum(1 for v in counts.values() if int(v or 0) > 0)
        print(f"Done — {len(counts)} artifacts persisted ({nonzero} with count > 0)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
