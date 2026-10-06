"""Print the exact record-level facts Section C will use for one report job.

Run inside the API container, for example:
  python scripts/diagnose_report_objective_facts.py <job-id> firm_aetheris

This intentionally uses the same objective resolver and live fact detectors as report
creation. It is an examiner/deployment diagnostic, not a separate evidence engine.
"""
from __future__ import annotations

import json
import sys

from app.db.session import SessionLocal, apply_firm_search_path
from app.db.sql_helpers import fetchone
from app.services.report_objective_case_facts import build_objective_case_fact
from app.services.report_template_service import resolve_report_objectives


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/diagnose_report_objective_facts.py <job-id> [firm_schema]")
        return 2
    job_id = sys.argv[1]
    schema = sys.argv[2] if len(sys.argv) > 2 else "firm_aetheris"

    with SessionLocal() as db:
        apply_firm_search_path(db, schema)
        intake = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:jid", {"jid": job_id}) or {}
        job = fetchone(db, "SELECT id, disk_source FROM jobs WHERE id=:jid", {"jid": job_id}) or {}
        disk_source = job.get("disk_source") or {}
        if isinstance(disk_source, str):
            try:
                disk_source = json.loads(disk_source)
            except Exception:
                disk_source = {}
        objectives = resolve_report_objectives(db, job_id, intake)
        print(f"Job: {job_id}")
        print(f"Schema: {schema}")
        print("Evidence source:")
        print(json.dumps({
            "base_name": disk_source.get("base_name"),
            "format": disk_source.get("format"),
            "mode": disk_source.get("mode"),
            "registered_segment_sha256": disk_source.get("segment_hashes") or [],
            "bytes_extracted_not_capacity": disk_source.get("bytes_extracted"),
            "files_extracted": disk_source.get("files_extracted"),
            "partial": disk_source.get("partial"),
        }, indent=2, default=str, ensure_ascii=False))
        print(f"Objectives: {len(objectives)}")
        print()
        for idx, objective in enumerate(objectives, 1):
            title = str(objective.get("title") or objective.get("objective_id") or f"Objective {idx}")
            print(f"[{idx}] {title}")
            try:
                fact = build_objective_case_fact(db, job_id, objective, intake=intake)
            except Exception as exc:
                print(json.dumps({"status": "DETECTOR_ERROR", "error": f"{type(exc).__name__}: {exc}"}, indent=2))
            else:
                print(json.dumps(fact or {"status": "NO_SPECIALIZED_DETECTOR"}, indent=2, default=str, ensure_ascii=False))
            print("-" * 88)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
