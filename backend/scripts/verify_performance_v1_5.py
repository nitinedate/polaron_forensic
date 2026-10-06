#!/usr/bin/env python3
"""Verify v1.5 stage-aware Aetheris forensic performance policy."""
from __future__ import annotations

import argparse
import json
import sys

from app.config import get_settings
from app.db.session import firm_session
from app.db.sql_helpers import fetchall, fetchone


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    ap.add_argument("--job-id", required=True)
    ap.add_argument("--apply-plan", action="store_true")
    args = ap.parse_args()

    settings = get_settings()
    summary = {
        "perf_policy_mode": str(getattr(settings, "perf_policy_mode", "")),
        "pipeline_sequential_agents": bool(getattr(settings, "pipeline_sequential_agents", False)),
        "rag_batch_size": int(getattr(settings, "rag_batch_size", 0) or 0),
        "rag_batch_size_cap": int(getattr(settings, "rag_batch_size_cap", 0) or 0),
        "rag_background_after_baseline": bool(getattr(settings, "rag_background_after_baseline", False)),
        "ocr_batch_limit": int(getattr(settings, "ocr_batch_limit", 0) or 0),
        "parse_workers": int(getattr(settings, "parse_workers", 0) or 0),
        "inventory_workers": int(getattr(settings, "axiom_inventory_workers", 0) or 0),
    }
    print("SETTINGS=" + json.dumps(summary, sort_keys=True))

    failures: list[str] = []
    if summary["perf_policy_mode"].strip().lower() not in {"responsive", "respect_env", "sequential", "stage_aware"}:
        failures.append("PERF_POLICY_MODE is not stage-aware/responsive")
    if not summary["pipeline_sequential_agents"]:
        failures.append("PIPELINE_SEQUENTIAL_AGENTS is not true")
    if summary["rag_batch_size"] > 24 or summary["rag_batch_size_cap"] > 24:
        failures.append("RAG ceiling exceeds v1.5 maximum 24")
    if summary["ocr_batch_limit"] > 8:
        failures.append("OCR batch ceiling exceeds 8")
    if summary["parse_workers"] > 2:
        failures.append("parse worker ceiling exceeds 2")
    if summary["inventory_workers"] > 2:
        failures.append("inventory worker ceiling exceeds 2")

    with firm_session(args.schema) as db:
        job = fetchone(
            db,
            "SELECT id,status,progress_pct,error,updated_at,pipeline_progress FROM jobs WHERE id=:id",
            {"id": args.job_id},
        )
        if not job:
            failures.append(f"job {args.job_id} not found in {args.schema}")
        else:
            print("JOB=" + json.dumps(dict(job), default=str, sort_keys=True))

        counts = fetchone(
            db,
            """SELECT
                 (SELECT count(*) FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence') AS rag_chunks,
                 (SELECT count(*) FROM job_artifacts WHERE job_id=:jid AND parse_status='pending') AS parse_pending,
                 (SELECT count(*) FROM job_artifacts WHERE job_id=:jid AND ocr_status='pending') AS ocr_pending,
                 (SELECT count(*) FROM disk_build_logs WHERE job_id=:jid) AS log_rows""",
            {"jid": args.job_id},
        ) or {}
        print("COUNTS=" + json.dumps(dict(counts), default=str, sort_keys=True))

        try:
            from app.services.dual_rag_index import _count_indexable_artifacts, _count_indexable_without_chunks

            total = int(_count_indexable_artifacts(db, args.job_id) or 0)
            remaining = int(_count_indexable_without_chunks(db, args.job_id) or 0)
            completed = max(total - remaining, 0)
            print("RAG_ARTIFACT_PROGRESS=" + json.dumps({
                "completed_artifacts": completed,
                "total_artifacts": total,
                "remaining_artifacts": remaining,
                "pct": round((100.0 * completed / total), 2) if total else 100.0,
                "chunks": int(counts.get("rag_chunks") or 0),
            }, sort_keys=True))
        except Exception as exc:
            print("RAG_ARTIFACT_PROGRESS_ERROR=" + repr(exc))

        long_tx = fetchall(
            db,
            """SELECT pid,client_addr::text AS client_addr,state,wait_event_type,wait_event,
                      EXTRACT(EPOCH FROM (now()-xact_start))::bigint AS xact_age_sec,
                      pg_blocking_pids(pid) AS blockers,
                      left(regexp_replace(query,E'[\\n\\r\\t]+',' ','g'),180) AS query
               FROM pg_stat_activity
               WHERE datname=current_database()
                 AND pid<>pg_backend_pid()
                 AND xact_start IS NOT NULL
                 AND now()-xact_start > interval '5 minutes'
               ORDER BY xact_start""",
            {},
        )
        print("LONG_TX=" + json.dumps([dict(r) for r in long_tx], default=str))

        if args.apply_plan and job:
            from app.services.performance_agent import apply_performance_advice

            result = apply_performance_advice(db, args.job_id)
            db.commit()
            print("LIVE_PLAN=" + json.dumps(result, default=str, sort_keys=True))
            if result.get("allow_parallel"):
                failures.append("live performance plan still allows parallel heavy agents")
            live = result.get("live_plan") or {}
            if int(live.get("rag_batch_size") or 0) > int(live.get("hardware_rag_ceiling") or 24):
                failures.append("live RAG batch exceeds hardware ceiling")

    if failures:
        for item in failures:
            print("FAIL: " + item, file=sys.stderr)
        return 2
    print("PASS: v1.5 stage-aware policy is active; heavy parse/OCR/RAG/graph work will not be intentionally overlapped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
