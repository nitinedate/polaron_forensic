#!/usr/bin/env python3
"""Runtime verification for Aetheris responsive processing hotfix v1.4."""
from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import text

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
        "dynamic_perf_enabled": bool(getattr(settings, "dynamic_perf_enabled", False)),
        "dynamic_perf_force": bool(getattr(settings, "dynamic_perf_force", True)),
        "pipeline_sequential_agents": bool(getattr(settings, "pipeline_sequential_agents", False)),
        "rag_batch_size": int(getattr(settings, "rag_batch_size", 0) or 0),
        "rag_batch_size_cap": int(getattr(settings, "rag_batch_size_cap", 0) or 0),
        "ocr_batch_limit": int(getattr(settings, "ocr_batch_limit", 0) or 0),
        "ocr_cpu_workers": int(getattr(settings, "ocr_cpu_workers", 0) or 0),
        "inventory_workers": int(getattr(settings, "axiom_inventory_workers", 0) or 0),
        "inventory_batch_size": int(getattr(settings, "axiom_inventory_batch_size", 0) or 0),
        "extract_mobile_workers": int(getattr(settings, "extract_mobile_workers", 0) or 0),
    }
    print("SETTINGS=" + json.dumps(summary, sort_keys=True))

    failures: list[str] = []
    if summary["perf_policy_mode"].strip().lower() not in {"responsive", "respect_env", "sequential"}:
        failures.append("PERF_POLICY_MODE is not responsive")
    if summary["dynamic_perf_force"]:
        failures.append("DYNAMIC_PERF_FORCE is still true")
    if not summary["pipeline_sequential_agents"]:
        failures.append("PIPELINE_SEQUENTIAL_AGENTS is not true")
    if summary["rag_batch_size"] > 16 or summary["rag_batch_size_cap"] > 16:
        failures.append("RAG batch ceiling is above 16")
    if summary["ocr_batch_limit"] > 8:
        failures.append("OCR batch ceiling is above 8")
    if summary["ocr_cpu_workers"] > 2:
        failures.append("OCR CPU worker ceiling is above 2")
    if summary["inventory_workers"] > 2:
        failures.append("Inventory worker ceiling is above 2")

    with firm_session(args.schema) as db:
        job = fetchone(
            db,
            "SELECT id,status,progress_pct,error,updated_at FROM jobs WHERE id=:id",
            {"id": args.job_id},
        )
        if not job:
            failures.append(f"job {args.job_id} was not found in {args.schema}")
        else:
            print("JOB=" + json.dumps(dict(job), default=str, sort_keys=True))

        if args.apply_plan and job:
            from app.services.performance_agent import apply_performance_advice

            result = apply_performance_advice(db, args.job_id)
            db.commit()
            print("APPLIED_PLAN=" + json.dumps(result, default=str, sort_keys=True))
            if result.get("allow_parallel"):
                failures.append("live performance plan still allows parallel pipeline agents")
            live = result.get("live_plan") or {}
            if int(live.get("rag_batch_size") or 0) > 16:
                failures.append("live RAG batch is above 16")
            if int(live.get("ocr_batch_limit") or 0) > 8:
                failures.append("live OCR batch is above 8")
            if int(live.get("inventory_workers") or 0) > 2:
                failures.append("live inventory workers is above 2")

        counts = fetchone(
            db,
            """SELECT
                 (SELECT count(*) FROM disk_build_logs WHERE job_id=:jid) AS log_rows,
                 (SELECT count(*) FROM rag_chunks WHERE job_id=:jid AND chunk_type='evidence') AS rag_chunks,
                 (SELECT count(*) FROM job_artifacts WHERE job_id=:jid AND parse_status='pending') AS parse_pending,
                 (SELECT count(*) FROM job_artifacts WHERE job_id=:jid AND ocr_status='pending') AS ocr_pending""",
            {"jid": args.job_id},
        )
        print("COUNTS=" + json.dumps(dict(counts or {}), default=str, sort_keys=True))

        # Long open transactions are a responsiveness hazard; report them without killing them.
        long_tx = fetchall(
            db,
            """SELECT pid, client_addr::text AS client_addr, state,
                      EXTRACT(EPOCH FROM (now()-xact_start))::bigint AS xact_age_sec,
                      wait_event_type, wait_event,
                      left(regexp_replace(query,E'[\\n\\r\\t]+',' ','g'),160) AS query
               FROM pg_stat_activity
               WHERE datname=current_database()
                 AND pid<>pg_backend_pid()
                 AND xact_start IS NOT NULL
                 AND now()-xact_start > interval '5 minutes'
               ORDER BY xact_start""",
            {},
        )
        print("LONG_TX=" + json.dumps([dict(r) for r in long_tx], default=str))

        indexes = fetchall(
            db,
            """SELECT indexname FROM pg_indexes
               WHERE schemaname=:schema AND tablename='job_artifacts'
                 AND indexname IN (
                   'ix_job_artifacts_job_parse_status',
                   'ix_job_artifacts_job_ocr_status',
                   'ix_job_artifacts_job_updated'
                 ) ORDER BY indexname""",
            {"schema": args.schema},
        )
        print("PERF_INDEXES=" + json.dumps([r["indexname"] for r in indexes]))

    if failures:
        for item in failures:
            print("FAIL: " + item, file=sys.stderr)
        return 2
    print("PASS: responsive processing policy is active; the current job remains preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
