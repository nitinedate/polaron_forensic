"""Inspect job pipeline data completeness."""
from __future__ import annotations

import json
import sys

from sqlalchemy import text

from app.db.session import SessionLocal

SCHEMA = "firm_aetheris"


def inspect(job_id: str | None = None) -> None:
    with SessionLocal() as db:
        if job_id:
            jobs = db.execute(
                text(
                    f"""SELECT id, status, progress_pct, files_total, files_extracted, bytes_extracted,
                               created_at, updated_at, pipeline_progress, disk_source, extracted_disk_uri
                        FROM {SCHEMA}.jobs WHERE id = :jid"""
                ),
                {"jid": job_id},
            ).fetchall()
        else:
            jobs = db.execute(
                text(
                    f"""SELECT id, status, progress_pct, files_total, files_extracted, bytes_extracted,
                               created_at, updated_at, pipeline_progress, disk_source, extracted_disk_uri
                        FROM {SCHEMA}.jobs ORDER BY created_at DESC LIMIT 1"""
                )
            ).fetchall()

        for j in jobs:
            jid = str(j[0])
            print("=== JOB", jid, "===")
            print("status:", j[1], "progress:", j[2])
            print("files_extracted:", j[4], "files_total:", j[3], "bytes:", j[5])
            print("created:", j[6], "updated:", j[7])
            print("disk_source:", j[9])
            print("extracted_disk_uri:", j[10])
            pp = j[8]
            if isinstance(pp, str):
                pp = json.loads(pp)
            if pp:
                print("phase:", pp.get("phase"))
                orch = pp.get("orchestration") or {}
                print("overall_pct:", orch.get("overall_pct"))
                for aid, st in (orch.get("agents") or {}).items():
                    print(f"  agent {aid}: {st.get('state')} — {st.get('detail')}")

            queries = {
                "job_artifacts": f"SELECT count(*) FROM {SCHEMA}.job_artifacts WHERE job_id=:jid",
                "parsed": f"SELECT count(*) FROM {SCHEMA}.job_artifacts WHERE job_id=:jid AND parse_status='parsed'",
                "pending_parse": f"SELECT count(*) FROM {SCHEMA}.job_artifacts WHERE job_id=:jid AND parse_status='pending'",
                "rag_chunks": f"SELECT count(*) FROM {SCHEMA}.rag_chunks WHERE job_id=:jid",
                "evidence_files": f"SELECT count(*) FROM {SCHEMA}.evidence_files WHERE job_id=:jid",
                "inventory_done": f"SELECT count(*) FROM {SCHEMA}.job_axiom_artifact_results WHERE job_id=:jid AND status='done'",
                "inventory_with_hits": f"SELECT count(*) FROM {SCHEMA}.job_axiom_artifact_results WHERE job_id=:jid AND status='done' AND COALESCE(artifact_count,0) > 0",
                "inventory_sum_counts": f"SELECT COALESCE(SUM(artifact_count),0) FROM {SCHEMA}.job_axiom_artifact_results WHERE job_id=:jid AND status='done'",
                "graph_sync": f"SELECT status FROM {SCHEMA}.graph_sync_state WHERE job_id=:jid",
                "disk_logs": f"SELECT count(*) FROM {SCHEMA}.disk_build_logs WHERE job_id=:jid",
            }
            for label, sql in queries.items():
                row = db.execute(text(sql), {"jid": jid}).fetchone()
                print(f"  {label}: {row[0]}")

            arts = db.execute(
                text(
                    f"""SELECT file_name, file_path, size_bytes, parse_status
                        FROM {SCHEMA}.job_artifacts WHERE job_id=:jid
                        ORDER BY size_bytes DESC NULLS LAST LIMIT 15"""
                ),
                {"jid": jid},
            ).fetchall()
            print("  top artifacts:")
            for a in arts:
                print(f"    {a[0]} | {a[3]} | {a[2]} bytes | {a[1][:120] if a[1] else ''}")

            top_inv = db.execute(
                text(
                    f"""SELECT artifact_id, artifact_count, answer
                        FROM {SCHEMA}.job_axiom_artifact_results
                        WHERE job_id=:jid AND status='done' AND COALESCE(artifact_count,0) > 0
                        ORDER BY artifact_count DESC LIMIT 15"""
                ),
                {"jid": jid},
            ).fetchall()
            print("  top inventory hits:")
            for r in top_inv:
                ans = (r[2] or "")[:80]
                print(f"    {r[0]}: count={r[1]} answer={ans}")

            stages = db.execute(
                text(
                    f"""SELECT stage, count(*) FROM {SCHEMA}.disk_build_logs
                        WHERE job_id=:jid GROUP BY stage ORDER BY count(*) DESC"""
                ),
                {"jid": jid},
            ).fetchall()
            print("  log stages:", [(s[0], s[1]) for s in stages])

            key_logs = db.execute(
                text(
                    f"""SELECT timestamp, stage, message FROM {SCHEMA}.disk_build_logs
                        WHERE job_id=:jid
                        ORDER BY timestamp ASC"""
                ),
                {"jid": jid},
            ).fetchall()
            print("  key log lines:")
            for ts, stage, msg in key_logs:
                if any(k in (msg or "").lower() for k in (
                    "extract", "materialize", "virtual", "segment", "inventory",
                    "chunk", "embed", "parse", "graph", "mobile", "zip", "folder",
                    "pipeline complete", "artifacts registered",
                )):
                    print(f"    [{stage}] {ts}: {(msg or '')[:160]}")


if __name__ == "__main__":
    inspect(sys.argv[1] if len(sys.argv) > 1 else None)
