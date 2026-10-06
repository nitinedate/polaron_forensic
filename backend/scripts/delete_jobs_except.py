"""Delete all jobs except one (explicit child-table cleanup for speed)."""
from __future__ import annotations

import sys

from sqlalchemy import text

from app.db.session import SessionLocal

KEEP = "320d2101-5842-4560-9a21-8e4399121082"
SCHEMA = "firm_aetheris"


def main() -> None:
    schema = sys.argv[2] if len(sys.argv) > 2 else SCHEMA
    delete_all = len(sys.argv) > 1 and sys.argv[1] in ("--all", "ALL", "*")
    keep_id = None if delete_all else (sys.argv[1] if len(sys.argv) > 1 else KEEP)
    with SessionLocal() as db:
        if delete_all:
            doomed = [
                str(r[0])
                for r in db.execute(
                    text(f"SELECT id FROM {schema}.jobs ORDER BY created_at"),
                    {},
                ).fetchall()
            ]
            print(f"deleting all {len(doomed)} jobs")
        else:
            doomed = [
                str(r[0])
                for r in db.execute(
                    text(f"SELECT id FROM {schema}.jobs WHERE id <> :keep ORDER BY created_at"),
                    {"keep": keep_id},
                ).fetchall()
            ]
            print(f"deleting {len(doomed)} jobs (keeping {keep_id})")
        for job_id in doomed:
            print(f"--- job {job_id} ---")
            per_job_steps = [
                f"""DELETE FROM {schema}.agent_tool_calls tc
                    USING {schema}.agent_runs r
                    WHERE tc.run_id = r.id AND r.job_id = :jid""",
                f"DELETE FROM {schema}.agent_runs WHERE job_id = :jid",
                f"DELETE FROM {schema}.agent_threads WHERE job_id = :jid",
                f"""DELETE FROM {schema}.report_exports e
                    USING {schema}.report_runs rr
                    WHERE e.report_run_id = rr.id AND rr.job_id = :jid""",
                f"DELETE FROM {schema}.rag_retrieval_log WHERE job_id = :jid",
                f"DELETE FROM {schema}.parser_runs WHERE job_id = :jid",
                f"DELETE FROM {schema}.disk_build_logs WHERE job_id = :jid",
                f"DELETE FROM {schema}.rag_chunks WHERE job_id = :jid",
                f"""DELETE FROM {schema}.artifact_parse_results apr
                    USING {schema}.job_artifacts ja
                    WHERE apr.job_artifact_id = ja.id AND ja.job_id = :jid""",
                f"""DELETE FROM {schema}.ocr_results ocr
                    USING {schema}.job_artifacts ja
                    WHERE ocr.job_artifact_id = ja.id AND ja.job_id = :jid""",
                f"DELETE FROM {schema}.job_artifacts WHERE job_id = :jid",
                f"DELETE FROM {schema}.evidence_files WHERE job_id = :jid",
                f"DELETE FROM {schema}.graph_sync_state WHERE job_id = :jid",
                f"DELETE FROM {schema}.artifact_scope WHERE job_id = :jid",
                f"DELETE FROM {schema}.selected_job_artifacts WHERE job_id = :jid",
                f"DELETE FROM {schema}.selected_job_objectives_procedure WHERE job_id = :jid",
                f"DELETE FROM {schema}.case_intake WHERE job_id = :jid",
                f"DELETE FROM {schema}.timeline_events WHERE job_id = :jid",
                f"DELETE FROM {schema}.report_sections WHERE job_id = :jid",
                f"DELETE FROM {schema}.report_runs WHERE job_id = :jid",
                f"DELETE FROM {schema}.job_axiom_artifact_results WHERE job_id = :jid",
                f"DELETE FROM {schema}.job_objective_observations WHERE job_id = :jid",
                f"DELETE FROM {schema}.job_count_reconciliation WHERE job_id = :jid",
                f"DELETE FROM {schema}.job_artifact_groups WHERE job_id = :jid",
                f"DELETE FROM {schema}.objective_procedure_scope WHERE job_id = :jid",
                f"UPDATE {schema}.cases SET job_id = NULL WHERE job_id = :jid",
                f"DELETE FROM {schema}.jobs WHERE id = :jid",
            ]
            for i, sql in enumerate(per_job_steps, 1):
                result = db.execute(text(sql), {"jid": job_id})
                db.commit()
                if result.rowcount:
                    print(f"  step {i}: {result.rowcount} rows")
            print(f"deleted job {job_id}")
        remaining = db.execute(
            text(f"SELECT id, status FROM {schema}.jobs ORDER BY created_at")
        ).fetchall()
        print("remaining jobs:", [dict(r._mapping) for r in remaining])


if __name__ == "__main__":
    main()
