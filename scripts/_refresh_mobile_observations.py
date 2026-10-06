"""Refresh mobile Objective/Procedure/Observations section with plain-English findings."""
from __future__ import annotations

from sqlalchemy import text

from app.config import get_settings
from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.report_generator import _fill_objective_observations, _structured_evidence

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
SCHEMA = "firm_aetheris"
SECTION = "objectives_procedure_observation"


def main() -> None:
    settings = get_settings()
    print("ollama", settings.ollama_base_url)
    with firm_session(SCHEMA) as db:
        intake = fetchone(db, "SELECT * FROM case_intake WHERE job_id=:j", {"j": JOB}) or {}
        run = fetchone(
            db,
            """SELECT id FROM report_runs
               WHERE job_id=:j AND status='completed'
               ORDER BY created_at DESC LIMIT 1""",
            {"j": JOB},
        )
        if not run:
            run = fetchone(
                db,
                "SELECT id FROM report_runs WHERE job_id=:j ORDER BY created_at DESC LIMIT 1",
                {"j": JOB},
            )
        if not run:
            raise SystemExit("no report_run")
        rid = str(run["id"])
        evidence_md, _structured = _structured_evidence(
            SECTION, db, JOB, intake, schema_name=SCHEMA
        )
        if not evidence_md or "Insufficient" in evidence_md:
            raise SystemExit(f"no template evidence: {(evidence_md or '')[:200]}")
        content = _fill_objective_observations(
            evidence_md,
            db,
            JOB,
            intake,
            schema_name=SCHEMA,
            primary_model=settings.llm_primary_model or settings.llm_fast_model,
        )
        # Sanity: never persist Ollama stubs.
        if "stub output" in content.lower() or "unavailable — stub" in content.lower():
            raise SystemExit("stub content still present")
        execute(
            db,
            """UPDATE report_sections
               SET content_md=:md, updated_at=NOW()
               WHERE report_run_id=:r AND section_key=:k""",
            {"md": content, "r": rid, "k": SECTION},
        )
        db.commit()
        obs = ""
        m = __import__("re").search(
            r"(?is)###\s*3\.\s*Observations\s*(.+)$", content
        )
        if m:
            obs = m.group(1).strip()
        print("updated section", SECTION, "run", rid)
        print("observations_preview:\n", obs[:1200])


if __name__ == "__main__":
    main()
