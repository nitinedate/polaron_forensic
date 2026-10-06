"""Rewrite Observations from stored Objective/Procedure in plain English (no LLM required)."""
from __future__ import annotations

import re
from sqlalchemy import text

from app.db.session import firm_session
from app.db.sql_helpers import execute, fetchone
from app.services.mobile_report_llm import plain_fallback_observations, strip_technical_noise
from app.services.report_generator import (
    _mobile_inventory_nonzero,
    _splice_mobile_observations,
)

JOB = "9b207c40-03c9-4fd1-b601-338296cc9803"
SCHEMA = "firm_aetheris"
SECTION = "objectives_procedure_observation"


def main() -> None:
    with firm_session(SCHEMA) as db:
        run = fetchone(
            db,
            """SELECT id FROM report_runs WHERE job_id=:j
               ORDER BY CASE status WHEN 'completed' THEN 0 ELSE 1 END, created_at DESC
               LIMIT 1""",
            {"j": JOB},
        )
        if not run:
            raise SystemExit("no report_run")
        rid = str(run["id"])
        row = fetchone(
            db,
            """SELECT content_md FROM report_sections
               WHERE report_run_id=:r AND section_key=:k""",
            {"r": rid, "k": SECTION},
        )
        if not row or not row.get("content_md"):
            raise SystemExit("section missing")
        template_md = str(row["content_md"])
        objective_m = re.search(r"(?is)###\s*1\.\s*Objective\s*(.*?)(?=###\s*2\.|\Z)", template_md)
        procedure_m = re.search(r"(?is)###\s*2\.\s*Procedure\s*(.*?)(?=###\s*3\.|\Z)", template_md)
        objective_txt = strip_technical_noise((objective_m.group(1).strip() if objective_m else "")[:900])
        procedure_txt = strip_technical_noise((procedure_m.group(1).strip() if procedure_m else "")[:900])
        nonzero = _mobile_inventory_nonzero(db, JOB)
        observations = plain_fallback_observations(
            nonzero,
            objective_txt=objective_txt,
            procedure_txt=procedure_txt,
        )
        content = _splice_mobile_observations(template_md, observations)
        if "stub output" in content.lower():
            raise SystemExit("stub still present")
        execute(
            db,
            """UPDATE report_sections SET content_md=:md, updated_at=NOW()
               WHERE report_run_id=:r AND section_key=:k""",
            {"md": content, "r": rid, "k": SECTION},
        )
        db.commit()
        obs = re.search(r"(?is)###\s*3\.\s*Observations\s*(.+)$", content)
        print("ok run", rid)
        print((obs.group(1).strip() if obs else content)[:1500])


if __name__ == "__main__":
    main()
