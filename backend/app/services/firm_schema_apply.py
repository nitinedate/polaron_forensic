"""Canonical list of firm-schema apply_* calls used at tenant provision time.

When Superadmin creates a tenant (+ firm admin invite), these run after the
base IAM/forensic scaffold in ``firm_schema.sql`` so the organization has every
table required for forensic work and user management.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.orm import Session

log = logging.getLogger("firm_schema_apply")

FIRM_SCHEMA_SQL = (Path(__file__).resolve().parent.parent / "db" / "firm_schema.sql").read_text(
    encoding="utf-8"
)

# Order matters: base forensic → phase3 → inventory → vuln → cases → extras.
# Keep in sync with updatedDatabase/03-*/02_apply_firm_functions.sql generators.
FIRM_APPLY_CALLS: tuple[str, ...] = (
    "SELECT public.apply_vuln_platform_v21()",
    "SELECT public.apply_firm_forensic_phase2(:schema)",
    "SELECT public.apply_firm_rag_gpu(:schema)",
    "SELECT public.apply_firm_job_control(:schema)",
    "SELECT public.apply_firm_phase3(:schema)",
    "SELECT public.apply_firm_phase3_fixes(:schema)",
    "SELECT public.apply_firm_phase3_export_intake(:schema)",
    "SELECT public.apply_firm_axiom_inventory(:schema)",
    "SELECT public.apply_firm_axiom_custom_objectives(:schema)",
    "SELECT public.apply_firm_vuln(:schema)",
    "SELECT public.apply_firm_vuln_brd(:schema)",
    "SELECT public.apply_firm_vuln_v21(:schema)",
    "SELECT public.apply_firm_vuln_extended(:schema)",
    "SELECT public.apply_firm_cases(:schema)",
    "SELECT public.apply_firm_vuln_orchestrator(:schema)",
    "SELECT public.apply_firm_agentic_ai(:schema)",
    "SELECT public.apply_firm_artifact_group_selection(:schema)",
    "SELECT public.apply_firm_report_template_selection(:schema)",
    "SELECT public.apply_firm_pipeline_heal(:schema)",
    "SELECT public.apply_firm_rag_image_evidence(:schema)",
    "SELECT public.apply_firm_vuln_edge_agent(:schema)",
    "SELECT public.apply_firm_vuln_edge_agent_recovery(:schema)",
    "SELECT public.apply_firm_vuln_scanner_role(:schema)",
    "SELECT public.apply_firm_scanner_agent_logs(CAST(:schema AS text))",
    "SELECT public.apply_firm_vuln_network_tokens(:schema)",
    "SELECT public.apply_firm_search_indexes_v1(CAST(:schema AS text))",
)


def apply_base_firm_ddl(db: Session, schema_name: str) -> None:
    """Create schema + base IAM / jobs / evidence tables from firm_schema.sql."""
    db.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"'))
    sql = FIRM_SCHEMA_SQL.replace("{schema}", schema_name)
    for statement in sql.split(";"):
        stmt = statement.strip()
        if stmt:
            db.execute(text(stmt))


def apply_firm_extension_functions(db: Session, schema_name: str, *, strict: bool = False) -> list[str]:
    """Run all apply_firm_* helpers. Returns list of failed call names (non-strict).

    Each call runs in a SAVEPOINT so one missing/broken apply_* cannot abort the
    outer provision transaction (Postgres InFailedSqlTransaction).
    """
    try:
        with db.begin_nested():
            db.execute(
                text(
                    """
                    CREATE OR REPLACE FUNCTION public.apply_firm_scanner_agent_logs(p_schema text)
                    RETURNS void LANGUAGE plpgsql AS $fn$
                    BEGIN
                      EXECUTE format(
                        'CREATE TABLE IF NOT EXISTS %I.scanner_agent_logs (
                           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                           created_at timestamptz NOT NULL DEFAULT now(),
                           agent_id text,
                           event text,
                           payload jsonb NOT NULL DEFAULT ''{}''::jsonb
                         )',
                        p_schema
                      );
                    END;
                    $fn$;
                    DO $guard$
                    BEGIN
                      -- Migration 037 owns the full search-index function. This is
                      -- only a bootstrap fallback for an older database where that
                      -- migration has not been installed; never replace the rich
                      -- function with a one-index stub during API startup.
                      IF to_regprocedure('public.apply_firm_search_indexes_v1(text)') IS NULL THEN
                        EXECUTE $create$
                          CREATE FUNCTION public.apply_firm_search_indexes_v1(p_schema text)
                          RETURNS void LANGUAGE plpgsql AS $body$
                          BEGIN
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_jobs_case_id ON %I.jobs (case_id)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path ON %I.job_artifacts (job_id, file_path)', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name_lower ON %I.job_artifacts (job_id, lower(file_name))', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_parse_pending ON %I.job_artifacts (job_id) WHERE parse_status = ''pending''', p_schema); EXCEPTION WHEN undefined_table THEN NULL; END;
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_findings_case_status_severity ON %I.vuln_findings (case_id, status, severity)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_findings_job_status ON %I.vuln_findings (scan_job_id, status)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
                            BEGIN EXECUTE format('CREATE INDEX IF NOT EXISTS ix_vuln_scan_targets_job_excluded_target ON %I.vuln_scan_targets (scan_job_id, excluded, target)', p_schema); EXCEPTION WHEN undefined_table OR undefined_column THEN NULL; END;
                          END;
                          $body$
                        $create$;
                      END IF;
                    END;
                    $guard$;
                    """
                )
            )
    except Exception as exc:
        log.warning("could not install optional apply_firm_* helpers: %s", exc)

    failed: list[str] = []
    for call in FIRM_APPLY_CALLS:
        params = {"schema": schema_name} if ":schema" in call else {}
        name = call.split("(")[0].replace("SELECT public.", "").strip()
        try:
            with db.begin_nested():
                db.execute(text(call), params)
        except Exception as exc:
            if strict:
                raise
            log.warning("firm apply skipped %s for %s: %s", name, schema_name, exc)
            failed.append(name)
    return failed


def provision_organization_schema(db: Session, schema_name: str) -> None:
    """Full org schema: base DDL + forensic/vuln/agentic extensions."""
    apply_base_firm_ddl(db, schema_name)
    apply_firm_extension_functions(db, schema_name, strict=False)
    # Compatibility patches for older function bodies.
    try:
        with db.begin_nested():
            db.execute(
                text(
                    f'ALTER TABLE "{schema_name}".cases '
                    "ADD COLUMN IF NOT EXISTS gap_site_json JSONB DEFAULT '{}'::jsonb"
                )
            )
    except Exception as exc:
        log.warning("gap_site_json ensure failed for %s: %s", schema_name, exc)
    db.flush()
