"""Ensure SQL functions from migrations/ are present (idempotent)."""

from __future__ import annotations

import sys
from pathlib import Path

backend_root = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_root))

from sqlalchemy import text

from app.db.session import SessionLocal, engine
from app.services.axiom_catalog_ingest import load_axiom_catalog_from_files
from app.services.encyclopedia_ingest import load_encyclopedia_from_jsonl
from app.services.firm_migrations import apply_all_firm_migrations
from app.services.firm_rbac_sync import sync_all_firm_rbac

# NOTE: 003_firm_schema_template.sql is NOT applied here — it contains a
# literal "{schema}" placeholder and is only used by tenant_provisioner.
MIGRATION_FILES = (
    "000_enable_pgvector.sql",
    "001_public_schema.sql",
    "002_platform_rbac_superadmin.sql",
    "004_firm_rbac_seed_function.sql",
    "005_restrict_firm_user_role.sql",
    "006_firm_forensic_phase2.sql",
    "007_firm_rag_gpu.sql",
    "008_firm_job_stop_resume.sql",
    "009_phase3_forensic_rag_report.sql",
    "010_axiom_job_inventory.sql",
    "010_rag_chunks_nullable_job_id.sql",
    "011_export_manifest_vol18_intake.sql",
    "011_objective_custom.sql",
    "012_firm_vuln_module.sql",
    "013_firm_vuln_brd_complete.sql",
    "014_firm_agentic_ai.sql",
    "015_artifact_group_selection.sql",
    "016_vuln_brd_v21.sql",
    "017_vuln_asv_pentest_edr.sql",
    "018_firm_cases.sql",
    "019_vuln_orchestrator.sql",
    "020_rename_installed_programs_non_microsoft.sql",
    "021_report_communication_url_artifacts.sql",
    "022_case_type_catalog.sql",
    "023_axiom_forensic_extensions.sql",
    "024_axiom_count_metadata_sync.sql",
    "025_report_template_selection.sql",
    "026_reports_objective_per_title.sql",
    "026_report_template_pdf_alignment.sql",
    "027_firm_pipeline_heal_events.sql",
    "028_firm_vuln_edge_agent.sql",
    "029_firm_rag_image_evidence.sql",
    "030_firm_vuln_edge_agent_recovery.sql",
    "031_firm_vuln_scanner_role.sql",
    "034_firm_vuln_network_tokens.sql",
    "036_ensure_platform_admin.sql",
    "037_search_performance_indexes.sql",
)


def migration_search_dirs() -> list[Path]:
    repo = Path(__file__).resolve().parents[1]
    return [
        repo / "migrations",
        Path("/migrations"),
        repo / "backend" / "app" / "db" / "sql_migrations",
        Path("/app/app/db/sql_migrations"),
        Path("/app/db/sql_migrations"),
    ]


def migrations_dir() -> Path:
    for candidate in migration_search_dirs():
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("migrations directory not found")


def find_migration(name: str) -> Path | None:
    for folder in migration_search_dirs():
        path = folder / name
        if path.is_file():
            return path
    return None


def main() -> None:
    for name in MIGRATION_FILES:
        path = find_migration(name)
        if path is None:
            print(f"skip missing migration: {name}")
            continue
        sql = path.read_text(encoding="utf-8")
        # Never apply unreplaced firm DDL templates (would create a "{schema}" schema).
        if "{schema}" in sql and "CREATE SCHEMA" in sql.upper():
            print(f"skip template with placeholder: {name}")
            continue
        try:
            with engine.begin() as conn:
                conn.execute(text("SET LOCAL statement_timeout = '15s'"))
                conn.execute(text(sql))
            print(f"applied {name}")
        except Exception as exc:
            # Idempotent helpers — one optional SQL file must not block API boot.
            # A live extract can hold locks; skip and let uvicorn start.
            print(f"warn: {name}: {exc}")
    print("SQL migration helpers applied.")
    db = SessionLocal()
    try:
        db.execute(text("SET statement_timeout = '15s'"))
        try:
            count = sync_all_firm_rbac(db)
            db.commit()
            print(f"Firm RBAC synced for {count} organization(s).")
        except Exception as exc:
            db.rollback()
            print(f"warn: firm RBAC sync: {exc}")

        try:
            migrated = apply_all_firm_migrations(db)
            print(f"Firm schema migrations applied for {migrated} organization(s).")
        except Exception as exc:
            db.rollback()
            print(f"warn: firm migrations: {exc}")

        try:
            db.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS public.encyclopedia_artifacts (
                        artifact_id TEXT PRIMARY KEY,
                        artifact_name TEXT NOT NULL DEFAULT '',
                        volume TEXT,
                        section TEXT,
                        category TEXT,
                        operating_system TEXT,
                        default_paths TEXT,
                        file_extensions TEXT,
                        evidence_value TEXT,
                        search_text TEXT,
                        raw_row JSONB NOT NULL DEFAULT '[]'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS public.encyclopedia_field_rows (
                        supplement TEXT NOT NULL,
                        artifact_id TEXT NOT NULL,
                        field_name TEXT NOT NULL,
                        where_found TEXT,
                        source_artifact TEXT,
                        notes TEXT,
                        search_text TEXT,
                        PRIMARY KEY (supplement, artifact_id, field_name)
                    );
                    """
                )
            )
            db.commit()
            enc = load_encyclopedia_from_jsonl(db, force=False)
            print(f"Encyclopedia catalog: {enc}")
        except Exception as exc:
            db.rollback()
            print(f"warn: encyclopedia catalog: {exc}")

        try:
            # Alembic may have been skipped (DuplicateTable on firms) leaving catalog missing.
            db.execute(
                text(
                    """
                    CREATE TABLE IF NOT EXISTS public.axiom_artifacts (
                        artifact_id TEXT PRIMARY KEY,
                        platform TEXT NOT NULL,
                        category TEXT NOT NULL,
                        application_or_profile TEXT,
                        artifact_name TEXT NOT NULL,
                        recovery_method TEXT,
                        reference_page INTEGER,
                        primary_objective_id TEXT,
                        secondary_objective_ids TEXT,
                        procedure_id TEXT,
                        observation_focus TEXT,
                        outline_path TEXT,
                        prompt_question TEXT,
                        critical BOOLEAN NOT NULL DEFAULT false,
                        sort_order INTEGER NOT NULL DEFAULT 0,
                        source_version TEXT,
                        source_published TEXT,
                        source_url TEXT,
                        mapping_note TEXT,
                        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS public.axiom_objectives (
                        objective_id TEXT PRIMARY KEY,
                        procedure_id TEXT,
                        domain TEXT,
                        title TEXT,
                        statement TEXT,
                        primary_artifact_families TEXT,
                        required_observation_fields TEXT,
                        minimum_corroboration TEXT,
                        limitations TEXT,
                        priority TEXT,
                        prompt_question TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE TABLE IF NOT EXISTS public.axiom_procedures (
                        procedure_id TEXT PRIMARY KEY,
                        objective_id TEXT,
                        domain TEXT,
                        title TEXT,
                        detailed_procedure TEXT,
                        mandatory_corroboration TEXT,
                        expected_output_fields TEXT,
                        limitations TEXT,
                        prompt_question TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    ALTER TABLE public.axiom_artifacts ADD COLUMN IF NOT EXISTS prompt_question TEXT;
                    ALTER TABLE public.axiom_objectives ADD COLUMN IF NOT EXISTS prompt_question TEXT;
                    ALTER TABLE public.axiom_procedures ADD COLUMN IF NOT EXISTS prompt_question TEXT;
                    """
                )
            )
            db.commit()
            axiom = load_axiom_catalog_from_files(db, force=False)
            print(f"AXIOM catalog: {axiom}")
        except Exception as exc:
            db.rollback()
            print(f"warn: AXIOM catalog: {exc}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
