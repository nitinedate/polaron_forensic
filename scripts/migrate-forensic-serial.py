"""Install serial control tables and evidence indexes in this product's database.

Run inside the Disk/Android/iOS API container. Evidence indexes use CONCURRENTLY;
the script never alters scanner tables, clears queues, or deletes evidence.
"""

from __future__ import annotations

import argparse

from app.db.session import SessionLocal, engine, firm_session
from app.services.forensic_serial_pipeline import (
    ensure_serial_schema,
    start_serial_pipeline,
)
from app.services.forensic_serial_policy import serial_enabled
from sqlalchemy import text

# Table, index, expression. Only the forensic evidence tables are targeted.
INDEXES = (
    ("job_artifacts", "ix_serial_artifacts_job_id", "(job_id,id)"),
    (
        "job_artifacts",
        "ix_serial_chunk_pending",
        "(job_id,id) WHERE COALESCE(metadata->>'serial_chunked','false')<>'true'",
    ),
    (
        "rag_chunks",
        "ix_serial_mobile_chunk_marker",
        "(job_id,(metadata->>'mobile_artifact_id')) WHERE metadata->>'serial_pipeline'='true'",
    ),
    (
        "mobile_normalized_artifacts",
        "ix_serial_mobile_job_artifact",
        "(job_id,artifact_id)",
    ),
    ("pipeline_work_items", "ix_serial_work_status", "(stage_run_id,status)"),
)


def migrate(schema: str, *, adopt_active: bool, reprocess_ready: bool = False) -> None:
    with firm_session(schema) as db:
        exists = db.execute(text("SELECT to_regclass('jobs')")).scalar()
        if not exists:
            return
        from app.services.progress_agent import ensure_progress_schema
        ensure_progress_schema(db)
        from app.service_identity import is_mobile_service

        if is_mobile_service():
            from app.services.mobile_forensic.storage import ensure_mobile_case_schema

            ensure_mobile_case_schema(db)
            db.commit()
        ensure_serial_schema(db)
    quote = engine.dialect.identifier_preparer.quote
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        connection.execute(text("SET lock_timeout='5s'"))
        connection.execute(
            text(
                f"DROP INDEX CONCURRENTLY IF EXISTS {quote(schema)}.ix_serial_vectors_pending"
            )
        )
        for table, name, definition in INDEXES:
            exists = connection.execute(
                text("SELECT to_regclass(:name)"), {"name": f"{schema}.{table}"}
            ).scalar()
            if not exists:
                continue  # Mobile tables are created by the mobile parse stage.
            valid = connection.execute(
                text("""SELECT i.indisvalid FROM pg_index i
                JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname=:schema AND c.relname=:name"""),
                {"schema": schema, "name": name},
            ).scalar()
            if valid is False:
                connection.execute(
                    text(f"DROP INDEX CONCURRENTLY {quote(schema)}.{quote(name)}")
                )
            connection.execute(
                text(
                    f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {quote(name)} ON {quote(schema)}.{quote(table)} {definition}"
                )
            )
        connection.execute(text("SET lock_timeout=DEFAULT"))
    print(f"{schema}: serial tables and indexes ready")
    if adopt_active or reprocess_ready:
        with firm_session(schema) as db:
            jobs = (
                db.execute(
                    text("""SELECT id,status FROM jobs WHERE stop_requested=FALSE
                AND extracted_disk_uri IS NOT NULL AND extraction_checkpoint IS NULL
                AND ((:active AND status IN ('extracted','disk_ready','indexing','indexed','parsed','artifacts_registered'))
                    OR (:ready AND status IN ('ready','completed','report_ready')))
                ORDER BY updated_at"""),
                    {"active": adopt_active, "ready": reprocess_ready},
                )
                .mappings()
                .all()
            )
        for job in jobs:
            job_id = job["id"]
            with firm_session(schema) as db:
                result = start_serial_pipeline(
                    db,
                    str(job_id),
                    schema_name=schema,
                    reprocess=reprocess_ready
                    and job["status"] in {"ready", "completed", "report_ready"},
                )
                print(
                    f"{schema} / {job_id}: {result['status']} {result.get('stage', result.get('reason', ''))}"
                )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema",
        action="append",
        help="Limit to this tenant schema; repeat as needed",
    )
    parser.add_argument(
        "--adopt-active",
        action="store_true",
        help="Hand finalized active jobs to the controller; preserve completed stages",
    )
    parser.add_argument(
        "--reprocess-ready",
        action="store_true",
        help="Apply new parsing, media observations and chunk policy to finalized historical jobs",
    )
    parser.add_argument(
        "--check-vision-model",
        action="store_true",
        help="Check that the configured local Ollama model supports images",
    )
    parser.add_argument(
        "--prepare-vision-model",
        action="store_true",
        help="Download the configured vision model to local Ollama before checking it",
    )
    args = parser.parse_args()
    if not serial_enabled():
        parser.error("Run this migration in a Disk or Mobile API container")
    if args.prepare_vision_model:
        from app.services.forensic_media_review import visual_model
        from app.services.model_router import _ollama_post

        print(f"Preparing local vision model {visual_model()}")
        _ollama_post(
            "/api/pull", {"model": visual_model(), "stream": False}, timeout=3600
        )
    if args.check_vision_model or args.prepare_vision_model:
        from app.services.forensic_media_review import check_model

        check_model()
        print("Configured local model supports image/video frame observations")
    if args.schema:
        schemas = args.schema
    else:
        with SessionLocal() as db:
            schemas = (
                db.execute(
                    text("""SELECT DISTINCT n.nspname FROM pg_namespace n
                JOIN pg_class c ON c.relnamespace=n.oid WHERE c.relname='jobs'
                AND c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname""")
                )
                .scalars()
                .all()
            )
    for schema in schemas:
        migrate(
            str(schema),
            adopt_active=args.adopt_active,
            reprocess_ready=args.reprocess_ready,
        )


if __name__ == "__main__":
    main()
