"""Indexes that keep Artifacts / Evidence / family Open off sequential scans.

Hot paths (measured on ~130k job_artifacts rows):
  * list ChatStorage / msgstore by lower(file_name)
  * ILIKE '%ChatStorage%' / '%msgstore.db%' on file_path
  * artifact_parse_results JOIN job_artifacts by job + parser_name
  * exact file_name media lookups
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute

log = logging.getLogger("evidence_browse_indexes")

_READY: set[int] = set()

# B-tree / expression indexes that do not need pg_trgm. Safe to run on every
# first browse of a firm schema (IF NOT EXISTS is cheap after the first build).
_BROWSE_INDEX_SQL = (
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name_lower
        ON job_artifacts (job_id, lower(file_name))
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path
        ON job_artifacts (job_id, file_path)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_size
        ON job_artifacts (job_id, size_bytes DESC NULLS LAST)
    """,
    # Cover WhatsApp store picks: job_id filter + ORDER BY size_bytes.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_name_size
        ON job_artifacts (job_id, lower(file_name), size_bytes DESC NULLS LAST)
    """,
    # Media resolve: exact basename match under a job (Open / Download path).
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name
        ON job_artifacts (job_id, file_name)
    """,
    # Path-prefix / LIKE '%tail' helpers for recovered Media/… lookups.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path_lower
        ON job_artifacts (job_id, lower(file_path))
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact
        ON artifact_parse_results (job_artifact_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_parser
        ON artifact_parse_results (parser_name)
    """,
    # Deleted-pipeline browse: filter by parser then join artifacts by id.
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_parser_artifact
        ON artifact_parse_results (parser_name, job_artifact_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_created
        ON artifact_parse_results (job_artifact_id, created_at DESC)
    """,
    # Parser browse + size join used by deleted social / carve fallbacks.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_size_id
        ON job_artifacts (job_id, size_bytes DESC NULLS LAST, id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_evidence_browse_cache_job
        ON job_evidence_browse_cache (job_id, cache_kind)
    """,
)

_CACHE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS job_evidence_browse_cache (
    job_id UUID NOT NULL,
    cache_kind TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, cache_kind)
)
"""

_TRGM_INDEX_SQL = (
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_path_trgm
        ON job_artifacts USING gin (file_path gin_trgm_ops)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_name_trgm
        ON job_artifacts USING gin (file_name gin_trgm_ops)
    """,
)


def ensure_evidence_browse_indexes(db: Session) -> None:
    """Idempotent DDL for evidence-list SQL. No-op after the first success per Session."""
    key = id(db)
    if key in _READY:
        return
    try:
        execute(db, _CACHE_TABLE_SQL)
    except Exception as exc:
        log.debug("evidence cache table skipped: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass
    for sql in _BROWSE_INDEX_SQL:
        try:
            execute(db, sql)
        except Exception as exc:
            log.debug("browse index skipped: %s", exc)
            try:
                db.rollback()
            except Exception:
                pass
    try:
        execute(db, "CREATE EXTENSION IF NOT EXISTS pg_trgm")
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    else:
        for sql in _TRGM_INDEX_SQL:
            try:
                execute(db, sql)
            except Exception as exc:
                log.debug("trgm index skipped: %s", exc)
                try:
                    db.rollback()
                except Exception:
                    pass
    try:
        db.flush()
    except Exception:
        pass
    _READY.add(key)
