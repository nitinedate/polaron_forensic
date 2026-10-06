"""Phase 2 integration tests (require PostgreSQL)."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

pytest.importorskip("psycopg2")

from app.db.session import SessionLocal, firm_session
from app.services.extracted_disk import _shard_worker


@pytest.fixture(scope="module")
def db_available():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        db.commit()
    except Exception as exc:
        pytest.skip(f"PostgreSQL unavailable: {exc}")
    finally:
        db.close()


def test_shard_worker_uploads_folder(db_available, tmp_path):
    schema_name = "firm_test_phase2"
    job_id = str(uuid.uuid4())
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "one.txt").write_text("alpha", encoding="utf-8")
    (evidence_dir / "two.txt").write_text("beta", encoding="utf-8")

    db = SessionLocal()
    try:
        db.execute(text("CREATE SCHEMA IF NOT EXISTS firm_test_phase2"))
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS firm_test_phase2.jobs (
                id UUID PRIMARY KEY,
                type VARCHAR(64) NOT NULL DEFAULT 'host_disk',
                status VARCHAR(32) NOT NULL DEFAULT 'created',
                progress_pct INTEGER NOT NULL DEFAULT 0,
                files_total INTEGER NOT NULL DEFAULT 0,
                files_extracted INTEGER NOT NULL DEFAULT 0,
                bytes_extracted BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS firm_test_phase2.evidence_files (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                job_id UUID NOT NULL REFERENCES firm_test_phase2.jobs(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                host_path TEXT,
                storage_uri TEXT,
                status VARCHAR(32) NOT NULL DEFAULT 'registered',
                source_kind VARCHAR(32) NOT NULL DEFAULT 'host',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        db.execute(
            text("INSERT INTO firm_test_phase2.jobs(id, status) VALUES (:id, 'registered')"),
            {"id": job_id},
        )
        db.execute(
            text("""
                INSERT INTO firm_test_phase2.evidence_files(job_id, original_name, host_path, storage_uri, status)
                VALUES (:job_id, '.', :host, :uri, 'registered')
            """),
            {
                "job_id": job_id,
                "host": str(evidence_dir),
                "uri": f"file://{evidence_dir}",
            },
        )
        db.commit()
    finally:
        db.close()

    nodes = [
        {"path": "one.txt", "name": "one.txt", "size_bytes": 5},
        {"path": "two.txt", "name": "two.txt", "size_bytes": 4},
    ]
    payload = {
        "schema_name": schema_name,
        "job_id": job_id,
        "shard_id": 0,
        "nodes": nodes,
        "zstd_level": 1,
    }
    result = _shard_worker(payload)
    assert result["files_extracted"] == 2
    assert result["bytes_extracted"] == 9
    assert result["part_uri"].startswith("s3://") or result["part_uri"].startswith("file://")
