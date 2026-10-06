from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_non_expiring_refresh_policy_is_present():
    security = (ROOT / "app" / "services" / "security.py").read_text(encoding="utf-8")
    config = (ROOT / "app" / "config.py").read_text(encoding="utf-8")
    assert "jwt_refresh_ttl_days: int = 0" in config
    assert "if days <= 0:" in security
    assert "datetime.max.replace(tzinfo=timezone.utc)" in security


def test_job_detail_default_is_lightweight():
    text = (ROOT / "app" / "routers" / "jobs.py").read_text(encoding="utf-8")
    assert "sync_progress: bool = Query(" in text
    marker = "if not sync_progress:\n        return _job_row(row)"
    assert marker in text
    assert text.index(marker) < text.index("enrichment = None", text.index("def get_job("))


def test_parse_drain_does_not_false_complete_on_exception():
    text = (ROOT / "app" / "tasks.py").read_text(encoding="utf-8")
    start = text.index('log.exception("Parse drain failed job=%s", job_id)')
    end = text.index("def parse_shard_sync", start)
    block = text[start:end]
    assert "status='indexing'" in block
    assert "progress_pct=100" not in block
    assert "automatic retry scheduled" in block
    assert 'bind=True,\n    name="app.tasks.parse_drain_task"' in text


def test_bulk_skip_is_split_and_no_large_monolithic_max_file_predicate():
    text = (ROOT / "app" / "services" / "artifact_parse.py").read_text(encoding="utf-8")
    start = text.index("def bulk_skip_non_parser_pending")
    end = text.index("def _parse_attempts", start)
    block = text[start:end]
    assert ":max_file" not in block
    assert "_bulk_update_pending_in_batches" in block
    assert "batch_size: int = 10_000" in text
    assert "FOR UPDATE SKIP LOCKED" in text
    assert "ltrim(lower(coalesce(extension" in text


def test_parse_shard_does_not_bind_all_paths_or_skip_in_parallel():
    text = (ROOT / "app" / "services" / "artifact_parse.py").read_text(encoding="utf-8")
    assert "PATH_ANY_CHUNK = 250" in text
    assert "def _fetch_pending_artifacts_for_paths" in text
    assert "if forensic_only and not paths:" in text
    assert "if forensic_only:\n        skip_low_value_pending" not in text


def test_live_schema_repair_has_queue_indexes():
    text = (ROOT / "scripts" / "apply_forensic_reliability_db.py").read_text(encoding="utf-8")
    assert "CREATE INDEX CONCURRENTLY" in text
    assert "ix_job_artifacts_job_parse_status" in text
    assert "ix_job_artifacts_job_ocr_status" in text
