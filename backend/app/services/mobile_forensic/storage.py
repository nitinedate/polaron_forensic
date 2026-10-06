"""Persist normalized mobile artifacts, inventory, run state and coverage."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.mobile_forensic.models import InventoryItem, NormalizedArtifact

log = logging.getLogger("mobile_forensic.storage")
_SCHEMA_READY: set[str] = set()


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"binary_length": len(raw), "hex_prefix": raw[:32].hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _dumps(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, default=str)


def ensure_mobile_case_schema(db) -> None:
    """Idempotent DDL for normalized mobile case tables."""
    key = id(db)
    if key in _SCHEMA_READY:
        return
    statements = [
        """
        CREATE TABLE IF NOT EXISTS mobile_evidence_sources (
            source_id TEXT PRIMARY KEY,
            job_id UUID NOT NULL,
            manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mobile_inventory_items (
            id BIGSERIAL PRIMARY KEY,
            job_id UUID NOT NULL,
            path TEXT NOT NULL,
            size_bytes BIGINT NOT NULL DEFAULT 0,
            extension TEXT,
            mime_hint TEXT,
            sha256 TEXT,
            status TEXT NOT NULL DEFAULT 'discovered',
            parser TEXT,
            error TEXT,
            meta JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (job_id, path)
        )
        """,
        "ALTER TABLE mobile_inventory_items ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        """
        CREATE TABLE IF NOT EXISTS mobile_normalized_artifacts (
            artifact_id TEXT PRIMARY KEY,
            job_id UUID NOT NULL,
            artifact_type TEXT NOT NULL,
            source_domain TEXT NOT NULL,
            timestamp_utc TIMESTAMPTZ,
            state TEXT NOT NULL DEFAULT 'allocated',
            ui_label TEXT,
            data JSONB NOT NULL DEFAULT '{}'::jsonb,
            forensic JSONB NOT NULL DEFAULT '{}'::jsonb,
            examiner_status TEXT NOT NULL DEFAULT 'pending_review',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "ALTER TABLE mobile_normalized_artifacts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        """
        CREATE TABLE IF NOT EXISTS mobile_artifact_relationships (
            id BIGSERIAL PRIMARY KEY,
            job_id UUID NOT NULL,
            from_artifact_id TEXT NOT NULL,
            to_artifact_id TEXT NOT NULL,
            rel_type TEXT NOT NULL,
            confidence JSONB NOT NULL DEFAULT '{}'::jsonb,
            reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
            UNIQUE (job_id, from_artifact_id, to_artifact_id, rel_type)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mobile_examiner_reviews (
            id BIGSERIAL PRIMARY KEY,
            job_id UUID NOT NULL,
            artifact_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            note TEXT,
            examiner TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mobile_analysis_runs (
            run_id TEXT PRIMARY KEY,
            job_id UUID NOT NULL,
            platform TEXT,
            status TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'inventory',
            inventory_total BIGINT NOT NULL DEFAULT 0,
            files_processed BIGINT NOT NULL DEFAULT 0,
            artifacts_written BIGINT NOT NULL DEFAULT 0,
            recovered_written BIGINT NOT NULL DEFAULT 0,
            unsupported_files BIGINT NOT NULL DEFAULT 0,
            parse_errors BIGINT NOT NULL DEFAULT 0,
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS mobile_coverage (
            job_id UUID NOT NULL,
            coverage_key TEXT NOT NULL,
            discovered BIGINT NOT NULL DEFAULT 0,
            processed BIGINT NOT NULL DEFAULT 0,
            artifacts BIGINT NOT NULL DEFAULT 0,
            recovered BIGINT NOT NULL DEFAULT 0,
            errors BIGINT NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (job_id, coverage_key)
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_mobile_inventory_job ON mobile_inventory_items(job_id)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_inventory_status ON mobile_inventory_items(job_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_job ON mobile_normalized_artifacts(job_id)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_domain ON mobile_normalized_artifacts(job_id, source_domain)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_state ON mobile_normalized_artifacts(job_id, state)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_ui_ts ON mobile_normalized_artifacts(job_id, ui_label, timestamp_utc)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_job_ts ON mobile_normalized_artifacts(job_id, timestamp_utc)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_job_ts_present ON mobile_normalized_artifacts(job_id, timestamp_utc) WHERE timestamp_utc IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_domain_state ON mobile_normalized_artifacts(job_id, source_domain, state)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_type ON mobile_normalized_artifacts(job_id, artifact_type)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_artifacts_family ON mobile_normalized_artifacts(job_id, ((data->>'artifact_family')))",
        "CREATE INDEX IF NOT EXISTS ix_mobile_examiner_job_art ON mobile_examiner_reviews(job_id, artifact_id)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_rel_job ON mobile_artifact_relationships(job_id)",
        "CREATE INDEX IF NOT EXISTS ix_mobile_runs_job ON mobile_analysis_runs(job_id, started_at DESC)",
    ]
    nested = None
    try:
        nested = db.begin_nested()
    except Exception:
        nested = None
    for sql in statements:
        try:
            execute(db, sql)
        except Exception as exc:
            log.debug("schema statement skipped/failed: %s", exc)
    try:
        db.flush()
    except Exception:
        pass
    try:
        from app.services.evidence_browse_indexes import ensure_evidence_browse_indexes
        ensure_evidence_browse_indexes(db)
    except Exception as exc:
        log.debug("evidence browse indexes skipped: %s", exc)
    try:
        fetchone(db, "SELECT 1 FROM mobile_inventory_items LIMIT 0")
    except Exception as exc:
        log.warning("mobile inventory schema unavailable after ensure: %s", exc)
        if nested is not None:
            try:
                nested.rollback()
            except Exception:
                pass
        return
    if nested is not None:
        try:
            nested.commit()
        except Exception:
            pass
    _SCHEMA_READY.add(key)


def persist_inventory(db, job_id: str, items: Iterable[InventoryItem]) -> int:
    ensure_mobile_case_schema(db)
    n = 0
    for it in items:
        execute(
            db,
            """INSERT INTO mobile_inventory_items
               (job_id, path, size_bytes, extension, mime_hint, sha256, status, parser, error, meta, updated_at)
               VALUES (:jid, :path, :sz, :ext, :mime, :sha, :st, :parser, :err, CAST(:meta AS jsonb), NOW())
               ON CONFLICT (job_id, path) DO UPDATE SET
                 size_bytes=EXCLUDED.size_bytes,
                 extension=EXCLUDED.extension,
                 mime_hint=EXCLUDED.mime_hint,
                 sha256=COALESCE(EXCLUDED.sha256, mobile_inventory_items.sha256),
                 status=EXCLUDED.status,
                 parser=EXCLUDED.parser,
                 error=EXCLUDED.error,
                 meta=EXCLUDED.meta,
                 updated_at=NOW()""",
            {
                "jid": job_id, "path": it.path, "sz": it.size, "ext": it.extension,
                "mime": it.mime_hint, "sha": it.sha256, "st": it.status,
                "parser": it.parser, "err": it.error, "meta": _dumps(it.meta or {}),
            },
        )
        n += 1
    return n


def persist_artifacts(db, job_id: str, artifacts: Iterable[NormalizedArtifact]) -> int:
    ensure_mobile_case_schema(db)
    n = 0
    for art in artifacts:
        f = art.forensic or {}
        execute(
            db,
            """INSERT INTO mobile_normalized_artifacts
               (artifact_id, job_id, artifact_type, source_domain, timestamp_utc, state, ui_label,
                data, forensic, examiner_status, updated_at)
               VALUES (:aid, :jid, :atype, :domain,
                       CAST(:ts AS timestamptz), :state, :ui,
                       CAST(:data AS jsonb), CAST(:forensic AS jsonb), :ex, NOW())
               ON CONFLICT (artifact_id) DO UPDATE SET
                 artifact_type=EXCLUDED.artifact_type,
                 source_domain=EXCLUDED.source_domain,
                 timestamp_utc=EXCLUDED.timestamp_utc,
                 data=EXCLUDED.data,
                 forensic=EXCLUDED.forensic,
                 state=EXCLUDED.state,
                 ui_label=EXCLUDED.ui_label,
                 updated_at=NOW()""",
            {
                "aid": art.artifact_id, "jid": job_id, "atype": art.artifact_type,
                "domain": art.source_domain, "ts": art.timestamp_utc,
                "state": f.get("state") or "allocated", "ui": f.get("ui_label"),
                "data": _dumps(art.data or {}), "forensic": _dumps(f),
                "ex": f.get("examiner_status") or "pending_review",
            },
        )
        n += 1
    return n


def persist_source_manifest(db, job_id: str, manifest: dict[str, Any]) -> None:
    ensure_mobile_case_schema(db)
    source_id = str(manifest.get("source_id") or f"SOURCE-{job_id[:8]}")
    execute(
        db,
        """INSERT INTO mobile_evidence_sources (source_id, job_id, manifest)
           VALUES (:sid, :jid, CAST(:m AS jsonb))
           ON CONFLICT (source_id) DO UPDATE SET manifest=EXCLUDED.manifest""",
        {"sid": source_id, "jid": job_id, "m": _dumps(manifest)},
    )


def start_analysis_run(db, job_id: str, *, platform: str) -> str:
    ensure_mobile_case_schema(db)
    run_id = str(uuid.uuid4())
    execute(
        db,
        """INSERT INTO mobile_analysis_runs (run_id, job_id, platform, status, phase)
           VALUES (:rid, :jid, :plat, 'running', 'inventory')""",
        {"rid": run_id, "jid": job_id, "plat": platform},
    )
    return run_id


def update_analysis_run(db, run_id: str, **fields: Any) -> None:
    if not fields:
        return
    allowed = {
        "status", "phase", "inventory_total", "files_processed", "artifacts_written",
        "recovered_written", "unsupported_files", "parse_errors", "details",
    }
    assignments: list[str] = []
    params: dict[str, Any] = {"rid": run_id}
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "details":
            assignments.append("details=CAST(:details AS jsonb)")
            params["details"] = _dumps(value or {})
        else:
            assignments.append(f"{key}=:{key}")
            params[key] = value
    if not assignments:
        return
    if fields.get("status") in {"completed", "failed"}:
        assignments.append("completed_at=NOW()")
    assignments.append("updated_at=NOW()")
    execute(db, f"UPDATE mobile_analysis_runs SET {', '.join(assignments)} WHERE run_id=:rid", params)


def upsert_coverage(
    db,
    job_id: str,
    coverage_key: str,
    *,
    discovered: int = 0,
    processed: int = 0,
    artifacts: int = 0,
    recovered: int = 0,
    errors: int = 0,
    status: str = "pending",
    details: dict[str, Any] | None = None,
) -> None:
    ensure_mobile_case_schema(db)
    execute(
        db,
        """INSERT INTO mobile_coverage
           (job_id, coverage_key, discovered, processed, artifacts, recovered, errors, status, details, updated_at)
           VALUES (:jid, :key, :d, :p, :a, :r, :e, :s, CAST(:details AS jsonb), NOW())
           ON CONFLICT (job_id, coverage_key) DO UPDATE SET
             discovered=EXCLUDED.discovered, processed=EXCLUDED.processed,
             artifacts=EXCLUDED.artifacts, recovered=EXCLUDED.recovered,
             errors=EXCLUDED.errors, status=EXCLUDED.status, details=EXCLUDED.details,
             updated_at=NOW()""",
        {
            "jid": job_id, "key": coverage_key, "d": discovered, "p": processed,
            "a": artifacts, "r": recovered, "e": errors, "s": status,
            "details": _dumps(details or {}),
        },
    )


def list_coverage(db, job_id: str) -> list[dict[str, Any]]:
    ensure_mobile_case_schema(db)
    rows = fetchall(
        db,
        """SELECT coverage_key, discovered, processed, artifacts, recovered, errors, status, details,
                  updated_at::text AS updated_at
           FROM mobile_coverage WHERE job_id=:jid ORDER BY coverage_key""",
        {"jid": job_id},
    )
    return [dict(r) for r in rows]


def list_artifacts(
    db, job_id: str, *, domain: str | None = None, state: str | None = None,
    ui_label: str | None = None, limit: int = 500, offset: int = 0,
) -> list[dict[str, Any]]:
    ensure_mobile_case_schema(db)
    clauses = ["job_id=:jid"]
    params: dict[str, Any] = {"jid": job_id, "lim": limit, "off": offset}
    if domain:
        clauses.append("source_domain=:domain"); params["domain"] = domain
    if state:
        clauses.append("state=:state"); params["state"] = state
    if ui_label:
        clauses.append("ui_label=:ui"); params["ui"] = ui_label
    rows = fetchall(
        db,
        f"""SELECT artifact_id, artifact_type, source_domain, timestamp_utc::text AS timestamp_utc,
                   state, ui_label, data, forensic, examiner_status
            FROM mobile_normalized_artifacts WHERE {' AND '.join(clauses)}
            ORDER BY timestamp_utc DESC NULLS LAST, artifact_id LIMIT :lim OFFSET :off""",
        params,
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        for k in ("data", "forensic"):
            if isinstance(d.get(k), str):
                try: d[k] = json.loads(d[k])
                except json.JSONDecodeError: pass
        out.append(d)
    return out


def artifact_counts_by_domain(db, job_id: str) -> dict[str, Any]:
    ensure_mobile_case_schema(db)
    rows = fetchall(
        db,
        """SELECT source_domain, state, count(*)::int AS c
           FROM mobile_normalized_artifacts WHERE job_id=:jid GROUP BY source_domain, state""",
        {"jid": job_id},
    )
    by_domain: dict[str, dict[str, int]] = {}
    total = 0
    for r in rows:
        dom, st, c = str(r["source_domain"]), str(r["state"]), int(r["c"])
        by_domain.setdefault(dom, {})[st] = c; total += c
    type_rows = fetchall(
        db,
        """SELECT artifact_type, count(*)::int AS c FROM mobile_normalized_artifacts
           WHERE job_id=:jid GROUP BY artifact_type ORDER BY c DESC""",
        {"jid": job_id},
    )
    family_rows = fetchall(
        db,
        """SELECT COALESCE(data->>'artifact_family','(unclassified)') AS family, count(*)::int AS c
           FROM mobile_normalized_artifacts WHERE job_id=:jid
           GROUP BY COALESCE(data->>'artifact_family','(unclassified)') ORDER BY c DESC""",
        {"jid": job_id},
    )
    family_state_rows = fetchall(
        db,
        """SELECT COALESCE(data->>'artifact_family','(unclassified)') AS family,
                  state, count(*)::int AS c
           FROM mobile_normalized_artifacts WHERE job_id=:jid
           GROUP BY COALESCE(data->>'artifact_family','(unclassified)'), state""",
        {"jid": job_id},
    )
    recovered_states = (
        'database_deleted', 'filesystem_recovered', 'freelist_candidate',
        'unverified', 'orphaned', 'cache_derived'
    )
    recovered_rows = fetchall(
        db,
        """SELECT COALESCE(data->>'artifact_family','(unclassified)') AS family, count(*)::int AS c
           FROM mobile_normalized_artifacts
           WHERE job_id=:jid AND state = ANY(CAST(:states AS text[]))
           GROUP BY COALESCE(data->>'artifact_family','(unclassified)')""",
        {"jid": job_id, "states": list(recovered_states)},
    )
    recovered_app_rows = fetchall(
        db,
        """SELECT LOWER(COALESCE(data->>'application','unknown')) AS application, count(*)::int AS c
           FROM mobile_normalized_artifacts
           WHERE job_id=:jid
             AND state = ANY(CAST(:states AS text[]))
             AND COALESCE(data->>'application','') <> ''
           GROUP BY LOWER(COALESCE(data->>'application','unknown'))""",
        {"jid": job_id, "states": list(recovered_states)},
    )
    inv_rows = fetchall(
        db,
        """SELECT status, count(*)::int AS c FROM mobile_inventory_items
           WHERE job_id=:jid GROUP BY status""",
        {"jid": job_id},
    )
    inventory_by_status = {str(r["status"]): int(r["c"]) for r in inv_rows}
    return {
        "total_artifacts": total,
        "by_domain": by_domain,
        "by_type": {str(r["artifact_type"]): int(r["c"]) for r in type_rows},
        "by_family": {str(r["family"]): int(r["c"]) for r in family_rows},
        "by_family_state": {
            f"{str(r['family'])}::{str(r['state'])}": int(r["c"]) for r in family_state_rows
        },
        "recovered_by_family": {str(r["family"]): int(r["c"]) for r in recovered_rows},
        "recovered_by_app": {str(r["application"]): int(r["c"]) for r in recovered_app_rows},
        "recovered_total": sum(int(r["c"]) for r in recovered_rows),
        "inventory_total": sum(inventory_by_status.values()),
        "inventory_by_status": inventory_by_status,
        "coverage": list_coverage(db, job_id),
    }


def save_examiner_review(db, job_id: str, artifact_id: str, *, decision: str, note: str | None = None, examiner: str | None = None) -> None:
    ensure_mobile_case_schema(db)
    execute(
        db,
        """INSERT INTO mobile_examiner_reviews (job_id, artifact_id, decision, note, examiner)
           VALUES (:jid, :aid, :dec, :note, :ex)""",
        {"jid": job_id, "aid": artifact_id, "dec": decision, "note": note, "ex": examiner},
    )
    execute(
        db,
        """UPDATE mobile_normalized_artifacts
           SET examiner_status=:dec,
               forensic=jsonb_set(COALESCE(forensic, '{}'::jsonb), '{examiner_status}', to_jsonb(:dec::text), true),
               updated_at=NOW()
           WHERE artifact_id=:aid AND job_id=:jid""",
        {"dec": decision, "aid": artifact_id, "jid": job_id},
    )


def timeline_rows(db, job_id: str, *, limit: int = 1000, offset: int = 0) -> list[dict[str, Any]]:
    ensure_mobile_case_schema(db)
    rows = fetchall(
        db,
        """SELECT artifact_id, artifact_type, source_domain, timestamp_utc::text AS timestamp_utc,
                  state, ui_label, data, forensic
           FROM mobile_normalized_artifacts
           WHERE job_id=:jid AND timestamp_utc IS NOT NULL
           ORDER BY timestamp_utc ASC, artifact_id ASC LIMIT :lim OFFSET :off""",
        {"jid": job_id, "lim": limit, "off": offset},
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        for k in ("data", "forensic"):
            if isinstance(d.get(k), str):
                try: d[k] = json.loads(d[k])
                except json.JSONDecodeError: pass
        out.append(d)
    return out
