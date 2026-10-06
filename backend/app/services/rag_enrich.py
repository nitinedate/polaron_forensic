"""Structured entity / annotation / ontology enrichment from parsed evidence.

The old rag_enrich task only wrote four log lines and marked the cards 100%.
This module scans artifact_parse_results and counts real encyclopedia mappings.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.db.sql_helpers import execute, fetchall, fetchone

log = logging.getLogger("rag_enrich")

# Large SQL batches. Row-by-row Python walks plus a full orchestration rebuild
# every 80 rows left Entity/Annotation/Ontology at ~10 rows/s (hours for 130k).
ENRICH_BATCH = 2500
ENRICH_HEARTBEAT_EVERY = 2500
ENRICH_SAMPLE_CHARS = 3500
ENRICH_NORMALIZED_CHARS = 12_000
ENRICH_WALK_MAX_NODES = 2_500
NIL_PARSE_ID = "00000000-0000-0000-0000-000000000000"
_SQL_COUNT_RES = {
    "user": r'"(?:user_profile|user|username|account|sid|owner)"\s*:\s*"[^"]+"',
    "process": r'"(?:executable|process|image_name|app)"\s*:\s*"[^"]+"',
    "registry": r'"(?:registry_key|key_path|hive)"\s*:\s*"[^"]+"',
    "host": r'"(?:hostname|computer|host|machine)"\s*:\s*"[^"]+"',
    "event": r'"(?:event_id|eventid)"\s*:',
    "database": r'"(?:table|db_table)"\s*:\s*"[^"]+"',
    "email": r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}",
    "ip": r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
}
_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

_USER_KEYS = frozenset({"user_profile", "user", "username", "account", "sid", "owner"})
_PROCESS_KEYS = frozenset({"executable", "process", "image_name", "app"})
_REGISTRY_KEYS = frozenset({"registry_key", "key_path", "hive"})
_HOST_KEYS = frozenset({"hostname", "computer", "host", "machine"})


def _as_obj(raw: Any, *, full: bool = False) -> Any:
    if isinstance(raw, str):
        sample = raw if full else raw[: max(ENRICH_NORMALIZED_CHARS, 1)]
        try:
            return json.loads(sample)
        except json.JSONDecodeError:
            return sample
    return raw


def extract_entities_from_normalized(normalized: Any) -> dict[str, int]:
    """Return mention counts by type for one parse payload."""
    counts: dict[str, int] = {}
    nodes = 0
    from app.services.forensic_serial_policy import current_stage

    full = current_stage() == "enrichment"

    def bump(kind: str) -> None:
        counts[kind] = counts.get(kind, 0) + 1

    def walk(obj: Any, depth: int = 0) -> None:
        nonlocal nodes
        if (not full and depth > 6) or obj is None:
            return
        nodes += 1
        if not full and nodes > ENRICH_WALK_MAX_NODES:
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                if not full and nodes > ENRICH_WALK_MAX_NODES:
                    return
                kl = str(key).lower()
                if isinstance(val, str) and val.strip():
                    text = val.strip() if full else val.strip()[:500]
                    if kl in _USER_KEYS:
                        bump("user")
                    elif kl in _PROCESS_KEYS:
                        bump("process")
                    elif kl in _REGISTRY_KEYS:
                        bump("registry")
                    elif kl in _HOST_KEYS:
                        bump("host")
                    elif kl in ("event_id", "eventid"):
                        bump("event")
                    elif kl in ("table", "db_table"):
                        bump("database")
                    elif "@" in text:
                        for _m in _EMAIL_RE.findall(text):
                            bump("email")
                    if _IPV4_RE.search(text):
                        bump("ip")
                walk(val, depth + 1)
        elif isinstance(obj, list):
            for item in obj if full else obj[:40]:
                walk(item, depth + 1)
        elif isinstance(obj, str) and obj:
            sample = obj if full else obj[:4000]
            if "@" in sample:
                for _m in _EMAIL_RE.findall(sample):
                    bump("email")
            for _m in _IPV4_RE.findall(sample):
                bump("ip")

    walk(_as_obj(normalized, full=full))
    return counts


def _merge_counts(dst: dict[str, int], src: dict[str, int]) -> None:
    for key, n in src.items():
        dst[key] = int(dst.get(key) or 0) + int(n or 0)


def read_enrichment_stats(pp: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(pp, dict):
        return {}
    stats = pp.get("enrichment_stats")
    return dict(stats) if isinstance(stats, dict) else {}


def load_enrichment_stats(db, job_id: str) -> dict[str, Any]:
    from app.services.pipeline_orchestrator import _parse_pp

    row = fetchone(db, "SELECT pipeline_progress FROM jobs WHERE id=:id", {"id": job_id})
    return read_enrichment_stats(_parse_pp((row or {}).get("pipeline_progress")))


def mark_empty_corpus_enrichment_complete(db, job_id: str) -> dict[str, Any]:
    """Stop the 30s rag_enrich loop when extract finished with nothing to scan."""
    stats = {
        "scanned": 0,
        "parse_total": 0,
        "entity_mentions": 0,
        "ontology_mapped": 0,
        "complete": True,
        "skipped": True,
        "reason": "empty_corpus",
    }
    persist_enrichment_stats(db, job_id, stats)
    return stats


def persist_enrichment_stats(db, job_id: str, stats: dict[str, Any]) -> None:
    payload = dict(stats)
    payload["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    execute(
        db,
        """UPDATE jobs
           SET pipeline_progress = jsonb_set(
                 COALESCE(pipeline_progress, '{}'::jsonb),
                 '{enrichment_stats}',
                 CAST(:stats AS jsonb)
               )
           WHERE id=:id""",
        {"id": job_id, "stats": json.dumps(payload)},
    )


def parse_result_cursor(value: Any) -> str:
    """artifact_parse_results.id is UUID. Legacy last_parse_id=0 must not hit SQL."""
    if value in (None, "", 0, "0"):
        return NIL_PARSE_ID
    text = str(value).strip()
    try:
        return str(uuid.UUID(text))
    except (ValueError, TypeError, AttributeError):
        return NIL_PARSE_ID


def count_parse_results(db, job_id: str) -> int:
    row = fetchone(
        db,
        """SELECT count(*) AS c
           FROM artifact_parse_results apr
           JOIN job_artifacts ja ON ja.id = apr.job_artifact_id
           WHERE ja.job_id=:jid""",
        {"jid": job_id},
    )
    return int((row or {}).get("c") or 0)


def seed_enrichment_progress(db, job_id: str) -> dict[str, Any]:
    """Heartbeat immediately, then publish parse_total so cards show 0 / N."""
    stats = load_enrichment_stats(db, job_id)
    stats["scanned"] = int(stats.get("scanned") or 0)
    stats["complete"] = bool(stats.get("complete"))
    persist_enrichment_stats(db, job_id, stats)
    if int(stats.get("parse_total") or 0) <= 0:
        stats["parse_total"] = count_parse_results(db, job_id)
        persist_enrichment_stats(db, job_id, stats)
    return stats


def _sql_aggregate_batch(db, job_id: str, last_id: str, batch_size: int) -> dict[str, Any] | None:
    """Count entities for the next page in Postgres. No JSON shipped to Python."""
    from app.services.forensic_serial_policy import current_stage

    params: dict[str, Any] = {
        "jid": job_id,
        "last": last_id,
        "lim": int(batch_size),
        "nchars": 0 if current_stage() == "enrichment" else ENRICH_SAMPLE_CHARS,
    }
    params.update({f"{kind}_re": pattern for kind, pattern in _SQL_COUNT_RES.items()})
    return fetchone(
        db,
        """
        WITH batch AS (
          SELECT apr.id,
                 CASE WHEN :nchars=0 THEN coalesce(apr.normalized::text, '')
                      ELSE left(coalesce(apr.normalized::text, ''), :nchars) END AS sample
          FROM job_artifacts ja
          JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
          WHERE ja.job_id=:jid AND apr.id > CAST(:last AS uuid)
          ORDER BY apr.id
          LIMIT :lim
        )
        SELECT
          (SELECT id FROM batch ORDER BY id DESC LIMIT 1) AS last_id,
          (SELECT count(*) FROM batch) AS scanned,
          (SELECT COALESCE(SUM(regexp_count(sample, :user_re, 1, 'i')), 0) FROM batch) AS user_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :process_re, 1, 'i')), 0) FROM batch) AS process_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :registry_re, 1, 'i')), 0) FROM batch) AS registry_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :host_re, 1, 'i')), 0) FROM batch) AS host_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :event_re, 1, 'i')), 0) FROM batch) AS event_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :database_re, 1, 'i')), 0) FROM batch) AS database_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :email_re, 1, 'i')), 0) FROM batch) AS email_n,
          (SELECT COALESCE(SUM(regexp_count(sample, :ip_re, 1, 'i')), 0) FROM batch) AS ip_n
        """,
        params,
    )


def run_rag_enrichment_batch(
    db,
    job_id: str,
    *,
    batch_size: int = ENRICH_BATCH,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
    current: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan the next batch of parse results. Returns updated stats."""
    from app.services.forensic_serial_policy import current_stage

    full = current_stage() == "enrichment"
    stats = dict(current) if current else load_enrichment_stats(db, job_id)
    if full and not stats.get("full_corpus"):
        stats = {}  # Legacy sample counts cannot stand in for a full serial scan.
    last_id = parse_result_cursor(stats.get("last_parse_id"))
    parse_total = int(stats.get("parse_total") or 0)
    if parse_total <= 0:
        parse_total = count_parse_results(db, job_id)
    ontology_mapped = int(stats.get("ontology_mapped") or 0)
    if ontology_mapped <= 0:
        enc_row = fetchone(
            db,
            """SELECT count(*) AS c FROM job_artifacts
               WHERE job_id=:jid AND encyclopedia_artifact_id IS NOT NULL""",
            {"jid": job_id},
        )
        ontology_mapped = int((enc_row or {}).get("c") or 0)

    by_type = {str(k): int(v) for k, v in (stats.get("entity_by_type") or {}).items()}
    mentions = int(stats.get("entity_mentions") or 0)
    scanned = int(stats.get("scanned") or 0)
    max_id = last_id
    processed = 0

    agg = None
    try:
        agg = _sql_aggregate_batch(db, job_id, last_id, batch_size)
    except Exception as exc:
        log.warning("enrich SQL aggregate failed job=%s (%s) — falling back to row scan", job_id, exc)
        try:
            db.rollback()
        except Exception:
            pass

    if agg is not None and "scanned" in agg:
        processed = int(agg.get("scanned") or 0)
        if processed > 0:
            max_id = parse_result_cursor(agg.get("last_id") or last_id)
            found = {
                kind: int(agg.get(f"{kind}_n") or 0)
                for kind in _SQL_COUNT_RES
                if int(agg.get(f"{kind}_n") or 0)
            }
            mentions += sum(found.values())
            _merge_counts(by_type, found)
            scanned += processed
    else:
        rows = fetchall(
            db,
            """SELECT apr.id, CASE WHEN :nchars=0 THEN coalesce(apr.normalized::text, '')
                                  ELSE left(coalesce(apr.normalized::text, ''), :nchars) END AS normalized
               FROM job_artifacts ja
               JOIN artifact_parse_results apr ON apr.job_artifact_id = ja.id
               WHERE ja.job_id=:jid AND apr.id > CAST(:last AS uuid)
               ORDER BY apr.id
               LIMIT :lim""",
            {
                "jid": job_id,
                "last": last_id,
                "lim": int(batch_size),
                "nchars": 0 if full else ENRICH_SAMPLE_CHARS,
            },
        )
        for row in rows or []:
            rid = parse_result_cursor(row.get("id"))
            if rid != NIL_PARSE_ID:
                max_id = rid
            sample = row.get("normalized")
            try:
                found = extract_entities_from_normalized(
                    json.loads(sample) if isinstance(sample, str) else sample
                )
            except Exception:
                found = extract_entities_from_normalized(sample)
            mentions += sum(found.values())
            _merge_counts(by_type, found)
            scanned += 1
            processed += 1

    complete = parse_total <= 0 or processed <= 0 or scanned >= parse_total
    stats = {
        **{key: value for key, value in stats.items() if key.startswith("mobile_")},
        "scanned": scanned,
        "parse_total": parse_total,
        "last_parse_id": max_id,
        "entity_mentions": mentions,
        "entity_by_type": by_type,
        "ontology_mapped": ontology_mapped,
        "complete": bool(complete),
        "full_corpus": full,
    }
    persist_enrichment_stats(db, job_id, stats)
    if on_progress is not None:
        on_progress(stats)
    return stats


def run_rag_enrichment_until_complete(
    db,
    job_id: str,
    *,
    batch_size: int = ENRICH_BATCH,
    max_batches: int = 2500,
    on_batch=None,
    on_progress=None,
) -> dict[str, Any]:
    """Scan every parse-result batch in this session. No Celery hop per batch."""
    try:
        stats = load_enrichment_stats(db, job_id)
    except Exception:
        stats = {}
    for _ in range(max(int(max_batches), 1)):
        stats = run_rag_enrichment_batch(
            db,
            job_id,
            batch_size=batch_size,
            on_progress=on_progress,
            current=stats,
        )
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        if on_batch is not None:
            on_batch(stats)
        if stats.get("complete"):
            return stats
    stats = dict(stats or {})
    stats["complete"] = False
    stats["truncated"] = True
    persist_enrichment_stats(db, job_id, stats)
    return stats
