"""Cross-pipeline logs (disk extract, mobile extract, vuln) with IST timestamps."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone
from app.forensic_common.job_types import MOBILE_JOB_TYPES

IST = ZoneInfo("Asia/Kolkata")
_TZ_SUFFIX = re.compile(r"(Z|[+-]\d{2}:?\d{2})$", re.IGNORECASE)

SOURCE_TYPES = ("disk", "mobile", "vuln")
ORIGINS = ("inhouse", "external")
LEVELS = ("error", "warning", "info", "debug")

_FORENSIC_SOURCE_SQL = """
CASE
  WHEN j.type IN ('mobile_extraction', 'android_mobile', 'ios_mobile', 'ios_backup', 'android_backup') THEN 'mobile'
  WHEN lower(coalesce(j.disk_source->>'source_type', '')) = 'mobile' THEN 'mobile'
  WHEN lower(coalesce(
    j.disk_source->>'axiom_platform',
    j.disk_source->>'evidence_platform',
    j.disk_source->>'mobile_os',
    ''
  )) IN ('android', 'ios') THEN 'mobile'
  ELSE 'disk'
END
""".strip()

_FORENSIC_LABEL_SQL = """
COALESCE(
  NULLIF(j.disk_source->>'display_name', ''),
  NULLIF(j.disk_source->>'label', ''),
  NULLIF(j.disk_source->>'original_name', ''),
  NULLIF(j.disk_source->>'host_path', ''),
  left(j.id::text, 8)
)
""".strip()


def with_ist_offset(value: str | None) -> str | None:
    """Treat timezone-naive filter values as IST (Asia/Kolkata)."""
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if _TZ_SUFFIX.search(raw):
        return raw
    if len(raw) == 16 and "T" in raw:
        raw = f"{raw}:00"
    return f"{raw}+05:30"


def format_timestamp_ist(ts: Any) -> str:
    if ts is None:
        return ""
    if isinstance(ts, str):
        raw = ts.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return ts
        ts = parsed
    if not isinstance(ts, datetime):
        return str(ts)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(IST).strftime("%d-%m-%Y %I:%M:%S %p IST")


def iso_utc(ts: Any) -> str:
    if ts is None:
        return ""
    if isinstance(ts, str):
        return ts
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat()
    return str(ts)


def classify_job_source(job_type: str | None, disk_source: Any = None) -> str:
    jtype = str(job_type or "")
    if jtype in MOBILE_JOB_TYPES:
        return "mobile"
    ds = disk_source if isinstance(disk_source, dict) else {}
    if str(ds.get("source_type") or "").lower() == "mobile":
        return "mobile"
    platform = str(
        ds.get("axiom_platform") or ds.get("evidence_platform") or ds.get("mobile_os") or ""
    ).lower()
    if platform in {"android", "ios"}:
        return "mobile"
    return "disk"


def normalize_level(level: str | None) -> str:
    raw = str(level or "info").strip().lower()
    if raw in {"warn", "warning"}:
        return "warning"
    if raw in {"err", "error", "failed", "fail"}:
        return "error"
    if raw in {"debug", "trace"}:
        return "debug"
    return "info"


def source_label(source_type: str) -> str:
    return {
        "disk": "Disk extract",
        "mobile": "Mobile extract",
        "vuln": "Vuln",
    }.get(source_type, source_type)


def origin_label(origin: str | None) -> str:
    return "External" if str(origin or "").lower() == "external" else "In-house"


def normalize_origin(origin: str | None) -> str | None:
    raw = str(origin or "").strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    if raw in {"", "all"}:
        return None
    if raw in {"external", "laptop", "edge", "remote"}:
        return "external"
    if raw in {"inhouse", "internal", "central", "premise"}:
        return "inhouse"
    return None


_EDGE_ORIGIN_SQL = """
CASE
  WHEN COALESCE((vj.orchestration_json->>'edge_agent')::boolean, false) THEN 'external'
  ELSE 'inhouse'
END
""".strip()


def _table_exists(db: Session, name: str) -> bool:
    row = fetchone(db, "SELECT to_regclass(:n) AS r", {"n": name})
    return bool(row and row.get("r"))


def _level_sql(alias: str, param: str) -> str:
    return (
        f"(CASE WHEN lower({alias}) IN ('warn', 'warning') THEN 'warning' "
        f"WHEN lower({alias}) IN ('err', 'error', 'failed', 'fail') THEN 'error' "
        f"WHEN lower({alias}) IN ('debug', 'trace') THEN 'debug' "
        f"ELSE 'info' END) = :{param}"
    )


def list_unified_logs(
    db: Session,
    *,
    source_type: str | None = None,
    origin: str | None = None,
    level: str | None = None,
    job_id: str | None = None,
    from_ts: str | None = None,
    to_ts: str | None = None,
    q: str | None = None,
    page: int = 1,
    page_size: int = 200,
    include_vuln: bool = True,
) -> dict[str, Any]:
    source = (source_type or "").strip().lower() or None
    if source == "all":
        source = None
    if source and source not in SOURCE_TYPES:
        source = None
    origin_key = normalize_origin(origin)

    want_level = normalize_level(level) if level and level.lower() not in {"", "all"} else None
    from_bound = with_ist_offset(from_ts)
    to_bound = with_ist_offset(to_ts)
    query = (q or "").strip()
    page = max(int(page or 1), 1)
    page_size = min(max(int(page_size or 200), 1), 500)
    offset = (page - 1) * page_size

    branches: list[str] = []
    params: dict[str, Any] = {"limit": page_size, "offset": offset}

    want_forensic = source in (None, "disk", "mobile") and origin_key in (None, "inhouse")
    want_vuln = include_vuln and source in (None, "vuln")
    want_vuln_external = want_vuln and origin_key in (None, "external")

    if want_forensic:
        from app.services.retired_agents import visible_pipeline_logs_sql
        clauses = [visible_pipeline_logs_sql("l.message")]
        if source in ("disk", "mobile"):
            clauses.append(f"({_FORENSIC_SOURCE_SQL}) = :forensic_source")
            params["forensic_source"] = source
        if job_id:
            clauses.append("l.job_id = CAST(:job_id AS uuid)")
            params["job_id"] = job_id
        if from_bound:
            clauses.append("l.timestamp >= CAST(:from_ts AS timestamptz)")
            params["from_ts"] = from_bound
        if to_bound:
            clauses.append("l.timestamp <= CAST(:to_ts AS timestamptz)")
            params["to_ts"] = to_bound
        if want_level:
            clauses.append(_level_sql("l.level", "level"))
            params["level"] = want_level
        if query:
            clauses.append("position(lower(:q) in lower(l.message)) > 0")
            params["q"] = query.lower()
        where = " AND ".join(clauses)
        branches.append(
            f"""
            SELECT
              ('forensic:' || l.id::text) AS id,
              l.job_id::text AS job_id,
              ({_FORENSIC_SOURCE_SQL}) AS source_type,
              'inhouse'::text AS origin,
              ({_FORENSIC_LABEL_SQL}) AS job_label,
              l.stage,
              l.level,
              l.message,
              l.timestamp
            FROM disk_build_logs l
            JOIN jobs j ON j.id = l.job_id
            WHERE {where}
            """
        )

    if want_vuln and _table_exists(db, "vuln_scan_engine_runs"):
        clauses = ["TRUE"]
        if origin_key:
            clauses.append(f"({_EDGE_ORIGIN_SQL}) = :origin")
            params["origin"] = origin_key
        if job_id:
            clauses.append("r.scan_job_id = CAST(:job_id AS uuid)")
            params["job_id"] = job_id
        if from_bound:
            clauses.append("COALESCE(r.started_at, r.created_at) >= CAST(:from_ts AS timestamptz)")
            params["from_ts"] = from_bound
        if to_bound:
            clauses.append("COALESCE(r.started_at, r.created_at) <= CAST(:to_ts AS timestamptz)")
            params["to_ts"] = to_bound
        if query:
            clauses.append(
                "position(lower(:q) in lower(COALESCE(r.error, '') || ' ' || r.engine || ' ' || r.status)) > 0"
            )
            params["q"] = query.lower()
        level_expr = """
            CASE
              WHEN COALESCE(r.error, '') <> '' OR r.status IN ('failed', 'error') THEN 'error'
              WHEN r.status IN ('warning', 'warn') THEN 'warning'
              ELSE 'info'
            END
        """
        if want_level:
            clauses.append(f"({level_expr}) = :level")
            params["level"] = want_level
        where = " AND ".join(clauses)
        branches.append(
            f"""
            SELECT
              ('vuln-run:' || r.id::text) AS id,
              r.scan_job_id::text AS job_id,
              'vuln'::text AS source_type,
              {_EDGE_ORIGIN_SQL} AS origin,
              ('Vuln · ' || r.engine || ' · ' || left(r.scan_job_id::text, 8)) AS job_label,
              r.engine AS stage,
              {level_expr} AS level,
              CASE
                WHEN COALESCE(r.error, '') <> '' THEN r.engine || ': ' || r.error
                ELSE r.engine || ' ' || r.status
                     || ' (' || COALESCE(r.findings_count, 0)::text || ' findings)'
              END AS message,
              COALESCE(r.started_at, r.created_at) AS timestamp
            FROM vuln_scan_engine_runs r
            JOIN vuln_scan_jobs vj ON vj.id = r.scan_job_id
            WHERE {where}
            """
        )

    if want_vuln and _table_exists(db, "vuln_scan_jobs"):
        clauses = ["TRUE"]
        if origin_key:
            clauses.append(f"({_EDGE_ORIGIN_SQL}) = :origin")
            params["origin"] = origin_key
        if job_id:
            clauses.append("vj.id = CAST(:job_id AS uuid)")
            params["job_id"] = job_id
        if from_bound:
            clauses.append("COALESCE(vj.updated_at, vj.created_at) >= CAST(:from_ts AS timestamptz)")
            params["from_ts"] = from_bound
        if to_bound:
            clauses.append("COALESCE(vj.updated_at, vj.created_at) <= CAST(:to_ts AS timestamptz)")
            params["to_ts"] = to_bound
        if query:
            clauses.append(
                "position(lower(:q) in lower(COALESCE(vj.error, '') || ' ' || vj.status)) > 0"
            )
            params["q"] = query.lower()
        level_expr = """
            CASE
              WHEN COALESCE(vj.error, '') <> '' OR vj.status IN ('failed', 'error') THEN 'error'
              ELSE 'info'
            END
        """
        if want_level:
            clauses.append(f"({level_expr}) = :level")
            params["level"] = want_level
        where = " AND ".join(clauses)
        branches.append(
            f"""
            SELECT
              ('vuln-job:' || vj.id::text) AS id,
              vj.id::text AS job_id,
              'vuln'::text AS source_type,
              {_EDGE_ORIGIN_SQL} AS origin,
              ((CASE WHEN COALESCE((vj.orchestration_json->>'edge_agent')::boolean, false)
                     THEN 'Laptop scan · ' ELSE 'Central scan · ' END)
               || left(vj.id::text, 8)) AS job_label,
              'scan_job'::text AS stage,
              {level_expr} AS level,
              CASE
                WHEN COALESCE(vj.error, '') <> '' THEN vj.error
                ELSE 'Scan job ' || vj.status
              END AS message,
              COALESCE(vj.updated_at, vj.created_at) AS timestamp
            FROM vuln_scan_jobs vj
            WHERE {where}
            """
        )

    if want_vuln_external and _table_exists(db, "scanner_agent_logs"):
        clauses = ["TRUE"]
        if job_id:
            clauses.append("l.job_id = CAST(:job_id AS uuid)")
            params["job_id"] = job_id
        if from_bound:
            clauses.append("l.created_at >= CAST(:from_ts AS timestamptz)")
            params["from_ts"] = from_bound
        if to_bound:
            clauses.append("l.created_at <= CAST(:to_ts AS timestamptz)")
            params["to_ts"] = to_bound
        if query:
            clauses.append("position(lower(:q) in lower(l.message)) > 0")
            params["q"] = query.lower()
        if want_level:
            clauses.append(_level_sql("l.level", "level"))
            params["level"] = want_level
        where = " AND ".join(clauses)
        branches.append(
            f"""
            SELECT
              ('laptop:' || l.id::text) AS id,
              l.job_id::text AS job_id,
              'vuln'::text AS source_type,
              'external'::text AS origin,
              ('Laptop · ' || COALESCE(NULLIF(s.name, ''), 'scanner')
               || CASE WHEN l.job_id IS NULL THEN '' ELSE ' · ' || left(l.job_id::text, 8) END)
                AS job_label,
              COALESCE(NULLIF(l.stage, ''), 'agent') AS stage,
              l.level,
              l.message,
              l.created_at AS timestamp
            FROM scanner_agent_logs l
            LEFT JOIN vuln_scanners s ON s.id = l.scanner_id
            WHERE {where}
            """
        )

    if want_vuln and _table_exists(db, "vuln_timeline_events"):
        clauses = ["TRUE"]
        if origin_key:
            clauses.append(f"({_EDGE_ORIGIN_SQL}) = :origin")
            params["origin"] = origin_key
        if job_id:
            clauses.append("t.source_id = CAST(:job_id AS uuid)")
            params["job_id"] = job_id
        if from_bound:
            clauses.append("t.timestamp_utc >= CAST(:from_ts AS timestamptz)")
            params["from_ts"] = from_bound
        if to_bound:
            clauses.append("t.timestamp_utc <= CAST(:to_ts AS timestamptz)")
            params["to_ts"] = to_bound
        if query:
            clauses.append(
                "position(lower(:q) in lower(COALESCE(t.summary, '') || ' ' || t.event_type)) > 0"
            )
            params["q"] = query.lower()
        level_expr = """
            CASE
              WHEN t.event_type ILIKE '%fail%' OR t.event_type ILIKE '%error%' THEN 'error'
              WHEN t.event_type ILIKE '%warn%' THEN 'warning'
              ELSE 'info'
            END
        """
        if want_level:
            clauses.append(f"({level_expr}) = :level")
            params["level"] = want_level
        where = " AND ".join(clauses)
        branches.append(
            f"""
            SELECT
              ('vuln-tl:' || t.id::text) AS id,
              t.source_id::text AS job_id,
              'vuln'::text AS source_type,
              COALESCE({_EDGE_ORIGIN_SQL}, 'inhouse') AS origin,
              COALESCE(t.event_type, 'timeline') AS job_label,
              COALESCE(t.event_type, 'timeline') AS stage,
              {level_expr} AS level,
              COALESCE(t.summary, t.event_type) AS message,
              t.timestamp_utc AS timestamp
            FROM vuln_timeline_events t
            LEFT JOIN vuln_scan_jobs vj ON vj.id = t.source_id
            WHERE {where}
            """
        )

    if not branches:
        return {"items": [], "total": 0, "page": page, "page_size": page_size}

    union_sql = " UNION ALL ".join(branches)
    total_row = fetchone(db, f"SELECT count(*) AS c FROM ({union_sql}) t", params) or {}
    rows = fetchall(
        db,
        f"""SELECT * FROM ({union_sql}) t
            ORDER BY timestamp DESC
            LIMIT :limit OFFSET :offset""",
        params,
    )
    items = []
    for row in rows:
        source_key = str(row.get("source_type") or "disk")
        origin_value = str(row.get("origin") or "inhouse")
        items.append(
            {
                "id": row["id"],
                "job_id": row.get("job_id"),
                "source_type": source_key,
                "source_label": source_label(source_key),
                "origin": origin_value,
                "origin_label": origin_label(origin_value),
                "job_label": row.get("job_label") or str(row.get("job_id") or "")[:8],
                "stage": row.get("stage") or "",
                "level": normalize_level(row.get("level")),
                "message": row.get("message") or "",
                "timestamp": iso_utc(row.get("timestamp")),
                "timestamp_ist": format_timestamp_ist(row.get("timestamp")),
            }
        )
    return {
        "items": items,
        "total": int(total_row.get("c") or 0),
        "page": page,
        "page_size": page_size,
    }


def list_log_sources(
    db: Session,
    *,
    source_type: str | None = None,
    origin: str | None = None,
    include_vuln: bool = True,
    limit: int = 200,
) -> list[dict[str, Any]]:
    source = (source_type or "").strip().lower() or None
    if source == "all":
        source = None
    origin_key = normalize_origin(origin)
    items: list[dict[str, Any]] = []
    limit = min(max(int(limit or 200), 1), 500)

    if source in (None, "disk", "mobile") and origin_key in (None, "inhouse"):
        params: dict[str, Any] = {"limit": limit}
        where = "TRUE"
        if source in ("disk", "mobile"):
            where = f"({_FORENSIC_SOURCE_SQL}) = :source"
            params["source"] = source
        rows = fetchall(
            db,
            f"""SELECT j.id, j.type, j.status, j.disk_source, j.updated_at,
                       ({_FORENSIC_SOURCE_SQL}) AS source_type,
                       ({_FORENSIC_LABEL_SQL}) AS job_label
                FROM jobs j
                WHERE {where}
                ORDER BY j.updated_at DESC
                LIMIT :limit""",
            params,
        )
        for row in rows:
            key = str(row.get("source_type") or classify_job_source(row.get("type"), row.get("disk_source")))
            items.append(
                {
                    "id": str(row["id"]),
                    "source_type": key,
                    "source_label": source_label(key),
                    "origin": "inhouse",
                    "origin_label": origin_label("inhouse"),
                    "label": f"{source_label(key)} · {row.get('job_label') or str(row['id'])[:8]}",
                    "status": row.get("status"),
                    "updated_at": iso_utc(row.get("updated_at")),
                    "updated_at_ist": format_timestamp_ist(row.get("updated_at")),
                }
            )

    if include_vuln and source in (None, "vuln") and _table_exists(db, "vuln_scan_jobs"):
        vuln_params: dict[str, Any] = {"limit": limit}
        where = "TRUE"
        if origin_key:
            where = f"({_EDGE_ORIGIN_SQL}) = :origin"
            vuln_params["origin"] = origin_key
        rows = fetchall(
            db,
            f"""SELECT vj.id, vj.status, vj.updated_at, vj.created_at,
                       ({_EDGE_ORIGIN_SQL}) AS origin
                FROM vuln_scan_jobs vj
                WHERE {where}
                ORDER BY COALESCE(vj.updated_at, vj.created_at) DESC
                LIMIT :limit""",
            vuln_params,
        )
        for row in rows:
            origin_value = str(row.get("origin") or "inhouse")
            prefix = "Laptop scan" if origin_value == "external" else "Central scan"
            items.append(
                {
                    "id": str(row["id"]),
                    "source_type": "vuln",
                    "source_label": source_label("vuln"),
                    "origin": origin_value,
                    "origin_label": origin_label(origin_value),
                    "label": f"{prefix} · {str(row['id'])[:8]}",
                    "status": row.get("status"),
                    "updated_at": iso_utc(row.get("updated_at") or row.get("created_at")),
                    "updated_at_ist": format_timestamp_ist(row.get("updated_at") or row.get("created_at")),
                }
            )

    items.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
    return items[:limit]
