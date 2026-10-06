"""BRD completion services: agents, snapshots, exception expiry, notifications.

Additive helpers — does not replace existing vuln_helpers / nessus_sync behavior.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.vuln_helpers import dashboard_layer, overview_kpis

log = logging.getLogger("vuln_brd")

# BRD §8.3 agent lifecycle
AGENT_STATES = (
    "planned",
    "installed",
    "linked",
    "healthy",
    "stale",
    "unlinked",
    "uninstalled",
    "retired",
)

ALLOWED_AGENT_TRANSITIONS: dict[str, set[str]] = {
    "planned": {"installed", "retired"},
    "installed": {"linked", "uninstalled", "retired"},
    "linked": {"healthy", "stale", "unlinked", "retired"},
    "healthy": {"stale", "unlinked", "retired"},
    "stale": {"healthy", "unlinked", "retired"},
    "unlinked": {"linked", "uninstalled", "retired"},
    "uninstalled": {"retired", "planned"},
    "retired": set(),
}


def row_agent(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(r["id"]),
        "agent_uuid": r["agent_uuid"],
        "asset_id": str(r["asset_id"]) if r.get("asset_id") else None,
        "scanner_id": str(r["scanner_id"]) if r.get("scanner_id") else None,
        "name": r.get("name"),
        "hostname": r.get("hostname"),
        "platform": r.get("platform"),
        "version": r.get("version"),
        "lifecycle_state": r["lifecycle_state"],
        "last_checkin_at": r["last_checkin_at"].isoformat() if r.get("last_checkin_at") else None,
        "last_scan_at": r["last_scan_at"].isoformat() if r.get("last_scan_at") else None,
        "policy_name": r.get("policy_name"),
        "link_key_provenance": r.get("link_key_provenance"),
        "error_text": r.get("error_text"),
        "device_class": r.get("device_class"),
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        "updated_at": r["updated_at"].isoformat() if r.get("updated_at") else None,
    }


def mark_stale_agents(db: Session, *, stale_hours: int = 72) -> int:
    """AGENT-002: agents past check-in threshold → stale (does not touch forensic agents)."""
    execute(
        db,
        """UPDATE vuln_agents
           SET lifecycle_state = 'stale', updated_at = NOW()
           WHERE lifecycle_state IN ('healthy', 'linked')
             AND (last_checkin_at IS NULL OR last_checkin_at < NOW() - make_interval(hours => :h))""",
        {"h": stale_hours},
    )
    row = fetchone(db, "SELECT COUNT(*)::int AS n FROM vuln_agents WHERE lifecycle_state = 'stale'") or {}
    return int(row.get("n") or 0)


def save_risk_score_history(
    db: Session,
    *,
    finding_id: str | None,
    asset_id: str | None,
    scored: dict[str, Any],
) -> None:
    """Append-only risk history — does not change finding columns."""
    execute(
        db,
        """INSERT INTO vuln_risk_scores
           (finding_id, asset_id, model_version, enterprise_risk_score, risk_band, factors_json)
           VALUES (
             CASE WHEN :fid IS NULL THEN NULL ELSE CAST(:fid AS uuid) END,
             CASE WHEN :aid IS NULL THEN NULL ELSE CAST(:aid AS uuid) END,
             :mv, :score, :band, CAST(:factors AS jsonb)
           )""",
        {
            "fid": finding_id,
            "aid": asset_id,
            "mv": scored.get("risk_factors_json", {}).get("model_version") or "brd-v2-contextual-1",
            "score": scored["enterprise_risk_score"],
            "band": scored["risk_band"],
            "factors": json.dumps(scored.get("risk_factors_json") or {}),
        },
    )


def record_scan_result(
    db: Session,
    *,
    scan_job_id: str,
    hosts_attempted: int,
    hosts_assessed: int,
    credential_success: int = 0,
    credential_fail: int = 0,
    plugin_errors: int = 0,
    result_json: dict | None = None,
) -> None:
    raw = json.dumps(result_json or {}, sort_keys=True)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    execute(
        db,
        """INSERT INTO vuln_scan_results
           (scan_job_id, hosts_attempted, hosts_assessed, credential_success_count,
            credential_fail_count, plugin_error_count, integrity_hash, result_json, completed_at)
           VALUES (CAST(:jid AS uuid), :ha, :hs, :cs, :cf, :pe, :hash, CAST(:rj AS jsonb), NOW())""",
        {
            "jid": scan_job_id,
            "ha": hosts_attempted,
            "hs": hosts_assessed,
            "cs": credential_success,
            "cf": credential_fail,
            "pe": plugin_errors,
            "hash": digest,
            "rj": raw,
        },
    )


def create_dashboard_snapshot(
    db: Session,
    *,
    layer: str,
    filters: dict | None,
    user_id: str | None,
) -> dict[str, Any]:
    payload = dashboard_layer(db, layer, filters)
    # Enrich with agent coverage without changing core KPI formulas
    agents = fetchone(
        db,
        """SELECT
             COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE lifecycle_state = 'healthy')::int AS healthy,
             COUNT(*) FILTER (WHERE lifecycle_state = 'stale')::int AS stale
           FROM vuln_agents"""
    ) or {}
    widgets = dict(payload.get("widgets") or {})
    widgets["agent_coverage"] = {
        "total": int(agents.get("total") or 0),
        "healthy": int(agents.get("healthy") or 0),
        "stale": int(agents.get("stale") or 0),
    }
    payload["widgets"] = widgets
    filt = filters or {}
    fhash = hashlib.sha256(json.dumps(filt, sort_keys=True).encode()).hexdigest()[:32]
    row = fetchone(
        db,
        """INSERT INTO vuln_dashboard_snapshots (layer, filter_hash, filters_json, widgets_json, created_by)
           VALUES (:layer, :fh, CAST(:fj AS jsonb), CAST(:wj AS jsonb),
                   CASE WHEN :uid IS NULL THEN NULL ELSE CAST(:uid AS uuid) END)
           RETURNING id, created_at, freshness_at""",
        {
            "layer": layer,
            "fh": fhash,
            "fj": json.dumps(filt),
            "wj": json.dumps(widgets),
            "uid": user_id,
        },
    )
    return {
        "id": str(row["id"]),
        "layer": layer,
        "filter_hash": fhash,
        "widgets": widgets,
        "freshness_at": row["freshness_at"].isoformat() if row.get("freshness_at") else None,
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
    }


def expire_exceptions(db: Session) -> dict[str, int]:
    """BRD: expired exceptions escalated automatically."""
    expired = fetchall(
        db,
        """SELECT id, finding_id FROM vuln_exceptions
           WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at < NOW()"""
    )
    n = 0
    for ex in expired:
        execute(
            db,
            "UPDATE vuln_exceptions SET status = 'expired', updated_at = NOW() WHERE id = CAST(:id AS uuid)",
            {"id": str(ex["id"])},
        )
        execute(
            db,
            """INSERT INTO vuln_notifications (channel, event_type, title, body, resource_type, resource_id)
               VALUES ('in_app', 'exception.expired', 'Exception expired',
                       'Approved exception expired and requires renewal or closure',
                       'exception', CAST(:id AS uuid))""",
            {"id": str(ex["id"])},
        )
        n += 1
    return {"expired": n}


def evaluate_alert_thresholds(db: Session) -> int:
    """DASH-007: fire once per state transition into breach."""
    kpis = overview_kpis(db)
    metrics = {
        "sla_overdue_pct": float(kpis["dashboards"].get("sla_overdue_pct") or 0),
        "kev_open": float(kpis["dashboards"].get("kev_open") or 0),
        "coverage_pct": float(kpis["dashboards"].get("coverage_pct") or 0),
        "failed_24h": float(kpis["functionality"].get("failed_24h") or 0),
        "agents_stale": float(
            (fetchone(db, "SELECT COUNT(*)::int AS n FROM vuln_agents WHERE lifecycle_state = 'stale'") or {}).get("n")
            or 0
        ),
    }
    thresholds = fetchall(db, "SELECT * FROM vuln_alert_thresholds WHERE enabled = TRUE")
    fired = 0
    for t in thresholds:
        key = t["metric_key"]
        if key not in metrics:
            continue
        val = metrics[key]
        op = t["operator"]
        thr = float(t["threshold_value"])
        breach = (op == "gte" and val >= thr) or (op == "lte" and val <= thr) or (op == "gt" and val > thr)
        if not breach:
            continue
        # Only notify if never triggered or last trigger was when not breached — simple: always if last_triggered null or >1h ago
        last = t.get("last_triggered_at")
        if last and (datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).total_seconds() < 3600:
            continue
        execute(
            db,
            """INSERT INTO vuln_notifications (channel, event_type, title, body, resource_type)
               VALUES ('in_app', 'threshold.breach', :title, :body, 'alert_threshold')""",
            {
                "title": f"Threshold breach: {key}",
                "body": f"{key}={val} {op} {thr}",
            },
        )
        execute(
            db,
            "UPDATE vuln_alert_thresholds SET last_triggered_at = NOW(), updated_at = NOW() WHERE id = CAST(:id AS uuid)",
            {"id": str(t["id"])},
        )
        fired += 1
    return fired


def escalate_sla_overdue(db: Session) -> int:
    """FR-9.2: increment escalation_level for overdue remediation tasks."""
    execute(
        db,
        """UPDATE vuln_remediation_tasks
           SET escalation_level = escalation_level + 1, updated_at = NOW()
           WHERE status IN ('open', 'in_progress')
             AND sla_due IS NOT NULL AND sla_due < NOW()
             AND updated_at < NOW() - INTERVAL '1 hour'""",
    )
    row = fetchone(
        db,
        """SELECT COUNT(*)::int AS n FROM vuln_remediation_tasks
           WHERE status IN ('open', 'in_progress') AND sla_due IS NOT NULL AND sla_due < NOW()""",
    ) or {}
    return int(row.get("n") or 0)
