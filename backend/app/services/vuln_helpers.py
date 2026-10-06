"""Shared helpers for vulnerability module SQL (firm search_path)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.aetheris_severity import aetheris_severity_sql


def _now() -> datetime:
    return datetime.now(timezone.utc)


def audit(db: Session, *, actor_id: str | None, action: str, resource_type: str, resource_id: str | None, details: dict | None = None) -> None:
    execute(
        db,
        """INSERT INTO vuln_audit_events (actor_id, action, resource_type, resource_id, details)
           VALUES (
             CASE WHEN :actor IS NULL THEN NULL ELSE CAST(:actor AS uuid) END,
             :action, :rtype,
             CASE WHEN :rid IS NULL THEN NULL ELSE CAST(:rid AS uuid) END,
             CAST(:details AS jsonb)
           )""",
        {
            "actor": actor_id,
            "action": action,
            "rtype": resource_type,
            "rid": resource_id,
            "details": json.dumps(details or {}),
        },
    )


def timeline(
    db: Session,
    *,
    case_id: str,
    source_type: str,
    source_id: str | None,
    event_type: str,
    actor: str | None,
    summary: str,
    asset_id: str | None = None,
) -> None:
    execute(
        db,
        """INSERT INTO vuln_timeline_events
           (case_id, source_type, source_id, event_type, actor, asset_id, summary)
           VALUES (
             CAST(:case_id AS uuid), :stype,
             CASE WHEN :sid IS NULL THEN NULL ELSE CAST(:sid AS uuid) END,
             :etype, :actor,
             CASE WHEN :aid IS NULL THEN NULL ELSE CAST(:aid AS uuid) END,
             :summary
           )""",
        {
            "case_id": case_id,
            "stype": source_type,
            "sid": source_id,
            "etype": event_type,
            "actor": actor,
            "aid": asset_id,
            "summary": summary,
        },
    )


def row_scanner(r: dict[str, Any]) -> dict[str, Any]:
    from app.services.scanner_credentials import infer_scanner_role, scanner_heartbeat_online

    role = infer_scanner_role(r)
    online = scanner_heartbeat_online(r)
    return {
        "id": str(r["id"]),
        "name": r["name"],
        "url": r["url"],
        "edition": r.get("edition"),
        "status": r["status"],
        "connection_mode": r.get("connection_mode") or "gmp",
        "scanner_role": role,
        "online": online,
        "agent_token_hint": r.get("agent_token_hint"),
        "openvas_ready": r.get("openvas_ready"),
        "agent_status_detail": r.get("agent_status_detail"),
        "openvas_ready_at": str(r.get("openvas_ready_at")) if r.get("openvas_ready_at") else None,
        "last_heartbeat_at": r["last_heartbeat_at"].isoformat() if r.get("last_heartbeat_at") else None,
        "plugin_feed_updated_at": r["plugin_feed_updated_at"].isoformat() if r.get("plugin_feed_updated_at") else None,
        "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
    }


def overview_kpis(db: Session) -> dict[str, Any]:
    findings = fetchone(
        db,
        """SELECT
             COUNT(*) FILTER (WHERE status = 'open')::int AS open_findings,
             COUNT(*) FILTER (WHERE status = 'open' AND is_kev)::int AS kev_open,
             COUNT(*) FILTER (WHERE status = 'open' AND risk_band = 'critical')::int AS critical_open,
             COALESCE(AVG(enterprise_risk_score) FILTER (WHERE status = 'open'), 0)::float AS avg_risk
           FROM vuln_findings"""
    ) or {}
    coverage = fetchone(
        db,
        """SELECT
             COUNT(*)::int AS assets,
             COUNT(*) FILTER (WHERE risk_score IS NOT NULL)::int AS assessed
           FROM vuln_assets WHERE lifecycle_state = 'active'"""
    ) or {}
    assets = int(coverage.get("assets") or 0)
    assessed = int(coverage.get("assessed") or 0)
    coverage_pct = round((assessed / assets) * 100.0, 1) if assets else 0.0
    sla = fetchone(
        db,
        """SELECT
             COUNT(*) FILTER (WHERE status IN ('open','in_progress') AND sla_due < NOW())::int AS overdue,
             COUNT(*) FILTER (WHERE status IN ('open','in_progress'))::int AS open_tasks
           FROM vuln_remediation_tasks"""
    ) or {}
    open_tasks = int(sla.get("open_tasks") or 0)
    overdue = int(sla.get("overdue") or 0)
    sla_pct = round(((open_tasks - overdue) / open_tasks) * 100.0, 1) if open_tasks else 100.0
    scans = fetchone(
        db,
        """SELECT
             COUNT(*) FILTER (WHERE status = 'running')::int AS running,
             COUNT(*) FILTER (WHERE status = 'failed' AND updated_at > NOW() - INTERVAL '24 hours')::int AS failed_24h
           FROM vuln_scan_jobs"""
    ) or {}
    rem = fetchone(
        db,
        """SELECT COUNT(*)::int AS n FROM vuln_remediation_tasks WHERE status IN ('open','in_progress')"""
    ) or {}
    exc = fetchone(
        db,
        """SELECT COUNT(*)::int AS n FROM vuln_exceptions WHERE status = 'pending'"""
    ) or {}
    scanners = fetchone(
        db,
        """SELECT COUNT(*) FILTER (WHERE status = 'active')::int AS active FROM vuln_scanners"""
    ) or {}
    return {
        "dashboards": {
            "enterprise_risk_score": round(float(findings.get("avg_risk") or 0), 1),
            "kev_open": int(findings.get("kev_open") or 0),
            "sla_overdue_pct": round(100.0 - sla_pct, 1) if open_tasks else 0.0,
            "coverage_pct": coverage_pct,
            "critical_open": int(findings.get("critical_open") or 0),
            "open_findings": int(findings.get("open_findings") or 0),
        },
        "functionality": {
            "scans_running": int(scans.get("running") or 0),
            "failed_24h": int(scans.get("failed_24h") or 0),
            "open_remediation": int(rem.get("n") or 0),
            "exceptions_pending": int(exc.get("n") or 0),
            "scanners_active": int(scanners.get("active") or 0),
        },
        "freshness": {"last_ingestion_at": _now().isoformat(), "stale": False},
    }


def dashboard_layer(db: Session, layer: str, filters: dict[str, Any] | None = None) -> dict[str, Any]:
    filters = filters or {}
    kpis = overview_kpis(db)
    severity = fetchall(
        db,
        f"""SELECT {aetheris_severity_sql('')} AS severity, COUNT(*)::int AS n FROM vuln_findings
           WHERE status = 'open' GROUP BY 1 ORDER BY n DESC"""
    )
    aging = fetchall(
        db,
        """SELECT
             CASE
               WHEN NOW() - first_seen_at < INTERVAL '7 days' THEN '0-7d'
               WHEN NOW() - first_seen_at < INTERVAL '30 days' THEN '8-30d'
               WHEN NOW() - first_seen_at < INTERVAL '90 days' THEN '31-90d'
               ELSE '90d+'
             END AS bucket,
             COUNT(*)::int AS n
           FROM vuln_findings WHERE status = 'open'
           GROUP BY 1 ORDER BY 1"""
    )
    scanners = fetchall(
        db,
        """SELECT id, name, status, last_heartbeat_at, version, plugin_feed_updated_at
           FROM vuln_scanners ORDER BY name"""
    )
    widgets: dict[str, Any] = {
        "severity_breakdown": [{"label": r["severity"], "value": r["n"]} for r in severity],
        "aging": [{"label": r["bucket"], "value": r["n"]} for r in aging],
        "kpis": kpis["dashboards"],
    }
    if layer in ("executive", "executive_risk", "vm_operations", "all"):
        widgets["executive"] = kpis["dashboards"]
        widgets["vm_operations"] = {
            **kpis["functionality"],
            "new_open": int(findings_count(db, "open")),
        }
    if layer in ("coverage", "coverage_hygiene", "all"):
        widgets["coverage"] = {"coverage_pct": kpis["dashboards"]["coverage_pct"]}
    if layer in ("scanner_health", "health", "all"):
        widgets["scanners"] = [
            {
                "id": str(s["id"]),
                "name": s["name"],
                "status": s["status"],
                "last_heartbeat_at": s["last_heartbeat_at"].isoformat() if s.get("last_heartbeat_at") else None,
                "version": s.get("version"),
                "plugin_feed_updated_at": s["plugin_feed_updated_at"].isoformat() if s.get("plugin_feed_updated_at") else None,
            }
            for s in scanners
        ]
        try:
            agents = fetchone(
                db,
                """SELECT
                     COUNT(*)::int AS total,
                     COUNT(*) FILTER (WHERE lifecycle_state = 'healthy')::int AS healthy,
                     COUNT(*) FILTER (WHERE lifecycle_state = 'stale')::int AS stale
                   FROM vuln_agents"""
            ) or {}
            widgets["agent_coverage"] = {
                "total": int(agents.get("total") or 0),
                "healthy": int(agents.get("healthy") or 0),
                "stale": int(agents.get("stale") or 0),
            }
        except Exception:
            widgets["agent_coverage"] = {"total": 0, "healthy": 0, "stale": 0}
    if layer in ("remediation", "remediation_sla", "all"):
        widgets["remediation"] = kpis["functionality"]
    if layer in ("compliance", "all"):
        evidence = fetchone(db, "SELECT COUNT(*)::int AS n FROM vuln_evidence_packages") or {}
        widgets["compliance"] = {"evidence_packages": int(evidence.get("n") or 0)}
    if layer in ("exceptions", "exception_governance", "all"):
        widgets["exceptions"] = {"pending": kpis["functionality"]["exceptions_pending"]}
    if layer in ("asset_intelligence", "assets", "all"):
        assets = fetchone(db, "SELECT COUNT(*)::int AS n FROM vuln_assets") or {}
        widgets["assets"] = {"count": int(assets.get("n") or 0)}
    return {
        "layer": layer,
        "filters": filters,
        "widgets": widgets,
        "freshness": kpis["freshness"],
        "metric_dictionary": {
            "coverage_pct": "Successfully assessed active assets / active in-scope assets",
            "enterprise_risk_score": "Mean enterprise contextual risk for open findings",
            "kev_open": "Open findings whose CVE is in CISA KEV",
            "sla_overdue_pct": "Open remediation tasks past SLA / open remediation tasks",
        },
    }


def findings_count(db: Session, status: str) -> int:
    row = fetchone(db, "SELECT COUNT(*)::int AS n FROM vuln_findings WHERE status = :s", {"s": status}) or {}
    return int(row.get("n") or 0)


def is_uuid(value: str | None) -> bool:
    if not value:
        return False
    try:
        UUID(str(value))
        return True
    except Exception:
        return False
