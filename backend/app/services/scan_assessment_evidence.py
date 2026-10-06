"""Durable vulnerability scan evidence and report-verification helpers.

A scan with zero findings is only a clean scan when there is durable evidence
that the intended targets were actually assessed.  This module deliberately
keeps that decision separate from the number of findings.
"""

from __future__ import annotations

import json
from typing import Any

from app.db.sql_helpers import fetchall, fetchone


def _json_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return dict(parsed) if isinstance(parsed, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
    return {}


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def infer_central_scan_result(db, job: dict[str, Any]) -> dict[str, Any] | None:
    """Build result evidence for a completed central/orchestrated job.

    Edge-agent jobs stay strict (laptop must post assessment_complete).
    Central jobs write findings and engine-run rows; those are enough to mark
    the requested targets assessed when the job completed.
    """
    orchestration = _json_obj(job.get("orchestration_json"))
    if orchestration.get("edge_agent"):
        return None
    if str(job.get("status") or "").lower() != "completed":
        return None

    job_id = str(job.get("id") or "")
    if not job_id:
        return None

    targets = fetchall(
        db,
        """SELECT target, excluded FROM vuln_scan_targets
           WHERE scan_job_id = CAST(:jid AS uuid)""",
        {"jid": job_id},
    )
    active = [str(t.get("target") or "").strip() for t in targets if not t.get("excluded") and str(t.get("target") or "").strip()]
    if not active:
        return None

    engines = fetchall(
        db,
        """SELECT engine, status FROM vuln_scan_engine_runs
           WHERE scan_job_id = CAST(:jid AS uuid)""",
        {"jid": job_id},
    )
    finished = [
        r
        for r in engines
        if str(r.get("status") or "").lower() in {"completed", "skipped", "failed"}
    ]
    real_done = [
        r
        for r in engines
        if str(r.get("status") or "").lower() == "completed"
    ]
    if not finished and not real_done:
        # Still allow findings-only evidence
        pass

    finding_hosts = fetchall(
        db,
        """
        SELECT DISTINCT COALESCE(
                 NULLIF(trim(a.primary_ip), ''),
                 NULLIF(trim(a.hostname), ''),
                 NULLIF(trim(f.risk_factors_json->>'host'), ''),
                 NULLIF(trim(f.risk_factors_json->>'hostname'), '')
               ) AS host
          FROM vuln_findings f
          LEFT JOIN vuln_assets a ON a.id = f.asset_id
         WHERE f.scan_job_id = CAST(:jid AS uuid)
        """,
        {"jid": job_id},
    )
    found = {str(r.get("host") or "").strip() for r in finding_hosts if str(r.get("host") or "").strip()}

    if real_done:
        assessed = list(active)
    else:
        assessed = [h for h in active if h in found]
    if not assessed:
        return None

    return {
        "hosts_attempted": len(active),
        "hosts_assessed": len(assessed),
        "plugin_error_count": 0,
        "result_json": {
            "assessment_complete": True,
            "assessed_hosts": assessed,
            "skipped_hosts": [],
            "inferred": True,
            "source": "central_orchestrator",
        },
    }


def load_case_scan_assessment(db, case_id: str) -> dict[str, Any]:
    """Return the verification state of the latest scan for a case.

    This is intentionally strict: ``completed`` alone does not imply a verified
    clean assessment.  A durable ``vuln_scan_results`` row with target/host
    coverage is required.
    """
    job = fetchone(
        db,
        """SELECT j.*,
                  (SELECT COUNT(*)::int FROM vuln_scan_targets t
                   WHERE t.scan_job_id = j.id) AS target_count,
                  (SELECT COUNT(*)::int FROM vuln_scan_targets t
                   WHERE t.scan_job_id = j.id AND NOT t.excluded) AS active_target_count
           FROM vuln_scan_jobs j
           WHERE j.case_id = CAST(:cid AS uuid)
           ORDER BY
             CASE WHEN j.status = 'running' THEN 0 ELSE 1 END,
             j.created_at DESC
           LIMIT 1""",
        {"cid": case_id},
    )
    if not job:
        return {
            "state": "not_performed",
            "verified": False,
            "clean_eligible": False,
            "message": "No vulnerability scan has been performed for this case.",
            "job_id": None,
            "target_count": 0,
            "hosts_attempted": 0,
            "hosts_assessed": 0,
        }

    job_id = str(job["id"])
    status = str(job.get("status") or "").strip().lower()
    target_count = _int(job.get("target_count"))
    active_target_count = _int(job.get("active_target_count"))
    orchestration = _json_obj(job.get("orchestration_json"))

    result = fetchone(
        db,
        """SELECT * FROM vuln_scan_results
           WHERE scan_job_id = CAST(:jid AS uuid)
           ORDER BY created_at DESC
           LIMIT 1""",
        {"jid": job_id},
    )
    if not result:
        result = infer_central_scan_result(db, job)
    result_json = _json_obj(result.get("result_json")) if result else {}
    hosts_attempted = _int(result.get("hosts_attempted")) if result else 0
    hosts_assessed = _int(result.get("hosts_assessed")) if result else 0
    plugin_error_details = result_json.get("plugin_error_details") or []
    if not isinstance(plugin_error_details, list):
        plugin_error_details = []
    plugin_error_details = [dict(x) for x in plugin_error_details if isinstance(x, dict)][:100]
    plugin_errors = max(_int(result.get("plugin_error_count")) if result else 0, len(plugin_error_details))
    report_id = result_json.get("report_id")
    task_id = result_json.get("task_id") or job.get("external_scan_id")
    assessed_hosts = result_json.get("assessed_hosts") or []
    if not isinstance(assessed_hosts, list):
        assessed_hosts = []
    skipped_hosts = result_json.get("skipped_hosts") or []
    if not isinstance(skipped_hosts, list):
        skipped_hosts = []
    skipped_hosts = [x for x in skipped_hosts if isinstance(x, (dict, str))]
    skipped_count = len(skipped_hosts)

    base = {
        "job_id": job_id,
        "job_status": status,
        "target_count": target_count,
        "active_target_count": active_target_count,
        "hosts_attempted": hosts_attempted,
        "hosts_assessed": hosts_assessed,
        "plugin_error_count": plugin_errors,
        "plugin_error_details": plugin_error_details,
        "task_id": str(task_id) if task_id else None,
        "report_id": str(report_id) if report_id else None,
        "assessed_hosts": [str(x) for x in assessed_hosts if str(x).strip()],
        "skipped_hosts": skipped_hosts,
        "skipped_count": skipped_count,
        "scan_start": result_json.get("scan_start"),
        "scan_end": result_json.get("scan_end"),
        "assessment_verdict": result_json.get("assessment_verdict"),
        "alive_test": result_json.get("alive_test"),
        "error": job.get("error"),
        "orchestration": orchestration,
    }

    if status in {"failed", "cancelled", "canceled"}:
        reason = str(job.get("error") or orchestration.get("partial_reason") or "scan did not complete")
        return {
            **base,
            "state": "incomplete",
            "verified": False,
            "clean_eligible": False,
            "message": f"Assessment incomplete - {reason}",
        }

    if status not in {"completed"}:
        label = status or "pending"
        return {
            **base,
            "state": "in_progress",
            "verified": False,
            "clean_eligible": False,
            "message": f"Vulnerability assessment is {label}; results are not final.",
        }

    if not result:
        return {
            **base,
            "state": "unverified",
            "verified": False,
            "clean_eligible": False,
            "message": (
                "Assessment unverified - the latest scan is marked completed but has no durable "
                "scan-result evidence."
            ),
        }

    explicit_complete = result_json.get("assessment_complete")
    is_edge_agent = bool(orchestration.get("edge_agent") or result_json.get("edge_agent"))
    if explicit_complete is False:
        reason = result_json.get("assessment_verdict") or "scanner reported incomplete host assessment"
        return {
            **base,
            "state": "incomplete",
            "verified": False,
            "clean_eligible": False,
            "message": f"Assessment incomplete - {reason}.",
        }
    if is_edge_agent and explicit_complete is not True:
        return {
            **base,
            "state": "unverified",
            "verified": False,
            "clean_eligible": False,
            "message": (
                "Assessment unverified - edge-agent result evidence does not explicitly confirm "
                "complete target assessment."
            ),
        }

    if target_count <= 0:
        return {
            **base,
            "state": "unverified",
            "verified": False,
            "clean_eligible": False,
            "message": "Assessment unverified - the scan has no target records.",
        }

    # Coverage is assessed + explicitly-accounted-for skips.  An unreachable
    # host is not an assessed host, but it must not erase the original scope by
    # being marked excluded during ingest.  Conversely, any skip prevents a
    # full-scope clean conclusion.
    accounted = min(target_count, hosts_assessed + skipped_count)
    if accounted < target_count:
        return {
            **base,
            "state": "incomplete",
            "verified": False,
            "clean_eligible": False,
            "message": (
                f"Assessment incomplete - scanner accounted for {accounted} of {target_count} "
                f"target(s) ({hosts_assessed} assessed, {skipped_count} skipped)."
            ),
        }

    if skipped_count > 0:
        return {
            **base,
            "state": "verified_with_skips",
            "verified": True,
            "clean_eligible": False,
            "message": (
                f"Assessment completed with scope exceptions - {hosts_assessed} of {target_count} "
                f"target(s) were assessed and {skipped_count} target(s) were unreachable/skipped. "
                "Findings for assessed hosts are valid, but the full requested scope is not clean-eligible."
            ),
        }

    if plugin_errors > 0:
        return {
            **base,
            "state": "verified_with_warnings",
            "verified": True,
            "clean_eligible": False,
            "message": (
                f"Assessment completed with warnings - {hosts_assessed} of {target_count} target(s) "
                f"were assessed, but Greenbone reported {plugin_errors} plugin/scanner error(s). "
                "Findings remain valid, but a zero-finding result must not be treated as a clean conclusion."
            ),
        }

    return {
        **base,
        "state": "verified",
        "verified": True,
        "clean_eligible": True,
        "message": (
            f"Assessment evidence verified - {hosts_assessed} of {target_count} target(s) "
            "were assessed."
        ),
    }


def merge_scan_assessments(items: list[dict[str, Any]]) -> dict[str, Any]:
    if not items:
        return {
            "state": "unverified",
            "verified": False,
            "clean_eligible": False,
            "message": "Assessment status is unavailable.",
            "target_count": 0,
            "hosts_attempted": 0,
            "hosts_assessed": 0,
        }
    target_count = sum(_int(x.get("target_count")) for x in items)
    attempted = sum(_int(x.get("hosts_attempted")) for x in items)
    assessed = sum(_int(x.get("hosts_assessed")) for x in items)
    bad = [x for x in items if not x.get("verified")]
    if bad:
        return {
            "state": "incomplete",
            "verified": False,
            "clean_eligible": False,
            "message": (
                f"Merged assessment contains {len(bad)} unverified/incomplete case(s); "
                "a clean conclusion is not permitted."
            ),
            "target_count": target_count,
            "hosts_attempted": attempted,
            "hosts_assessed": assessed,
            "cases": items,
        }
    warning_cases = [x for x in items if not x.get("clean_eligible")]
    if warning_cases:
        warning_count = sum(_int(x.get("plugin_error_count")) for x in warning_cases)
        warning_details: list[dict[str, Any]] = []
        for item in warning_cases:
            for detail in item.get("plugin_error_details") or []:
                if isinstance(detail, dict):
                    warning_details.append(dict(detail))
        return {
            "state": "verified_with_warnings",
            "verified": True,
            "clean_eligible": False,
            "message": (
                f"Assessment coverage verified across all cases - {assessed} host(s) assessed, "
                f"with {warning_count} plugin/scanner warning(s). A clean zero-finding conclusion is not permitted."
            ),
            "target_count": target_count,
            "hosts_attempted": attempted,
            "hosts_assessed": assessed,
            "plugin_error_count": warning_count,
            "plugin_error_details": warning_details[:100],
            "cases": items,
        }
    return {
        "state": "verified",
        "verified": True,
        "clean_eligible": True,
        "message": f"Assessment evidence verified across all cases - {assessed} host(s) assessed.",
        "target_count": target_count,
        "hosts_attempted": attempted,
        "hosts_assessed": assessed,
        "cases": items,
    }
