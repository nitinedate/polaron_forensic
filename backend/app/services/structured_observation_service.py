"""Structured Section-C observations backed by the supplied AXIOM forensic KB.

V8 replaces the former "sum every linked artifact count" implementation.  The new
engine partitions PRIMARY vs SUPPORTING evidence according to the attached report
knowledge base and never treats broad catalog totals as the answer to an unrelated
objective.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute, fetchall
from app.services.axiom_forensic_kb import canonical_artifact_family, knowledge_base_fingerprint, objective_knowledge_plan
from app.services.axiom_forensic_report_engine import (
    build_objective_evidence_brief,
    deterministic_observation_from_brief,
)

OBSERVATION_STATUSES = frozenset({
    "CONFIRMED", "PROBABLE", "POSSIBLE", "NOT_FOUND", "INCONCLUSIVE", "NOT_EXAMINED",
})


def _parse_required_fields(raw: Any) -> list[str]:
    if isinstance(raw, (list, tuple, set)):
        return [str(x).strip() for x in raw if str(x).strip()]
    text = str(raw or "").strip()
    if not text:
        return []
    import re
    return [x.strip() for x in re.split(r"[,;|\n]+", text) if x.strip()]


def _confidence_for_count(
    count: int,
    *,
    corroboration_count: int = 0,
    domains: list[str] | None = None,
) -> tuple[str, str]:
    if count <= 0:
        return "NOT_FOUND", "HIGH"
    doms = [str(d) for d in (domains or []) if d]
    if corroboration_count >= 2 and not (doms and all(d == "unverified_source_hit" for d in doms)):
        return "CONFIRMED", "HIGH"
    if doms and all(d == "unverified_source_hit" for d in doms):
        return "POSSIBLE", "LOW"
    return "PROBABLE", "MEDIUM"


def _artifacts_for_objective(
    db: Session,
    job_id: str,
    objective_id: str,
    enabled_keys: set[str],
    *,
    objective_title: str = "",
    platform: str | None = None,
) -> list[dict[str, Any]]:
    """Compatibility artifact lookup filtered by KB relationships for this title."""
    del objective_id
    plan = objective_knowledge_plan(objective_title)
    allowed = set(plan.get("primary_artifact_families") or []) | set(plan.get("supporting_artifact_families") or []) | set(plan.get("corroborating_artifact_families") or [])
    if not allowed:
        return []
    params: dict[str, Any] = {"jid": job_id}
    platform_sql = ""
    if platform:
        platform_sql = " AND aa.platform=:platform"
        params["platform"] = platform
    rows = fetchall(
        db,
        f"""SELECT aa.artifact_id, aa.artifact_name, aa.observation_focus,
                    COALESCE(r.occurrence_count, r.artifact_count, 0) AS artifact_count,
                    r.count_domain, r.answer, r.query_snapshot, r.confidence
             FROM public.axiom_artifacts aa
             JOIN job_axiom_artifact_results r ON r.artifact_id=aa.artifact_id AND r.job_id=:jid
             WHERE 1=1 {platform_sql}""",
        params,
    )
    out: list[dict[str, Any]] = []
    primary = set(plan.get("direct_primary_artifact_families") or [])
    supporting = (
        set(plan.get("primary_artifact_families") or [])
        | set(plan.get("supporting_artifact_families") or [])
        | set(plan.get("corroborating_artifact_families") or [])
    ) - primary
    for row in rows:
        aid = str(row.get("artifact_id") or "")
        if enabled_keys and aid not in enabled_keys:
            continue
        family = canonical_artifact_family(row.get("artifact_name"))
        if family not in allowed:
            continue
        out.append({
            "artifact_id": aid,
            "label": row.get("artifact_name") or aid,
            "artifact_family": family,
            "relationship": "PRIMARY" if family in primary else ("SUPPORTING" if family in supporting else "CONTEXTUAL"),
            "occurrence_count": int(row.get("artifact_count") or 0),
            "count_domain": row.get("count_domain") or "artifact_record",
            "answer": str(row.get("answer") or "").strip(),
            "observation_focus": str(row.get("observation_focus") or "").strip(),
            "query_snapshot": row.get("query_snapshot"),
            "confidence": row.get("confidence") or "HIGH",
        })
    return out


def _plain_observation_text(
    objective: dict[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    status: str,
    rag_snippets: list[str] | None = None,
    limitations: list[str] | None = None,
    intake: dict[str, Any] | None = None,
    facts: list[str] | None = None,
) -> str:
    """Legacy fallback without hand-written per-title conclusions."""
    from app.services.report_observation_style import format_client_observation
    merged_facts = [*(facts or []), *(limitations or [])]
    return format_client_observation(
        str(objective.get("title") or ""),
        status=status,
        artifacts=artifacts,
        rag_snippets=rag_snippets,
        facts=merged_facts,
        device_word="phone" if "mobile" in str((intake or {}).get("report_type") or "").lower() else "computer",
    )


def build_structured_observation(
    db: Session,
    job_id: str,
    objective: dict[str, Any],
    *,
    intake: dict[str, Any],
    enabled_artifact_keys: set[str],
    schema_name: str | None = None,
) -> dict[str, Any]:
    del enabled_artifact_keys, schema_name
    brief = build_objective_evidence_brief(db, job_id, objective, intake=intake)
    observation = deterministic_observation_from_brief(brief)
    status = str(brief.get("status") or "INCONCLUSIVE")
    positive_count = sum(int(c.get("count") or 0) for c in (brief.get("allowed_counts") or []) if isinstance(c.get("count"), int))
    corroboration = sum(1 for r in (brief.get("report_results") or []) if r.get("primary_artifact_present"))
    _, confidence = _confidence_for_count(
        positive_count,
        corroboration_count=corroboration,
        domains=[str(e.get("count_domain") or "") for r in (brief.get("report_results") or []) for e in (r.get("primary_evidence") or [])],
    )
    case_fact = brief.get("case_fact") or {}
    if case_fact.get("confidence") in {"A", "B", "C", "D", "E"}:
        confidence = str(case_fact.get("confidence"))
    structured = {
        "status": status,
        "confidence": confidence,
        "knowledge_base": "aetheris_axiom_kb_starter",
        "knowledge_base_fingerprint": knowledge_base_fingerprint(),
        "knowledge_plan": brief.get("knowledge_plan") or {},
        "report_results": brief.get("report_results") or [],
        "counts": [
            {
                "report_id": c.get("report_id"),
                "label": c.get("report_title"),
                "occurrence_count": c.get("count"),
                "count_domain": c.get("unit"),
            }
            for c in (brief.get("allowed_counts") or [])
        ],
        "facts": [
            *[fact for r in (brief.get("report_results") or []) for fact in (r.get("safe_facts") or [])],
            *list((case_fact.get("safe_evidence") or [])),
        ],
        "case_fact": case_fact,
        "limitations": brief.get("limitations") or [],
        "examiner_review_required": bool(brief.get("examiner_review_required")),
        "evidence_brief": brief,
    }
    return {
        "objective_id": str(objective.get("id") or objective.get("objective_id") or ""),
        "status": status,
        "confidence": confidence,
        "structured_json": structured,
        "observation_md": observation,
        "source_artifact_ids": [
            str(e.get("artifact_id"))
            for r in (brief.get("report_results") or [])
            for e in [*(r.get("primary_evidence") or []), *(r.get("supporting_evidence") or [])]
            if e.get("artifact_id")
        ],
        "query_snapshot": {"kb_report_ids": (brief.get("knowledge_plan") or {}).get("report_ids") or []},
    }


def persist_job_observation(db: Session, job_id: str, observation: dict[str, Any]) -> None:
    execute(
        db,
        """INSERT INTO job_objective_observations
           (job_id, objective_id, status, structured_json, observation_md, confidence,
            source_artifact_ids, query_snapshot, updated_at)
           VALUES (:jid, :oid, :status, CAST(:sj AS jsonb), :omd, :conf,
                   :aids, CAST(:qs AS jsonb), NOW())
           ON CONFLICT (job_id, objective_id) DO UPDATE SET
             status=EXCLUDED.status, structured_json=EXCLUDED.structured_json,
             observation_md=EXCLUDED.observation_md, confidence=EXCLUDED.confidence,
             source_artifact_ids=EXCLUDED.source_artifact_ids,
             query_snapshot=EXCLUDED.query_snapshot, updated_at=NOW()""",
        {
            "jid": job_id,
            "oid": observation["objective_id"],
            "status": observation["status"],
            "sj": json.dumps(observation.get("structured_json") or {}, default=str),
            "omd": observation.get("observation_md"),
            "conf": observation.get("confidence"),
            "aids": observation.get("source_artifact_ids") or [],
            "qs": json.dumps(observation.get("query_snapshot") or {}, default=str),
        },
    )
    db.flush()


def build_all_structured_observations(
    db: Session,
    job_id: str,
    intake: dict[str, Any],
    objectives: list[dict[str, Any]],
    *,
    schema_name: str | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for objective in objectives:
        obs = build_structured_observation(
            db,
            job_id,
            objective,
            intake=intake,
            enabled_artifact_keys=set(),
            schema_name=schema_name,
        )
        persist_job_observation(db, job_id, obs)
        out.append(obs)
    return out
