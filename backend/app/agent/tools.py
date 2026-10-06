"""Agent tools — thin wrappers over existing forensic/vuln services.

Does not modify extract, RAG index, or vuln business logic.
Mutating pipeline actions are NOT exposed as autonomous tools.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from sqlalchemy.orm import Session

log = logging.getLogger("agent.tools")

ToolFn = Callable[..., dict[str, Any]]


def tool_retrieve_evidence(db: Session, *, job_id: str, query: str, top_k: int = 8) -> dict[str, Any]:
    from app.retrieval.hybrid import hybrid_retrieve

    chunks = hybrid_retrieve(db, job_id, query, top_k=top_k) or []
    slim = [
        {
            "id": str(c.get("id") or ""),
            "file_path": c.get("file_path"),
            "score": c.get("rrf_score") or c.get("score"),
            "content": (c.get("content") or "")[:600],
        }
        for c in chunks[:top_k]
    ]
    return {"chunks": slim, "count": len(slim)}


def tool_answer_question(db: Session, *, job_id: str, query: str) -> dict[str, Any]:
    from app.retrieval.answer import compose_answer
    from app.retrieval.hybrid import hybrid_retrieve

    chunks = hybrid_retrieve(db, job_id, query, top_k=12) or []
    result = compose_answer(query, chunks, db=db, job_id=job_id)
    return {
        "answer": result.get("answer") or result.get("text") or "",
        "confidence": result.get("confidence"),
        "facts": result.get("facts") or {},
        "chunk_count": len(chunks),
    }


def tool_understand_query(db: Session, *, job_id: str, query: str) -> dict[str, Any]:
    from app.retrieval.query_understand import understand_query

    return understand_query(db, job_id, query) or {}


def tool_job_status(db: Session, *, job_id: str) -> dict[str, Any]:
    from app.db.sql_helpers import fetchone

    row = fetchone(
        db,
        """SELECT id, status, files_total, files_done, error, updated_at
           FROM jobs WHERE id = CAST(:id AS uuid)""",
        {"id": job_id},
    )
    if not row:
        return {"error": "job_not_found"}
    return {
        "job_id": str(row["id"]),
        "status": row["status"],
        "files_total": row.get("files_total"),
        "files_done": row.get("files_done"),
        "error": row.get("error"),
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
    }


def tool_intake_validate(db: Session, *, job_id: str) -> dict[str, Any]:
    from app.services.report_generator import _intake_ready

    ready, missing = _intake_ready(db, job_id)
    missing_list = list(missing or [])
    suggestions = (
        [f"Complete required intake field: {m}" for m in missing_list]
        if missing_list
        else ["Intake looks complete for report generation."]
    )
    return {
        "ready": ready,
        "missing": missing_list,
        "suggestions": suggestions,
        "message": "Intake validated" if ready else "Intake incomplete",
    }


def tool_scope_advise(db: Session, *, job_id: str) -> dict[str, Any]:
    from app.db.sql_helpers import fetchall, fetchone

    job = fetchone(db, "SELECT status FROM jobs WHERE id = CAST(:id AS uuid)", {"id": job_id})
    arts = fetchone(
        db,
        """SELECT COUNT(*)::int AS n,
                  COUNT(*) FILTER (WHERE parse_status = 'parsed')::int AS parsed
           FROM job_artifacts WHERE job_id = CAST(:id AS uuid)""",
        {"id": job_id},
    ) or {}
    top = fetchall(
        db,
        """SELECT COALESCE(category, 'unknown') AS category, COUNT(*)::int AS n
           FROM job_artifacts WHERE job_id = CAST(:id AS uuid)
           GROUP BY 1 ORDER BY n DESC LIMIT 15""",
        {"id": job_id},
    )
    advice = []
    if not job:
        return {"error": "job_not_found"}
    status = job["status"]
    total = int(arts.get("n") or 0)
    parsed = int(arts.get("parsed") or 0)
    if total == 0:
        advice.append("No artifacts registered yet — complete disk extract / artifact registration first.")
    elif parsed < total * 0.5:
        advice.append("Fewer than half of artifacts are parsed — drain parse queue before deep analysis.")
    else:
        advice.append("Artifact inventory looks usable for scoped investigation.")
    if top:
        advice.append("Top categories: " + ", ".join(f"{r['category']}({r['n']})" for r in top[:5]))
    return {
        "job_status": status,
        "artifacts_total": total,
        "artifacts_parsed": parsed,
        "categories": [{"category": r["category"], "count": r["n"]} for r in top],
        "advice": advice,
    }


def tool_report_qa(db: Session, *, job_id: str) -> dict[str, Any]:
    from app.db.sql_helpers import fetchall

    sections = fetchall(
        db,
        """SELECT section_key, status, LEFT(COALESCE(content, ''), 200) AS preview
           FROM report_sections WHERE job_id = CAST(:id AS uuid)
           ORDER BY section_key""",
        {"id": job_id},
    )
    if not sections:
        return {
            "status": "no_report",
            "message": "No report sections found. Generate a report first.",
            "sections": [],
        }
    empty = [s["section_key"] for s in sections if not (s.get("preview") or "").strip()]
    issues = []
    if empty:
        issues.append(f"Empty sections: {', '.join(empty[:10])}")
    issues.append(f"{len(sections)} section(s) present for QA review.")
    return {
        "status": "ok" if not empty else "needs_work",
        "section_count": len(sections),
        "empty_sections": empty,
        "issues": issues,
        "sections": [
            {"key": s["section_key"], "status": s.get("status"), "preview": s.get("preview")}
            for s in sections[:30]
        ],
    }


def tool_vuln_overview(db: Session, **_: Any) -> dict[str, Any]:
    """Optional cross-module read — only if vuln tables exist."""
    try:
        from app.config import get_settings
        from app.services.vuln_helpers import overview_kpis

        if not get_settings().vuln_module_enabled:
            return {"disabled": True}
        return overview_kpis(db)
    except Exception as exc:
        return {"error": str(exc), "hint": "Vulnerability module tables may be missing"}


TOOL_REGISTRY: dict[str, dict[str, Any]] = {
    "retrieve_evidence": {
        "description": "Hybrid retrieve evidence chunks for a job query",
        "fn": tool_retrieve_evidence,
        "params": ["job_id", "query"],
    },
    "answer_question": {
        "description": "Compose a grounded forensic answer from retrieved evidence",
        "fn": tool_answer_question,
        "params": ["job_id", "query"],
    },
    "understand_query": {
        "description": "Extract filters/intent from a natural language query",
        "fn": tool_understand_query,
        "params": ["job_id", "query"],
    },
    "job_status": {
        "description": "Get forensic job status summary",
        "fn": tool_job_status,
        "params": ["job_id"],
    },
    "intake_validate": {
        "description": "Validate intake readiness for reporting",
        "fn": tool_intake_validate,
        "params": ["job_id"],
    },
    "scope_advise": {
        "description": "Advise investigation scope from artifact inventory",
        "fn": tool_scope_advise,
        "params": ["job_id"],
    },
    "report_qa": {
        "description": "QA checklist over existing report sections",
        "fn": tool_report_qa,
        "params": ["job_id"],
    },
    "vuln_overview": {
        "description": "Read-only vulnerability module overview KPIs (if enabled)",
        "fn": tool_vuln_overview,
        "params": [],
    },
}


def list_tools() -> list[dict[str, str]]:
    return [{"name": k, "description": v["description"]} for k, v in TOOL_REGISTRY.items()]


def run_tool(db: Session, tool_name: str, **kwargs: Any) -> dict[str, Any]:
    meta = TOOL_REGISTRY.get(tool_name)
    if not meta:
        return {"error": f"unknown_tool:{tool_name}"}
    try:
        return meta["fn"](db, **kwargs)
    except TypeError:
        # Drop unexpected kwargs
        allowed = {p: kwargs[p] for p in meta.get("params", []) if p in kwargs}
        if "job_id" in kwargs and "job_id" not in allowed:
            allowed["job_id"] = kwargs["job_id"]
        if "query" in kwargs and "query" in meta.get("params", []):
            allowed["query"] = kwargs["query"]
        return meta["fn"](db, **allowed)
    except Exception as exc:
        log.exception("Tool %s failed", tool_name)
        return {"error": str(exc)}


def tools_prompt_block() -> str:
    lines = ["Available tools (respond with JSON only when choosing tools):"]
    for name, meta in TOOL_REGISTRY.items():
        lines.append(f"- {name}: {meta['description']} params={meta['params']}")
    lines.append(
        'To call tools, reply with JSON: {"tools":[{"name":"tool_name","args":{...}}, ...], "final":false}'
    )
    lines.append('When finished, reply with JSON: {"final":true, "answer":"..."}')
    return "\n".join(lines)
