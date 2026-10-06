"""Section-C evidence helpers driven by the supplied AXIOM forensic KB.

V8 removes the old manually maintained title/question/query dictionaries.  Evidence
questions, procedures, artifact families and RAG terms are generated from the integrated
58-report / 18-procedure knowledge base.  Compatibility functions remain because report
intake and mobile code import this module.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall
from app.services.axiom_forensic_kb import (
    OBJECTIVE_REPORT_MAP,
    canonical_artifact_family,
    controlled_procedure_text,
    evidence_questions_for_objective,
    objective_knowledge_plan,
    rag_terms_for_objective,
    sanitize_narrative_text,
    text_contains_prohibited_payload,
)

STATUS_OPENING: dict[str, str] = {
    "CONFIRMED": "The examination found clear information about",
    "PROBABLE": "The examination found strong indications about",
    "POSSIBLE": "The examination found some indications about",
    "NOT_FOUND": "The examination did not find primary evidence about",
    "INCONCLUSIVE": "The examination could not determine",
    "NOT_EXAMINED": "This topic was not reviewed because",
}

HEADER_EVIDENCE_QUESTIONS: dict[str, list[str]] = {
    title: evidence_questions_for_objective(title) for title in OBJECTIVE_REPORT_MAP
}

OBSERVATION_PLAIN_LANGUAGE_GUIDE = """
Use simple language for a reader with no forensic or IT background. State what the
controlled evidence proves, what it does not prove, and one short explanation beginning
with "This means". Do not expose internal paths, registry keys, parser names, SQL/query
names, raw XML/JSON, package manifests, or unrelated artifact totals.
""".strip()

PROHIBITED_OVERSTATEMENT = (
    "Do not claim intent, ownership, authorship, execution, exfiltration, remote access, "
    "deletion, compromise, file transfer or user action beyond what the primary evidence directly supports."
)


def evidence_text_is_raw_payload(text: str | None) -> bool:
    return text_contains_prohibited_payload(text or "")


def is_reference_detail_objective(title: str) -> bool:
    return bool(objective_knowledge_plan(str(title or "")).get("reports"))


def reference_observation_contract(title: str) -> dict[str, Any]:
    plan = objective_knowledge_plan(str(title or ""))
    required_fields: list[str] = []
    rules: list[str] = []
    corroboration = 1
    for report in plan.get("reports") or []:
        for field in [*(report.get("required_fields") or []), *(report.get("optional_fields") or [])]:
            s = str(field).strip()
            if s and s not in required_fields:
                required_fields.append(s)
        relationships = {str(m.get("relationship") or "").upper() for m in report.get("artifact_mappings") or []}
        if "CORROBORATING" in relationships:
            corroboration = max(corroboration, 2)
        rules.append(
            f"For {report.get('title')}, only PRIMARY artifact families may determine the {str((report.get('count_rule') or {}).get('unit') or 'reported event').lower().replace('_', ' ')} count."
        )
    rules.extend([
        "Supporting/corroborating artifacts may strengthen the finding but may not inflate the primary count.",
        "Apply report-specific semantic deduplication and parent/refined-result protection.",
        "Do not substitute a broad artifact total for the entity/action asked by the objective.",
    ])
    return {
        "required_fields": required_fields,
        "query_hints": rag_terms_for_objective(title),
        "observation_rules": rules,
        "corroboration_min": corroboration,
        "report_ids": list(plan.get("report_ids") or []),
        "primary_artifact_families": list(plan.get("direct_primary_artifact_families") or []),
        "all_mapped_primary_artifact_families": list(plan.get("primary_artifact_families") or []),
    }


def reference_observation_contract_text(title: str) -> str:
    contract = reference_observation_contract(title)
    if not contract.get("report_ids"):
        return ""
    lines = [
        "AXIOM KB EVIDENCE CONTRACT (internal; do not quote this heading in the report):",
        f"- Controlled reports: {', '.join(contract.get('report_ids') or [])}",
        f"- Primary artifact families: {', '.join(contract.get('primary_artifact_families') or []) or 'none'}",
        f"- Required/optional fields: {', '.join((contract.get('required_fields') or [])[:24]) or 'n/a'}",
        f"- Minimum corroboration: {contract.get('corroboration_min') or 1}",
    ]
    lines.extend(f"- {rule}" for rule in (contract.get("observation_rules") or [])[:8])
    return "\n".join(lines)


def reference_artifact_context_mode(title: str, label: str) -> str:
    family = canonical_artifact_family(label)
    if not family:
        return "drop"
    plan = objective_knowledge_plan(title)
    if family in set(plan.get("direct_primary_artifact_families") or []):
        return "direct_count"
    if family in (
        set(plan.get("primary_artifact_families") or [])
        | set(plan.get("supporting_artifact_families") or [])
        | set(plan.get("corroborating_artifact_families") or [])
    ):
        return "candidate_only"
    return "drop"


def reference_safe_counts(title: str, counts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in counts or []:
        label = str(row.get("label") or row.get("artifact_name") or row.get("artifact_id") or "")
        if reference_artifact_context_mode(title, label) == "direct_count":
            out.append(row)
    return out


def _relevance_tokens(title: str) -> set[str]:
    terms = rag_terms_for_objective(title)
    return {
        token for term in terms for token in re.split(r"[^a-z0-9]+", term.lower())
        if len(token) > 3 and token not in {"report", "evidence", "identify", "activity", "information"}
    }


def reference_chunk_relevant(title: str, hit: dict[str, Any]) -> bool:
    text = " ".join(str(hit.get(k) or "") for k in ("content", "file_path", "artifact_name", "category"))
    if evidence_text_is_raw_payload(text):
        return False
    tokens = _relevance_tokens(title)
    low = text.lower()
    return bool(tokens and any(t in low for t in tokens))


def reference_inconclusive_observation(title: str) -> str:
    plan = objective_knowledge_plan(title)
    names = [str(r.get("title") or "") for r in (plan.get("reports") or [])[:3] if r.get("title")]
    scope = ", ".join(names) or "the controlled report rules"
    return (
        f"The available evidence was reviewed using {scope}, but it did not provide enough primary, record-level detail to make a reliable finding for this question. "
        "Supporting or broad artifact totals were not used as a substitute. "
        "This means the report does not make a conclusion that the controlled evidence cannot support."
    )


def artifact_plain_explanation(label: str | None) -> str | None:
    family = canonical_artifact_family(label or "")
    return f"AXIOM {family} evidence" if family else None


def simplify_evidence_detail(text: str, *, max_len: int = 600) -> str:
    return sanitize_narrative_text(text, max_len=max_len)


def friendly_artifact_label(label: str | None) -> str:
    family = canonical_artifact_family(label or "")
    if family:
        return family
    return re.sub(r"[_-]+", " ", str(label or "")).strip()


def humanize_observation_text(text: str) -> str:
    body = sanitize_narrative_text(text, max_len=1400)
    if not body:
        return ""
    body = re.sub(r"\b(?:artifact record|count domain|query key|collector)\b", "evidence record", body, flags=re.I)
    body = re.sub(r"\s+", " ", body).strip()
    return body


def _intake_block(intake: dict[str, Any] | None) -> str:
    if not intake:
        return ""
    lines: list[str] = []
    for label, key in (
        ("Report type", "report_type"), ("Case type", "case_type"), ("Organization", "organization"),
        ("Relevant background", "background"), ("Incident summary", "incident_summary"),
    ):
        value = str(intake.get(key) or "").strip()
        if value:
            lines.append(f"- {label}: {value[:800]}")
    return "\n".join(lines)


def list_catalog_artifacts_for_objective(
    db: Session,
    *,
    axiom_objective_id: str | None,
    header_title: str = "",
    platform: str = "Windows",
    limit: int = 24,
) -> list[dict[str, str]]:
    """Return current catalog rows whose names map to KB families for this objective."""
    del axiom_objective_id
    plan = objective_knowledge_plan(header_title)
    allowed = set(plan.get("primary_artifact_families") or []) | set(plan.get("supporting_artifact_families") or []) | set(plan.get("corroborating_artifact_families") or [])
    if not allowed:
        return []
    rows = fetchall(
        db,
        """SELECT artifact_id, category, artifact_name, observation_focus
             FROM public.axiom_artifacts
             WHERE platform=:platform
             ORDER BY category, sort_order, artifact_name LIMIT 500""",
        {"platform": platform},
    )
    out: list[dict[str, str]] = []
    for row in rows:
        family = canonical_artifact_family(row.get("artifact_name"))
        if family not in allowed:
            continue
        out.append({
            "artifact_id": str(row.get("artifact_id") or ""),
            "category": str(row.get("category") or ""),
            "name": str(row.get("artifact_name") or ""),
            "artifact_family": str(family or ""),
            "relationship": "PRIMARY" if family in set(plan.get("primary_artifact_families") or []) else "SUPPORTING",
            "observation_focus": str(row.get("observation_focus") or ""),
        })
        if len(out) >= limit:
            break
    return out


def build_objective_evidence_prompt(
    *,
    header_title: str,
    objective_statement: str,
    procedure_text: str,
    report_type: str | None = None,
    axiom_objective_id: str | None = None,
    required_observation_fields: str | None = None,
    expected_output_fields: str | None = None,
    minimum_corroboration: str | None = None,
    limitations: str | None = None,
    intake: dict[str, Any] | None = None,
    linked_artifacts: list[dict[str, str]] | None = None,
) -> str:
    del axiom_objective_id
    plan = objective_knowledge_plan(header_title, objective_statement)
    questions = evidence_questions_for_objective(header_title, objective_statement)
    parts = [
        "FORENSIC EVIDENCE PROMPT — SUPPLIED AXIOM KNOWLEDGE BASE",
        f"Investigation area: {header_title}",
        f"Report type: {report_type or 'forensic'}",
        f"Controlled KB reports: {', '.join(plan.get('report_ids') or []) or 'none'}",
        f"Controlled procedures: {', '.join(plan.get('procedure_ids') or []) or 'none'}",
        "",
        "OBJECTIVE:",
        str(objective_statement or "").strip() or "—",
        "",
        "CONTROLLED PROCEDURE:",
        controlled_procedure_text(header_title, procedure_text),
        "",
        "PRIMARY ARTIFACT FAMILIES (only these may determine the reported count):",
        ", ".join(plan.get("primary_artifact_families") or []) or "none",
        "SUPPORTING/CORROBORATING FAMILIES (traceability only; never inflate the count):",
        ", ".join([*(plan.get("supporting_artifact_families") or []), *(plan.get("corroborating_artifact_families") or [])]) or "none",
        "",
        "EVIDENCE QUESTIONS:",
        *[f"{i + 1}. {q}" for i, q in enumerate(questions)],
    ]
    if linked_artifacts:
        parts.extend(["", "CURRENT CATALOG ROWS MAPPED TO THE KB:"])
        for art in linked_artifacts[:24]:
            parts.append(f"- {art.get('name')}: {art.get('artifact_family') or 'unmapped'} ({art.get('relationship') or 'supporting'})")
    for heading, value in (
        ("ADDITIONAL REQUIRED FIELDS", required_observation_fields),
        ("EXPECTED OUTPUT FIELDS", expected_output_fields),
        ("MINIMUM CORROBORATION", minimum_corroboration),
        ("SOURCE LIMITATIONS", limitations),
    ):
        if value:
            parts.extend(["", f"{heading}:", str(value).strip()])
    intake_txt = _intake_block(intake)
    if intake_txt:
        parts.extend(["", "CASE CONTEXT:", intake_txt])
    parts.extend(["", "PROHIBITED OVERSTATEMENT:", PROHIBITED_OVERSTATEMENT])
    return "\n".join(parts)


def build_rag_query(objective: dict[str, Any]) -> str:
    title = str(objective.get("title") or "").strip()
    statement = str(objective.get("objective") or objective.get("statement") or "").strip()
    terms = rag_terms_for_objective(title, statement)
    return " ".join(terms[:16] + ["current case evidence identity timestamp action recovery state"])


def build_rag_queries(objective: dict[str, Any]) -> list[str]:
    title = str(objective.get("title") or "").strip()
    statement = str(objective.get("objective") or objective.get("statement") or "").strip()
    terms = rag_terms_for_objective(title, statement)
    out = [build_rag_query(objective)]
    for term in terms[1:12]:
        out.append(f"{title} {term} current case forensic evidence")
    seen: set[str] = set()
    return [q for q in out if not (q.lower() in seen or seen.add(q.lower()))][:12]


def retrieve_objective_evidence(
    db: Session,
    job_id: str,
    objective: dict[str, Any],
    *,
    schema_name: str | None = None,
    top_k: int = 18,
    skip_vector: bool = False,
) -> list[dict[str, Any]]:
    from app.retrieval.hybrid import hybrid_retrieve

    title = str(objective.get("title") or "")
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for query in build_rag_queries(objective):
        try:
            hits = hybrid_retrieve(db, job_id, query, top_k=8, schema_name=schema_name, skip_vector=skip_vector)
        except Exception:
            if skip_vector:
                continue
            try:
                hits = hybrid_retrieve(db, job_id, query, top_k=8, schema_name=schema_name, skip_vector=True)
            except Exception:
                continue
        for hit in hits or []:
            content = str(hit.get("content") or "").strip()
            if not content or evidence_text_is_raw_payload(content) or not reference_chunk_relevant(title, hit):
                continue
            key = (str(hit.get("artifact_id") or ""), str(hit.get("file_path") or ""), content[:96])
            if key in seen:
                continue
            seen.add(key)
            safe = dict(hit)
            safe["content"] = simplify_evidence_detail(content, max_len=600)
            merged.append(safe)
            if len(merged) >= top_k:
                return merged
    return merged


def ensure_reports_objective_evidence_columns(db: Session) -> None:
    from sqlalchemy import text
    exists = db.execute(text("SELECT to_regclass('public.reports_objective') IS NOT NULL")).scalar()
    if not exists:
        return
    for column in (
        "evidence_prompt text", "required_observation_fields text", "expected_output_fields text", "axiom_objective_id text"
    ):
        db.execute(text(f"ALTER TABLE public.reports_objective ADD COLUMN IF NOT EXISTS {column}"))
    db.flush()


def sync_axiom_objective_prompt_questions(db: Session) -> int:
    """Mirror KB-backed prompts into legacy rows for UI compatibility only.

    Runtime report generation no longer reads forensic procedure/evidence semantics from
    ``public.axiom_objectives``. This mirror keeps older admin/intake screens readable
    while the supplied KB remains authoritative.
    """
    from sqlalchemy import text
    from app.services.report_template_service import _REPORT_TITLE_AXIOM_OBJECTIVE_ID
    from app.services.report_examination_narratives import format_client_objective

    updated = 0
    for header_title, oid in _REPORT_TITLE_AXIOM_OBJECTIVE_ID.items():
        prompt = build_objective_evidence_prompt(
            header_title=header_title,
            objective_statement=format_client_objective(header_title),
            procedure_text=controlled_procedure_text(header_title),
        )
        db.execute(
            text("UPDATE public.axiom_objectives SET prompt_question=:p, updated_at=NOW() WHERE objective_id=:oid AND objective_id NOT LIKE 'RPT-%'"),
            {"p": prompt[:12000], "oid": oid},
        )
        updated += 1
    db.flush()
    return updated


def format_procedure_for_report(procedure_text: str, title: str = "") -> str:
    if title:
        # Printed procedure is deliberately short/non-technical. The full controlled
        # KB procedure is still used by the evidence planner and never replaced by
        # this presentation sentence.
        from app.services.report_examination_narratives import format_client_procedure
        return format_client_procedure(title)
    text = sanitize_narrative_text(procedure_text, max_len=1800)
    return text or "—"


def status_label(status: str) -> str:
    return status if status in STATUS_OPENING else "NOT_FOUND"
