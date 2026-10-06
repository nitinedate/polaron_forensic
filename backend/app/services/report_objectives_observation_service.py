"""Build Section C using the integrated AXIOM forensic knowledge base.

The user-supplied ``aetheris_axiom_kb_starter`` is authoritative for report
procedures, allowed artifact families, evidence relationships, count units,
deduplication rules, zero-result wording and report-agent guardrails.

The LLM is deliberately the *last* step.  It receives a sanitized evidence brief
after deterministic filtering/counting.  It cannot select the evidence set or
change a count.  If its wording fails validation, the deterministic observation
is used instead.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.services.axiom_forensic_kb import REPORT_AGENT_SYSTEM_RULES, sanitize_narrative_text
from app.services.axiom_forensic_report_engine import validate_observation_against_brief
from app.services.model_router import generate_text
from app.services.report_objective_evidence import (
    format_procedure_for_report,
    humanize_observation_text,
    retrieve_objective_evidence,
)
from app.services.report_observation_style import (
    client_safe_observation,
    observation_is_client_length,
    observation_leaks_technical,
)
from app.services.structured_observation_service import (
    build_structured_observation,
    persist_job_observation,
)


def build_intake_context(intake: dict[str, Any]) -> str:
    """Small client-safe intake block used only as report-writing context."""
    lines: list[str] = []
    for label, key in (
        ("Report type", "report_type"),
        ("Case type", "case_type"),
        ("Organization", "organization"),
        ("Case number", "case_number"),
        ("Background", "background"),
        ("Incident summary", "incident_summary"),
    ):
        value = sanitize_narrative_text(intake.get(key), max_len=700)
        if value:
            lines.append(f"{label}: {value}")
    return "\n".join(lines)


def _agent_safe_brief(brief: dict[str, Any]) -> dict[str, Any]:
    """Remove collector/provenance internals before the brief reaches an LLM."""
    plan = brief.get("knowledge_plan") or {}
    results: list[dict[str, Any]] = []
    for result in brief.get("report_results") or []:
        results.append(
            {
                "report_id": result.get("report_id"),
                "report_title": result.get("report_title"),
                "report_objective": result.get("report_objective"),
                "objective_role": result.get("objective_role"),
                "count_unit": result.get("count_unit"),
                "reported_count": result.get("reported_count"),
                "count_basis": result.get("count_basis"),
                "key_entities": result.get("key_entities") or {},
                "safe_facts": [
                    sanitize_narrative_text(x, max_len=280)
                    for x in (result.get("safe_facts") or [])
                    if sanitize_narrative_text(x, max_len=280)
                ][:6],
                "zero_result_rule": result.get("zero_result_rule") or {},
                "limitations": result.get("limitations") or [],
                "examiner_review_required": bool(result.get("examiner_review_required")),
            }
        )
    case_fact_present = bool(brief.get("case_fact"))
    return {
        "objective": brief.get("objective") or {},
        "status": brief.get("status"),
        "knowledge_plan": {
            "report_ids": plan.get("report_ids") or [],
            "direct_report_ids": plan.get("direct_report_ids") or [],
            "supporting_report_ids": plan.get("supporting_report_ids") or [],
            "procedure_ids": plan.get("procedure_ids") or [],
            "limitations": plan.get("limitations") or [],
            "knowledge_base_version": plan.get("knowledge_base_version"),
            "reference_exemplar_guidance": plan.get("reference_exemplar_guidance") or {},
            "document_report_model": plan.get("document_report_model") or {},
        },
        # When an objective-specific live detector exists, its record-level finding is
        # authoritative. Hiding generic KB report results prevents the writer from
        # mixing a live positive fact with a generic zero-result sentence (V10 could
        # produce contradictions such as "1 Recycle Bin item" + "no deleted files").
        "report_results": [] if case_fact_present else results,
        "allowed_counts": brief.get("allowed_counts") or [],
        "case_fact": {
            "status": (brief.get("case_fact") or {}).get("status"),
            "observation": sanitize_narrative_text((brief.get("case_fact") or {}).get("observation"), max_len=1050),
            "simple_explanation": sanitize_narrative_text((brief.get("case_fact") or {}).get("simple_explanation"), max_len=420),
            "key_entities": (brief.get("case_fact") or {}).get("key_entities") or {},
            "safe_evidence": [
                sanitize_narrative_text(x, max_len=300)
                for x in ((brief.get("case_fact") or {}).get("safe_evidence") or [])
                if sanitize_narrative_text(x, max_len=300)
            ][:10],
            "confidence": (brief.get("case_fact") or {}).get("confidence"),
        } if brief.get("case_fact") else None,
        "limitations": brief.get("limitations") or [],
        "examiner_review_required": bool(brief.get("examiner_review_required")),
        "intake_context": brief.get("intake_context") or {},
    }


def _indexed_evidence_for_agent(chunks: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Sanitized RAG snippets are contextual facts, never an independent count source."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for chunk in chunks or []:
        content = sanitize_narrative_text(chunk.get("content"), max_len=520)
        if not content:
            continue
        key = content.lower()[:180]
        if key in seen:
            continue
        seen.add(key)
        item = {"content": content}
        name = sanitize_narrative_text(chunk.get("artifact_name") or chunk.get("category"), max_len=100)
        if name:
            item["source_type"] = name
        out.append(item)
        if len(out) >= 10:
            break
    return out


def _observation_prompt(
    objective: dict[str, Any],
    *,
    brief: dict[str, Any],
    indexed_evidence: list[dict[str, str]],
    deterministic_draft: str,
    intake_context: str,
) -> str:
    """The writer sees only post-rule-engine facts and sanitized supporting snippets."""
    title = str(objective.get("title") or "Examination objective")
    safe = _agent_safe_brief(brief)
    return f"""Write ONLY the final Observation paragraph for Section C of a forensic report.

INVESTIGATION AREA: {title}

DETERMINISTIC AXIOM-KB EVIDENCE BRIEF:
{json.dumps(safe, ensure_ascii=False, default=str, indent=2)[:12000]}

SANITIZED INDEXED EVIDENCE (supporting context only):
{json.dumps(indexed_evidence, ensure_ascii=False, default=str, indent=2)[:7000]}

CASE CONTEXT:
{intake_context or 'No additional case context.'}

SAFE FALLBACK DRAFT:
{deterministic_draft}

WRITING REQUIREMENTS:
- Use the supplied knowledge-base result and only the facts shown above.
- The reference_exemplar_guidance was learned from the supplied examiner reports. Use it only for evidence questions, decision boundaries and writing structure; never copy an example case value or conclusion.
- document_report_model was trained from the physical reports in document_report_model. Run its extraction_queries against the current case's extracted content, then write the observation with its writing_moves. Never copy a fact from those physical reports.
- Follow the evidence progression: candidate records -> classify/exclude noise -> deduplicate/correlate -> objective-specific finding -> limitation -> simple meaning.
- Keep access/presence/connection separate from transfer/use/execution/unauthorized intent unless direct evidence supports the stronger claim.
- When case_fact is present it is the objective-specific result from the full current-case records used by Sections A/B/D. Treat it as authoritative over generic catalog totals or RAG prose.
- Do not contradict a case_fact or replace a named service/account/device/file with a vague phrase such as "relevant traces were found".
- Only values in allowed_counts may be written as forensic event/item/device/file/message/account counts.
- Supporting indexed evidence may supply an exact name, date, service, account, device, file or action only when it is explicitly present in the snippet; it may not create or change a count.
- A SUPPORTING report result is context. Do not turn its generic total into the answer to this objective.
- If the status is INCONCLUSIVE or NOT_EXAMINED, say what could and could not be established instead of guessing.
- Do not use words such as suspicious, unauthorized, exfiltration, transferred, executed, deleted or compromised unless the direct evidence in the brief supports that exact statement.
- Never include raw XML/JSON, package/BlockMap content, internal paths, registry dumps, parser/query names, catalog IDs, or evidence-source labels such as Laptop [1].
- Write 2 to 5 short factual sentences in very simple language, followed by one short sentence beginning with 'This means'.
- Keep the finding complete. Page packing is the Formation Agent's job; do not omit a supported fact to save space and do not invent filler to pad a page.
- No markdown, heading, bullets or technical implementation terminology.
"""


def _finalize_observation(
    text: str,
    *,
    title: str,
    device_label: str,
    fallback: str,
    brief: dict[str, Any],
) -> str:
    candidate = humanize_observation_text(text)
    valid, _ = validate_observation_against_brief(candidate, brief)
    if (
        not valid
        or not observation_is_client_length(candidate)
        or observation_leaks_technical(candidate)
    ):
        candidate = humanize_observation_text(fallback)
    return client_safe_observation(
        candidate,
        title=title,
        device_word=device_label or "computer",
    )


def fill_objective_observations(
    db: Session,
    job_id: str,
    intake: dict[str, Any],
    objectives: list[dict[str, Any]],
    *,
    schema_name: str,
    primary_model: str,
    device_label: str,
    polish_with_llm: bool = True,
    progress_cb=None,
) -> str:
    """Generate Section C from the supplied AXIOM KB and current-case evidence.

    The previous V7 path maintained independent per-title evidence dictionaries,
    AXIOM prompt templates, generic artifact totals and a second LLM planning layer.
    Those sources of truth are intentionally not used here.
    """
    from app.services.evidence_contract_planner import attach_evidence_contracts_to_objectives
    from app.services.mobile_report_service import is_mobile_intake
    from app.services.report_examination_narratives import format_client_objective
    from app.services.report_generator_agent import (
        display_objective_title,
        ensure_all_objectives_in_report,
        repair_section_c_objectives,
        sanitize_section_c_markdown,
    )

    def _progress(phase: str, sub_i: int, sub_n: int, title: str = "") -> None:
        if progress_cb:
            try:
                progress_cb(phase, sub_i, sub_n, title)
            except Exception:
                pass

    mobile = is_mobile_intake(intake)
    if not objectives:
        heading = "## OBJECTIVE, OBSERVATION with FINDINGS" if mobile else "## C. OBJECTIVE, PROCEDURE & OBSERVATION"
        return f"{heading}\n\n**No examination objectives selected in Case intake.**\n"

    # Hydrate saved RPT IDs to client-facing titles/objectives, then attach a deterministic
    # KB contract. No LLM is allowed to create or refine the contract.
    objectives = repair_section_c_objectives(objectives, db)
    n_obj = max(1, len(objectives))
    _progress("planning", 0, n_obj, "AXIOM knowledge-base mapping")
    objectives = attach_evidence_contracts_to_objectives(
        db,
        job_id,
        intake,
        objectives,
        domain="mobile" if mobile else "disk",
        model=None,
        use_llm=False,
        progress_cb=lambda i, n, title="": _progress("planning", i, n, display_objective_title(title, db)),
    )

    heading = "## OBJECTIVE, OBSERVATION with FINDINGS" if mobile else "## C. OBJECTIVE, PROCEDURE & OBSERVATION"
    parts: list[str] = [heading, ""]
    intake_context = build_intake_context(intake)

    for idx, objective in enumerate(objectives, 1):
        title = display_objective_title(objective, db)
        _progress("objective", idx, n_obj, title)

        # Build + persist the deterministic observation first. This is the authoritative
        # evidence result even when the writing model is later used for readability.
        built = build_structured_observation(
            db,
            job_id,
            objective,
            intake=intake,
            enabled_artifact_keys=set(),
            schema_name=schema_name,
        )
        brief = ((built.get("structured_json") or {}).get("evidence_brief") or {})
        deterministic = str(built.get("observation_md") or "").strip()
        observation = deterministic

        indexed_chunks: list[dict[str, Any]] = []
        if polish_with_llm and primary_model:
            try:
                indexed_chunks = retrieve_objective_evidence(
                    db,
                    job_id,
                    objective,
                    schema_name=schema_name,
                    top_k=12,
                    skip_vector=True,
                )
            except Exception:
                indexed_chunks = []
            indexed_evidence = _indexed_evidence_for_agent(indexed_chunks)
            try:
                polished = generate_text(
                    _observation_prompt(
                        objective,
                        brief=brief,
                        indexed_evidence=indexed_evidence,
                        deterministic_draft=deterministic,
                        intake_context=intake_context,
                    ),
                    model=primary_model,
                    system=REPORT_AGENT_SYSTEM_RULES,
                    temperature=0.08,
                    timeout=45,
                ).strip()
            except Exception:
                polished = ""
            observation = _finalize_observation(
                polished,
                title=title,
                device_label=device_label,
                fallback=deterministic,
                brief=brief,
            )
        else:
            observation = _finalize_observation(
                deterministic,
                title=title,
                device_label=device_label,
                fallback=deterministic,
                brief=brief,
            )

        # Persist the exact text that will appear in Section C so Analysis Summary and
        # audit/review views do not retain an older generic observation.
        built["observation_md"] = observation
        structured_json = built.get("structured_json") or {}
        structured_json["indexed_evidence_used_for_writing"] = _indexed_evidence_for_agent(indexed_chunks)
        built["structured_json"] = structured_json
        persist_job_observation(db, job_id, built)

        # The attached knowledge base is authoritative for the printed Objective.
        # Saved intake/database wording is retained only as selection metadata and may
        # not override the controlled report definition at generation time.
        objective_text = format_client_objective(title) or "To examine this area using the controlled forensic procedure."
        procedure_text = format_procedure_for_report(
            str(objective.get("procedure_text") or objective.get("procedure") or ""),
            title=title,
        )

        parts.extend(
            [
                f"### {idx}. {title}",
                "",
                "**Objective**",
                "",
                objective_text,
                "",
                "**Procedure**",
                "",
                procedure_text,
                "",
                "**Observation**",
                "",
                observation,
                "",
            ]
        )

    markdown = "\n".join(parts)
    if not mobile:
        markdown = sanitize_section_c_markdown(markdown)
        markdown = ensure_all_objectives_in_report(markdown, objectives)
    return markdown


def assemble_section_c_from_saved_observations(
    db: Session,
    job_id: str,
    intake: dict[str, Any],
    *,
    require_all: bool = True,
) -> str:
    """Rebuild C. OBJECTIVE, PROCEDURE & OBSERVATION from persisted job observations.

    Used when report generation is interrupted after observations are saved but
    before the combined Section C page is written.
    """
    from app.db.sql_helpers import fetchall
    from app.services.mobile_report_service import is_mobile_intake
    from app.services.report_examination_narratives import format_client_objective
    from app.services.report_generator_agent import (
        display_objective_title,
        ensure_all_objectives_in_report,
        sanitize_section_c_markdown,
    )
    from app.services.report_objective_evidence import format_procedure_for_report
    from app.services.report_template_service import resolve_report_objectives

    objectives = resolve_report_objectives(db, job_id, intake)
    if not objectives:
        return ""
    rows = fetchall(
        db,
        """SELECT objective_id, observation_md, status FROM job_objective_observations
           WHERE job_id=:jid""",
        {"jid": job_id},
    ) or []
    obs_by_id = {str(r.get("objective_id") or ""): r for r in rows}
    covered = 0
    for obj in objectives:
        oid = str(obj.get("id") or obj.get("objective_id") or "")
        if str((obs_by_id.get(oid) or {}).get("observation_md") or "").strip():
            covered += 1
    if covered == 0:
        return ""
    if require_all and covered < len(objectives):
        return ""

    mobile = is_mobile_intake(intake)
    heading = "## OBJECTIVE, OBSERVATION with FINDINGS" if mobile else "## C. OBJECTIVE, PROCEDURE & OBSERVATION"
    parts: list[str] = [heading, ""]
    for idx, objective in enumerate(objectives, 1):
        oid = str(objective.get("id") or objective.get("objective_id") or "")
        title = display_objective_title(objective, db)
        observation = str((obs_by_id.get(oid) or {}).get("observation_md") or "").strip()
        if not observation:
            observation = f"See the examination record for {title}."
        objective_text = format_client_objective(title) or "To examine this area using the controlled forensic procedure."
        procedure_text = format_procedure_for_report(
            str(objective.get("procedure_text") or objective.get("procedure") or ""),
            title=title,
        )
        parts.extend(
            [
                f"### {idx}. {title}",
                "",
                "**Objective**",
                "",
                objective_text,
                "",
                "**Procedure**",
                "",
                procedure_text,
                "",
                "**Observation**",
                "",
                observation,
                "",
            ]
        )
    markdown = "\n".join(parts)
    if not mobile:
        markdown = sanitize_section_c_markdown(markdown)
        markdown = ensure_all_objectives_in_report(markdown, objectives)
    return markdown
