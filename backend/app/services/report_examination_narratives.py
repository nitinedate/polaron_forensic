"""Compatibility facade for examination narratives.

V8 removes the manually maintained objective/procedure playbook that duplicated AXIOM
knowledge in this file.  All narrative, search and evidence-source guidance now comes
from the integrated user-supplied ``aetheris_axiom_kb_starter`` definitions.
"""
from __future__ import annotations

from typing import Any

from app.services.axiom_forensic_kb import (
    OBJECTIVE_REPORT_MAP,
    controlled_objective_text,
    controlled_procedure_text,
    objective_knowledge_plan,
    rag_terms_for_objective,
)


def _narrative_for(title: str) -> dict[str, Any]:
    plan = objective_knowledge_plan(title)
    procedures = plan.get("procedures") or []
    steps: list[str] = []
    for procedure in procedures:
        for step in procedure.get("steps") or []:
            text = str(step or "").strip()
            if text and text not in steps:
                steps.append(text)
    evidence_sources: list[str] = []
    for family in [
        *(plan.get("direct_primary_artifact_families") or []),
        *(plan.get("supporting_artifact_families") or []),
        *(plan.get("corroborating_artifact_families") or []),
    ]:
        if family and family not in evidence_sources:
            evidence_sources.append(str(family))
    return {
        "narrative": controlled_procedure_text(title, max_steps=0),
        "check_steps": steps[:8],
        "client_steps": steps[:5],
        "rag_queries": rag_terms_for_objective(title),
        "evidence_sources": evidence_sources[:16],
        "kb_report_ids": plan.get("report_ids") or [],
        "kb_procedure_ids": plan.get("procedure_ids") or [],
        "limitations": plan.get("limitations") or [],
    }


EXAMINATION_NARRATIVES: dict[str, dict[str, Any]] = {
    title: _narrative_for(title) for title in OBJECTIVE_REPORT_MAP
}
CLIENT_PROCEDURE_STEPS: dict[str, list[str]] = {
    title: list(data.get("client_steps") or []) for title, data in EXAMINATION_NARRATIVES.items()
}
CLIENT_OBJECTIVE_STATEMENTS: dict[str, str] = {
    title: controlled_objective_text(title) for title in OBJECTIVE_REPORT_MAP
}


def get_examination_narrative(title: str) -> dict[str, Any] | None:
    display = str(title or "").strip()
    if not display:
        return None
    if display in EXAMINATION_NARRATIVES:
        return dict(EXAMINATION_NARRATIVES[display])
    plan = objective_knowledge_plan(display)
    return _narrative_for(display) if plan.get("reports") else None


def format_examination_block(title: str) -> str:
    data = get_examination_narrative(title)
    if not data:
        return ""
    lines = [
        "Controlled examination approach:",
        str(data.get("narrative") or "").strip(),
        "",
        "Controlled procedure steps:",
    ]
    lines.extend(f"• {step}" for step in (data.get("check_steps") or [])[:8])
    sources = data.get("evidence_sources") or []
    if sources:
        lines.extend(["", "Mapped AXIOM artifact families: " + "; ".join(str(x) for x in sources) + "."])
    return "\n".join(lines).strip()


def _join_client_terms(values: list[str]) -> str:
    vals = [str(v).strip() for v in values if str(v).strip()]
    if not vals:
        return "relevant forensic records"
    if len(vals) == 1:
        return vals[0]
    if len(vals) == 2:
        return f"{vals[0]} and {vals[1]}"
    return ", ".join(vals[:-1]) + f", and {vals[-1]}"


def _client_family_name(value: str) -> str:
    """Plain display wording only; evidence semantics remain in the supplied KB."""
    text = str(value or "").strip()
    replacements = {
        "Browser History": "browser history",
        "Browser Downloads": "download history",
        "Cloud Files": "cloud-related file records",
        "Cloud Activity": "cloud activity",
        "USB Devices": "USB/device records",
        "LNK Files": "shortcut-file records",
        "Jump Lists": "recent-file/program records",
        "Recycle Bin": "Recycle Bin records",
        "Deleted Files": "deleted-file records",
        "Email Communications": "email/account records",
        "User Accounts": "user-account records",
        "Documents": "document records",
        "Keyword Search": "document text",
        "Instant Messaging": "messaging records",
        "Chat Messages": "chat-message records",
        "Encrypted Files": "encrypted/protected file records",
    }
    return replacements.get(text, text[:1].lower() + text[1:] if text else text)


def format_client_objective(title: str) -> str:
    """Short non-technical Objective for the printed report.

    The five supplied examiner reports are used as a wording/method exemplar layer.
    They never provide current-case facts, counts or conclusions.
    """
    display = str(title or "").strip()
    if not display:
        return ""
    try:
        from app.services.report_reference_kb import reference_client_objective, reference_pattern_for_objective

        pattern = reference_pattern_for_objective(display)
        learned = reference_client_objective(display)
        # Preserve the established printed wording for legacy Aetheris objective names.
        # Reference-corpus wording is used directly when the intake title itself uses the
        # supplied examiner-report canonical title; aliases still benefit from the
        # exemplar evidence rules and procedure guidance.
        if learned and pattern and str(pattern.get("canonical_title") or "").strip().lower() == display.lower():
            return learned
    except Exception:
        pass
    return f"To examine the device for evidence related to {display.lower()}."


def format_client_procedure(title: str) -> str:
    """Short client-facing procedure derived from KB plus supplied-report exemplars."""
    display = str(title or "").strip()
    try:
        from app.services.report_reference_kb import reference_client_procedure

        learned = reference_client_procedure(display)
        if learned:
            return learned
    except Exception:
        pass
    plan = objective_knowledge_plan(display)
    families: list[str] = []
    for family in [
        *(plan.get("direct_primary_artifact_families") or []),
        *(plan.get("primary_artifact_families") or []),
        *(plan.get("supporting_artifact_families") or []),
    ]:
        name = _client_family_name(str(family))
        if name and name not in families:
            families.append(name)
        if len(families) >= 4:
            break
    if not families:
        return "The relevant forensic records on the device were examined to answer this question."
    return f"The relevant {_join_client_terms(families)} were examined and correlated to answer this question."
