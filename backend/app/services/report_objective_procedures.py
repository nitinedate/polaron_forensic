"""Compatibility facade for report procedures.

V8 removes the old hand-written per-title procedure library.  Procedures now come from
the integrated AXIOM forensic knowledge base supplied by the user.  These functions are
kept because intake/template code imports them, but they no longer maintain a second
source of forensic procedure truth.
"""
from __future__ import annotations

import re

from app.services.axiom_forensic_kb import (
    OBJECTIVE_REPORT_MAP,
    controlled_procedure_text,
    objective_knowledge_plan,
)


def _numbered_steps(text: str) -> list[str]:
    body = re.sub(r"\s+", " ", str(text or "")).strip()
    if not body:
        return []
    parts = re.split(r"(?=\b\d+[.)]\s+)", body)
    return [p.strip() for p in parts if p.strip() and re.match(r"^\d+[.)]\s+", p.strip())]


def append_numbered_steps(base: str, extra_steps: list[str]) -> str:
    """Append de-duplicated numbered steps to a procedure block."""
    body = re.sub(r"\s+", " ", str(base or "")).strip()
    existing = _numbered_steps(body)
    texts = [re.sub(r"^\d+[.)]\s+", "", s).strip() for s in existing]
    for extra in extra_steps or []:
        clean = re.sub(r"^\d+[.)]\s+", "", re.sub(r"\s+", " ", str(extra or "")).strip())
        if clean and clean.lower() not in {x.lower() for x in texts}:
            texts.append(clean)
    return " ".join(f"{i + 1}. {text}" for i, text in enumerate(texts)) if texts else body


def procedure_for_title(title: str, fallback: str = "") -> str:
    """Return the controlled KB procedure for a current Aetheris objective."""
    title = str(title or "").strip()
    plan = objective_knowledge_plan(title, fallback)
    if plan.get("procedures"):
        return controlled_procedure_text(title, fallback)
    return str(fallback or "").strip() or controlled_procedure_text(title, fallback)


def enrich_axiom_procedure_for_title(title: str, axiom_procedure: str) -> str:
    """Compatibility signature: the supplied KB procedure is authoritative.

    ``axiom_procedure`` is deliberately ignored. V8 removes the old second procedure
    source so a database/imported procedure cannot silently override the controlled
    procedure shipped in ``aetheris_axiom_kb_starter``.
    """
    del axiom_procedure
    return procedure_for_title(title)


def build_pointwise_procedure(
    *,
    title: str,
    artifact_families: str = "",
    examine_fields: str = "",
    verify_sources: str = "",
    corroborate: str = "",
    observation_focus: str = "",
    include_ocr_company_scan: bool = False,
) -> str:
    """Legacy signature retained; now delegates to the controlled KB."""
    fallback = observation_focus or " ".join(x for x in (artifact_families, examine_fields, verify_sources, corroborate) if x)
    return procedure_for_title(title, fallback)


# Compatibility mapping used by existing tests/UI code; values are generated from the KB,
# not maintained as a separate forensic knowledge dictionary.
REPORT_OBJECTIVE_PROCEDURES: dict[str, str] = {
    title: controlled_procedure_text(title) for title in OBJECTIVE_REPORT_MAP
}

# Kept for import compatibility. Required outputs now live in each KB report's count_rule,
# observation_rule, optional_fields and artifact mappings.
REFERENCE_OUTPUT_REQUIREMENTS: dict[str, str] = {}
