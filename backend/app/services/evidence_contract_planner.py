"""Deterministic evidence-contract planner backed by the supplied AXIOM KB.

The previous implementation optionally asked an LLM to invent/refine an evidence
contract.  V8 intentionally removes that path: the attached KB decides the evidence
families, count rules and procedures; the LLM only writes the final narrative.
"""
from __future__ import annotations

from typing import Any

from app.services.evidence_contract import (
    baseline_evidence_contract,
    contract_to_evidence_prompt_section,
    validate_evidence_contract,
)


def plan_evidence_contract(
    *,
    title: str,
    objective_statement: str = "",
    procedure_text: str = "",
    intake: dict[str, Any] | None = None,
    domain: str = "disk",
    model: str | None = None,
    allowed_artifact_names: set[str] | None = None,
    **_: Any,
) -> dict[str, Any]:
    del objective_statement, procedure_text, intake, model
    return validate_evidence_contract(
        baseline_evidence_contract(title, domain=domain),
        allowed_artifact_names=allowed_artifact_names,
    )


def _merge_axiom_requirements(row: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    """Compatibility hook; V8 does not merge legacy DB evidence rules.

    The attached KB is the single runtime source of artifact relationships, required
    fields, corroboration and limitations. Legacy columns may remain in PostgreSQL for
    history/UI compatibility, but they cannot change the report-agent contract.
    """
    del row
    return validate_evidence_contract(contract)


def attach_evidence_contracts_to_objectives(
    db,
    job_id: str,
    intake: dict[str, Any],
    objectives: list[dict[str, Any]],
    *,
    domain: str,
    model: str | None = None,
    use_llm: bool = False,
    progress_cb=None,
    **_: Any,
) -> list[dict[str, Any]]:
    del db, job_id, model, use_llm
    out: list[dict[str, Any]] = []
    total = max(1, len(objectives))
    for index, objective in enumerate(objectives, 1):
        row = dict(objective or {})
        title = str(row.get("title") or "").strip()
        contract = baseline_evidence_contract(title, domain=domain)
        contract = _merge_axiom_requirements(row, contract)
        row["evidence_contract"] = contract
        row["linked_artifact_names"] = list(contract.get("artifact_names") or [])
        block = contract_to_evidence_prompt_section(contract)
        # V8 intentionally discards any legacy/database prompt text. The supplied KB
        # is the only forensic-evidence contract used by the report agent.
        row["evidence_prompt"] = block
        out.append(row)
        if progress_cb:
            try:
                progress_cb(index, total, title)
            except Exception:
                pass
    return out


def ensure_objective_contracts(
    db,
    job_id: str,
    intake: dict[str, Any],
    objectives: list[dict[str, Any]],
    *,
    domain: str = "disk",
    **kwargs: Any,
) -> list[dict[str, Any]]:
    return attach_evidence_contracts_to_objectives(db, job_id, intake, objectives, domain=domain, **kwargs)
