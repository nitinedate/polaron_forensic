"""Evidence-contract compatibility layer backed by the supplied AXIOM KB.

V8 removes the previous manually-maintained per-title artifact/path/question tables.
Contracts are derived from the attached knowledge base report definitions and controlled
procedures.  This keeps one forensic source of truth while preserving the dictionary
shape expected by existing intake/mobile code.
"""
from __future__ import annotations

from typing import Any

from app.services.axiom_forensic_kb import (
    evidence_questions_for_objective,
    objective_knowledge_plan,
    rag_terms_for_objective,
)

EVIDENCE_CONTRACT_SCHEMA_VERSION = 2


def empty_evidence_contract(*, domain: str = "disk") -> dict[str, Any]:
    return {
        "schema_version": EVIDENCE_CONTRACT_SCHEMA_VERSION,
        "domain": domain,
        "artifact_ids": [],
        "artifact_names": [],
        "path_patterns": [],
        "count_domains": [],
        "required_fields": [],
        "corroboration_min": 1,
        "rag_queries": [],
        "evidence_questions": [],
        "prohibited_claims": [
            "Do not invent artifact counts, identities, participants, actions, or timestamps.",
            "Do not count supporting/corroborating/contextual evidence as a primary forensic event.",
            "Do not infer file copy from USB/MTP connection alone.",
            "Do not infer upload/download from a cloud website visit alone.",
            "Do not include raw XML/JSON/package/registry payloads in client observations.",
        ],
        "linked_artifact_ids": [],
        "report_ids": [],
        "procedure_ids": [],
        "source": "axiom_forensic_kb",
    }


def validate_evidence_contract(
    contract: dict[str, Any] | None,
    *,
    allowed_artifact_names: set[str] | None = None,
) -> dict[str, Any]:
    base = empty_evidence_contract(domain=str((contract or {}).get("domain") or "disk"))
    if not isinstance(contract, dict):
        return base
    out = {**base, **{k: v for k, v in contract.items() if k in base or k in {"title", "axiom_objective_id"}}}
    names = [str(n).strip() for n in (out.get("artifact_names") or []) if str(n).strip()]
    # Only apply current-catalog filtering when it actually contains KB family names.
    if allowed_artifact_names is not None:
        filtered = [n for n in names if n in allowed_artifact_names]
        if filtered:
            names = filtered
    out["artifact_names"] = names[:80]
    for key, limit in (
        ("artifact_ids", 80), ("linked_artifact_ids", 80), ("path_patterns", 40),
        ("count_domains", 40), ("required_fields", 80), ("rag_queries", 32),
        ("evidence_questions", 24), ("prohibited_claims", 16), ("report_ids", 80),
        ("procedure_ids", 32),
    ):
        out[key] = [str(x) for x in (out.get(key) or []) if str(x).strip()][:limit]
    try:
        out["corroboration_min"] = max(1, int(out.get("corroboration_min") or 1))
    except Exception:
        out["corroboration_min"] = 1
    out["schema_version"] = EVIDENCE_CONTRACT_SCHEMA_VERSION
    return out


def _baseline(title: str, *, domain: str) -> dict[str, Any]:
    plan = objective_knowledge_plan(title)
    required_fields: list[str] = []
    count_domains: list[str] = []
    corroboration_min = 1
    for report in plan.get("reports") or []:
        for field in [*(report.get("required_fields") or []), *(report.get("optional_fields") or [])]:
            s = str(field).strip()
            if s and s not in required_fields:
                required_fields.append(s)
        unit = str((report.get("count_rule") or {}).get("unit") or "").strip()
        if unit and unit not in count_domains:
            count_domains.append(unit)
        if any(str(m.get("relationship") or "").upper() == "CORROBORATING" for m in report.get("artifact_mappings") or []):
            corroboration_min = max(corroboration_min, 2)

    contract = empty_evidence_contract(domain=domain)
    contract.update({
        "title": title,
        "report_ids": list(plan.get("report_ids") or []),
        "procedure_ids": list(plan.get("procedure_ids") or []),
        "artifact_names": list(dict.fromkeys([
            *(plan.get("primary_artifact_families") or []),
            *(plan.get("supporting_artifact_families") or []),
            *(plan.get("corroborating_artifact_families") or []),
        ])),
        "count_domains": count_domains,
        "required_fields": required_fields,
        "corroboration_min": corroboration_min,
        "rag_queries": rag_terms_for_objective(title),
        "evidence_questions": evidence_questions_for_objective(title),
        "source": "axiom_forensic_kb",
    })
    contract = _augment_accuracy_contract(contract)
    return validate_evidence_contract(contract)



def _augment_accuracy_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Add deterministic derived-state fields required for defensible reporting."""
    report_ids = {str(x) for x in (contract.get("report_ids") or [])}

    def add(key: str, *values: str) -> None:
        rows = list(contract.get(key) or [])
        for value in values:
            if value and value not in rows:
                rows.append(value)
        contract[key] = rows

    if "USB_DEVICES" in report_ids:
        add("required_fields", "distinct_physical_device_count", "device_model_or_identity")
        add(
            "rag_queries",
            "distinct physical device USB serial VID PID manufacturer model interface volume deduplication",
        )
        add(
            "evidence_questions",
            "How many distinct physical devices remain after deduplicating interface, volume and repeated connection rows?",
        )
        add(
            "prohibited_claims",
            "Observation rule: never report raw USB interface or volume rows as distinct physical devices; deduplicate to stable device identity first.",
        )

    if "EMAIL_COMMUNICATIONS" in report_ids:
        add("required_fields", "account_state")
        add(
            "evidence_questions",
            "Which email accounts are supported as currently configured accounts on the examined system?",
            "Which email addresses are only historical correspondents, message participants, browser traces or previously used accounts?",
        )
        add(
            "prohibited_claims",
            "Do not describe an address as a currently configured email account when evidence supports only historical message participation or a browser trace.",
        )
    return contract

def baseline_disk_evidence_contract(title: str) -> dict[str, Any]:
    return _baseline(title, domain="disk")


def baseline_mobile_evidence_contract(title: str) -> dict[str, Any]:
    return _baseline(title, domain="mobile")


def baseline_evidence_contract(title: str, *, domain: str) -> dict[str, Any]:
    return _baseline(title, domain=domain)


def contract_to_evidence_prompt_section(contract: dict[str, Any]) -> str:
    lines = [
        "AXIOM FORENSIC KNOWLEDGE CONTRACT:",
        f"- Knowledge reports: {', '.join(contract.get('report_ids') or []) or 'none'}",
        f"- Controlled procedures: {', '.join(contract.get('procedure_ids') or []) or 'none'}",
        f"- Primary/supporting artifact families in scope: {', '.join((contract.get('artifact_names') or [])[:20]) or 'none'}",
        f"- Count units: {', '.join(contract.get('count_domains') or []) or 'n/a'}",
        f"- Required/optional evidence fields: {', '.join((contract.get('required_fields') or [])[:24]) or 'n/a'}",
        "- Count only PRIMARY evidence according to the selected KB report definition; supporting/corroborating evidence may strengthen a finding but must not inflate the count.",
        "- Apply the KB exclusion and semantic-deduplication rules before writing an observation.",
    ]
    qs = contract.get("evidence_questions") or []
    if qs:
        lines.append("Evidence questions:")
        lines.extend(f"  * {q}" for q in qs[:10])
    lines.extend(f"- Prohibited: {p}" for p in (contract.get("prohibited_claims") or [])[:10])
    return "\n".join(lines)


def mobile_objective_statement(title: str) -> str:
    plan = objective_knowledge_plan(title)
    reports = plan.get("reports") or []
    if reports:
        return " ".join(str(r.get("objective") or "").strip() for r in reports[:2] if r.get("objective"))
    return title
