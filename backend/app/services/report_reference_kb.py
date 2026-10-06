"""Curated report-exemplar guidance learned from the supplied forensic report corpus.

This is deliberately *not* a store of case facts.  It teaches the report agent how the
reference reports connect Section B artifacts -> Section C Objective/Procedure/
Observation -> Section D Annexure -> Section E summary.  Counts, dates, names, URLs and
conclusions are always resolved from the current case by the deterministic collectors.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
from typing import Any

_CORPUS_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "report_reference_corpus" / "all_forensic_reports_v2.json"

_STOP = {
    "the", "and", "for", "with", "from", "this", "that", "use", "used", "using",
    "analysis", "review", "verify", "verification", "activity", "tools", "tool",
}


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _tokens(value: Any) -> set[str]:
    return {t for t in _norm(value).split() if len(t) > 2 and t not in _STOP}


@lru_cache(maxsize=1)
def load_reference_corpus() -> dict[str, Any]:
    return json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _patterns() -> tuple[dict[str, Any], ...]:
    return tuple(load_reference_corpus().get("objective_patterns") or [])


def reference_corpus_fingerprint() -> str:
    return hashlib.sha256(_CORPUS_PATH.read_bytes()).hexdigest()


def reference_corpus_summary() -> dict[str, int]:
    data = load_reference_corpus()
    return {
        "source_reports": len(data.get("sources") or []),
        "artifact_categories": len(data.get("artifact_inventory") or []),
        "objective_patterns": len(data.get("objective_patterns") or []),
        "training_rules": len(data.get("training_rules") or []),
        "writing_style_rules": len((data.get("writing_style") or {}).get("rules") or []),
        "consistency_rules": len(data.get("cross_section_consistency") or []),
    }


def reference_pattern_for_objective(title: str, statement: str = "") -> dict[str, Any] | None:
    """Resolve a report title to the closest curated Objective/Procedure pattern.

    Exact canonical titles/aliases win.  Fuzzy matching requires more than one useful
    token so a generic word such as ``network`` cannot silently map an unrelated custom
    objective to a reference pattern.
    """
    title_n = _norm(title)
    statement_n = _norm(statement)
    for pattern in _patterns():
        names = [pattern.get("canonical_title"), *(pattern.get("aliases") or [])]
        if any(title_n and title_n == _norm(name) for name in names):
            return deepcopy(pattern)

    query = _tokens(f"{title} {statement}")
    if not query:
        return None
    best: tuple[float, dict[str, Any] | None] = (0.0, None)
    for pattern in _patterns():
        names = " ".join([str(pattern.get("canonical_title") or ""), *(str(x) for x in pattern.get("aliases") or [])])
        hay = _tokens(names)
        overlap = query & hay
        if len(overlap) < 2:
            continue
        score = len(overlap) / max(1, min(len(query), len(hay)))
        if title_n and any(_norm(a) in title_n or title_n in _norm(a) for a in pattern.get("aliases") or [] if _norm(a)):
            score += 0.5
        if score > best[0]:
            best = (score, pattern)
    return deepcopy(best[1]) if best[1] else None


def reference_report_ids_for_objective(title: str, statement: str = "") -> list[str]:
    pattern = reference_pattern_for_objective(title, statement)
    return [str(x) for x in (pattern or {}).get("kb_report_ids") or [] if str(x).strip()]


def reference_client_objective(title: str, statement: str = "") -> str:
    pattern = reference_pattern_for_objective(title, statement)
    return str((pattern or {}).get("client_objective") or "").strip()


def reference_client_procedure(title: str, statement: str = "") -> str:
    pattern = reference_pattern_for_objective(title, statement)
    return str((pattern or {}).get("client_procedure") or "").strip()


def reference_evidence_questions(title: str, statement: str = "") -> list[str]:
    pattern = reference_pattern_for_objective(title, statement)
    return [str(x).strip() for x in (pattern or {}).get("required_questions") or [] if str(x).strip()]


def reference_decision_rules(title: str, statement: str = "") -> list[str]:
    pattern = reference_pattern_for_objective(title, statement)
    return [str(x).strip() for x in (pattern or {}).get("decision_rules") or [] if str(x).strip()]


def reference_annexure_kinds(title: str, statement: str = "") -> list[str]:
    pattern = reference_pattern_for_objective(title, statement)
    return [str(x).strip() for x in (pattern or {}).get("annexure_kinds") or [] if str(x).strip()]


def reference_agent_guidance(title: str, statement: str = "") -> dict[str, Any]:
    """Small safe object that can be included in the LLM evidence brief.

    It contains method/wording guidance only; there are intentionally no example counts,
    URLs, devices or case-specific findings.
    """
    pattern = reference_pattern_for_objective(title, statement)
    if not pattern:
        return {}
    writing_style = load_reference_corpus().get("writing_style") or {}
    return {
        "pattern_id": pattern.get("id"),
        "canonical_title": pattern.get("canonical_title"),
        "required_questions": list(pattern.get("required_questions") or []),
        "decision_rules": list(pattern.get("decision_rules") or []),
        "reference_states": list(pattern.get("reference_states") or []),
        "annexure_kinds": list(pattern.get("annexure_kinds") or []),
        "query_strategy": deepcopy(pattern.get("query_strategy") or {}),
        "query_principles": list(load_reference_corpus().get("query_principles") or []),
        "writing_style_rules": list(writing_style.get("rules") or []),
        "reference_corpus_version": load_reference_corpus().get("version"),
    }


def validate_reference_corpus() -> list[str]:
    data = load_reference_corpus()
    errors: list[str] = []
    ids: set[str] = set()
    for row in data.get("objective_patterns") or []:
        rid = str(row.get("id") or "").strip()
        if not rid:
            errors.append("objective pattern with blank id")
        elif rid in ids:
            errors.append(f"duplicate objective pattern id: {rid}")
        ids.add(rid)
        for required in ("canonical_title", "client_objective", "client_procedure", "kb_report_ids", "decision_rules"):
            if not row.get(required):
                errors.append(f"{rid or '<blank>'}: missing {required}")
    return errors
