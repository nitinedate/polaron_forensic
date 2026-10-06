"""Client-safe observation formatting using the supplied AXIOM KB.

The old module contained hand-written "gold" conclusions per objective.  Those reusable
sentences were a source of repeated and irrelevant observations.  V8 keeps only safety,
length and deterministic fallback formatting; forensic meaning now comes from the KB
evidence brief for the current case.
"""
from __future__ import annotations

import re
from typing import Any

from app.services.axiom_forensic_kb import (
    canonical_artifact_family,
    objective_knowledge_plan,
    sanitize_narrative_text,
    text_contains_prohibited_payload,
)

OBSERVATION_STYLE_GUIDE = """
Write 2–5 short factual sentences for a non-technical reader. Use only the current-case
deterministic evidence brief. State the supported finding, an important limit when
needed, and end with one short sentence beginning "This means". Never reuse sample
report values or generic artifact totals.
""".strip()

_TECHNICAL_LEAK_RE = re.compile(
    r"(?:[A-Za-z]:\\|/(?:Users|home|var|Windows|usr)/|\\\\[A-Za-z0-9_.$-]+\\|"
    r"\b(?:Users|Windows|ProgramData|AppData)(?:[\\/][^\s,;]+)+|"
    r"\b(?:NTUSER(?:\.DAT)?|USBSTOR|SetupAPI|SECURITY\.EVTX|query[_ ]key|count[_ ]domain|"
    r"artifact[_ ]record|AppxBlockMap(?:\.xml)?|GET /api/|registry hive|MFT|USN)\b)",
    re.I,
)
_RAW_CATALOG_TOTAL_RE = re.compile(
    r"\b\d[\d,]*\s+(?:(?:file|artifact\s+record|record|item)s?(?:\s+occurrences?)?)\s*\([^)]*\)", re.I
)


def simple_explanation_for_title(title: str) -> str:
    del title
    return "This means the conclusion is based only on evidence that directly answers this question."


def ensure_simple_explanation(text: str, *, title: str) -> str:
    body = str(text or "").strip()
    if not body:
        return body
    if re.search(r"\bthis means\b", body, re.I):
        return body
    return f"{body} {simple_explanation_for_title(title)}".strip()


def observation_leaks_technical(text: str) -> bool:
    body = str(text or "").strip()
    if not body:
        return False
    return bool(
        text_contains_prohibited_payload(body)
        or _TECHNICAL_LEAK_RE.search(body)
        or _RAW_CATALOG_TOTAL_RE.search(body)
        or body.startswith(("[{", "{\"", "{'"))
    )


def observation_is_client_length(text: str) -> bool:
    body = str(text or "").strip()
    if not body:
        return False
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", body) if s.strip()]
    return 2 <= len(sentences) <= 6 and len(body) <= 1400


def _nonzero(artifacts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out = []
    for art in artifacts or []:
        try:
            n = int(art.get("occurrence_count") or art.get("count") or 0)
        except Exception:
            n = 0
        if n > 0:
            out.append(art)
    return out


def format_client_observation(
    title: str,
    *,
    status: str = "",
    artifacts: list[dict[str, Any]] | None = None,
    rag_snippets: list[str] | None = None,
    facts: list[str] | None = None,
    device_word: str = "computer",
) -> str:
    """Fail-closed compatibility fallback with no reconstructed catalog counts."""
    del artifacts, rag_snippets, facts, device_word
    title = str(title or "this question").strip() or "this question"
    status = str(status or "").upper()
    plan = objective_knowledge_plan(title)
    if status == "NOT_EXAMINED" or not plan.get("reports"):
        body = (
            f"For {title}, the supplied AXIOM knowledge base does not define a direct controlled finding that can answer the question as written. "
            "No unrelated artifact category or count was used as a substitute."
        )
    elif status == "INCONCLUSIVE":
        body = (
            f"For {title}, related evidence may be present, but the controlled evidence is not specific enough to make a reliable finding. "
            "Supporting or broad artifact totals were not treated as proof by themselves."
        )
    else:
        body = (
            f"For {title}, no direct primary evidence matching the controlled report criteria was established. "
            "Supporting or broad artifact totals were not treated as proof by themselves."
        )
    return ensure_simple_explanation(body, title=title)


def client_safe_observation(text: str, *, title: str = "", device_word: str = "computer") -> str:
    del device_word
    body = sanitize_narrative_text(text, max_len=1400)
    # If sanitization had to remove an internal path, the original paragraph is not a
    # client-safe forensic observation. Fail closed rather than keeping surrounding
    # generic counts or conclusions after a path was removed.
    if body and "[internal path omitted]" not in body and not observation_leaks_technical(body):
        return ensure_simple_explanation(body, title=title)
    return format_client_observation(title, status="NOT_FOUND")
