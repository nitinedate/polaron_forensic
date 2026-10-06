"""Split compound forensic questions into atomic sub-questions."""

from __future__ import annotations

import json
import re

from app.config import get_settings
from app.services.model_router import generate_text

_FORENSIC_TOPIC = re.compile(
    r"\b(operating\s+system|\bos\b|hardware|users?|accounts?|usb|browser|email|phone|"
    r"whatsapp|artifacts?|documents?|registry|timeline|password|logon|login|"
    r"connected\s+devices|installed\s+programs?)\b",
    re.I,
)

_KNOWN_COMPOUND_SPLITS: list[tuple[re.Pattern[str], list[str]]] = [
    (
        re.compile(r"\boperating\s+system\b.*\bhardware\b|\bhardware\b.*\boperating\s+system\b", re.I),
        ["Provide operating system information", "Provide hardware information"],
    ),
    (
        re.compile(
            r"\b(users?|accounts?)\b.*\b(?:operating\s+system|\bos\b)\b|"
            r"\b(?:operating\s+system|\bos\b)\b.*\b(users?|accounts?)\b",
            re.I,
        ),
        ["List all Windows user accounts on this system", "Provide operating system information"],
    ),
    (
        re.compile(r"\boperating\s+system\b.*\busers?\b|\busers?\b.*\boperating\s+system\b", re.I),
        ["Provide operating system information", "List all Windows user accounts on this system"],
    ),
]


def _normalize_sub_question(text: str) -> str:
    q = (text or "").strip().rstrip(".")
    if not q:
        return ""
    if not q.endswith("?"):
        low = q.lower()
        if not re.search(r"\b(provide|list|show|give|what|which|how many|who)\b", low):
            q = f"Provide {q}"
        if "information" not in low and "details" not in low and not q.endswith("?"):
            q = f"{q} information"
    return q.strip()


def _split_explicit_questions(query: str) -> list[str] | None:
    if "?" not in query:
        return None
    parts = [p.strip() for p in re.split(r"\?\s+", query.strip()) if p.strip()]
    if len(parts) < 2:
        return None
    out: list[str] = []
    for i, part in enumerate(parts):
        text = part if part.endswith("?") else f"{part}?"
        out.append(_normalize_sub_question(text))
    return [q for q in out if q]


def _split_and_clause(query: str) -> list[str] | None:
    m = re.match(
        r"^(?:provide|give|list|show|tell me(?: about)?|what(?:'s| is| are)?)\s+(.+?)\s+and\s+(.+?)"
        r"(?:\s+(?:information|info|details?))?\.?$",
        query.strip(),
        re.I,
    )
    if not m:
        return None
    left, right = m.group(1).strip(), m.group(2).strip()
    if not _FORENSIC_TOPIC.search(left) and not _FORENSIC_TOPIC.search(right):
        return None
    suffix = ""
    if re.search(r"\b(information|info|details?)\b", query, re.I):
        suffix = " information"
    return [
        _normalize_sub_question(f"Provide {left}{suffix}"),
        _normalize_sub_question(f"Provide {right}{suffix}"),
    ]


def _looks_compound(query: str) -> bool:
    q = query or ""
    if re.search(r"\?\s+\S", q):
        return True
    if re.search(r"\band\b", q, re.I) and _FORENSIC_TOPIC.search(q):
        return True
    if re.search(r"\b(as well as|also|in addition to)\b", q, re.I):
        return True
    return False


def _llm_decompose(query: str) -> list[str]:
    settings = get_settings()
    try:
        raw = generate_text(
            f"Split this forensic examiner question into separate atomic questions (one topic each). "
            f"Return JSON array of strings only.\n\nQuestion: {query}",
            model=settings.llm_fast_model,
            system=(
                "You split compound forensic questions. Each sub-question must be self-contained and "
                "ask about exactly one topic (OS, hardware, users, USB, browser, etc.). "
                "Reply with JSON array only, e.g. [\"Provide operating system information\", "
                "\"Provide hardware information\"]."
            ),
            temperature=0,
        )
        m = re.search(r"\[.*\]", raw, re.DOTALL)
        if not m:
            return [query.strip()]
        parsed = json.loads(m.group())
        if isinstance(parsed, list):
            out = [_normalize_sub_question(str(item)) for item in parsed if str(item).strip()]
            out = [q for q in out if q]
            if len(out) >= 2:
                return out
    except Exception:
        pass
    return [query.strip()]


def decompose_query(query: str) -> list[str]:
    """Return one or more atomic sub-questions for sequential answering."""
    q = (query or "").strip()
    if not q:
        return []

    explicit = _split_explicit_questions(q)
    if explicit and len(explicit) >= 2:
        return explicit

    for pattern, subs in _KNOWN_COMPOUND_SPLITS:
        if pattern.search(q):
            return list(subs)

    and_split = _split_and_clause(q)
    if and_split and len(and_split) >= 2:
        return and_split

    if _looks_compound(q):
        return _llm_decompose(q)

    return [q]
