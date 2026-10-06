"""Query understanding — extract OS/category/dimension filters."""

from __future__ import annotations

import json
import re

from app.config import get_settings
from app.services.model_router import generate_text


def understand_query(query: str) -> dict:
    settings = get_settings()
    filters: dict = {"os": None, "category": None, "dimensions": []}
    q_lower = query.lower()
    for os in ("windows", "linux", "macos", "android", "ios"):
        if os in q_lower:
            filters["os"] = os
    for cat in ("registry", "browser", "email", "timeline", "user account", "prefetch", "event log"):
        if cat in q_lower:
            filters["category"] = cat
    for dim in ("who", "what", "when", "where"):
        if dim in q_lower.split():
            filters["dimensions"].append(dim)

    try:
        raw = generate_text(
            f"Extract JSON filters from forensic query. Keys: os, category, dimensions[]. Query: {query}",
            model=settings.llm_fast_model,
            system="Reply with JSON only.",
            temperature=0,
        )
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            filters.update({k: v for k, v in parsed.items() if v})
    except Exception:
        pass
    return {"query": query, "filters": filters}
