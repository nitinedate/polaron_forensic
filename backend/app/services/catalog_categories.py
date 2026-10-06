"""Canonical Magnet/report catalog category labels (single name per section)."""

from __future__ import annotations

import re

from sqlalchemy import text
from sqlalchemy.orm import Session

# Display title used everywhere in UI, queries, and reports.
EMAIL_CALENDAR_CATEGORY = "Email & Calendar"
ENCRYPTION_CREDENTIALS_CATEGORY = "Encryption & Credentials"

_CANONICAL_BY_NORM: dict[str, str] = {
    "email and calendar": EMAIL_CALENDAR_CATEGORY,
    "email & calendar": EMAIL_CALENDAR_CATEGORY,
    "encryption and credentials": ENCRYPTION_CREDENTIALS_CATEGORY,
    "encryption & credentials": ENCRYPTION_CREDENTIALS_CATEGORY,
}


def norm_category_key(category: str | None) -> str:
    """Lowercase normalized key for comparisons."""
    text_val = re.sub(r"\s+", " ", (category or "").strip().lower())
    return text_val.replace("&", "and")


def canonical_category(category: str | None) -> str:
    """Return the single display name for a catalog section."""
    raw = (category or "Other").strip() or "Other"
    norm = norm_category_key(raw)
    if norm in _CANONICAL_BY_NORM:
        return _CANONICAL_BY_NORM[norm]
    return raw


def is_email_calendar_category(category: str | None) -> bool:
    return norm_category_key(category) == "email and calendar"


def normalize_axiom_category_labels(db: Session, *, platform: str) -> None:
    """Persist canonical section names in public.axiom_artifacts (idempotent)."""
    db.execute(
        text(
            """UPDATE public.axiom_artifacts
               SET category = :canonical
               WHERE platform = :platform
                 AND lower(regexp_replace(regexp_replace(trim(category), '&', 'and', 'g'), '\\s+', ' ', 'g')) = :norm
                 AND category IS DISTINCT FROM :canonical"""
        ),
        {
            "platform": platform,
            "canonical": EMAIL_CALENDAR_CATEGORY,
            "norm": "email and calendar",
        },
    )
    db.execute(
        text(
            """UPDATE public.axiom_artifacts
               SET category = :canonical
               WHERE platform = :platform
                 AND lower(regexp_replace(regexp_replace(trim(category), '&', 'and', 'g'), '\\s+', ' ', 'g')) = :norm
                 AND category IS DISTINCT FROM :canonical"""
        ),
        {
            "platform": platform,
            "canonical": ENCRYPTION_CREDENTIALS_CATEGORY,
            "norm": "encryption and credentials",
        },
    )
    db.flush()


def dedupe_subcategories(subcategories: list[dict]) -> list[dict]:
    """Merge duplicate artifact labels after category consolidation."""
    import re as _re

    def _label_key(label: str) -> str:
        return _re.sub(r"\s+", " ", (label or "").strip().lower())

    merged: dict[str, dict] = {}
    order: list[str] = []
    for sub in subcategories:
        label_key = _label_key(str(sub.get("label") or sub.get("key") or ""))
        if not label_key:
            continue
        if label_key not in merged:
            merged[label_key] = dict(sub)
            order.append(label_key)
            continue
        prev = merged[label_key]
        prev_count = int(prev.get("count") or 0)
        sub_count = int(sub.get("count") or 0)
        prev_key = str(prev.get("key") or "")
        sub_key = str(sub.get("key") or "")
        if sub_key.startswith("RPT-") and not prev_key.startswith("RPT-"):
            merged[label_key] = {**sub, "count": max(prev_count, sub_count)}
        else:
            prev["count"] = max(prev_count, sub_count)
            if sub.get("critical"):
                prev["critical"] = True
    return [merged[key] for key in order]
