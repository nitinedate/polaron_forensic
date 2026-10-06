"""Report model learned from the physical PDFs in document_report_model.

The files teach agents two skills:
  * which queries pull the relevant rows out of extracted case content
  * how to write the observation after those rows are in hand

The model does not store exemplar case facts. A physical report is never an answer
for a different case.
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Any

_DIR = Path(__file__).resolve().parents[1] / "knowledge" / "document_report_model"
_MODEL_PATH = _DIR / "report_model.json"

_STOP = {
    "the", "and", "for", "with", "from", "this", "that", "use", "used", "using",
    "analysis", "review", "verify", "verification", "activity", "usage",
}


def _norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _tokens(value: Any) -> set[str]:
    return {token for token in _norm(value).split() if len(token) > 2 and token not in _STOP}


@lru_cache(maxsize=1)
def load_document_report_model() -> dict[str, Any]:
    return json.loads(_MODEL_PATH.read_text(encoding="utf-8"))


def document_report_files() -> list[str]:
    return sorted(path.name for path in _DIR.glob("*.pdf"))


def document_report_summary() -> dict[str, int]:
    data = load_document_report_model()
    return {
        "physical_reports": len(document_report_files()),
        "documents_in_model": len(data.get("documents") or []),
        "trained_objectives": len(data.get("objectives") or []),
        "observation_rules": len((data.get("observation_writing") or {}).get("rules") or []),
    }


def trained_objective(title: str, statement: str = "") -> dict[str, Any] | None:
    """Closest physical-report objective. Exact titles win; fuzzy match needs two tokens."""
    title_n = _norm(title)
    best: tuple[float, dict[str, Any] | None] = (0.0, None)
    for row in load_document_report_model().get("objectives") or []:
        name = _norm(row.get("title"))
        if title_n and title_n == name:
            return row
        query = _tokens(f"{title} {statement}")
        overlap = query & _tokens(row.get("title"))
        if len(overlap) < 2:
            continue
        score = len(overlap) / max(1, min(len(query), len(_tokens(row.get("title")))))
        if title_n and (title_n in name or name in title_n):
            score += 0.5
        if score > best[0]:
            best = (score, row)
    return best[1]


def extraction_queries_for_objective(title: str, statement: str = "") -> list[str]:
    row = trained_objective(title, statement)
    if not row:
        return []
    return [str(item).strip() for item in row.get("extraction_queries") or [] if str(item).strip()]


def document_model_for_agent(title: str, statement: str = "") -> dict[str, Any]:
    """Small object the report agent may see. No exemplar filenames or case facts."""
    data = load_document_report_model()
    row = trained_objective(title, statement)
    payload: dict[str, Any] = {
        "version": data.get("version"),
        "query_method": list(data.get("query_method") or []),
        "observation_rules": list((data.get("observation_writing") or {}).get("rules") or []),
    }
    if not row:
        return payload
    payload.update(
        {
            "matched_training_title": row.get("title"),
            "extraction_queries": list(row.get("extraction_queries") or []),
            "examination_method": row.get("examination_method") or "",
            "observation_shape": row.get("observation_shape") or "",
            "writing_moves": list(row.get("writing_moves") or []),
        }
    )
    return payload
