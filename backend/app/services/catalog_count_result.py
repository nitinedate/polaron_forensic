"""AXIOM-aligned count result contract (DOCX §1–3, §8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

COUNT_DOMAIN_LABELS: dict[str, str] = {
    "artifact_record": "artifact record occurrences",
    "file_occurrence": "file occurrences",
    "unique_content": "unique content items",
    "recovered": "recovered items",
    "unverified_source_hit": "unverified source-file hits",
}

PARSER_VERSION = "aetheris/axiom-count/1.0"


@dataclass
class CountResult:
    occurrence_count: int
    unique_content_count: int | None = None
    count_domain: str = "artifact_record"
    query_id: str = ""
    parser_version: str = PARSER_VERSION
    evidence_scope: str = "job_artifacts"
    warnings: list[str] = field(default_factory=list)
    query_snapshot: dict[str, Any] = field(default_factory=dict)
    confidence: str = "HIGH"

    @property
    def primary_count(self) -> int:
        return int(self.occurrence_count or 0)

    def domain_label(self) -> str:
        return COUNT_DOMAIN_LABELS.get(self.count_domain, self.count_domain.replace("_", " "))

    def answer_text(self, artifact_name: str) -> str:
        count = self.primary_count
        label = self.domain_label()
        base = f"{count:,} {label} ({artifact_name})"
        if self.unique_content_count is not None and self.unique_content_count != count:
            base += f"; {self.unique_content_count:,} unique content"
        if self.warnings:
            base += f" — note: {self.warnings[0][:120]}"
        return base

    def persist_fields(self) -> dict[str, Any]:
        return {
            "artifact_count": self.primary_count,
            "occurrence_count": self.primary_count,
            "unique_count": self.unique_content_count,
            "count_domain": self.count_domain,
            "parser_version": self.parser_version,
            "confidence": self.confidence,
            "query_snapshot": self.query_snapshot or None,
        }


def count_result_from_int(
    count: int,
    *,
    artifact_name: str,
    count_domain: str = "artifact_record",
    query_id: str = "",
    query_snapshot: dict[str, Any] | None = None,
    unique_count: int | None = None,
    confidence: str = "HIGH",
) -> CountResult:
    return CountResult(
        occurrence_count=int(count or 0),
        unique_content_count=unique_count,
        count_domain=count_domain,
        query_id=query_id,
        query_snapshot={
            "query_id": query_id,
            **(query_snapshot or {}),
        },
        confidence=confidence,
    )
