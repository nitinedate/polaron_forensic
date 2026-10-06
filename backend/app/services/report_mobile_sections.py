"""Mobile report section builders — Device Information / Extraction Summary.

Uses structured fact tables (Sujit / Vivo sample layout). LLM polishing is off by
default so report generation cannot hang on a slow Ollama call for these sections.
"""

from __future__ import annotations

from app.services.mobile_report_service import (
    build_device_information_markdown,
    build_extraction_summary_markdown,
)


def build_mobile_device_report_markdown(
    db,
    job_id: str,
    intake: dict | None = None,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    use_llm: bool = False,
) -> str:
    return build_device_information_markdown(
        db,
        job_id,
        intake,
        schema_name=schema_name,
        primary_model=primary_model,
        use_llm=use_llm,
    )


def build_mobile_extraction_report_markdown(
    db,
    job_id: str,
    intake: dict | None = None,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
    use_llm: bool = False,
) -> str:
    return build_extraction_summary_markdown(
        db,
        job_id,
        intake,
        schema_name=schema_name,
        primary_model=primary_model,
        use_llm=use_llm,
    )
