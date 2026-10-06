"""OS and user profile report sections — prompt-only via identity_evidence_prompts."""

from __future__ import annotations

from app.services.identity_evidence_prompts import (
    build_os_report_section,
    build_user_report_section,
)


def build_os_report_markdown(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
) -> str:
    return build_os_report_section(
        db, job_id, schema_name=schema_name, primary_model=primary_model,
    )


def build_user_report_markdown(
    db,
    job_id: str,
    *,
    schema_name: str | None = None,
    primary_model: str | None = None,
) -> str:
    return build_user_report_section(
        db, job_id, schema_name=schema_name, primary_model=primary_model,
    )
