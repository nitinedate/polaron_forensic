"""Tests for handbook-aligned SQL query fragments."""

from app.services.artifact_list_queries import list_where_for_artifact_name
from app.services.axiom_section_queries import EMLX_FILE_WHERE, EMAIL_ATTACHMENT_WHERE
from app.services.catalog_categories import EMAIL_CALENDAR_CATEGORY
from app.services.handbook_query_sql import (
    EXTENSIONLESS_MAIL_WHERE,
    sql_handbook_evidence_fallback,
    sql_media_where,
)


def test_emlx_where_includes_maildir_and_extensionless() -> None:
    low = EMLX_FILE_WHERE.lower()
    assert "maildir" in low
    assert ".eml" in low
    assert "library/mail" in low


def test_email_attachment_where_includes_maildir() -> None:
    assert "maildir" in EMAIL_ATTACHMENT_WHERE.lower()


def test_email_attachment_where_escapes_maildir_colon_bind() -> None:
    from sqlalchemy import text

    from app.services.handbook_query_sql import EMAIL_ATTACHMENT_WHERE, sql_ilike_contains

    assert "\\:2" in sql_ilike_contains(":2,S")
    stmt = text(
        "SELECT count(*) FROM job_artifacts WHERE job_id=:jid AND ("
        + EMAIL_ATTACHMENT_WHERE.strip()
        + ")"
    )
    stmt.bindparams(jid="job")


def test_extensionless_mail_where_covers_thunderbird() -> None:
    assert "thunderbird" in EXTENSIONLESS_MAIL_WHERE.lower()


def test_media_where_includes_handbook_picture_exts() -> None:
    sql = sql_media_where("picture").lower()
    assert ".heic" in sql
    assert ".cr2" in sql or ".raw" in sql


def test_mbox_list_where_uses_handbook_query() -> None:
    suffix, _ = list_where_for_artifact_name(
        None,  # type: ignore[arg-type]
        "job",
        artifact_name="Mbox Emails",
        category=EMAIL_CALENDAR_CATEGORY,
        platform="Windows",
    )
    assert "mbox" in suffix.lower()
    assert "thunderbird" in suffix.lower() or "maildir" in suffix.lower()


def test_handbook_fallback_targets_mail_artifacts() -> None:
    sql = sql_handbook_evidence_fallback("unknown mail cache", category="email & calendar")
    assert "maildir" in sql.lower() or ".eml" in sql.lower()


def test_handbook_fallback_false_for_unrelated() -> None:
    assert sql_handbook_evidence_fallback("ic os") == "FALSE"
