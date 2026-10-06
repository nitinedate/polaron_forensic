"""Summarize saved job_artifacts evidence — extensions, extensionless, unclassified."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.sql_helpers import fetchall, fetchone


def build_evidence_coverage(db: Session, job_id: str) -> dict[str, Any]:
    total_row = fetchone(
        db,
        "SELECT count(*) c, coalesce(sum(size_bytes),0) bytes FROM job_artifacts WHERE job_id=:jid",
        {"jid": job_id},
    )
    total = int(total_row["c"]) if total_row else 0
    total_bytes = int(total_row["bytes"]) if total_row else 0

    ext_rows = fetchall(
        db,
        """
        SELECT
          CASE
            WHEN coalesce(nullif(trim(extension), ''), '') = ''
              OR lower(coalesce(extension,'')) IN ('.', '(none)', 'none')
            THEN '(extensionless)'
            ELSE lower(extension)
          END AS ext,
          count(*) AS c,
          coalesce(sum(size_bytes), 0) AS bytes,
          count(*) FILTER (WHERE coalesce(size_bytes, 0) <= 1024) AS tiny_le_1kb
        FROM job_artifacts
        WHERE job_id = :jid
        GROUP BY 1
        ORDER BY c DESC
        LIMIT 80
        """,
        {"jid": job_id},
    )
    by_extension = [
        {
            "extension": r["ext"],
            "count": int(r["c"]),
            "bytes": int(r["bytes"] or 0),
            "tiny_le_1kb": int(r["tiny_le_1kb"] or 0),
        }
        for r in ext_rows
    ]

    extensionless = next((x for x in by_extension if x["extension"] == "(extensionless)"), None)
    unclassified_row = fetchone(
        db,
        """
        SELECT count(*) c FROM job_artifacts
        WHERE job_id=:jid
          AND (
            encyclopedia_artifact_id IS NULL
            OR encyclopedia_artifact_id IN ('', 'unknown', 'unmatched', 'other')
          )
        """,
        {"jid": job_id},
    )
    tiny_row = fetchone(
        db,
        """
        SELECT count(*) c FROM job_artifacts
        WHERE job_id=:jid AND coalesce(size_bytes, 0) <= 1024
        """,
        {"jid": job_id},
    )

    return {
        "job_id": job_id,
        "total_files": total,
        "total_bytes": total_bytes,
        "extensionless_count": int(extensionless["count"]) if extensionless else 0,
        "extensionless_tiny_le_1kb": int(extensionless["tiny_le_1kb"]) if extensionless else 0,
        "unclassified_count": int(unclassified_row["c"]) if unclassified_row else 0,
        "tiny_le_1kb_count": int(tiny_row["c"]) if tiny_row else 0,
        "by_extension": by_extension,
        "notes": [
            "All rows are files already saved in job_artifacts (extracted + materialized).",
            "Extensionless includes Chromium History/Cookies-style names and maildir messages.",
            "Unclassified files are saved evidence not yet mapped to an AXIOM catalog key — use Show all / Unclassified on Artifacts.",
            "Tiny files (≤1 KB) are retained when path/extension rules match — they are often prefs, sidecars, or crypto headers.",
        ],
    }
