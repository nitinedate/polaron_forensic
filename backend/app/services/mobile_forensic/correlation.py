"""Correlate normalized mobile artifacts (message↔media, contact↔identity)."""

from __future__ import annotations

import json
import logging
from pathlib import PurePosixPath
from typing import Any

from app.db.sql_helpers import execute
from app.services.mobile_forensic.models import NormalizedArtifact
from app.services.mobile_forensic.storage import ensure_mobile_case_schema

log = logging.getLogger("mobile_forensic.correlation")


def correlate_artifacts(
    db,
    job_id: str,
    artifacts: list[NormalizedArtifact],
) -> int:
    """Write scored relationships; never mutates source artifacts."""
    ensure_mobile_case_schema(db)
    by_name: dict[str, list[NormalizedArtifact]] = {}
    messages: list[NormalizedArtifact] = []
    contacts: list[NormalizedArtifact] = []
    media: list[NormalizedArtifact] = []

    for a in artifacts:
        name = str((a.data or {}).get("name") or "").lower()
        path = str((a.data or {}).get("path") or a.forensic.get("source_path") or "")
        if name:
            by_name.setdefault(name, []).append(a)
        elif path:
            by_name.setdefault(PurePosixPath(path).name.lower(), []).append(a)
        if a.artifact_type in ("app_message", "sms", "mms"):
            messages.append(a)
        elif a.artifact_type in ("contact", "identity", "account"):
            contacts.append(a)
        elif a.artifact_type in ("photo", "video", "audio", "orphaned_media", "file"):
            media.append(a)

    n = 0
    for msg in messages:
        blob = " ".join(str(v) for v in (msg.data or {}).values() if v is not None).lower()
        for med in media:
            med_name = str((med.data or {}).get("name") or PurePosixPath(str((med.data or {}).get("path") or "")).name).lower()
            if med_name and med_name in blob:
                n += _upsert_rel(
                    db,
                    job_id,
                    msg.artifact_id,
                    med.artifact_id,
                    "message_attachment",
                    score=0.75,
                    reasons=["filename_in_message_fields"],
                )

    # Contact ↔ identity by phone/email overlap
    for i, a in enumerate(contacts):
        a_vals = {str(v).lower() for v in (a.data or {}).values() if v}
        for b in contacts[i + 1 :]:
            b_vals = {str(v).lower() for v in (b.data or {}).values() if v}
            overlap = a_vals & b_vals
            if overlap:
                n += _upsert_rel(
                    db,
                    job_id,
                    a.artifact_id,
                    b.artifact_id,
                    "same_identity",
                    score=0.65,
                    reasons=[f"shared_fields:{len(overlap)}"],
                )
    return n


def _upsert_rel(
    db,
    job_id: str,
    from_id: str,
    to_id: str,
    rel_type: str,
    *,
    score: float,
    reasons: list[str],
) -> int:
    try:
        execute(
            db,
            """INSERT INTO mobile_artifact_relationships
               (job_id, from_artifact_id, to_artifact_id, rel_type, confidence, reasons)
               VALUES (:jid, :frm, :too, :rt, CAST(:conf AS jsonb), CAST(:rs AS jsonb))
               ON CONFLICT (job_id, from_artifact_id, to_artifact_id, rel_type) DO UPDATE SET
                 confidence=EXCLUDED.confidence,
                 reasons=EXCLUDED.reasons""",
            {
                "jid": job_id,
                "frm": from_id,
                "too": to_id,
                "rt": rel_type,
                "conf": json.dumps({"score": score, "label": "MEDIUM" if score < 0.8 else "HIGH"}),
                "rs": json.dumps(reasons),
            },
        )
        return 1
    except Exception as exc:
        log.debug("relationship upsert skipped: %s", exc)
        return 0


def correlate_artifacts_db(db, job_id: str) -> int:
    """Database-native correlation for large mobile cases.

    Avoids loading every message/media artifact into Python and avoids the previous
    O(messages × media) nested loop. Exact media filename/path references are linked.
    """
    ensure_mobile_case_schema(db)
    inserted = 0
    try:
        result = execute(
            db,
            """INSERT INTO mobile_artifact_relationships
               (job_id, from_artifact_id, to_artifact_id, rel_type, confidence, reasons)
               SELECT :jid, m.artifact_id, f.artifact_id, 'message_attachment',
                      '{"score":0.90,"label":"HIGH"}'::jsonb,
                      '["normalized_media_filename_match"]'::jsonb
               FROM mobile_normalized_artifacts m
               JOIN mobile_normalized_artifacts f
                 ON f.job_id=m.job_id
                AND f.source_domain IN ('media','files')
                AND lower(COALESCE(f.data->>'name','')) = lower(
                    COALESCE(NULLIF(m.data->>'media_name',''),
                             regexp_replace(COALESCE(m.data->>'media_path',''), '^.*/', ''))
                )
               WHERE m.job_id=:jid
                 AND m.artifact_type='app_message'
                 AND (COALESCE(m.data->>'media_name','') <> '' OR COALESCE(m.data->>'media_path','') <> '')
               ON CONFLICT (job_id, from_artifact_id, to_artifact_id, rel_type) DO UPDATE SET
                 confidence=EXCLUDED.confidence, reasons=EXCLUDED.reasons""",
            {"jid": job_id},
        )
        try:
            inserted += int(getattr(result, "rowcount", 0) or 0)
        except Exception:
            pass
    except Exception as exc:
        log.debug("database attachment correlation skipped: %s", exc)
    return inserted
