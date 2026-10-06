"""Recompute and persist Section B artifact counts for one job."""

from __future__ import annotations

import json

from sqlalchemy import text

from app.db.session import SessionLocal
from app.db.sql_helpers import execute
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact_result
from app.services.encryption_inventory import clear_encryption_count_cache
from app.services.inventory_path_cache import clear_path_cache

JOB = "d963d7b1-fc00-40bb-865e-85fc365f874b"

TARGETS = [
    ("USB Devices", "Connected Devices"),
    ("Your Phone Device", "Connected Devices"),
    ("Remote Desktop Protocol (RDP)", "Connected Devices"),
    ("Feature Usage", "Application Usages"),
    ("Installed Microsoft Programs", "Application Usages"),
    ("Installed Programs (Non-Microsoft)", "Application Usages"),
    ("Windows Defender Logs", "Application Usages"),
    ("Web Chat URLs", "Communication"),
    ("Social Media URLs", "Communication"),
    ("Malware/Phishing URLs", "Communication"),
    ("CSV Documents", "Documents"),
    ("Microsoft PowerPoint Documents", "Documents"),
    ("Microsoft Excel Documents", "Documents"),
    ("PDF Documents", "Documents"),
    ("RTF Documents", "Documents"),
    ("Text Documents", "Documents"),
    ("Microsoft Word Documents", "Documents"),
    ("Email Attachments", "Email & Calendar"),
    ("EML(X) Files", "Email & Calendar"),
    ("Windows Mail", "Email & Calendar"),
    ("Outlook Emails", "Email & Calendar"),
    ("Outlook Tasks", "Email & Calendar"),
    ("Outlook Contacts", "Email & Calendar"),
    ("Outlook Appointments", "Email & Calendar"),
    ("Encrypted Files", "Encryption & Credentials"),
    ("Windows Stored Credentials", "Encryption & Credentials"),
    ("Audio", "Media"),
    ("Picture", "Media"),
    ("Video", "Media"),
    ("Photoshop Files", "Media"),
    ("Logfile Analysis", "Operating System"),
    ("Jump List", "Operating System"),
    ("LNK Files", "Operating System"),
    ("Web Related Files", "Web Related"),
]


def main() -> None:
    clear_path_cache(JOB)
    clear_encryption_count_cache(JOB)
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))

    for name, category in TARGETS:
        rows = db.execute(
            text(
                """
                SELECT artifact_id FROM public.axiom_artifacts
                WHERE platform='Windows' AND artifact_name=:n
                ORDER BY CASE WHEN artifact_id LIKE 'RPT-%' THEN 0 ELSE 1 END, artifact_id
                """
            ),
            {"n": name},
        ).fetchall()
        if not rows:
            print(f"SKIP missing catalog: {name}")
            continue
        for (aid,) in rows:
            try:
                result = count_axiom_catalog_artifact_result(
                    db,
                    JOB,
                    artifact_name=name,
                    category=category,
                    artifact_id=str(aid),
                )
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                print(f"FAIL {aid} {name}: {exc}")
                continue
            persist = result.persist_fields()
            count = result.primary_count
            answer = result.answer_text(name)
            execute(
                db,
                """INSERT INTO job_axiom_artifact_results
                   (job_id, artifact_id, artifact_count, status, answer, error,
                    count_domain, occurrence_count, unique_count, query_snapshot,
                    parser_version, confidence, updated_at)
                   VALUES (:jid, :aid, :cnt, 'done', :ans, NULL,
                           :cd, :oc, :uc, CAST(:qs AS jsonb), :pv, :conf, NOW())
                   ON CONFLICT (job_id, artifact_id) DO UPDATE SET
                     artifact_count=EXCLUDED.artifact_count,
                     status='done',
                     answer=EXCLUDED.answer,
                     error=NULL,
                     count_domain=EXCLUDED.count_domain,
                     occurrence_count=EXCLUDED.occurrence_count,
                     unique_count=EXCLUDED.unique_count,
                     query_snapshot=EXCLUDED.query_snapshot,
                     parser_version=EXCLUDED.parser_version,
                     confidence=EXCLUDED.confidence,
                     updated_at=NOW()""",
                {
                    "jid": JOB,
                    "aid": str(aid),
                    "cnt": count,
                    "ans": (answer or "")[:8000],
                    "cd": persist.get("count_domain"),
                    "oc": persist.get("occurrence_count"),
                    "uc": persist.get("unique_count"),
                    "qs": json.dumps(persist.get("query_snapshot") or {}),
                    "pv": persist.get("parser_version"),
                    "conf": persist.get("confidence"),
                },
            )
            db.commit()
            print(f"OK {aid:<12} {count:>8}  {name}")

    db.close()


if __name__ == "__main__":
    main()
