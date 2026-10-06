"""Fill remaining Section B gaps (counts only — no message body dumps) and persist."""

from __future__ import annotations

import json

from sqlalchemy import text

from app.db.session import SessionLocal
from app.db.sql_helpers import execute
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact_result
from app.services.browser_url_inventory import clear_browser_url_cache
from app.services.encryption_inventory import clear_encryption_count_cache
from app.services.inventory_path_cache import clear_path_cache
from app.services.pst_mailbox_inventory import clear_pst_cache, scan_job_pst_mailboxes

JOB = "d963d7b1-fc00-40bb-865e-85fc365f874b"

PDF = {
    "USB Devices": 39,
    "Your Phone Device": 2,
    "Remote Desktop Protocol (RDP)": 6,
    "Feature Usage": 42,
    "Installed Microsoft Programs": 31,
    "Installed Programs (Non-Microsoft)": 167,
    "Windows Defender Logs": 3,
    "Web Chat URLs": 10,
    "Social Media URLs": 50,
    "Malware/Phishing URLs": 0,
    "CSV Documents": 5,
    "Microsoft PowerPoint Documents": 21,
    "Microsoft Excel Documents": 150,
    "PDF Documents": 400,
    "RTF Documents": 5847,
    "Text Documents": 2473,
    "Microsoft Word Documents": 305,
    "Email Attachments": 312,
    "EML(X) Files": 18,
    "Windows Mail": 0,
    "Outlook Emails": 216,
    "Outlook Tasks": 0,
    "Outlook Contacts": 0,
    "Outlook Appointments": 0,
    "Encrypted Files": 56,
    "Windows Stored Credentials": 0,
    "Audio": 594,
    "Picture": 70580,
    "Video": 330,
    "Photoshop Files": 50,
    "Logfile Analysis": 12463,
    "Jump List": 721,
    "LNK Files": 1443,
}

CATS = {
    "USB Devices": "Connected Devices",
    "Your Phone Device": "Connected Devices",
    "Remote Desktop Protocol (RDP)": "Connected Devices",
    "Feature Usage": "Application Usages",
    "Installed Microsoft Programs": "Application Usages",
    "Installed Programs (Non-Microsoft)": "Application Usages",
    "Windows Defender Logs": "Application Usages",
    "Web Chat URLs": "Communication",
    "Social Media URLs": "Communication",
    "Malware/Phishing URLs": "Communication",
    "CSV Documents": "Documents",
    "Microsoft PowerPoint Documents": "Documents",
    "Microsoft Excel Documents": "Documents",
    "PDF Documents": "Documents",
    "RTF Documents": "Documents",
    "Text Documents": "Documents",
    "Microsoft Word Documents": "Documents",
    "Email Attachments": "Email & Calendar",
    "EML(X) Files": "Email & Calendar",
    "Windows Mail": "Email & Calendar",
    "Outlook Emails": "Email & Calendar",
    "Outlook Tasks": "Email & Calendar",
    "Outlook Contacts": "Email & Calendar",
    "Outlook Appointments": "Email & Calendar",
    "Encrypted Files": "Encryption & Credentials",
    "Windows Stored Credentials": "Encryption & Credentials",
    "Audio": "Media",
    "Picture": "Media",
    "Video": "Media",
    "Photoshop Files": "Media",
    "Logfile Analysis": "Operating System",
    "Jump List": "Operating System",
    "LNK Files": "Operating System",
    "Web Related Files": "Web Related",
}


def _warm_media(db) -> dict:
    from app.services.disk_ext_census import ensure_disk_extension_censuses
    from app.services.media_inventory import build_media_disk_inventory

    ensure_disk_extension_censuses(db, JOB, force=True)
    inv = build_media_disk_inventory(db, JOB, force=True)
    return {
        "picture": inv.get("picture"),
        "picture_with_thumbcache": inv.get("picture_with_thumbcache"),
        "thumbcache_entries": inv.get("thumbcache_entries"),
        "video": inv.get("video"),
        "audio": inv.get("audio"),
        "photoshop": inv.get("photoshop"),
        "enumerated_files": inv.get("enumerated_files"),
        "source": inv.get("source"),
    }


def main() -> None:
    clear_path_cache(JOB)
    clear_encryption_count_cache(JOB)
    clear_pst_cache(JOB)
    clear_browser_url_cache(JOB)

    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))

    print("=== Warm media/document census + thumbcache ===")
    try:
        media = _warm_media(db)
        print("media", media)
    except Exception as exc:
        db.rollback()
        print("media_warm_failed", type(exc).__name__, str(exc)[:200])

    print("=== PST mailbox scan (counts only) ===")
    try:
        pst = scan_job_pst_mailboxes(db, JOB, force=True)
        print(
            "pst",
            {
                "mailbox_files": pst.get("mailbox_files"),
                "message_count": pst.get("message_count"),
                "attachment_estimate": pst.get("attachment_estimate"),
                "metadata_rows": len(pst.get("messages") or []),
            },
        )
    except Exception as exc:
        db.rollback()
        print("pst_failed", type(exc).__name__, str(exc)[:200])

    print("=== Persist Section B ===")
    print(f"{'Artifact':<40} {'PDF':>8} {'NEW':>8} {'DELTA':>8}")
    gaps = []
    for name, expected in list(PDF.items()) + [("Web Related Files", None)]:
        category = CATS[name]
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
        count = 0
        for (aid,) in rows or [(None,)]:
            if not aid:
                continue
            try:
                result = count_axiom_catalog_artifact_result(
                    db, JOB, artifact_name=name, category=category, artifact_id=str(aid)
                )
            except Exception as exc:
                db.rollback()
                print(f"{name:<40} FAIL {exc}")
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
        if expected is None:
            print(f"{name:<40} {'n/a':>8} {count:>8}")
            continue
        delta = count - expected
        print(f"{name:<40} {expected:>8} {count:>8} {delta:>+8}")
        if delta:
            gaps.append((abs(delta), name, expected, count, delta))

    print("\nTop remaining gaps:")
    for _a, name, expected, count, delta in sorted(gaps, reverse=True)[:12]:
        print(f"  {delta:+8}  PDF={expected} NEW={count}  {name}")
    db.close()


if __name__ == "__main__":
    main()
