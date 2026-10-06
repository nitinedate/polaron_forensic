"""Re-run full-disk media census with system-video filter; persist Media Section B."""

from __future__ import annotations

import json

from sqlalchemy import text

from app.db.session import SessionLocal
from app.db.sql_helpers import execute
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact_result
from app.services.media_inventory import build_media_disk_inventory

JOB = "d963d7b1-fc00-40bb-865e-85fc365f874b"
MEDIA = [
    ("Audio", "Media"),
    ("Picture", "Media"),
    ("Video", "Media"),
    ("Photoshop Files", "Media"),
]


def main() -> None:
    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))
    # Clear cached media so force rebuild applies new video path filter.
    row = db.execute(text("SELECT disk_source FROM jobs WHERE id=:j"), {"j": JOB}).mappings().first()
    ds = row["disk_source"] if row else {}
    if isinstance(ds, str):
        ds = json.loads(ds)
    if isinstance(ds, dict):
        ds.pop("media_disk_inventory", None)
        ds.pop("document_disk_inventory", None)
        ds.pop("lnk_disk_count", None)
        db.execute(
            text("UPDATE jobs SET disk_source=CAST(:ds AS jsonb), updated_at=NOW() WHERE id=:j"),
            {"j": JOB, "ds": json.dumps(ds)},
        )
        db.commit()

    inv = build_media_disk_inventory(db, JOB, force=True)
    print(
        {
            "picture": inv.get("picture"),
            "picture_with_thumbcache": inv.get("picture_with_thumbcache"),
            "thumbs": inv.get("thumbcache_entries"),
            "video": inv.get("video"),
            "audio": inv.get("audio"),
            "photoshop": inv.get("photoshop"),
            "enumerated": inv.get("enumerated_files"),
            "source": inv.get("source"),
        }
    )
    for name, cat in MEDIA:
        rows = db.execute(
            text(
                """SELECT artifact_id FROM public.axiom_artifacts
                   WHERE platform='Windows' AND artifact_name=:n
                   ORDER BY CASE WHEN artifact_id LIKE 'RPT-%' THEN 0 ELSE 1 END"""
            ),
            {"n": name},
        ).fetchall()
        for (aid,) in rows:
            result = count_axiom_catalog_artifact_result(
                db, JOB, artifact_name=name, category=cat, artifact_id=str(aid)
            )
            persist = result.persist_fields()
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
                     occurrence_count=EXCLUDED.occurrence_count,
                     answer=EXCLUDED.answer,
                     query_snapshot=EXCLUDED.query_snapshot,
                     updated_at=NOW()""",
                {
                    "jid": JOB,
                    "aid": str(aid),
                    "cnt": result.primary_count,
                    "ans": result.answer_text(name)[:8000],
                    "cd": persist.get("count_domain"),
                    "oc": persist.get("occurrence_count"),
                    "uc": persist.get("unique_count"),
                    "qs": json.dumps(persist.get("query_snapshot") or {}),
                    "pv": persist.get("parser_version"),
                    "conf": persist.get("confidence"),
                },
            )
            db.commit()
            print(name, result.primary_count)
    db.close()


if __name__ == "__main__":
    main()
