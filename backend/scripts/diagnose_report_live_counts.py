"""Live + stored counts for report-template artifacts (runs inside API container)."""
from __future__ import annotations

import json
import sys

from sqlalchemy import text

from app.db.session import SessionLocal, apply_firm_search_path
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact_result
from app.services.report_catalog_sync import REPORT_ARTIFACTS


def main() -> int:
    job_id = sys.argv[1] if len(sys.argv) > 1 else "d0996306-8429-420a-8303-a19357488596"
    print(f"Job: {job_id}")
    print(f"{'Artifact':32} {'stored':>8} {'live':>8}  query / collector")
    print("-" * 90)

    with SessionLocal() as db:
        apply_firm_search_path(db, "firm_aetheris")
        inv = db.execute(
            text("SELECT disk_source->'media_disk_inventory' AS inv FROM jobs WHERE id=:j"),
            {"j": job_id},
        ).mappings().first()
        media = inv["inv"] if inv else None
        if media:
            print(
                "media_disk_inventory:",
                {k: media.get(k) for k in ("audio", "picture", "video", "photoshop", "enumerated_files", "picture_with_thumbcache")},
            )
        else:
            print("media_disk_inventory: NOT CACHED (live media counts will trigger full-disk scan)")
        print()

        for art in REPORT_ARTIFACTS:
            name = art["name"]
            cat = art["category"]
            stored = db.execute(
                text(
                    """
                    SELECT jar.occurrence_count, jar.query_id, jar.query_snapshot
                    FROM job_axiom_artifact_results jar
                    JOIN public.axiom_artifacts aa ON aa.artifact_id = jar.artifact_id
                    WHERE jar.job_id=:j AND aa.artifact_name=:n AND aa.category=:c
                    LIMIT 1
                    """
                ),
                {"j": job_id, "n": name, "c": cat},
            ).mappings().first()
            db_count = int(stored["occurrence_count"]) if stored else None
            snap = stored["query_snapshot"] if stored else {}
            if isinstance(snap, str):
                try:
                    snap = json.loads(snap)
                except Exception:
                    snap = {}

            result = count_axiom_catalog_artifact_result(
                db, job_id, artifact_name=name, category=cat,
            )
            live = int(result.occurrence_count)
            collector = (result.query_snapshot or {}).get("collector") or snap.get("collector") or "-"
            query_id = result.query_id or (stored["query_id"] if stored else "") or "-"
            db_s = "" if db_count is None else str(db_count)
            print(f"{name:32} {db_s:>8} {live:>8}  {query_id} / {collector}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
