"""Deep diagnosis: PDF vs Excel vs stored vs live for report-template artifacts."""
from __future__ import annotations

import json
import sys

from sqlalchemy import text

from app.db.session import SessionLocal, apply_firm_search_path
from app.services.axiom_aligned_counts import (
    count_axiom_catalog_artifact,
    count_catalog_artifact_fallback,
    count_logfile_analysis_occurrences,
    count_media_occurrences_axiom,
    count_url_visit_occurrences,
)
from app.services.email_inventory import collect_email_artifact, count_eml_files, count_windows_mail
from app.services.report_catalog_sync import REPORT_ARTIFACTS

JOB = sys.argv[1] if len(sys.argv) > 1 else "d0996306-8429-420a-8303-a19357488596"


def main() -> int:
    with SessionLocal() as db:
        apply_firm_search_path(db, "firm_aetheris")
        inv = db.execute(
            text("SELECT disk_source->'media_disk_inventory' AS inv FROM jobs WHERE id=:j"),
            {"j": JOB},
        ).mappings().first()
        media = inv["inv"] if inv else {}
        print("=== media_disk_inventory ===")
        print(json.dumps(media, indent=2) if media else "NOT CACHED")
        print()

        browser = db.execute(
            text("SELECT count(*) AS c FROM job_artifacts WHERE job_id=:j AND (file_path ILIKE '%/History' OR file_path ILIKE '%places.sqlite%')"),
            {"j": JOB},
        ).scalar()
        print(f"Browser DB artifacts (History/places): {browser}")
        from app.services.browser_url_inventory import collect_job_browser_url_records

        urls = collect_job_browser_url_records(db, JOB)
        print(f"Browser URL records collected: {len(urls)}")
        chat = [u for u in urls if "whatsapp" in str(u.get("url", "")).lower() or "discord" in str(u.get("url", "")).lower()]
        print(f"Sample web-chat-like URLs: {len(chat)}")
        print()

        eml = count_eml_files(db, JOB)
        wm = count_windows_mail(db, JOB)
        print("=== Email collectors ===")
        print(f"EML(X): {eml}")
        print(f"Windows Mail: {wm}")
        wm_fb = count_catalog_artifact_fallback(db, JOB, artifact_name="Windows Mail", category="Email & Calendar")
        eml_fb = count_catalog_artifact_fallback(db, JOB, artifact_name="EML(X) Files", category="Email & Calendar")
        print(f"Windows Mail encyclopedia fallback: {wm_fb}")
        print(f"EML(X) encyclopedia fallback: {eml_fb}")
        print()

        log = count_logfile_analysis_occurrences(db, JOB)
        file_row = db.execute(
            text(
                """
                SELECT count(*) FROM job_artifacts ja
                WHERE ja.job_id=:j AND (
                  lower(coalesce(extension,'')) IN ('.log','.evtx','.etl')
                  OR file_path ILIKE '%/winevt/Logs/%'
                )
                """
            ),
            {"j": JOB},
        ).scalar()
        print(f"Logfile Analysis live={log}, job_artifacts log/evtx/winevt only={file_row}")
        print()

        print("=== Report template: stored vs live vs fallback ===")
        print(f"{'Artifact':28} {'stored':>8} {'live':>8} {'fallback':>8}")
        print("-" * 60)
        for art in REPORT_ARTIFACTS:
            name = art["name"]
            cat = art["category"]
            stored = db.execute(
                text(
                    """
                    SELECT r.occurrence_count, r.query_snapshot
                    FROM job_axiom_artifact_results r
                    JOIN public.axiom_artifacts aa ON aa.artifact_id = r.artifact_id
                    WHERE r.job_id=:j AND aa.artifact_name=:n AND aa.category=:c
                    """
                ),
                {"j": JOB, "n": name, "c": cat},
            ).mappings().first()
            db_count = int(stored["occurrence_count"]) if stored else None
            live = count_axiom_catalog_artifact(db, JOB, artifact_name=name, category=cat)
            fb = count_catalog_artifact_fallback(db, JOB, artifact_name=name, category=cat)
            if name.lower() in {"picture", "audio", "video", "photoshop files"}:
                kind = name.lower().replace("photoshop files", "photoshop")
                media_live = count_media_occurrences_axiom(db, JOB, kind)
            else:
                media_live = None
            extra = f" media={media_live}" if media_live is not None else ""
            print(f"{name:28} {str(db_count or ''):>8} {live:>8} {fb:>8}{extra}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
