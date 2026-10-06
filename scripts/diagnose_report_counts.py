"""Diagnose report-template artifact counts vs PDF for a job."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from app.db.session import SessionLocal, apply_firm_search_path
from app.services.axiom_aligned_counts import (
    count_axiom_catalog_artifact,
    count_axiom_catalog_artifact_result,
    count_logfile_analysis_occurrences,
    count_media_occurrences_axiom,
    count_url_visit_occurrences,
)
from app.services.email_inventory import collect_email_artifact, count_eml_files, count_windows_mail
from app.services.report_catalog_sync import REPORT_ARTIFACTS
from compare_pdf_excel_artifacts import load_excel, parse_pdf_artifacts, normalize_key


def main() -> int:
    job_id = sys.argv[1] if len(sys.argv) > 1 else "d0996306-8429-420a-8303-a19357488596"
    pdf_path = Path(
        sys.argv[2]
        if len(sys.argv) > 2
        else r"d:\all\Fotrensics_Data\DISK1\HDD\Report\Ex-5 Histotechlab1 Report.pdf"
    )
    xlsx_path = Path(
        sys.argv[3]
        if len(sys.argv) > 3
        else r"e:\artifacts_d0996306 (1).xlsx"
    )

    pdf = parse_pdf_artifacts(pdf_path)
    excel = load_excel(xlsx_path)
    pdf_by_norm = {normalize_key(k): v for k, v in pdf.items()}
    excel_by_norm = {normalize_key(k): v for k, v in excel.items()}

    print(f"Job: {job_id}")
    print(f"PDF: {pdf_path} ({len(pdf)} artifacts)")
    print(f"Excel: {xlsx_path} ({len(excel)} rows)")
    print()
    print(f"{'Artifact':32} {'PDF':>8} {'Excel':>8} {'DB':>8} {'live':>8}  collector/query")
    print("-" * 110)

    with SessionLocal() as db:
        apply_firm_search_path(db, "firm_aetheris")
        from sqlalchemy import text

        inv_row = db.execute(
            text("SELECT disk_source->'media_disk_inventory' AS inv FROM jobs WHERE id=:j"),
            {"j": job_id},
        ).mappings().first()
        inv = inv_row["inv"] if inv_row else None
        if inv:
            print(
                "media_disk_inventory cached:",
                {k: inv.get(k) for k in ("audio", "picture", "video", "photoshop", "enumerated_files")},
            )
        else:
            print("media_disk_inventory: NOT CACHED")
        print()

        for art in REPORT_ARTIFACTS:
            name = art["name"]
            cat = art["category"]
            norm = normalize_key(name)
            pdf_count = pdf_by_norm.get(norm)
            excel_count = excel_by_norm.get(norm)

            stored = db.execute(
                text(
                    """
                    SELECT jar.occurrence_count, jar.query_id, jar.query_snapshot
                    FROM job_axiom_artifact_results jar
                    JOIN axiom_artifacts aa ON aa.id = jar.artifact_id
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
            live_count = int(result.occurrence_count)
            collector = (result.query_snapshot or {}).get("collector") or snap.get("collector")
            query_id = result.query_id or (stored["query_id"] if stored else "")

            pdf_s = "" if pdf_count is None else str(pdf_count)
            excel_s = "" if excel_count is None else str(excel_count)
            db_s = "" if db_count is None else str(db_count)
            flag = " ***" if pdf_count is not None and live_count != pdf_count else ""
            print(
                f"{name:32} {pdf_s:>8} {excel_s:>8} {db_s:>8} {live_count:>8}{flag}  {collector or '-'} / {query_id or '-'}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
