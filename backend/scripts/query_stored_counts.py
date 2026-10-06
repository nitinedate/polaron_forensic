from app.db.session import SessionLocal, apply_firm_search_path
from sqlalchemy import text

JOB = "d0996306-8429-420a-8303-a19357488596"
NAMES = [
    "Picture", "Audio", "Video", "Photoshop Files",
    "Web Chat URLs", "Social Media URLs", "Windows Mail", "EML(X) Files",
    "Logfile Analysis", "Outlook Emails",
]

with SessionLocal() as db:
    apply_firm_search_path(db, "firm_aetheris")
    rows = db.execute(
        text(
            """
            SELECT r.artifact_id, aa.artifact_name, aa.category,
                   r.occurrence_count, r.artifact_count, r.query_snapshot
            FROM job_axiom_artifact_results r
            JOIN public.axiom_artifacts aa ON aa.artifact_id = r.artifact_id
            WHERE r.job_id=:j AND aa.artifact_name = ANY(:names)
            ORDER BY aa.category, aa.artifact_name
            """
        ),
        {"j": JOB, "names": NAMES},
    ).mappings().all()
    for r in rows:
        snap = r["query_snapshot"]
        print(
            f"{r['artifact_name']:22} stored={r['occurrence_count']:>8} "
            f"artifact_count={r['artifact_count']:>8} snap={str(snap)[:100]}"
        )
