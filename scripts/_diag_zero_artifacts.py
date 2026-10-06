"""Diagnose near-zero AXIOM artifact inventory results."""
from __future__ import annotations

import json
from sqlalchemy import text
from app.db.session import firm_session_readonly

schema = "firm_aetheris"
with firm_session_readonly(schema) as db:
    jobs = db.execute(
        text(
            "SELECT id, status, created_at, updated_at "
            "FROM jobs ORDER BY created_at DESC LIMIT 3"
        )
    ).mappings().all()
    print("JOBS:")
    for j in jobs:
        print(dict(j))
    if not jobs:
        raise SystemExit(0)
    jid = str(jobs[0]["id"])
    arts = db.execute(
        text("SELECT COUNT(*) c FROM job_artifacts WHERE job_id=:j"), {"j": jid}
    ).scalar()
    print("job_artifacts", arts)
    res = db.execute(
        text(
            """
      SELECT status, COUNT(*) c,
             SUM(CASE WHEN COALESCE(artifact_count,0)>0 THEN 1 ELSE 0 END) nonzero
      FROM job_axiom_artifact_results WHERE job_id=:j GROUP BY status
    """
        ),
        {"j": jid},
    ).mappings().all()
    print("results by status:", [dict(r) for r in res])
    top = db.execute(
        text(
            """
      SELECT a.artifact_name, a.category, r.artifact_count, r.status,
             left(coalesce(r.error,''),160) err,
             left(coalesce(r.answer,''),120) answer
      FROM job_axiom_artifact_results r
      JOIN public.axiom_artifacts a ON a.artifact_id=r.artifact_id
      WHERE r.job_id=:j
      ORDER BY COALESCE(r.artifact_count,0) DESC, a.artifact_name
      LIMIT 50
    """
        ),
        {"j": jid},
    ).mappings().all()
    print("TOP:")
    for r in top:
        print(dict(r))
    zeros = db.execute(
        text(
            """
      SELECT a.category, COUNT(*) n,
             SUM(CASE WHEN COALESCE(r.artifact_count,0)>0 THEN 1 ELSE 0 END) nz,
             SUM(COALESCE(r.artifact_count,0)) total_hits
      FROM job_axiom_artifact_results r
      JOIN public.axiom_artifacts a ON a.artifact_id=r.artifact_id
      WHERE r.job_id=:j
      GROUP BY a.category ORDER BY total_hits DESC, n DESC
    """
        ),
        {"j": jid},
    ).mappings().all()
    print("BY CAT:")
    for r in zeros:
        print(dict(r))
    ds = db.execute(text("SELECT disk_source FROM jobs WHERE id=:j"), {"j": jid}).scalar()
    d = ds if isinstance(ds, dict) else json.loads(ds or "{}")
    carve = d.get("signature_carve_inventory") or {}
    print("carve keys", sorted(carve.keys()))
    print("carve axiom_counts", carve.get("axiom_counts"))
    print(
        "carve hit_total",
        carve.get("hit_total"),
        "sources",
        carve.get("sources_scanned"),
        "unalloc",
        carve.get("unalloc_bytes_scanned"),
    )
    print(
        "platform",
        d.get("axiom_platform"),
        d.get("evidence_platform"),
        "source_type",
        d.get("source_type"),
    )
    # Sample a few live counts
    from app.services.axiom_aligned_counts import count_axiom_catalog_artifact

    for name, cat in [
        ("USB Devices", "Connected Devices"),
        ("Picture", "Media"),
        ("PDF Documents", "Documents"),
        ("Jump Lists", "File Access and Handling"),
        ("Outlook Emails", "Email & Calendar"),
        ("Web Chat URLs", "Communication"),
    ]:
        try:
            c = count_axiom_catalog_artifact(
                db, jid, artifact_name=name, category=cat
            )
            print(f"LIVE count {name!r}: {c}")
        except Exception as exc:
            print(f"LIVE count {name!r} FAILED: {exc}")
