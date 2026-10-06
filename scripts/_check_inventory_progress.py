from sqlalchemy import text
from app.db.session import firm_session_readonly

with firm_session_readonly("firm_aetheris") as db:
    jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
    res = db.execute(
        text(
            """
      SELECT status, COUNT(*) c,
             SUM(CASE WHEN COALESCE(artifact_count,0)>0 THEN 1 ELSE 0 END) nz
      FROM job_axiom_artifact_results WHERE job_id=:j GROUP BY status
    """
        ),
        {"j": jid},
    ).mappings().all()
    print("status:", [dict(r) for r in res])
    top = db.execute(
        text(
            """
      SELECT a.artifact_name, r.artifact_count
      FROM job_axiom_artifact_results r
      JOIN public.axiom_artifacts a ON a.artifact_id=r.artifact_id
      WHERE r.job_id=:j AND COALESCE(r.artifact_count,0)>0
      ORDER BY r.artifact_count DESC LIMIT 25
    """
        ),
        {"j": jid},
    ).mappings().all()
    print("nonzero:")
    for r in top:
        print(dict(r))
    cats = db.execute(
        text(
            """
      SELECT a.category,
             SUM(CASE WHEN COALESCE(r.artifact_count,0)>0 THEN 1 ELSE 0 END) nz,
             COUNT(*) n,
             SUM(COALESCE(r.artifact_count,0)) hits
      FROM job_axiom_artifact_results r
      JOIN public.axiom_artifacts a ON a.artifact_id=r.artifact_id
      WHERE r.job_id=:j
      GROUP BY a.category ORDER BY hits DESC
    """
        ),
        {"j": jid},
    ).mappings().all()
    print("cats:")
    for r in cats:
        print(dict(r))
