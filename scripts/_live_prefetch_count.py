from sqlalchemy import text
from app.db.session import firm_session_readonly
from app.services.axiom_aligned_counts import count_axiom_catalog_artifact, count_axiom_catalog_artifact_result
from app.services.inventory_path_cache import clear_path_cache, ensure_fallback_path_counts

jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
with firm_session_readonly("firm_aetheris") as db:
    rows = [
        dict(r)
        for r in db.execute(
            text(
                "SELECT artifact_id, artifact_name, category FROM public.axiom_artifacts WHERE platform='Windows'"
            )
        ).mappings().all()
    ]
    clear_path_cache(jid)
    ensure_fallback_path_counts(db, jid, rows)
    for name in [
        "Prefetch Files - Windows 8/10/11",
        "Windows Viber Chat Messages",
        "Windows Event Logs",
    ]:
        meta = next(r for r in rows if r["artifact_name"] == name)
        c = count_axiom_catalog_artifact(
            db,
            jid,
            artifact_name=name,
            category=meta["category"],
            artifact_id=str(meta["artifact_id"]),
        )
        cr = count_axiom_catalog_artifact_result(
            db,
            jid,
            artifact_name=name,
            category=meta["category"],
            artifact_id=str(meta["artifact_id"]),
        )
        print(
            name,
            "count=",
            c,
            "result=",
            cr.primary_count,
            "domain=",
            cr.count_domain,
            "snap=",
            str(cr.query_snapshot)[:200],
        )
