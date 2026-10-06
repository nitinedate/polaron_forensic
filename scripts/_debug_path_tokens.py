"""Debug why Prefetch/Viber path-index counts explode."""
from __future__ import annotations

from sqlalchemy import text
from app.db.session import firm_session_readonly
from app.services.inventory_path_cache import (
    _tokens_from_name,
    ensure_fallback_path_counts,
    get_fallback_path_count,
    clear_path_cache,
)

with firm_session_readonly("firm_aetheris") as db:
    jid = "7b338252-27c8-4f68-9029-d9bde42c4a2c"
    rows = db.execute(
        text(
            """
      SELECT artifact_id, artifact_name FROM public.axiom_artifacts
      WHERE platform='Windows' AND artifact_name IN (
        'Prefetch Files - Windows 8/10/11',
        'Windows Viber Chat Messages',
        'Windows Event Logs',
        'USB Devices',
        'Jump Lists'
      )
    """
        )
    ).mappings().all()
    for r in rows:
        print(r["artifact_name"], "tokens=", sorted(_tokens_from_name(r["artifact_name"])))

    clear_path_cache(jid)
    ensure_fallback_path_counts(db, jid, [dict(r) for r in rows])
    for r in rows:
        print(
            "path_count",
            r["artifact_name"],
            get_fallback_path_count(jid, str(r["artifact_id"])),
        )

    # How many paths contain 'prefetch' / 'viber'?
    for tok in ("prefetch", "viber", "event", "events"):
        n = db.execute(
            text(
                "SELECT count(*) FROM job_artifacts WHERE job_id=:j AND lower(file_path) LIKE :p"
            ),
            {"j": jid, "p": f"%{tok}%"},
        ).scalar()
        print(f"paths containing {tok!r}: {n}")
