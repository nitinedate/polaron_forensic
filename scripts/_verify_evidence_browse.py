"""Verify browser URL extraction + evidence browse for Section B."""

from sqlalchemy import text

from app.db.session import SessionLocal
from app.db.sql_helpers import fetchall
from app.services.artifact_evidence_browse import list_evidence_items
from app.services.artifact_list_queries import list_where_for_catalog_key
from app.services.browser_url_inventory import (
    _BROWSER_SOURCE_SQL,
    _CACHE_LOCK,
    _URL_RECORDS_CACHE,
    _URL_TOTALS_CACHE,
    collect_job_browser_url_records,
    compute_communication_url_totals,
)
from app.services.url_category_counts import classify_url_category

JOB = "d963d7b1-fc00-40bb-865e-85fc365f874b"


def main() -> None:
    with _CACHE_LOCK:
        _URL_RECORDS_CACHE.pop(JOB, None)
        _URL_TOTALS_CACHE.pop(JOB, None)

    db = SessionLocal()
    db.execute(text("SET search_path TO firm_aetheris, public"))

    rows = fetchall(db, _BROWSER_SOURCE_SQL, {"j": JOB})
    print("browser source rows", len(rows))
    for r in rows[:12]:
        print(" ", r.get("file_path"), r.get("size_bytes"))

    recs = collect_job_browser_url_records(db, JOB)
    print("url records", len(recs))
    cats: dict[str, int] = {}
    for r in recs:
        c = classify_url_category(r.get("url") or "") or "other"
        cats[c] = cats.get(c, 0) + int(r.get("visit_count") or 1)
    print("visit totals by category", cats)
    print("totals helper", compute_communication_url_totals(db, JOB))

    for key in ("RPT-ART-004", "RPT-ART-005", "RPT-ART-013"):
        ev = list_evidence_items(db, JOB, catalog_key=key, page=1, page_size=5)
        if not ev:
            print(key, "no evidence mode")
            continue
        sample = ev["items"][0]["title"][:100] if ev["items"] else None
        print(key, "total", ev["total"], "sample", sample)

    suf, params = list_where_for_catalog_key(db, JOB, "AX-0194")
    cnt = db.execute(
        text(f"SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid {suf}"),
        params,
    ).mappings().first()
    print("outlook email files", cnt)

    db.close()


if __name__ == "__main__":
    main()
