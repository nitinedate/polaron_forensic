"""Print the AXIOM Section B artifact → count domain → query/collector → sources catalog.

Works without a database (reads the code-level specs). Use it to answer
"which query produces this artifact's number?" before opening psql.

    cd backend
    python scripts/axiom_query_catalog.py            # markdown table
    python scripts/axiom_query_catalog.py --csv > axiom_query_catalog.csv
    python scripts/axiom_query_catalog.py --job <uuid> --dsn postgresql://... --schema firm_x   # live counts
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def static_rows() -> list[dict]:
    from app.services.axiom_count_spec import ARTIFACT_COUNT_METADATA
    from app.services.axiom_query_manifest import (
        COLLECTOR_SOURCES,
        _SQL_COLLECTORS,
        _document_extensions_for,
        _runnable_fragments,
        _runnable_sql_for,
    )

    frags = _runnable_fragments()
    rows = []
    for name, meta in ARTIFACT_COUNT_METADATA.items():
        qk = str(meta.get("query_key") or "")
        cm = COLLECTOR_SOURCES.get(qk) or _SQL_COLLECTORS.get(qk) or {}
        if not cm and _document_extensions_for(name):
            cm = COLLECTOR_SOURCES["DOCUMENT_FULL_DISK"]
        rows.append(
            {
                "artifact": name,
                "count_domain": meta.get("count_domain"),
                "record_unit": cm.get("record_unit") or meta.get("record_unit"),
                "query_key": qk,
                "collector": cm.get("collector") or "",
                "sources": " | ".join(cm.get("sources") or []),
                "sql_where": _runnable_sql_for(name, qk, frags) or "",
                "axiom_note": cm.get("axiom_note") or "",
            }
        )
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", action="store_true")
    ap.add_argument("--job", help="job uuid: emit the live per-job manifest instead of the static catalog")
    ap.add_argument("--dsn", default=os.environ.get("DATABASE_URL"))
    ap.add_argument("--schema", default=None, help="firm schema (search_path) for the job")
    args = ap.parse_args()

    if args.job:
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import Session

        from app.services.axiom_query_manifest import build_query_manifest, manifest_to_csv

        eng = create_engine(args.dsn)
        with Session(eng) as db:
            if args.schema:
                db.execute(text(f'SET search_path TO "{args.schema}", public'))
            m = build_query_manifest(db, args.job)
        if args.csv:
            sys.stdout.write(manifest_to_csv(m))
        else:
            print(f"job={m['job_id']} platform={m['platform']} artifacts={m['artifact_total']} "
                  f"with_reference={m['with_axiom_reference']} matched={m['matched']} gaps={m['gaps']}")
            for it in m["items"]:
                print(f"{it['artifact_name']:<40} {str(it['app_count']):>8} {str(it['axiom_count']):>8} "
                      f"{str(it['delta']):>8}  {it['count_domain']:<18} {it['query_key']}")
        return 0

    rows = static_rows()
    if args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
        return 0
    print("| Artifact | Domain | Record unit | Query key | Collector | Sources |")
    print("|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['artifact']} | {r['count_domain']} | {r['record_unit'] or ''} | {r['query_key']} | "
              f"{r['collector']} | {r['sources']} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
