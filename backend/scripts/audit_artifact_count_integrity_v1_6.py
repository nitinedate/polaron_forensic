from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import text

from app.db.session import SessionLocal, apply_firm_search_path
from app.services.artifact_selection_catalog import resolve_job_axiom_platform
from app.services.axiom_artifact_runner import load_stored_axiom_inventory, persist_collector_counts
from app.services.report_catalog_sync import REPORT_ARTIFACTS, ensure_report_template_artifacts


def _norm(s: str) -> str:
    return " ".join((s or "").strip().lower().replace(" / ", "/").split())


def _pct(delta: int, reference: int | None) -> float | None:
    if reference in (None, 0):
        return None
    return round((delta / reference) * 100.0, 2)


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit authoritative report-template artifact counts")
    ap.add_argument("--job", required=True)
    ap.add_argument("--schema", default="firm_aetheris")
    ap.add_argument("--reference-json")
    ap.add_argument("--out", default="/app/data/artifact_count_audit_v1_6.json")
    ap.add_argument("--csv", default="/app/data/artifact_count_audit_v1_6.csv")
    ap.add_argument("--no-refresh", action="store_true")
    args = ap.parse_args()

    reference: dict[str, int] = {}
    if args.reference_json:
        p = Path(args.reference_json)
        if p.exists():
            raw = json.loads(p.read_text(encoding="utf-8"))
            reference = {_norm(k): int(v) for k, v in raw.items()}

    with SessionLocal() as db:
        apply_firm_search_path(db, args.schema)
        platform = resolve_job_axiom_platform(db, args.job)
        ensure_report_template_artifacts(db, platform=platform)
        db.commit()
        if not args.no_refresh:
            print("Refreshing report-template collectors from evidence ...", flush=True)
            persist_collector_counts(db, args.job, platform=platform, report_only=True)
            db.commit()

        stored = load_stored_axiom_inventory(db, args.job)
        rows: list[dict] = []
        for art in REPORT_ARTIFACTS:
            name = art["name"]
            cat = art["category"]
            r = db.execute(
                text("""
                    SELECT artifact_id FROM public.axiom_artifacts
                    WHERE platform=:p AND artifact_name=:n AND category=:c
                    ORDER BY artifact_id LIMIT 1
                """),
                {"p": platform, "n": name, "c": cat},
            ).mappings().first()
            aid = str(r["artifact_id"]) if r else ""
            meta = stored.get(aid) or {}
            count = int(meta.get("count") or 0)
            ref = reference.get(_norm(name))
            delta = count - ref if ref is not None else None
            snap = meta.get("query_snapshot") or {}
            rows.append({
                "category": cat,
                "artifact": name,
                "artifact_id": aid,
                "reference_count": ref,
                "application_count": count,
                "delta": delta,
                "delta_pct": _pct(delta, ref) if delta is not None else None,
                "count_domain": meta.get("count_domain"),
                "query_id": snap.get("query_key") or snap.get("query_id"),
                "collector": snap.get("collector"),
                "confidence": meta.get("confidence"),
                "status": meta.get("status"),
                "query_snapshot": snap,
            })

        # Browser provenance/domain diagnostics are intentionally separate from primary counts.
        url_diag: dict = {}
        try:
            from app.services.browser_url_inventory import collect_job_browser_url_records
            from app.services.url_category_counts import classify_url_category
            urls = collect_job_browser_url_records(db, args.job)
            origins = Counter(str(r.get("record_origin") or "browser_history") for r in urls)
            hosts = Counter()
            categories = Counter()
            for rec in urls:
                if str(rec.get("record_origin") or "browser_history") != "browser_history":
                    continue
                url = str(rec.get("url") or "")
                host = (urlparse(url).hostname or "").lower()
                visits = max(int(rec.get("visit_count") or 0), 1)
                if host:
                    hosts[host] += visits
                categories[classify_url_category(url) or "other"] += visits
            url_diag = {
                "record_origins": dict(origins),
                "primary_visit_categories": dict(categories),
                "top_primary_hosts": hosts.most_common(40),
            }
        except Exception as exc:
            url_diag = {"error": str(exc)}

        payload = {
            "version": "1.6",
            "job_id": args.job,
            "schema": args.schema,
            "platform": platform,
            "reference_source": "operator-supplied benchmark JSON; validation only; never used as application count input",
            "rows": rows,
            "url_diagnostics": url_diag,
        }
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        with Path(args.csv).open("w", newline="", encoding="utf-8-sig") as fh:
            fields = [
                "category", "artifact", "artifact_id", "reference_count", "application_count",
                "delta", "delta_pct", "count_domain", "query_id", "collector", "confidence", "status",
            ]
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k) for k in fields})

        comparable = [r for r in rows if r["reference_count"] is not None]
        exact = sum(1 for r in comparable if r["delta"] == 0)
        print(f"Audit written: {args.out}")
        print(f"CSV written:   {args.csv}")
        print(f"Reference matches: {exact}/{len(comparable)} exact")
        print("Largest absolute deltas:")
        for r in sorted(comparable, key=lambda x: abs(int(x["delta"] or 0)), reverse=True)[:12]:
            print(f"  {r['artifact']}: reference={r['reference_count']} application={r['application_count']} delta={r['delta']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
