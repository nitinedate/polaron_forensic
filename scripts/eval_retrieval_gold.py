"""Gold retrieval evaluation harness — build gold set, benchmark Recall@k, tune RRF weights."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

backend_root = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(backend_root))

from sqlalchemy import text

from app.config import get_settings
from app.db.session import SessionLocal, firm_session
from app.retrieval.hybrid import hybrid_retrieve
from app.services.encyclopedia_ingest import load_encyclopedia_from_jsonl


def build_gold_set(db) -> list[dict]:
    """Build gold questions from encyclopedia field rows + artifact search text."""
    rows = db.execute(
        text(
            """SELECT fr.field_name, fr.artifact_id, fr.search_text, fr.where_found,
                      ea.artifact_name, ea.category, ea.operating_system
               FROM public.encyclopedia_field_rows fr
               JOIN public.encyclopedia_artifacts ea ON ea.artifact_id = fr.artifact_id
               WHERE fr.search_text IS NOT NULL
               ORDER BY fr.supplement, fr.artifact_id
               LIMIT 500"""
        )
    ).mappings().all()

    gold: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        q = f"Where is {r['field_name']} found on {r.get('operating_system') or 'Windows'}?"
        key = f"{q}:{r['artifact_id']}"
        if key in seen:
            continue
        seen.add(key)
        gold.append({
            "question": q,
            "expected_artifact_ids": [r["artifact_id"]],
            "filters": {
                "os": (r.get("operating_system") or "").lower() or None,
                "category": (r.get("category") or "").lower() or None,
            },
            "source": "field_row",
            "field_name": r["field_name"],
        })

    arts = db.execute(
        text(
            """SELECT artifact_id, artifact_name, search_text, category, operating_system
               FROM public.encyclopedia_artifacts
               WHERE search_text IS NOT NULL AND length(search_text) > 50
               LIMIT 300"""
        )
    ).mappings().all()
    for a in arts:
        q = f"What forensic artifact is {a['artifact_name']}?"
        key = f"{q}:{a['artifact_id']}"
        if key in seen:
            continue
        seen.add(key)
        gold.append({
            "question": q,
            "expected_artifact_ids": [a["artifact_id"]],
            "filters": {"category": (a.get("category") or "").lower() or None},
            "source": "artifact",
        })

    return gold


def recall_at_k(expected: list[str], retrieved: list[dict], k: int) -> float:
    got = {str(c.get("artifact_id")) for c in retrieved[:k] if c.get("artifact_id")}
    exp = {str(e) for e in expected}
    if not exp:
        return 0.0
    return len(got & exp) / len(exp)


def run_benchmark(
    fdb,
    job_id: str,
    gold: list[dict],
    *,
    limit: int = 100,
    rrf_k: int | None = None,
) -> dict:
    settings = get_settings()
    k = rrf_k or settings.retrieval_rrf_k
    r1 = r3 = r5 = r10 = 0.0
    misses: list[dict] = []
    n = 0
    subset = gold[:limit]
    for g in subset:
        hits = hybrid_retrieve(fdb, job_id, g["question"], filters=g.get("filters"), top_k=10)
        r1 += recall_at_k(g["expected_artifact_ids"], hits, 1)
        r3 += recall_at_k(g["expected_artifact_ids"], hits, 3)
        r5 += recall_at_k(g["expected_artifact_ids"], hits, 5)
        r10 += recall_at_k(g["expected_artifact_ids"], hits, 10)
        if recall_at_k(g["expected_artifact_ids"], hits, 5) < 1.0:
            misses.append({"question": g["question"], "expected": g["expected_artifact_ids"], "got": [h.get("artifact_id") for h in hits[:5]]})
        n += 1

    return {
        "job_id": job_id,
        "questions": n,
        "rrf_k": k,
        "recall_at_1": r1 / n if n else 0,
        "recall_at_3": r3 / n if n else 0,
        "recall_at_5": r5 / n if n else 0,
        "recall_at_10": r10 / n if n else 0,
        "misses_sample": misses[:20],
        "target_recall_at_5": 0.95,
        "passes_target": (r5 / n >= 0.95) if n else False,
    }


def tune_rrf_k(fdb, job_id: str, gold: list[dict], *, limit: int = 50) -> dict:
    """Grid search RRF k parameter on a subset."""
    best = {"k": 60, "recall_at_5": 0.0}
    for k in (20, 40, 60, 80, 100):
        result = run_benchmark(fdb, job_id, gold, limit=limit, rrf_k=k)
        if result["recall_at_5"] > best["recall_at_5"]:
            best = {"k": k, "recall_at_5": result["recall_at_5"]}
    return best


def main() -> None:
    parser = argparse.ArgumentParser(description="RAG retrieval gold-set evaluation")
    parser.add_argument("--limit", type=int, default=100, help="Max gold questions to evaluate")
    parser.add_argument("--tune", action="store_true", help="Run RRF k tuning grid")
    parser.add_argument("--job-id", type=str, default=None, help="Specific job UUID")
    args = parser.parse_args()

    eval_dir = Path(__file__).resolve().parents[1] / "data" / "eval"
    eval_dir.mkdir(parents=True, exist_ok=True)
    gold_path = eval_dir / "gold_retrieval.jsonl"
    baseline_path = eval_dir / "baseline_retrieval.json"

    db = SessionLocal()
    load_encyclopedia_from_jsonl(db, force=False)
    gold = build_gold_set(db)
    with gold_path.open("w", encoding="utf-8") as f:
        for g in gold:
            f.write(json.dumps(g) + "\n")
    print(f"Wrote {len(gold)} gold questions to {gold_path}")

    firm = db.execute(text("SELECT schema_name FROM public.firms WHERE status='active' LIMIT 1")).mappings().first()
    db.close()
    if not firm:
        print("No active firm — gold set only, skipping live eval")
        return

    schema = firm["schema_name"]
    with firm_session(schema) as fdb:
        if args.job_id:
            job_id = args.job_id
        else:
            job_row = fdb.execute(text("SELECT id FROM jobs WHERE status IN ('indexed','report_ready') ORDER BY updated_at DESC LIMIT 1")).mappings().first()
            if not job_row:
                job_row = fdb.execute(text("SELECT id FROM jobs ORDER BY created_at DESC LIMIT 1")).mappings().first()
            if not job_row:
                print("No jobs — skipping retrieval metrics")
                return
            job_id = str(job_row["id"])

        if args.tune:
            tuned = tune_rrf_k(fdb, job_id, gold, limit=min(50, args.limit))
            print(f"Best RRF k={tuned['k']} Recall@5={tuned['recall_at_5']:.2%}")

        result = run_benchmark(fdb, job_id, gold, limit=args.limit)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        result["embedding_model"] = get_settings().rag_embedding_model
        result["gold_set_size"] = len(gold)

        baseline_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Recall@1:  {result['recall_at_1']:.2%}")
        print(f"Recall@3:  {result['recall_at_3']:.2%}")
        print(f"Recall@5:  {result['recall_at_5']:.2%}")
        print(f"Recall@10: {result['recall_at_10']:.2%}")
        print(f"Target Recall@5 ≥ 95%: {'PASS' if result['passes_target'] else 'FAIL'}")
        print(f"Baseline written to {baseline_path}")


if __name__ == "__main__":
    main()
