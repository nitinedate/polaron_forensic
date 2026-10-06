"""Diagnose a stalled "Artifact inventory — 0 / N" stage in under a minute (V45.2).

Run inside the api container (it has Redis, Postgres and Celery access):

    docker compose exec api python /app/../diagnostics/diagnose_inventory_stall.py <job_id> [firm_schema]

or from the repo root on Windows:  Diagnose-Inventory-Stall.cmd <job_id> [firm_schema]

It prints, in order, the five things that decide whether inventory is
(a) not running, (b) queued behind other work, (c) running but slow in a
specific step, or (d) blocked inside Postgres:

  1. Celery: is axiom_artifact_inventory_task active/reserved on any worker?
  2. Redis: inventory job lock + GPU/CPU heavy lanes (holder, age, stale?)
  3. Redis: depth of disk-parse / disk-inventory / disk-build queues
  4. Postgres: every non-idle session touching this job's tables — running
     query, wait_event, and who is blocking whom (pg_blocking_pids)
  5. disk_build_logs: last 15 artifact_inventory lines with age

Read-only. Nothing is modified.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone


def _age(ts) -> str:
    if ts is None:
        return "?"
    if getattr(ts, "tzinfo", None) is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return f"{(datetime.now(timezone.utc) - ts).total_seconds():,.0f}s ago"


def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    job_id = sys.argv[1]
    schema = sys.argv[2] if len(sys.argv) > 2 else None
    sys.path.insert(0, "/app")

    # ------------------------------------------------------------- 1. Celery
    section("1. Celery — is the inventory task running or reserved anywhere?")
    try:
        from app.celery_app import celery

        insp = celery.control.inspect(timeout=5.0)
        found = False
        for kind, data in (("active", insp.active() or {}), ("reserved", insp.reserved() or {}), ("scheduled", insp.scheduled() or {})):
            for worker, tasks in data.items():
                for t in tasks or []:
                    name = t.get("name") or (t.get("request") or {}).get("name") or ""
                    args = t.get("args") or (t.get("request") or {}).get("args") or []
                    if "inventory" in name or job_id in json.dumps(args):
                        found = True
                        started = t.get("time_start")
                        age = f"{time.time() - float(started):,.0f}s" if started else "-"
                        print(f"  [{kind}] {worker}: {name} args={args} pid={t.get('worker_pid')} running={age}")
        if not found:
            print("  NO inventory task active/reserved on any worker -> it is not running (dead, lost, or never dispatched)")
        stats = insp.stats() or {}
        for w, s in stats.items():
            pool = (s.get("pool") or {})
            print(f"  worker {w}: pool={pool.get('implementation','?')} max-concurrency={pool.get('max-concurrency','?')} processes={len(pool.get('processes') or [])}")
    except Exception as exc:
        print(f"  celery inspect failed: {exc}")

    # -------------------------------------------------------------- 2. Redis
    section("2. Redis — job lock + heavy lanes")
    try:
        from app.services import job_locks as jl

        client = jl._redis_client()
        prefix = jl._service_lane_prefix()
        keys = [jl.job_lock_key("inventory", job_id)]
        keys += [k.decode() if isinstance(k, bytes) else k for k in client.scan_iter(match=f"*inventory*{job_id}*")]
        seen = set()
        for k in keys:
            if k in seen:
                continue
            seen.add(k)
            raw = client.get(k)
            if raw is None:
                continue
            ttl = client.ttl(k)
            try:
                d = json.loads(raw)
                hb = d.get("heartbeat")
                print(f"  {k}: ttl={ttl}s pid={d.get('pid')} reason={d.get('reason')} heartbeat={time.time()-float(hb):,.0f}s ago stale={jl.heavy_holder_is_stale(d)}")
            except Exception:
                print(f"  {k}: ttl={ttl}s value={raw[:80]!r}")
        if len(seen) == 0:
            print("  no inventory lock held -> either finished, never started, or expired (worker dead > 300s)")
        for key in jl._gpu_slot_keys():
            h = jl._lock_held(key)
            print(f"  GPU lane {key}: {('held by %s pid=%s %.0fs' % (h.get('reason'), h.get('pid'), time.time()-float(h.get('started') or time.time()))) if h else 'free'}")
        for key in jl._cpu_slot_keys():
            h = jl._lock_held(key)
            print(f"  CPU lane {key}: {('held by %s pid=%s job=%s' % (h.get('reason'), h.get('pid'), h.get('job_id'))) if h else 'free'}")
    except Exception as exc:
        print(f"  redis inspection failed: {exc}")

    # ------------------------------------------------------- 3. Queue depth
    section("3. Redis — Celery queue depth (tasks waiting for a free worker slot)")
    try:
        import redis as _redis

        url = os.environ.get("REDIS_URL") or "redis://redis:6379/0"
        r = _redis.Redis.from_url(url)
        for q in ("disk-inventory", "disk-parse", "disk-build", "rag-index", "ocr", "agent-orchestration"):
            n = r.llen(q)
            flag = "   <-- inventory waits here if every slot is busy" if q in ("disk-parse", "disk-inventory") and n else ""
            print(f"  {q:20s} {n}{flag}")
    except Exception as exc:
        print(f"  queue depth failed: {exc}")

    # ------------------------------------------------------- 4. Postgres
    section("4. Postgres — non-idle sessions, waits and blockers")
    try:
        from sqlalchemy import text

        from app.db.session import SessionLocal

        db = SessionLocal()
        if schema:
            db.execute(text(f'SET search_path TO "{schema}", public'))
        rows = db.execute(text("""
            SELECT pid, application_name, state, wait_event_type, wait_event,
                   now() - query_start AS running_for,
                   now() - state_change AS in_state_for,
                   pg_blocking_pids(pid) AS blocked_by,
                   left(regexp_replace(query, '\\s+', ' ', 'g'), 160) AS q
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND pid <> pg_backend_pid()
              AND state <> 'idle'
            ORDER BY query_start NULLS LAST
        """)).mappings().all()
        if not rows:
            print("  no non-idle sessions -> the DB is NOT where the time goes; the task is not running or is idle in Python")
        for r in rows:
            blk = list(r["blocked_by"] or [])
            print(f"  pid={r['pid']} app={r['application_name'] or '-'} state={r['state']} wait={r['wait_event_type'] or '-'}/{r['wait_event'] or '-'} running={r['running_for']} blocked_by={blk or '-'}")
            print(f"      {r['q']}")
        idle_tx = db.execute(text("""
            SELECT count(*) AS n, coalesce(max(now() - state_change), interval '0') AS oldest
            FROM pg_stat_activity
            WHERE datname = current_database() AND state = 'idle in transaction'
        """)).mappings().one()
        print(f"  idle-in-transaction sessions: {idle_tx['n']} (oldest {idle_tx['oldest']}) -> these block any ALTER TABLE/index DDL")
        locks = db.execute(text("""
            SELECT l.pid, l.mode, l.granted, c.relname
            FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
            WHERE NOT l.granted
        """)).mappings().all()
        for l in locks:
            print(f"  WAITING LOCK pid={l['pid']} mode={l['mode']} on {l['relname']}")
        n_art = db.execute(text("SELECT count(*) FROM job_artifacts WHERE job_id=:j"), {"j": job_id}).scalar()
        inv = db.execute(text("""
            SELECT count(*) AS total, sum(CASE WHEN artifact_count IS NOT NULL THEN 1 ELSE 0 END) AS counted
            FROM job_axiom_artifact_results WHERE job_id=:j
        """), {"j": job_id}).mappings().one()
        print(f"  job_artifacts={n_art:,}  job_axiom_artifact_results total={inv['total']} counted={inv['counted']}")
    except Exception as exc:
        print(f"  postgres inspection failed: {exc}")
        db = None

    # ------------------------------------------------------- 5. Logs
    section("5. disk_build_logs — last 15 artifact_inventory lines")
    try:
        if db is not None:
            rows = db.execute(text("""
                SELECT timestamp, level, left(message, 150) AS m
                FROM disk_build_logs
                WHERE job_id=:j AND stage IN ('artifact_inventory','axiom_artifacts','supervisor')
                ORDER BY timestamp DESC LIMIT 15
            """), {"j": job_id}).mappings().all()
            for r in rows:
                print(f"  {_age(r['timestamp']):>12}  {r['level']:7s} {r['m']}")
            if rows:
                print(f"\n  newest inventory/supervisor line is {_age(rows[0]['timestamp'])}. "
                      "If > 5 min and no task is active (section 1), the supervisor should re-dispatch; "
                      "if a task IS active with no new lines, it is stuck in the step named by the last line.")
    except Exception as exc:
        print(f"  log read failed: {exc}")

    section("Interpretation")
    print("""  A. Section 1 empty + section 3 shows disk-parse > 0      -> queued behind parse/enrich (fixed by disk-inventory lane, V45.2)
  B. Section 1 empty + section 3 all zero                    -> task lost (worker OOM/restart). Lock in section 2 stale -> supervisor re-queues in <=10 min;
                                                                force now: POST /api/jobs/<id>/artifact-inventory/rerun (or restart worker-parse)
  C. Section 1 shows task active + section 4 has a session with wait=Lock and blocked_by -> DB lock chain: kill the blocking idle-in-transaction pid
  D. Section 1 shows task active + section 4 session running one SELECT for minutes       -> slow query; copy it and EXPLAIN ANALYZE
  E. Section 1 shows task active + section 4 has no session                               -> Python-side work (path-token regex index / census in RAM); check worker CPU & memory limit (worker-parse 8G)""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
