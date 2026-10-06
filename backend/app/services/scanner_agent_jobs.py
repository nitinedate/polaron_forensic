"""Claim / progress / result ingest for edge scanner agents."""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
from datetime import datetime, timezone
from typing import Any

from uuid import UUID

from app.db.sql_helpers import execute, fetchall, fetchone
from app.services.scan_orchestrator import ingest_engine_results
from app.services.vuln_helpers import timeline

log = logging.getLogger("scanner_agent_jobs")


def _orch(job: dict[str, Any]) -> dict[str, Any]:
    raw = job.get("orchestration_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return raw if isinstance(raw, dict) else {}


def job_is_edge_agent(job: dict[str, Any]) -> bool:
    orch = _orch(job)
    return bool(orch.get("edge_agent"))


def _version_tuple(value: Any) -> tuple[int, int, int]:
    """Parse an agent version conservatively for resume-capability gating."""
    nums = [int(x) for x in re.findall(r"\d+", str(value or ""))[:3]]
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def _agent_supports_resume(db, scanner_id: str) -> bool:
    row = fetchone(
        db,
        "SELECT version FROM vuln_scanners WHERE id = CAST(:sid AS uuid)",
        {"sid": scanner_id},
    )
    return _version_tuple((row or {}).get("version")) >= (1, 1, 1)


def _agent_supports_parallel(db, scanner_id: str) -> bool:
    """Parallel queue dispatch is opt-in by agent version to preserve old agents.

    An empty/missing version is treated as current (1.2+). Laptop-NITIN and
    other newly registered scanners otherwise sat in the legacy single-job
    gate and never claimed queued work.
    """
    row = fetchone(
        db,
        "SELECT version FROM vuln_scanners WHERE id = CAST(:sid AS uuid)",
        {"sid": scanner_id},
    )
    raw = str((row or {}).get("version") or "").strip()
    if not raw:
        return True
    return _version_tuple(raw) >= (1, 2, 0)




EDGE_OWNER_PROTOCOL_VERSION = (1, 2, 22)
EDGE_OWNER_LEASE_SEC = 90


def _normalize_agent_instance(value: Any) -> str:
    """Bound the runtime owner id supplied by a laptop scanner process."""
    text = str(value or "").strip()
    if not text:
        return ""
    # UUIDs plus a short optional prefix are sufficient; reject control/odd chars.
    text = re.sub(r"[^A-Za-z0-9_.:-]", "", text)[:128]
    return text


def _scanner_registered_version(db, scanner_id: str) -> tuple[int, int, int]:
    row = fetchone(
        db,
        "SELECT version FROM vuln_scanners WHERE id = CAST(:sid AS uuid)",
        {"sid": scanner_id},
    )
    return _version_tuple((row or {}).get("version"))


def _job_owner_instance(job: dict[str, Any]) -> str:
    return _normalize_agent_instance(_orch(job).get("edge_owner_instance"))


def _assign_job_owner(db, row: dict[str, Any], agent_instance_id: str) -> dict[str, Any]:
    """Persist ownership without a schema migration (inside orchestration_json)."""
    instance = _normalize_agent_instance(agent_instance_id)
    if not instance:
        return row
    orch = _orch(row)
    orch["edge_owner_instance"] = instance
    orch["edge_owner_seen_at"] = datetime.now(timezone.utc).isoformat()
    execute(
        db,
        """UPDATE vuln_scan_jobs
              SET orchestration_json = CAST(:orch AS jsonb), updated_at = NOW()
            WHERE id = CAST(:id AS uuid)""",
        {"orch": json.dumps(orch), "id": str(row["id"])},
    )
    row = dict(row)
    row["orchestration_json"] = orch
    return row


def _owner_conflict(job: dict[str, Any], agent_instance_id: str | None) -> bool:
    owner = _job_owner_instance(job)
    if not owner:
        return False
    incoming = _normalize_agent_instance(agent_instance_id)
    return not incoming or incoming != owner


def _fresh_running_edge_job(db, scanner_id: str) -> dict[str, Any] | None:
    """Find a job whose current owner is actively updating this scanner slot."""
    return fetchone(
        db,
        """SELECT *
             FROM vuln_scan_jobs
            WHERE scanner_id = CAST(:sid AS uuid)
              AND status = 'running'
              AND completed_at IS NULL
              AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = true
              /* fresh_edge_owner_guard */
              AND updated_at > NOW() - (:lease_sec * INTERVAL '1 second')
            ORDER BY updated_at DESC
            FOR UPDATE SKIP LOCKED
            LIMIT 1""",
        {"sid": scanner_id, "lease_sec": EDGE_OWNER_LEASE_SEC},
    )


def _valid_active_job_ids(values: list[str] | None) -> list[str]:
    import uuid

    out: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        try:
            value = str(uuid.UUID(str(raw).strip()))
        except (ValueError, TypeError, AttributeError):
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
        if len(out) >= 16:
            break
    return out


def _normalize_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.casefold()


def _job_target_list(db, job_id: str) -> list[str]:
    rows = fetchall(
        db,
        """SELECT target, excluded
           FROM vuln_scan_targets
           WHERE scan_job_id = CAST(:id AS uuid)
           ORDER BY target""",
        {"id": job_id},
    )
    return [
        str(t["target"]).strip()
        for t in rows
        if not t.get("excluded") and str(t.get("target") or "").strip()
    ]


def network_key_from_targets(targets: list[str] | None) -> frozenset[str]:
    """IPv4 /24, IPv6 /64, or literal name. Different keys are different networks."""
    keys: set[str] = set()
    for raw in targets or []:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            keys.add(text.casefold())
            continue
        if isinstance(ip, ipaddress.IPv4Address):
            keys.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
        else:
            keys.add(str(ipaddress.ip_network(f"{ip}/64", strict=False)))
    return frozenset(keys)


def _job_network_key(db, job_id: str) -> frozenset[str]:
    return network_key_from_targets(_job_target_list(db, job_id))


def _clip_chunk_tasks_to_job(chunk_tasks: Any, job_hosts: list[str]) -> list[dict[str, Any]]:
    """Drop OpenVAS task metadata whose hosts are not this job's targets."""
    allowed = {_normalize_host(h) for h in job_hosts}
    allowed.discard("")
    out: list[dict[str, Any]] = []
    if not isinstance(chunk_tasks, list):
        return out
    for item in chunk_tasks:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("task_id") or "").strip()
        raw_hosts = [str(h).strip() for h in (item.get("hosts") or []) if str(h).strip()]
        keys = {_normalize_host(h) for h in raw_hosts}
        keys.discard("")
        if not tid or not keys or not keys <= allowed:
            continue
        out.append({"task_id": tid, "hosts": raw_hosts})
    return out


_BLOCK_NETWORK = frozenset({"__mixed_active_networks__"})


def _required_network_key(db, active_job_ids: list[str]) -> frozenset[str] | None:
    """Network the laptop is already scanning, or None if it is idle.

    Mixed in-flight identities block further claims so we do not add a third
    site's IPs into the same OpenVAS wave.
    """
    if not active_job_ids:
        return None
    keys = [_job_network_key(db, jid) for jid in active_job_ids]
    first = keys[0]
    if any(k != first for k in keys[1:]):
        log.warning(
            "Scanner already has mixed network identities in-flight; withholding new claims"
        )
        return _BLOCK_NETWORK
    return first


def _network_compatible(job_key: frozenset[str], required: frozenset[str] | None) -> bool:
    if required is None:
        return True
    return job_key == required


def _stale_scanner_queued_job(
    db, scanner_id: str, exclude_ids: list[str]
) -> dict[str, Any] | None:
    """Claim a queued edge job left on an offline/stale laptop scanner.

    Jobs are bound to scanner_id. After Laptop-NITIN (or any new laptop) is
    registered, a queued row aimed at the previous token stays queued forever
    unless this online agent adopts it.
    """
    params: dict[str, Any] = {"sid": scanner_id}
    exclude_sql = ""
    if exclude_ids:
        placeholders: list[str] = []
        for idx, value in enumerate(exclude_ids):
            key = f"stale_ex_{idx}"
            placeholders.append(f"CAST(:{key} AS uuid)")
            params[key] = value
        exclude_sql = " AND j.id NOT IN (" + ", ".join(placeholders) + ")"
    return fetchone(
        db,
        f"""
        SELECT j.*
        FROM vuln_scan_jobs j
        JOIN vuln_scanners s ON s.id = j.scanner_id
        WHERE j.status IN ('queued', 'pending')
          /* stale_scanner_queued */
          AND COALESCE((j.orchestration_json->>'edge_agent')::boolean, false) = true
          AND j.scanner_id <> CAST(:sid AS uuid)
          AND (j.scheduled_at IS NULL OR j.scheduled_at <= NOW())
          AND (
            s.last_heartbeat_at IS NULL
            OR s.last_heartbeat_at < NOW() - INTERVAL '3 minutes'
          )
          AND (
            lower(coalesce(s.connection_mode, '')) = 'edge_agent'
            OR lower(coalesce(s.url, '')) LIKE 'agent://%'
          )
          {exclude_sql}
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 1
        """,
        params,
    )


def touch_scanner_heartbeat(db, scanner_id: str, *, version: str | None = None,
                            openvas_ready: bool | None = None, detail: str | None = None) -> None:
    # Once a scanner has upgraded, an accidentally left-running older agent must
    # not downgrade the shared scanner version and regain queue access.
    current = fetchone(
        db,
        "SELECT version FROM vuln_scanners WHERE id = CAST(:id AS uuid)",
        {"id": scanner_id},
    )
    existing = str((current or {}).get("version") or "").strip()
    incoming = str(version or "").strip()
    chosen: str | None = None
    if incoming and (not existing or _version_tuple(incoming) >= _version_tuple(existing)):
        chosen = incoming
    execute(
        db,
        """UPDATE vuln_scanners
           SET last_heartbeat_at = NOW(),
               version = COALESCE(:ver, version),
               updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {"id": scanner_id, "ver": chosen},
    )
    if openvas_ready is not None:
        from app.services.scanner_agent_auth import ensure_edge_agent_readiness_columns
        ensure_edge_agent_readiness_columns(db)
        execute(db, """UPDATE vuln_scanners SET openvas_ready=:ready, agent_status_detail=:detail,
            openvas_ready_at=CASE WHEN :ready THEN NOW() ELSE NULL END,
            updated_at=NOW() WHERE id = CAST(:id AS uuid)""",
            {"id": scanner_id, "ready": openvas_ready, "detail": str(detail or "")[:1000] or None})


def _scanner_role_for_job(db, row: dict[str, Any]) -> str:
    from app.services.scanner_credentials import infer_scanner_role

    sid = row.get("scanner_id")
    if not sid:
        return infer_scanner_role(None)
    scanner = fetchone(
        db,
        "SELECT * FROM vuln_scanners WHERE id = CAST(:id AS uuid)",
        {"id": str(sid)},
    )
    return infer_scanner_role(scanner)


def _job_payload(db, row: dict[str, Any], *, resumed: bool = False) -> dict[str, Any]:
    targets = fetchall(
        db,
        """SELECT target, target_type, credential_ref, excluded
           FROM vuln_scan_targets
           WHERE scan_job_id = CAST(:id AS uuid)
           ORDER BY target""",
        {"id": str(row["id"])},
    )
    orch = _orch(row)
    progress = dict(orch.get("edge_progress") or {})
    target_list = [
        str(t["target"]).strip()
        for t in targets
        if not t.get("excluded") and str(t.get("target") or "").strip()
    ]
    chunk_tasks = _clip_chunk_tasks_to_job(orch.get("edge_chunk_tasks") or [], target_list)
    has_resume = bool(resumed or str(row.get("external_scan_id") or "").strip() or chunk_tasks)
    return {
        "id": str(row["id"]),
        "case_id": str(row["case_id"]),
        "status": row["status"],
        "authorization_ref": row.get("authorization_ref"),
        "external_scan_id": row.get("external_scan_id"),
        "progress_pct": progress.get("pct"),
        "progress_message": progress.get("message"),
        "resume": has_resume,
        "chunk_tasks": chunk_tasks,
        "assessed_hosts": [
            str(x).strip() for x in (orch.get("assessed_hosts") or []) if str(x).strip()
        ],
        "skipped_hosts": orch.get("skipped_hosts") or [],
        "scan_policy_request": orch.get("scan_policy_request") or {},
        "target_progress": orch.get("target_progress") or {},
        "progress_event_seq": orch.get("progress_event_seq") or 0,
        "policy_snapshots": orch.get("policy_snapshots") or {},
        "scanner_role": _scanner_role_for_job(db, row),
        "targets": [
            {
                "target": t["target"],
                "target_type": t.get("target_type") or "host",
                "credential_ref": t.get("credential_ref"),
                "excluded": bool(t.get("excluded")),
            }
            for t in targets
            if not t.get("excluded")
        ],
    }


def claim_next_job(
    db,
    scanner_id: str,
    *,
    active_job_ids: list[str] | None = None,
    agent_instance_id: str | None = None,
) -> dict[str, Any] | None:
    """Return one claimable job without head-of-line blocking.

    Agent versions before 1.2.0 keep the legacy one-running-job behaviour.
    Version 1.2.0+ sends the jobs already owned by its local worker pool. The
    server first offers a recoverable running job that is *not* already active
    locally, then atomically claims any queued/pending job with
    ``FOR UPDATE SKIP LOCKED``. No FIFO/LIFO ordering is imposed.

    A historical ``running`` row with no ``external_scan_id`` is deliberately
    not allowed to block unrelated queued jobs for a 1.2.0+ agent. It remains
    visible for operator cleanup, which is safer than inventing a duplicate
    OpenVAS task id.
    """
    supports_parallel = _agent_supports_parallel(db, scanner_id)
    active = _valid_active_job_ids(active_job_ids) if supports_parallel else []
    agent_instance = _normalize_agent_instance(agent_instance_id)

    # v1.2.22 ownership protocol. After a scanner has upgraded, only an agent
    # that sends an instance id may claim work. This fences off an old duplicate
    # scanner-agent process that still has the same bearer token.
    if _scanner_registered_version(db, scanner_id) >= EDGE_OWNER_PROTOCOL_VERSION and not agent_instance:
        log.warning(
            "Scanner %s is registered for edge ownership protocol but caller supplied no instance id; withholding work",
            scanner_id,
        )
        return None

    # If this caller reports no locally-active job, do not assume the scanner is
    # idle. Another process/container with the same token may currently own the
    # scanner slot. A fresh running row is the server-side lease.
    if not active:
        fresh_running = _fresh_running_edge_job(db, scanner_id)
        if fresh_running:
            owner = _job_owner_instance(fresh_running)
            task_id = str(fresh_running.get("external_scan_id") or "").strip()
            if owner and owner != agent_instance:
                log.warning(
                    "Withholding scanner %s queue from instance %s; live job %s is owned by %s",
                    scanner_id,
                    agent_instance or "legacy",
                    fresh_running.get("id"),
                    owner,
                )
                return None
            # Jobs started before v1.2.22 have no owner. The upgraded process may
            # adopt that one live task immediately instead of waiting for lease expiry.
            if agent_instance and not owner:
                fresh_running = _assign_job_owner(db, fresh_running, agent_instance)
                owner = agent_instance
            if task_id and _agent_supports_resume(db, scanner_id):
                timeline(
                    db,
                    case_id=str(fresh_running["case_id"]),
                    source_type="scan_job",
                    source_id=str(fresh_running["id"]),
                    event_type="scan.edge_resumed",
                    actor="scanner-agent",
                    summary=f"Edge scanner owner resumed live OpenVAS task {task_id}",
                )
                return _job_payload(db, fresh_running, resumed=True)
            # A newly claimed worker gets a short window to create/persist its
            # Greenbone task id. Never let a second process take another job here.
            return None

    # Self-heal a legacy/racy edge job that was marked completed before the
    # durable vuln_scan_results row was committed.  A completed UI state alone
    # is not scan evidence.  Hand the job back to the same scanner so it can
    # harvest the existing GVMD report (or safely recreate only missing work).
    # This specifically repairs "completed but no durable scan-result evidence"
    # without inventing assessment coverage.
    recover_params: dict[str, Any] = {"sid": scanner_id}
    recover_exclude = ""
    if active:
        placeholders: list[str] = []
        for idx, value in enumerate(active):
            key = f"recover_ex_{idx}"
            placeholders.append(f"CAST(:{key} AS uuid)")
            recover_params[key] = value
        recover_exclude = " AND j.id NOT IN (" + ", ".join(placeholders) + ")"
    recoverable = fetchone(
        db,
        f"""
        SELECT j.*
        FROM vuln_scan_jobs j
        WHERE j.scanner_id = CAST(:sid AS uuid)
          AND j.status = 'completed'
          AND COALESCE((j.orchestration_json->>'edge_agent')::boolean, false) = true
          AND NULLIF(BTRIM(COALESCE(j.external_scan_id, '')), '') IS NOT NULL
          AND NOT EXISTS (
              SELECT 1
              FROM vuln_scan_results r
              WHERE r.scan_job_id = j.id
                AND COALESCE((r.result_json->>'edge_agent')::boolean, false) = true
                AND COALESCE((r.result_json->>'assessment_complete')::boolean, false) = true
          )
          {recover_exclude}
        ORDER BY j.completed_at ASC NULLS LAST, j.created_at ASC
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 1
        """,
        recover_params,
    )
    if recoverable and _agent_supports_resume(db, scanner_id):
        jid = str(recoverable["id"])
        row = fetchone(
            db,
            """
            UPDATE vuln_scan_jobs
               SET status = 'running', completed_at = NULL, error = NULL, updated_at = NOW()
             WHERE id = CAST(:id AS uuid)
            RETURNING *
            """,
            {"id": jid},
        )
        timeline(
            db,
            case_id=str(row["case_id"]),
            source_type="scan_job",
            source_id=jid,
            event_type="scan.edge_evidence_recovery",
            actor="scanner-agent",
            summary="Recovering durable OpenVAS result evidence for previously completed edge job",
        )
        log.warning(
            "Reopening completed edge job %s because durable scan-result evidence is missing",
            jid,
        )
        row = _assign_job_owner(db, row, agent_instance)
        return _job_payload(db, row, resumed=True)

    # Backward compatibility: old single-worker agents must never be handed a
    # second job while any edge job is running.
    if not supports_parallel:
        running = fetchone(
            db,
            """
            SELECT *
            FROM vuln_scan_jobs
            WHERE scanner_id = CAST(:sid AS uuid)
              AND status = 'running'
              AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = true
            ORDER BY started_at ASC NULLS LAST, created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """,
            {"sid": scanner_id},
        )
        if running:
            task_id = str(running.get("external_scan_id") or "").strip()
            if task_id and _agent_supports_resume(db, scanner_id):
                timeline(
                    db,
                    case_id=str(running["case_id"]),
                    source_type="scan_job",
                    source_id=str(running["id"]),
                    event_type="scan.edge_resumed",
                    actor="scanner-agent",
                    summary=f"Edge scanner agent resumed OpenVAS task {task_id}",
                )
                running = _assign_job_owner(db, running, agent_instance)
                return _job_payload(db, running, resumed=True)
            log.warning(
                "Scanner %s has running edge job %s that cannot be resumed "
                "(task_id=%s); not withholding the queue",
                scanner_id,
                running.get("id"),
                task_id or "missing",
            )

    # Parallel agents may already own multiple jobs. Offer only a running job
    # that is not already represented by a local worker, has a real task id,
    # and belongs to the same network identity as in-flight work.
    required_key = _required_network_key(db, active)
    exclude_ids = list(active)

    def _exclude_clause(ids: list[str], params: dict[str, Any]) -> str:
        if not ids:
            return ""
        placeholders: list[str] = []
        for idx, value in enumerate(ids):
            key = f"ex_{idx}"
            placeholders.append(f"CAST(:{key} AS uuid)")
            params[key] = value
        return " AND id NOT IN (" + ", ".join(placeholders) + ")"

    if supports_parallel:
        for _ in range(12):
            params: dict[str, Any] = {"sid": scanner_id}
            exclude_sql = _exclude_clause(exclude_ids, params)
            running = fetchone(
                db,
                f"""
                SELECT *
                FROM vuln_scan_jobs
                WHERE scanner_id = CAST(:sid AS uuid)
                  AND status = 'running'
                  AND completed_at IS NULL
                  AND NULLIF(BTRIM(COALESCE(external_scan_id, '')), '') IS NOT NULL
                  AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = true
                  {exclude_sql}
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                params,
            )
            if not running:
                break
            if not _network_compatible(_job_network_key(db, str(running["id"])), required_key):
                log.info(
                    "Withholding running job %s; different network than in-flight laptop work",
                    running["id"],
                )
                exclude_ids.append(str(running["id"]))
                continue
            task_id = str(running.get("external_scan_id") or "").strip()
            timeline(
                db,
                case_id=str(running["case_id"]),
                source_type="scan_job",
                source_id=str(running["id"]),
                event_type="scan.edge_resumed",
                actor="scanner-agent",
                summary=f"Parallel edge worker resumed OpenVAS task {task_id}",
            )
            running = _assign_job_owner(db, running, agent_instance)
            return _job_payload(db, running, resumed=True)

    # Work-conserving, unordered claim. SELECT first so a different network is
    # skipped without flipping its status to running.
    exclude_ids = list(active)
    for _ in range(12):
        params = {"sid": scanner_id}
        exclude_sql = _exclude_clause(exclude_ids, params)
        candidate = fetchone(
            db,
            f"""
            SELECT *
            FROM vuln_scan_jobs
            WHERE scanner_id = CAST(:sid AS uuid)
              AND status IN ('queued', 'pending')
              AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = true
              AND (scheduled_at IS NULL OR scheduled_at <= NOW())
              {exclude_sql}
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """,
            params,
        )
        if not candidate:
            candidate = _stale_scanner_queued_job(db, scanner_id, exclude_ids)
            if not candidate:
                return None
        jid = str(candidate["id"])
        if not _network_compatible(_job_network_key(db, jid), required_key):
            log.info(
                "Skipping queued job %s; different network than in-flight laptop work",
                jid,
            )
            exclude_ids.append(jid)
            continue
        row = fetchone(
            db,
            """
            UPDATE vuln_scan_jobs
               SET scanner_id = CAST(:sid AS uuid),
                   status = 'running',
                   started_at = COALESCE(started_at, NOW()),
                   updated_at = NOW(),
                   error = NULL
             WHERE id = CAST(:id AS uuid)
            RETURNING *
            """,
            {"id": jid, "sid": scanner_id},
        )
        if not row:
            return None
        timeline(
            db,
            case_id=str(row["case_id"]),
            source_type="scan_job",
            source_id=str(row["id"]),
            event_type="scan.edge_claimed",
            actor="scanner-agent",
            summary="Parallel edge worker claimed queued job",
        )
        row = _assign_job_owner(db, row, agent_instance)
        return _job_payload(db, row, resumed=False)
    return None

def _target_event_state(event: str, *, status: str | None = None,
                        progress_pct: Any = None, error: str | None = None) -> dict[str, Any]:
    aliases = {"queued": "pending", "waiting": "pending", "start_attempt": "scanning",
               "started": "scanning", "resumed": "scanning", "progress": "scanning",
               "running": "scanning", "scan_failed": "failed", "start_error": "failed",
               "poll_error": "failed", "stopped": "failed", "canceled": "cancelled"}
    raw = str(status or event or "pending").strip().lower()
    state = aliases.get(raw, raw)
    if state not in {"pending", "scanning", "completed", "failed", "skipped", "incomplete", "cancelled"}:
        state = "pending"
    try:
        number = float(progress_pct or 0)
    except (TypeError, ValueError, OverflowError):
        number = 0.0
    if not math.isfinite(number):
        number = 0.0
    pct = max(0, min(99 if state == "scanning" else 100, int(number)))
    if state == "pending":
        pct = 0
    elif state in {"completed", "incomplete"}:
        pct = 100
    activity = {"pending": "Waiting", "scanning": f"In progress ({pct}%)",
                "completed": "Completed", "failed": "Failed", "skipped": "Skipped",
                "incomplete": "Incomplete - assessment coverage not verified", "cancelled": "Cancelled"}[state]
    if error and state in {"failed", "skipped", "incomplete"}:
        activity += ": " + str(error)[:160]
    return {"status": state, "progress_pct": pct, "activity": activity}


def _merge_edge_target_progress(previous: Any, incoming: Any, targets: list[str]) -> dict[str, Any]:
    """Merge only assigned, non-excluded hosts and keep verified terminal states."""
    allowed = {_normalize_host(host): str(host) for host in targets}
    prior = previous if isinstance(previous, dict) else {}
    merged = {host: dict(state) for host, state in prior.items()
              if host in allowed.values() and isinstance(state, dict)}
    if not isinstance(incoming, dict):
        return merged
    stamp = datetime.now(timezone.utc).isoformat()
    for raw_host, raw in incoming.items():
        host = allowed.get(_normalize_host(str(raw_host)))
        if not host or not isinstance(raw, dict):
            continue
        status = str(raw.get("status") or raw.get("event") or "pending").lower()
        if status not in {"queued", "waiting", "pending", "running", "scanning", "started",
                          "progress", "resumed", "completed", "failed", "scan_failed",
                          "skipped", "incomplete", "cancelled", "canceled", "stopped"}:
            continue
        old = merged.get(host, {})
        seq = raw.get("event_seq")
        old_seq = old.get("event_seq")
        if isinstance(seq, bool) or (seq is not None and (not isinstance(seq, int) or not 0 <= seq < 2**53)):
            continue
        if isinstance(old_seq, int) and (seq is None or seq <= old_seq):
            # A delayed previous-task poll cannot reopen a newer assessment.
            continue
        state = _target_event_state(status, progress_pct=raw.get("progress_pct", raw.get("progress")),
                                    error=raw.get("error"))
        task_id = str(raw.get("task_id") or "")[:128]
        same_task = not task_id or task_id == str(old.get("task_id") or "")
        if old.get("status") in {"completed", "incomplete", "skipped", "failed", "cancelled"} and same_task:
            # A delayed poll/log cannot turn a finished host back into running.
            # A new OpenVAS task ID may explicitly start a new assessment.
            if state["status"] in {"pending", "scanning"} or old.get("coverage"):
                continue
        if state["status"] == "scanning" and old.get("status") == "scanning" and same_task:
            state["progress_pct"] = max(state["progress_pct"], _target_event_state("running", progress_pct=old.get("progress_pct"))["progress_pct"])
            state["activity"] = f"In progress ({state['progress_pct']}%)"
        activity = str(raw.get("activity") or "")[:240]
        if activity and state["status"] in {"failed", "skipped", "incomplete"}:
            state["activity"] = activity
        state["updated_at"] = stamp
        if seq is not None:
            state["event_seq"] = seq
        if task_id:
            state["task_id"] = task_id
        if isinstance(raw.get("open_ports"), list):
            ports = set()
            for value in raw["open_ports"][:2048]:
                try:
                    port = int(value)
                except (TypeError, ValueError, OverflowError):
                    continue
                if not isinstance(value, bool) and 1 <= port <= 65535:
                    ports.add(port)
            state["open_ports"] = sorted(ports)
        retained = dict(old)
        if task_id and old.get("task_id") and not same_task:
            retained.pop("coverage", None)
        merged[host] = dict(retained, **state)
    return merged


def update_target_progress(db, *, scanner_id: str, job_id: str, target: str, event: str,
                           status: str | None = None, progress_pct: Any = None,
                           open_ports: list[int] | None = None, task_id: str | None = None,
                           error: str | None = None, agent_instance_id: str | None = None) -> dict[str, Any]:
    """Compatibility API for a single progress event, with the same ownership fence."""
    job = fetchone(db, """SELECT * FROM vuln_scan_jobs WHERE id=CAST(:id AS uuid)
                      AND scanner_id=CAST(:sid AS uuid) FOR UPDATE""", {"id": job_id, "sid": scanner_id})
    if not job or not job_is_edge_agent(job):
        return {"status": "missing"}
    if _owner_conflict(job, agent_instance_id):
        return {"status": "owner_mismatch"}
    targets = _job_target_list(db, job_id)
    canonical = next((h for h in targets if _normalize_host(h) == _normalize_host(target)), None)
    if canonical is None:
        return {"status": "invalid_target"}
    if str(job.get("status") or "").lower() in {"completed", "failed", "cancelled", "canceled"}:
        return {"status": "terminal"}
    state = _target_event_state(event, status=status, progress_pct=progress_pct, error=error)
    if open_ports is not None:
        state["open_ports"] = open_ports
    if task_id:
        state["task_id"] = task_id
    orch = _orch(job)
    merged = _merge_edge_target_progress(orch.get("target_progress"), {canonical: state}, targets)
    orch["target_progress"] = merged
    execute(db, """UPDATE vuln_scan_jobs SET orchestration_json=CAST(:orch AS jsonb),
                   updated_at=NOW() WHERE id=CAST(:id AS uuid)""", {"orch": json.dumps(orch), "id": job_id})
    return {"status": "ok", "target_progress": merged[canonical]}


def update_job_progress(
    db,
    *,
    scanner_id: str,
    job_id: str,
    status: str | None = None,
    progress_pct: float | None = None,
    message: str | None = None,
    external_scan_id: str | None = None,
    error: str | None = None,
    chunk_tasks: list[dict[str, Any]] | None = None,
    target_progress: dict[str, dict[str, Any]] | None = None,
    policy_snapshots: dict[str, dict[str, Any]] | None = None,
    agent_instance_id: str | None = None,
) -> dict[str, Any]:
    job = fetchone(
        db,
        """SELECT * FROM vuln_scan_jobs
           WHERE id = CAST(:id AS uuid) AND scanner_id = CAST(:sid AS uuid) FOR UPDATE""",
        {"id": job_id, "sid": scanner_id},
    )
    if not job:
        return {}
    if not job_is_edge_agent(job):
        return {}
    if _owner_conflict(job, agent_instance_id):
        log.warning(
            "Rejected progress for edge job %s from non-owner instance %s (owner=%s)",
            job_id,
            _normalize_agent_instance(agent_instance_id) or "legacy",
            _job_owner_instance(job),
        )
        return {"id": job_id, "status": job.get("status"), "owner_mismatch": True}
    if not _job_owner_instance(job) and _normalize_agent_instance(agent_instance_id):
        job = _assign_job_owner(db, job, _normalize_agent_instance(agent_instance_id))

    orch = _orch(job)
    progress = dict(orch.get("edge_progress") or {})
    if progress_pct is not None:
        progress["pct"] = max(0.0, min(100.0, float(progress_pct)))
    if message:
        progress["message"] = message[:500]
    orch["edge_progress"] = progress
    orch["edge_agent"] = True
    orch["enabled"] = False
    # V45.4a: record which agent build produced this result (from its last heartbeat).
    try:
        ver_row = fetchone(
            db, "SELECT version FROM vuln_scanners WHERE id = CAST(:sid AS uuid)", {"sid": scanner_id}
        )
        agent_ver = str((ver_row or {}).get("version") or "").strip()
        orch["edge_agent_version"] = agent_ver or None
        orch["edge_agent_build"] = (
            "v45.4" if "v45" in agent_ver else ("legacy (pre-V45.4)" if agent_ver else "unknown")
        )
    except Exception:
        orch["edge_agent_version"] = None
    if _normalize_agent_instance(agent_instance_id):
        orch["edge_owner_instance"] = _normalize_agent_instance(agent_instance_id)
        orch["edge_owner_seen_at"] = datetime.now(timezone.utc).isoformat()
    if chunk_tasks is not None:
        orch["edge_chunk_tasks"] = _clip_chunk_tasks_to_job(
            chunk_tasks, _job_target_list(db, job_id)
        )
    if target_progress is not None:
        floor = orch.get("progress_event_seq") or 0
        floor = floor if isinstance(floor, int) and not isinstance(floor, bool) else 0
        accepted = {host: state for host, state in target_progress.items() if isinstance(state, dict)
                    and (floor == 0 or (isinstance(state.get("event_seq"), int)
                    and not isinstance(state["event_seq"], bool) and state["event_seq"] > floor))}
        merged = _merge_edge_target_progress(orch.get("target_progress"), accepted,
                                              _job_target_list(db, job_id))
        orch["target_progress"] = merged
        seqs = [s.get("event_seq", 0) for s in merged.values() if isinstance(s.get("event_seq"), int)]
        orch["progress_event_seq"] = max([floor] + seqs)
    if policy_snapshots is not None:
        from app.services.scanner_service_policy import clip_policy_snapshots

        policies = clip_policy_snapshots(policy_snapshots, _job_target_list(db, job_id))
        orch["policy_snapshots"] = dict(orch.get("policy_snapshots") or {}, **policies)

    new_status = (status or job.get("status") or "running").lower()
    if new_status not in {"running", "failed", "cancelled", "canceled", "queued"}:
        new_status = "running"

    current = str(job.get("status") or "").lower()
    # Never reopen a verified completed job. A late progress PATCH used to
    # flip completed back to running and leave the UI at 99%.
    # A failed job MAY be reclaimed when the laptop is running a live OpenVAS
    # task — otherwise a premature empty ingest freezes the UI on
    # "missing OpenVAS task id" while Greenbone is still scanning.
    reclaim_failed = (
        current == "failed"
        and new_status == "running"
        and bool(str(external_scan_id or "").strip())
    )
    if current in {"completed", "failed", "cancelled", "canceled"}:
        if new_status == "running" and not reclaim_failed:
            return _job_payload(db, job, resumed=False)
        if current == "completed" and new_status != "completed":
            return _job_payload(db, job, resumed=False)

    execute(
        db,
        """UPDATE vuln_scan_jobs
           SET status = :st,
               external_scan_id = COALESCE(:eid, external_scan_id),
               error = CASE
                 WHEN :st = 'running' THEN NULL
                 WHEN CAST(:err AS text) IS NULL THEN error
                 ELSE CAST(:err AS text)
               END,
               orchestration_json = CAST(:orch AS jsonb),
               updated_at = NOW(),
               completed_at = CASE
                 WHEN :st IN ('failed', 'cancelled', 'canceled') THEN NOW()
                 WHEN :st = 'running' THEN NULL
                 ELSE completed_at
               END
           WHERE id = CAST(:id AS uuid)""",
        {
            "st": new_status,
            "eid": external_scan_id,
            "err": (error[:2000] if error else None),
            "orch": json.dumps(orch),
            "id": job_id,
        },
    )
    if new_status in {"failed", "cancelled", "canceled"}:
        timeline(
            db,
            case_id=str(job["case_id"]),
            source_type="scan_job",
            source_id=job_id,
            event_type="scan.failed" if new_status == "failed" else "scan.cancelled",
            actor="scanner-agent",
            summary=(error or message or new_status)[:500],
        )
    return {"id": job_id, "status": new_status, "progress": progress}


class RetryNotAllowed(ValueError):
    def __init__(self, message: str, *, code: str = "retry_not_allowed"):
        super().__init__(message)
        self.code = code


def _retry_requires_fresh_openvas(job: dict[str, Any], orch: dict[str, Any]) -> bool:
    """Return True when retrying a job whose persisted GMP identity is unusable.

    Evidence-only failures (for example a report socket drop after a real task
    completed) keep their task/report ids so the laptop can harvest the existing
    report.  But a failure that never attempted a host and has no report must not
    be sent back forever with stale ``external_scan_id`` / ``edge_chunk_tasks``.
    """
    err = " ".join(str(job.get("error") or "").lower().split())
    try:
        attempted = max(0, int(orch.get("hosts_attempted") or 0))
    except (TypeError, ValueError):
        attempted = 0
    report_id = str(orch.get("report_id") or "").strip()
    zero_work_markers = (
        "missing openvas task id",
        "no openvas task/report was created",
        "attempted 0 of",
        "assessed 0 of",
    )
    return attempted == 0 and not report_id and any(marker in err for marker in zero_work_markers)


def _clear_stale_edge_resume_state(orch: dict[str, Any]) -> dict[str, Any]:
    """Remove only prior scan-attempt evidence; keep job authorization/targets."""
    out = dict(orch or {})
    for key in (
        "edge_chunk_tasks",
        "assessed_hosts",
        "skipped_hosts",
        "hosts_attempted",
        "hosts_assessed",
        "report_id",
        "assessment_complete",
        "clean_eligible",
        "completed_with_warnings",
        "plugin_error_count",
        "result_payload_ok",
        "report_result_count",
        "uploaded_vulnerability_rows",
        "partial",
        "partial_reason",
        "edge_progress",
        "target_progress",
        "host_coverage",
        "degraded_hosts",
        "service_coverage",
        "policy_snapshots",
    ):
        out.pop(key, None)
    out["edge_agent"] = True
    out["edge_resume_requested"] = True
    out["edge_force_fresh_openvas"] = True
    return out


def retry_edge_job(db, job_id: str, *, actor: str) -> dict[str, Any]:
    """Requeue one failed edge job with its original authorized targets.

    Keeps ``vuln_scan_targets``, ``scanner_id``, ``case_id``, and task ids, and
    never copies hosts from another job.  V2.3 could persist a temporary TCP
    reachability decision as ``excluded=true``. An explicit operator Resume
    restores those original rows so the job cannot be dispatched with an empty
    target list.
    """
    job = fetchone(
        db,
        "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid) FOR UPDATE",
        {"id": job_id},
    )
    if not job:
        raise RetryNotAllowed("Scan job not found", code="not_found")
    if not job_is_edge_agent(job):
        raise RetryNotAllowed(
            "Only laptop edge-agent jobs can be resumed in place",
            code="not_edge_job",
        )
    current = str(job.get("status") or "").lower()
    if current not in {"failed", "cancelled", "canceled"}:
        raise RetryNotAllowed(
            f"Scan job is {current}; only failed or cancelled jobs can be resumed",
            code="job_not_failed",
        )
    orch = _orch(job)
    force_fresh_openvas = _retry_requires_fresh_openvas(job, orch)
    if force_fresh_openvas:
        orch = _clear_stale_edge_resume_state(orch)
        log.warning(
            "Retrying edge job %s as a fresh OpenVAS attempt because prior state had zero attempted hosts and no report",
            job_id,
        )
    else:
        orch["edge_agent"] = True
        orch["edge_resume_requested"] = True
        orch.pop("edge_force_fresh_openvas", None)
    execute(
        db,
        """UPDATE vuln_scan_targets
              SET excluded = false
            WHERE scan_job_id = CAST(:id AS uuid)
              AND excluded = true""",
        {"id": job_id},
    )
    execute(
        db,
        """UPDATE vuln_scan_jobs
           SET status = 'queued',
               completed_at = NULL,
               error = NULL,
               external_scan_id = CASE WHEN :fresh THEN NULL ELSE external_scan_id END,
               updated_at = NOW(),
               orchestration_json = CAST(:orch AS jsonb)
         WHERE id = CAST(:id AS uuid)""",
        {"id": job_id, "orch": json.dumps(orch), "fresh": force_fresh_openvas},
    )
    timeline(
        db,
        case_id=str(job["case_id"]),
        source_type="scan_job",
        source_id=job_id,
        event_type="scan.edge_retry_queued",
        actor=actor,
        summary=(
            "Failed edge job requeued with original targets for a fresh OpenVAS task"
            if force_fresh_openvas
            else "Failed edge job requeued with original targets and recoverable OpenVAS task ids"
        ),
    )
    row = fetchone(
        db,
        "SELECT * FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)",
        {"id": job_id},
    )
    return _job_payload(db, row or job, resumed=True)


def retry_failed_edge_jobs_for_case(db, case_id: str, *, actor: str) -> dict[str, Any]:
    """Requeue each failed edge job in a case independently (no target merge)."""
    rows = fetchall(
        db,
        """SELECT id
           FROM vuln_scan_jobs
           WHERE case_id = CAST(:cid AS uuid)
             AND status IN ('failed', 'cancelled', 'canceled')
             AND COALESCE((orchestration_json->>'edge_agent')::boolean, false) = true
           ORDER BY created_at ASC""",
        {"cid": case_id},
    )
    retried: list[dict[str, Any]] = []
    for row in rows:
        payload = retry_edge_job(db, str(row["id"]), actor=actor)
        retried.append(
            {
                "id": payload.get("id"),
                "status": payload.get("status"),
                "target_count": len(payload.get("targets") or []),
            }
        )
    return {"count": len(retried), "retried": retried}


def _nonneg_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def evaluate_edge_ingest_verdict(
    *,
    target_list: list[str],
    skipped_details: list[dict[str, Any]],
    skipped_set: set[str],
    assessed_list: list[str],
    status: str,
    partial: bool,
    partial_reason: str | None,
    error: str | None,
    external_scan_id: str | None,
    report_id: str | None,
    task_status: str | None,
    hosts_attempted: int,
    hosts_assessed: int,
    report_result_count: int,
    plugin_error_count: int,
    scan_start: str | None,
    scan_end: str | None,
    assessment_complete: bool | None,
    assessment_verdict: str | None,
    report_read_error: str | None,
    vulnerability_count: int,
    evidence_present: bool,
) -> dict[str, Any]:
    """Decide whether an edge upload is a verified assessment.

    OpenVAS ``Done`` is not enough by itself. Every requested literal IP must
    have host evidence in the report; reachability guesses cannot reduce the
    assessment scope or create a clean result.
    """
    target_count = len(target_list)
    attempted = hosts_attempted
    assessed = hosts_assessed
    task_status_norm = str(task_status or "").strip().lower()
    status_norm = str(status or "completed").strip().lower()

    task_ok = task_status_norm in {
        "done",
        "finished",
        "succeeded",
        "completed",
        "complete",
        "success",
    }
    literal_ip_targets: list[str] = []
    for target in target_list:
        try:
            tip = str(ipaddress.ip_address(target))
        except ValueError:
            continue
        literal_ip_targets.append(tip)
    required_count = len(literal_ip_targets)
    normalized_assessed: set[str] = set()
    for host in assessed_list:
        try:
            normalized_assessed.add(str(ipaddress.ip_address(host)))
        except ValueError:
            normalized_assessed.add(host.casefold())
    missing_ip_targets = [t for t in literal_ip_targets if t not in normalized_assessed]
    target_identity_ok = not missing_ip_targets
    coverage_ok = required_count > 0 and target_identity_ok
    scan_timestamps_ok = bool(scan_start and scan_end)
    plugin_health_ok = plugin_error_count == 0
    # With the edge agent requesting rows=-1/min_qod=0, the raw Greenbone
    # report result count must exactly match the uploaded parsed rows.  The old
    # zero-only check missed partial parser/filter loss (for example raw=81,
    # uploaded=3), which could make a shallow scan look valid.
    result_payload_ok = report_result_count == vulnerability_count

    effective_report_id = report_id
    # Accept completion only when the full requested target identity is proven.
    if (
        status_norm == "completed"
        and coverage_ok
        and task_ok
        and effective_report_id
    ):
        if assessment_complete is not True:
            assessment_complete = True
        if not assessment_verdict or assessment_verdict in {
            "target_not_in_report",
            "partial_coverage",
            "incomplete_coverage",
            "partial_or_running",
        }:
            assessment_verdict = (
                "assessed"
            )
        if not scan_timestamps_ok and effective_report_id:
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).isoformat()
            scan_start = scan_start or now
            scan_end = scan_end or now
            scan_timestamps_ok = True

    partial_blocks = bool(partial) and not coverage_ok
    verified_complete = bool(
        status_norm == "completed"
        and not partial_blocks
        and assessment_complete is True
        and evidence_present
        and external_scan_id
        and effective_report_id
        and task_ok
        and coverage_ok
        and scan_timestamps_ok
        and result_payload_ok
        and not report_read_error
    )

    reasons: list[str] = []
    if status_norm in {"failed", "cancelled", "canceled"}:
        reasons.append(error or f"agent reported {status_norm}")
    if partial_blocks:
        reasons.append(partial_reason or "agent reported a partial scan")
    if not evidence_present:
        reasons.append("edge agent did not provide durable host-assessment evidence (agent 1.1.0+ required)")
    if not external_scan_id:
        reasons.append("missing OpenVAS task id")
    if not effective_report_id:
        reasons.append("missing OpenVAS report id")
    if task_status_norm and not task_ok:
        reasons.append(f"OpenVAS task status is {task_status}")
    if target_count <= 0:
        reasons.append("scan has no active targets")
    elif required_count > 0 and attempted < required_count and not target_identity_ok:
        reasons.append(f"attempted {attempted} of {required_count} reachable target(s)")
    if required_count > 0 and assessed < required_count and not target_identity_ok:
        reasons.append(f"assessed {assessed} of {required_count} reachable target(s)")
    if missing_ip_targets:
        reasons.append("OpenVAS report has no assessment evidence for target(s): " + ", ".join(missing_ip_targets))
    if skipped_details:
        reasons.append(
            "skipped unreachable: " + ", ".join(str(x.get("host")) for x in skipped_details[:20])
        )
    if not scan_timestamps_ok:
        reasons.append("missing OpenVAS scan_start/scan_end evidence")
    if not result_payload_ok:
        reasons.append(
            f"OpenVAS result integrity mismatch: report declares {report_result_count} result(s) "
            f"but the agent uploaded {vulnerability_count} parsed row(s)"
        )
    if assessment_complete is False and not coverage_ok:
        reasons.append(assessment_verdict or "scanner reported incomplete host assessment")
    if report_read_error:
        reasons.append(f"report read error: {report_read_error}")

    final_status = "completed" if verified_complete else "failed"
    if status_norm in {"cancelled", "canceled"}:
        final_status = "cancelled"

    err_text = error
    if final_status != "completed" and not err_text:
        unique_reasons = list(
            dict.fromkeys(
                r
                for r in reasons
                if r and not str(r).startswith("skipped unreachable:")
            )
        )
        err_text = "Assessment incomplete - " + "; ".join(unique_reasons or ["verification evidence missing"])
    if partial_blocks and partial_reason and partial_reason not in (err_text or ""):
        err_text = ((err_text + "; ") if err_text else "") + f"partial: {partial_reason}"
    if final_status == "completed":
        err_text = None

    return {
        "verified_complete": verified_complete,
        "final_status": final_status,
        "err_text": err_text,
        "reasons": reasons,
        "coverage_ok": coverage_ok,
        "task_ok": task_ok,
        "target_identity_ok": target_identity_ok,
        "missing_ip_targets": missing_ip_targets,
        "required_count": required_count,
        "scan_timestamps_ok": scan_timestamps_ok,
        "plugin_health_ok": plugin_health_ok,
        "clean_eligible": bool(verified_complete and plugin_health_ok and result_payload_ok and not skipped_details),
        "result_payload_ok": result_payload_ok,
        "effective_report_id": effective_report_id,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "assessment_complete": assessment_complete,
        "assessment_verdict": assessment_verdict,
        "status_norm": status_norm,
    }


def ingest_agent_results(
    db,
    *,
    scanner_id: str,
    job_id: str,
    vulnerabilities: list[dict[str, Any]],
    status: str = "completed",
    external_scan_id: str | None = None,
    partial: bool = False,
    partial_reason: str | None = None,
    error: str | None = None,
    report_id: str | None = None,
    task_status: str | None = None,
    hosts_attempted: int | None = None,
    hosts_assessed: int | None = None,
    assessed_hosts: list[str] | None = None,
    skipped_hosts: list[Any] | None = None,
    report_result_count: int | None = None,
    plugin_error_count: int | None = None,
    plugin_error_details: list[dict[str, Any]] | None = None,
    scan_start: str | None = None,
    scan_end: str | None = None,
    assessment_complete: bool | None = None,
    assessment_verdict: str | None = None,
    alive_test: str | None = None,
    report_read_error: str | None = None,
    agent_instance_id: str | None = None,
    host_coverage: dict[str, Any] | None = None,
    service_coverage: dict[str, Any] | None = None,
    policy_snapshots: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Ingest an edge-agent result and persist host-assessment evidence.

    A completed OpenVAS task is not equivalent to a verified assessment.  The
    central service requires durable evidence that the intended targets were
    actually assessed before it can leave the job in ``completed`` state.
    """
    job = fetchone(
        db,
        """SELECT * FROM vuln_scan_jobs
           WHERE id = CAST(:id AS uuid) AND scanner_id = CAST(:sid AS uuid) FOR UPDATE""",
        {"id": job_id, "sid": scanner_id},
    )
    if not job:
        return {"status": "missing", "findings": 0}
    if not job_is_edge_agent(job):
        return {"status": "not_edge_job", "findings": 0}
    if _owner_conflict(job, agent_instance_id):
        log.warning(
            "Rejected terminal results for edge job %s from non-owner instance %s (owner=%s)",
            job_id,
            _normalize_agent_instance(agent_instance_id) or "legacy",
            _job_owner_instance(job),
        )
        return {"status": "owner_mismatch", "findings": 0}
    if not _job_owner_instance(job) and _normalize_agent_instance(agent_instance_id):
        job = _assign_job_owner(db, job, _normalize_agent_instance(agent_instance_id))

    targets = fetchall(
        db,
        """SELECT target, target_type, excluded FROM vuln_scan_targets
           WHERE scan_job_id = CAST(:id AS uuid)""",
        {"id": job_id},
    )
    active_targets = [t for t in targets if not t.get("excluded")]
    target_list = [str(t["target"]).strip() for t in active_targets if str(t.get("target") or "").strip()]
    target_count = len(target_list)
    case_id = str(job["case_id"])

    findings = ingest_engine_results(
        db,
        case_id=case_id,
        scan_job_id=job_id,
        engine="openvas",
        targets=target_list,
        vulnerabilities=vulnerabilities or [],
        credentialed=False,
    )

    attempted = _nonneg_int(hosts_attempted)
    assessed = _nonneg_int(hosts_assessed)
    error_details = [dict(x) for x in (plugin_error_details or []) if isinstance(x, dict)][:100]
    plugin_errors = max(_nonneg_int(plugin_error_count), len(error_details))
    result_count = _nonneg_int(report_result_count)
    assessed_list = sorted({str(x).strip() for x in (assessed_hosts or []) if str(x).strip()})

    skipped_details: list[dict[str, Any]] = []
    skipped_set: set[str] = set()
    for item in skipped_hosts or []:
        if isinstance(item, dict):
            host = str(item.get("host") or item.get("target") or "").strip()
            reason = str(item.get("reason") or "unreachable").strip() or "unreachable"
        else:
            host = str(item).strip()
            reason = "unreachable"
        if not host:
            continue
        skipped_details.append({"host": host, "reason": reason})
        try:
            skipped_set.add(str(ipaddress.ip_address(host)))
        except ValueError:
            skipped_set.add(host.casefold())

    evidence_present = any(
        value is not None
        for value in (
            assessment_complete,
            report_id,
            hosts_attempted,
            hosts_assessed,
            report_result_count,
            plugin_error_count,
        )
    ) or bool(skipped_details)

    verdict = evaluate_edge_ingest_verdict(
        target_list=target_list,
        skipped_details=skipped_details,
        skipped_set=skipped_set,
        assessed_list=assessed_list,
        status=status,
        partial=partial,
        partial_reason=partial_reason,
        error=error,
        external_scan_id=external_scan_id,
        report_id=report_id,
        task_status=task_status,
        hosts_attempted=attempted,
        hosts_assessed=assessed,
        report_result_count=result_count,
        plugin_error_count=plugin_errors,
        scan_start=scan_start,
        scan_end=scan_end,
        assessment_complete=assessment_complete,
        assessment_verdict=assessment_verdict,
        report_read_error=report_read_error,
        vulnerability_count=len(vulnerabilities or []),
        evidence_present=evidence_present,
    )
    verified_complete = bool(verdict["verified_complete"])
    final_status = str(verdict["final_status"])
    err_text = verdict["err_text"]
    required_count = int(verdict["required_count"])
    missing_ip_targets = list(verdict["missing_ip_targets"])
    target_identity_ok = bool(verdict["target_identity_ok"])
    scan_timestamps_ok = bool(verdict["scan_timestamps_ok"])
    plugin_health_ok = bool(verdict["plugin_health_ok"])
    result_payload_ok = bool(verdict["result_payload_ok"])
    effective_report_id = verdict["effective_report_id"]
    scan_start = verdict["scan_start"]
    scan_end = verdict["scan_end"]
    assessment_complete = verdict["assessment_complete"]
    assessment_verdict = verdict["assessment_verdict"]

    evidence = {
        "edge_agent": True,
        "task_id": external_scan_id,
        "report_id": effective_report_id,
        "task_status": task_status,
        "targets": target_list,
        "hosts_attempted": attempted,
        "hosts_assessed": assessed,
        "assessed_hosts": assessed_list,
        "skipped_hosts": skipped_details,
        "reachable_target_count": required_count,
        "missing_ip_targets": missing_ip_targets,
        "target_identity_ok": target_identity_ok,
        "scan_timestamps_ok": scan_timestamps_ok,
        "plugin_health_ok": plugin_health_ok,
        # A scan that skipped any requested host is verified as an execution,
        # but it is not eligible for a "clean/no vulnerabilities" conclusion
        # over the full requested scope.
        "clean_eligible": bool(verified_complete and plugin_health_ok and result_payload_ok and not skipped_details),
        "completed_with_warnings": bool(verified_complete and (plugin_errors > 0 or bool(skipped_details))),
        "result_payload_ok": result_payload_ok,
        "report_result_count": result_count,
        "plugin_error_count": plugin_errors,
        "plugin_error_details": error_details,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "assessment_complete": verified_complete,
        "agent_assessment_complete": assessment_complete,
        "assessment_verdict": assessment_verdict,
        "alive_test": alive_test,
        "report_read_error": report_read_error,
        "partial": bool(partial),
        "partial_reason": partial_reason,
        "uploaded_vulnerability_rows": len(vulnerabilities or []),
        "ingested_findings": findings,
    }

    # Keep a single durable evidence row for the current edge-agent upload so
    # retries remain idempotent and reporting does not double-count coverage.
    execute(
        db,
        "DELETE FROM vuln_scan_results WHERE scan_job_id = CAST(:jid AS uuid)",
        {"jid": job_id},
    )
    from app.services.vuln_brd import record_scan_result

    orch = _orch(job)
    from app.services.scanner_service_policy import analyze_services, clip_policy_snapshots

    # Rebuild family status from source rows rather than trusting a client pass.
    # Scope and ownership are enforced by the same locked job as other evidence.
    orch["service_coverage"] = {
        host: analyze_services(vulnerabilities, host=host, coverage=(host_coverage or {}).get(host))
        for host in target_list
    }
    saved_policies = clip_policy_snapshots(orch.get("policy_snapshots"), target_list)
    saved_policies.update(clip_policy_snapshots(policy_snapshots, target_list))
    orch["policy_snapshots"] = saved_policies
    orch["edge_agent"] = True
    orch["enabled"] = False
    if _normalize_agent_instance(agent_instance_id):
        orch["edge_owner_instance"] = _normalize_agent_instance(agent_instance_id)
        orch["edge_owner_seen_at"] = datetime.now(timezone.utc).isoformat()
    if final_status == "completed" and plugin_errors > 0:
        progress_message = f"assessment completed with {plugin_errors} scanner warning(s)"
    elif final_status == "completed":
        progress_message = "assessment verified"
    else:
        progress_message = "assessment incomplete"
    orch["edge_progress"] = {
        "pct": 100.0,
        "message": progress_message,
    }
    orch["assessment_complete"] = verified_complete
    orch["clean_eligible"] = bool(verified_complete and plugin_health_ok and result_payload_ok and not skipped_details)
    orch["completed_with_warnings"] = bool(verified_complete and (plugin_errors > 0 or bool(skipped_details)))
    orch["hosts_attempted"] = attempted
    orch["hosts_assessed"] = assessed
    orch["report_id"] = effective_report_id
    orch["skipped_hosts"] = skipped_details
    orch["assessed_hosts"] = assessed_list
    # V45.4: per-IP coverage from the agent. A host whose port scanner was killed
    # is shown as "incomplete" with the reason, never as a green "completed".
    host_cov = host_coverage if isinstance(host_coverage, dict) else None
    # V45.4 central guard: an agent that predates the coverage verdict uploads no
    # host_coverage at all. Recognise the truncated-scan signature anyway
    # (scanner errors present and <= 3 results per assessed host, all info) and
    # mark every assessed host incomplete rather than green.
    if not host_cov and int(plugin_errors or 0) > 0:
        per_host = int(result_count or 0) / float(max(int(assessed or 0), 1))
        non_info = 0
        for v in vulnerabilities or []:
            sev = str((v or {}).get("severity") or (v or {}).get("threat") or "").strip().lower()
            if sev and sev not in {"info", "log", "none", "informational", "0", "0.0"}:
                non_info += 1
        if per_host <= 3.0 and non_info == 0:
            reason = (
                f"legacy agent (no coverage data): {int(result_count or 0)} informational result(s) over "
                f"{int(assessed or 0)} host(s) with {int(plugin_errors or 0)} scanner error(s) - port scan did not finish"
            )
            host_cov = {
                str(h): {"verdict": "degraded_legacy_signature", "reason": reason, "open_tcp_ports": [], "nvts_launched": 0}
                for h in assessed_list
            }
    if isinstance(host_cov, dict) and host_cov:
        tp = dict(orch.get("target_progress") or {}) if isinstance(orch.get("target_progress"), dict) else {}
        degraded_now: list[str] = []
        for cov_host, cov in host_cov.items():
            if not isinstance(cov, dict):
                continue
            verdict = str(cov.get("verdict") or "full")
            entry = dict(tp.get(cov_host) or {})
            if verdict.startswith("degraded"):
                degraded_now.append(str(cov_host))
                entry["status"] = "incomplete"
                entry["activity"] = f"Incomplete — {str(cov.get('reason') or verdict)[:160]}"
            else:
                entry["status"] = "completed"
                entry["activity"] = "Completed"
            entry["coverage"] = {
                "verdict": verdict,
                "open_tcp_ports": len(cov.get("open_tcp_ports") or []),
                "nvts_launched": int(cov.get("nvts_launched") or 0),
            }
            tp[str(cov_host)] = entry
        orch["target_progress"] = tp
        orch["host_coverage"] = host_cov
        orch["degraded_hosts"] = degraded_now
        if degraded_now:
            orch["completed_with_warnings"] = True
            orch["clean_eligible"] = False
            orch["partial"] = True
            orch["partial_reason"] = (
                f"{len(degraded_now)} host(s) incomplete — port scan did not finish: {', '.join(degraded_now[:5])}"
            )[:500]
            orch["edge_progress"] = {"pct": 100.0, "message": orch["partial_reason"]}
    orch["reachable_target_count"] = required_count
    orch["plugin_error_count"] = plugin_errors
    orch["result_payload_ok"] = result_payload_ok
    orch["report_result_count"] = result_count
    orch["uploaded_vulnerability_rows"] = len(vulnerabilities or [])
    if partial or orch.get("degraded_hosts"):
        orch["partial"] = True
        orch["partial_reason"] = (partial_reason or orch.get("partial_reason") or "Partial assessment")[:500]
    else:
        orch.pop("partial", None)
        orch.pop("partial_reason", None)

    # Persist and return the effective coverage flags, not just the agent's
    # top-level claims. A finished task can still have an incomplete port scan.
    evidence.update({
        "partial": bool(orch.get("partial")),
        "partial_reason": orch.get("partial_reason"),
        "clean_eligible": bool(orch.get("clean_eligible")),
        "completed_with_warnings": bool(orch.get("completed_with_warnings")),
        "host_coverage": host_cov,
        "service_coverage": orch["service_coverage"],
        "policy_snapshots": orch["policy_snapshots"],
        "degraded_hosts": list(orch.get("degraded_hosts") or []),
    })
    record_scan_result(
        db,
        scan_job_id=job_id,
        hosts_attempted=attempted,
        hosts_assessed=assessed,
        credential_success=0,
        credential_fail=0,
        plugin_errors=plugin_errors,
        result_json=evidence,
    )

    execute(
        db,
        """UPDATE vuln_scan_jobs
           SET status = :st,
               external_scan_id = COALESCE(:eid, external_scan_id),
               error = :err,
               orchestration_json = CAST(:orch AS jsonb),
               completed_at = NOW(),
               updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {
            "st": final_status,
            "eid": external_scan_id,
            "err": (err_text[:2000] if err_text else None),
            "orch": json.dumps(orch),
            "id": job_id,
        },
    )

    if final_status == "completed":
        if plugin_errors > 0:
            summary = (
                f"Edge assessment completed with warnings: {assessed}/{target_count} target(s) assessed; "
                f"{plugin_errors} plugin/scanner warning(s); {findings} finding(s) ingested"
            )
        else:
            summary = (
                f"Edge assessment verified: {assessed}/{target_count} target(s) assessed; "
                f"{findings} finding(s) ingested"
            )
        event_type = "scan.completed"
    else:
        summary = (err_text or "Edge assessment incomplete")[:500]
        event_type = "scan.cancelled" if final_status == "cancelled" else "scan.failed"

    timeline(
        db,
        case_id=case_id,
        source_type="scan_job",
        source_id=job_id,
        event_type=event_type,
        actor="scanner-agent",
        summary=summary,
    )
    log.info(
        "Edge agent job %s ingested %s findings status=%s attempted=%s assessed=%s report=%s",
        job_id,
        findings,
        final_status,
        attempted,
        assessed,
        report_id,
    )
    return {
        "status": final_status,
        "findings": findings,
        "partial": bool(orch.get("partial")),
        "assessment_complete": verified_complete,
        "clean_eligible": bool(orch.get("clean_eligible")),
        "completed_with_warnings": bool(orch.get("completed_with_warnings")),
        "plugin_error_count": plugin_errors,
        "hosts_attempted": attempted,
        "hosts_assessed": assessed,
        "report_id": report_id,
        "error": err_text,
    }


def ingest_agent_logs(db, *, scanner_id: str, entries: list[dict[str, Any]]) -> int:
    """Persist log lines uploaded by a laptop/edge scanner-agent."""
    row = fetchone(db, "SELECT to_regclass('scanner_agent_logs') AS r")
    if not row or not row.get("r"):
        return 0
    stored = 0
    for raw in (entries or [])[:200]:
        if not isinstance(raw, dict):
            continue
        message = str(raw.get("message") or "").strip()[:2000]
        if not message:
            continue
        level = str(raw.get("level") or "info").strip().lower()
        if level in {"warn"}:
            level = "warning"
        if level not in {"debug", "info", "warning", "error"}:
            level = "info"
        job_id = str(raw.get("job_id") or "").strip() or None
        if job_id:
            try:
                job_id = str(UUID(job_id))
            except Exception:
                job_id = None
        ts = str(raw.get("ts") or "").strip() or None
        try:
            execute(
                db,
                """INSERT INTO scanner_agent_logs
                     (scanner_id, job_id, level, logger, stage, message, created_at)
                   VALUES (
                     CAST(:scanner_id AS uuid),
                     CASE WHEN :job_id IS NULL THEN NULL ELSE CAST(:job_id AS uuid) END,
                     :level, :logger, :stage, :message,
                     COALESCE(CAST(:ts AS timestamptz), NOW())
                   )""",
                {
                    "scanner_id": scanner_id,
                    "job_id": job_id,
                    "level": level,
                    "logger": str(raw.get("logger") or "")[:120] or None,
                    "stage": str(raw.get("stage") or "")[:64] or None,
                    "message": message,
                    "ts": ts,
                },
            )
            stored += 1
        except Exception:
            log.debug("skip malformed agent log row", exc_info=True)
    return stored
