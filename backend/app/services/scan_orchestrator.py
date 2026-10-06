"""Multi-scanner orchestration pipeline."""

from __future__ import annotations

import json
import logging
import math
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable

from app.config import get_settings
from app.db.sql_helpers import execute, fetchone, fetchall
from app.services.multi_scanner_clients import get_aux_scanner
from app.services.scanner_adapter import enrich_stub_scan_details, get_scanner_client
from app.services.aetheris_severity import aetheris_severity_sql
from app.services.vuln_correlation import correlate_case_findings
from app.services.vuln_finding_ingest import refresh_asset_risk, upsert_finding

log = logging.getLogger("scan_orchestrator")

DEFAULT_PIPELINE: list[dict[str, Any]] = [
    {"engine": "nmap", "role": "discovery"},
    {"engine": "openvas", "role": "vulnerability", "required": True},
    {"engine": "nuclei", "role": "rapid_cve"},
    {"engine": "zap", "role": "webapp"},
    {"engine": "wazuh", "role": "endpoint"},
    {"engine": "trivy", "role": "container"},
]

NETWORK_TYPES = {"", "host", "hostname", "ip", "ipv4", "ipv6", "cidr", "network"}
WEB_TYPES = NETWORK_TYPES | {"url", "uri", "web", "webapp", "website"}
CONTAINER_TYPES = {"image", "container", "container_image", "docker_image", "oci", "oci_image"}
ENDPOINT_TYPES = {"endpoint", "agent", "wazuh_agent"}


def _orch_dict(job: dict[str, Any] | None) -> dict[str, Any]:
    raw = (job or {}).get("orchestration_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = None
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, list):
        return {"pipeline": raw}
    return {}


def adaptive_openvas_timeout_sec(host_count: int, settings: Any | None = None) -> int:
    """Wall-clock cap when GVM_SCAN_TIMEOUT_SEC is 0 (Full and fast needs hours, not minutes)."""
    settings = settings or get_settings()
    try:
        configured = int(getattr(settings, "gvm_scan_timeout_sec", 0) or 0)
    except (TypeError, ValueError):
        configured = 0
    if configured > 0:
        return configured
    profile = getattr(settings, "gvm_port_profile", "fast")
    profile_s = profile.strip().lower() if isinstance(profile, str) else "fast"
    n = max(1, int(host_count or 1))
    # Fast port profiles finish sooner; full/IANA ranges need multi-hour headroom.
    per_host = 900 if profile_s in {"fast", "quick", "top"} else 3600
    return min(14_400, 600 + per_host * n)


def _merge_orchestration(db, scan_job_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    row = fetchone(
        db,
        "SELECT orchestration_json FROM vuln_scan_jobs WHERE id = CAST(:id AS uuid)",
        {"id": scan_job_id},
    )
    orch = _orch_dict({"orchestration_json": (row or {}).get("orchestration_json")})
    for key, value in patch.items():
        if key == "target_progress" and isinstance(value, dict):
            merged = dict(orch.get("target_progress") or {}) if isinstance(orch.get("target_progress"), dict) else {}
            for ip, state in value.items():
                prev = dict(merged.get(ip) or {}) if isinstance(merged.get(ip), dict) else {}
                if isinstance(state, dict):
                    engines = dict(prev.get("engines") or {})
                    engines.update(state.get("engines") or {})
                    prev.update(state)
                    prev["engines"] = engines
                    merged[str(ip)] = prev
                else:
                    merged[str(ip)] = state
            orch["target_progress"] = merged
        else:
            orch[key] = value
    execute(
        db,
        """UPDATE vuln_scan_jobs
              SET orchestration_json = CAST(:orch AS jsonb), updated_at = NOW()
            WHERE id = CAST(:id AS uuid)""",
        {"orch": json.dumps(orch), "id": scan_job_id},
    )
    return orch


def _set_targets_activity(
    db,
    scan_job_id: str,
    ips: list[str],
    *,
    status: str,
    activity: str,
    engine: str | None = None,
    engine_status: str | None = None,
) -> None:
    patch: dict[str, Any] = {}
    progress: dict[str, Any] = {}
    for ip in ips:
        host = str(ip or "").strip()
        if not host:
            continue
        entry: dict[str, Any] = {"status": status, "activity": activity}
        if engine:
            entry["engines"] = {engine: engine_status or status}
        progress[host] = entry
    if not progress:
        return
    patch["target_progress"] = progress
    _merge_orchestration(db, scan_job_id, patch)


def resolve_pipeline(job: dict) -> list[dict[str, Any]]:
    raw = job.get("orchestration_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = None
    if isinstance(raw, dict) and raw.get("pipeline"):
        return list(raw["pipeline"])
    if isinstance(raw, list):
        return raw
    settings = get_settings()
    if settings.vuln_orchestration_enabled:
        return [dict(step) for step in DEFAULT_PIPELINE]
    return [{"engine": "openvas", "role": "vulnerability", "required": True}]


def _record_engine_run(
    db,
    *,
    scan_job_id: str,
    engine: str,
    role: str | None,
    status: str,
    findings_count: int = 0,
    error: str | None = None,
    metadata: dict | None = None,
) -> None:
    execute(
        db,
        """INSERT INTO vuln_scan_engine_runs
           (scan_job_id, engine, role, status, started_at, completed_at, findings_count, error, metadata_json)
           VALUES (CAST(:jid AS uuid), :engine, :role, :status, NOW(), NOW(), :fc, :err, CAST(:meta AS jsonb))""",
        {
            "jid": scan_job_id,
            "engine": engine,
            "role": role,
            "status": status,
            "fc": findings_count,
            "err": (error or "")[:2000] or None,
            "meta": json.dumps(metadata or {}),
        },
    )


def _ensure_asset(db, *, case_id: str, target: str) -> str:
    existing = fetchone(
        db,
        """SELECT id FROM vuln_assets
           WHERE case_id = CAST(:cid AS uuid) AND (primary_ip = :t OR hostname = :t) LIMIT 1""",
        {"cid": case_id, "t": target},
    )
    if existing:
        return str(existing["id"])
    row = fetchone(
        db,
        """INSERT INTO vuln_assets (case_id, hostname, primary_ip, asset_type, lifecycle_state)
           VALUES (CAST(:cid AS uuid), :t, :t, 'host', 'active') RETURNING id""",
        {"cid": case_id, "t": target},
    )
    return str(row["id"])


def ingest_engine_results(
    db,
    *,
    case_id: str,
    scan_job_id: str,
    engine: str,
    targets: list[str],
    vulnerabilities: list[dict[str, Any]],
    credentialed: bool,
) -> int:
    """Persist every scanner row once and attribute it to its reported host.

    ``vulnerabilities`` is a report-level collection.  The previous code
    nested that collection under ``targets`` and therefore ingested N x M
    rows for an N-target report.  It also reused a mutable ``asset_id`` across
    rows, which could attach a finding to the host from the preceding row.
    """
    count = 0
    clean_targets = [str(t).strip() for t in targets if str(t).strip()]
    asset_cache: dict[str, str] = {}
    touched_assets: set[str] = set()

    def _asset_for(host: str) -> str:
        if host not in asset_cache:
            asset_cache[host] = _ensure_asset(db, case_id=case_id, target=host)
        return asset_cache[host]

    for raw_vuln in vulnerabilities:
        v = dict(raw_vuln)
        reported_host = str(v.get("host") or "").strip()
        if not reported_host or reported_host == "*":
            if not clean_targets:
                log.warning("Skipping hostless %s finding for scan %s: no target is available", engine, scan_job_id)
                continue
            # Scanner-wide informational rows have no host identity. Store
            # them once, rather than duplicating them onto every target.
            reported_host = clean_targets[0]

        asset_id = _asset_for(reported_host)
        touched_assets.add(asset_id)
        v["scan_engine"] = engine
        if upsert_finding(
            db,
            case_id=case_id,
            scan_job_id=scan_job_id,
            asset_id=asset_id,
            vuln=v,
            credentialed=credentialed,
            source=engine,
        ):
            count += 1

    for asset_id in touched_assets:
        refresh_asset_risk(db, asset_id)
    return count


def _target_rows_for_engine(engine: str, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    active = [t for t in targets if not t.get("excluded")]
    if engine in {"openvas", "greenbone", "gvm", "nessus", "tenable", "nmap"}:
        allowed = NETWORK_TYPES
    elif engine in {"zap", "owasp_zap", "nuclei"}:
        allowed = WEB_TYPES
    elif engine == "trivy":
        allowed = CONTAINER_TYPES
    elif engine == "wazuh":
        allowed = ENDPOINT_TYPES
    else:
        return active
    return [t for t in active if str(t.get("target_type") or "host").strip().lower() in allowed]


def scan_job_progress(db, job: dict[str, Any]) -> dict[str, Any]:
    """Derive UI progress from job status and per-engine run rows."""
    status = (job.get("status") or "pending").lower()
    if status == "completed":
        # V45.4a: completed edge jobs say which agent build ran and whether any host is incomplete.
        try:
            orch_done = _orch_dict(job)
        except Exception:
            orch_done = {}
        if orch_done.get("edge_agent"):
            parts = ["Complete"]
            degraded = orch_done.get("degraded_hosts") or []
            if degraded:
                parts[0] = f"Complete - {len(degraded)} host(s) incomplete"
            ver = orch_done.get("edge_agent_version")
            build = orch_done.get("edge_agent_build")
            if ver:
                parts.append(f"agent {ver}" + (f" - {build}" if build and build.startswith("legacy") else ""))
            return {"progress_pct": 100, "progress_label": " · ".join(parts)[:120]}
        return {"progress_pct": 100, "progress_label": "Complete"}
    if status == "failed":
        return {"progress_pct": 100, "progress_label": "Failed"}
    if status == "cancelled":
        return {"progress_pct": 0, "progress_label": "Cancelled"}

    orch = _orch_dict(job)
    if orch.get("edge_agent"):
        edge = orch.get("edge_progress") or {}
        try:
            pct = float(edge.get("pct") or (5 if status == "queued" else 15))
        except (TypeError, ValueError):
            pct = 5.0 if status == "queued" else 15.0
        msg = str(edge.get("message") or ("Waiting for on-site agent" if status == "queued" else "Edge OpenVAS"))
        return {"progress_pct": max(0, min(99, int(pct))), "progress_label": msg[:80]}

    if status == "queued":
        return {"progress_pct": 5, "progress_label": "Waiting for on-site agent"}

    pipeline = resolve_pipeline(job)
    total_engines = max(len(pipeline), 1)
    runs = fetchall(
        db,
        """SELECT engine, status FROM vuln_scan_engine_runs
           WHERE scan_job_id = CAST(:jid AS uuid)
           ORDER BY started_at DESC NULLS LAST""",
        {"jid": str(job["id"])},
    )
    latest_by_engine: dict[str, str] = {}
    for r in runs:
        eng = str(r.get("engine") or "")
        if eng and eng not in latest_by_engine:
            latest_by_engine[eng] = (r.get("status") or "").lower()
    finished = sum(1 for s in latest_by_engine.values() if s in {"completed", "failed", "skipped"})
    running_engines = [e for e, s in latest_by_engine.items() if s == "running"]
    running = len(running_engines)
    live = orch.get("live_progress") if isinstance(orch.get("live_progress"), dict) else {}
    try:
        ov_frac = float(live.get("openvas_pct") or 0) / 100.0
    except (TypeError, ValueError):
        ov_frac = 0.0
    ov_frac = max(0.0, min(1.0, ov_frac))

    if status == "pending":
        return {"progress_pct": 8, "progress_label": "Queued"}

    if finished >= total_engines:
        pct = 95
    elif running > 0 and any(e in {"openvas", "greenbone", "gvm"} for e in running_engines):
        pct = min(99, max(15, int(((finished + ov_frac) / total_engines) * 100)))
    elif finished > 0 or running > 0:
        pct = min(92, max(15, int((finished / total_engines) * 100)))
    else:
        pct = 20

    live_label = str(live.get("label") or "").strip()
    if live_label:
        label = live_label[:80]
    elif running_engines:
        label = f"Running {', '.join(running_engines)} ({finished}/{total_engines})"
    elif finished > 0:
        label = f"{finished}/{total_engines} engines"
    else:
        label = "Running"

    return {"progress_pct": pct, "progress_label": label}


def _progress_pct(info: dict[str, Any]) -> float:
    raw = info.get("progress", 0)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _wait_for_openvas(
    client: Any,
    external_id: str,
    *,
    host_count: int = 1,
    on_progress: Callable[[float, str], None] | None = None,
) -> dict[str, Any]:
    """Poll OpenVAS until complete; extend near the end; harvest partial results on timeout."""
    settings = get_settings()

    def _int_setting(name: str, default: int) -> int:
        raw = getattr(settings, name, default)
        if raw is None:
            return default
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default

    poll_sec = max(2, _int_setting("gvm_scan_poll_interval_sec", 15))
    configured_timeout = max(0, _int_setting("gvm_scan_timeout_sec", 0))
    timeout_sec = configured_timeout if configured_timeout > 0 else adaptive_openvas_timeout_sec(host_count, settings)
    grace_sec = max(0, _int_setting("gvm_scan_near_complete_grace_sec", 0))
    near_pct = max(50, _int_setting("gvm_scan_near_complete_progress_pct", 85))
    # GVM_SCAN_STALL_SEC=0 disables stall harvest (do not force a 90s default —
    # that aborted live Full-and-fast jobs and marked them completed with 0 vulns).
    stall_sec = max(0, _int_setting("gvm_scan_stall_sec", 0))
    stall_pct = max(40, _int_setting("gvm_scan_stall_progress_pct", 95))
    deadline = time.monotonic() + timeout_sec
    grace_used = False
    last_details: dict[str, Any] = {}
    last_progress = -1.0
    last_progress_change = time.monotonic()

    def _harvest_partial(reason: str) -> dict[str, Any]:
        nonlocal last_details
        # Best-effort stop so lingering NVTs do not keep burning CPU.
        stop = getattr(client, "stop_scan", None)
        if callable(stop):
            try:
                stop(external_id)
            except Exception as exc:
                log.warning("OpenVAS stop after stall/timeout failed: %s", exc)
        try:
            details = client.scan_details(external_id)
            if isinstance(details, dict):
                last_details = details
        except Exception as exc:
            log.warning("OpenVAS harvest after stall/timeout failed: %s", exc)
        info = last_details.get("info") or {}
        progress = _progress_pct(info)
        vulns = last_details.get("vulnerabilities") or []
        out = dict(last_details)
        out["partial"] = True
        out["partial_reason"] = f"{reason} at {progress:.0f}% ({len(vulns)} vulns)"
        log.warning(
            "OpenVAS task %s %s — ingesting available results (%d vulns, %.0f%%)",
            external_id,
            reason,
            len(vulns),
            progress,
        )
        return out

    while True:
        details = client.scan_details(external_id)
        last_details = details if isinstance(details, dict) else {}
        info = last_details.get("info") or {}
        status = str(info.get("status") or "running").lower()
        progress = _progress_pct(info)
        if on_progress:
            try:
                on_progress(progress, status)
            except Exception:
                log.debug("OpenVAS progress callback failed", exc_info=True)

        if status == "completed":
            return last_details
        if status in {"failed", "cancelled", "canceled", "stopped", "interrupted"}:
            # Still return results if the scanner produced vulns before stopping.
            vulns = last_details.get("vulnerabilities") or []
            if vulns or progress >= near_pct:
                last_details = dict(last_details)
                last_details["partial"] = True
                last_details["partial_reason"] = f"task ended with status {info.get('gmp_status') or status}"
                log.warning(
                    "OpenVAS task %s ended as %s with %d findings — ingesting partial results",
                    external_id,
                    status,
                    len(vulns),
                )
                return last_details
            raw = info.get("gmp_status") or status
            raise RuntimeError(f"OpenVAS task {external_id} ended with status: {raw}")

        now = time.monotonic()
        if progress != last_progress:
            last_progress = progress
            last_progress_change = now
        elif (
            stall_sec > 0
            and progress >= stall_pct
            and (now - last_progress_change) >= stall_sec
        ):
            return _harvest_partial(f"stalled {stall_sec}s at >={stall_pct}%")

        if deadline is not None and now >= deadline:
            if not grace_used and progress >= near_pct and grace_sec > 0:
                grace_used = True
                deadline = now + grace_sec
                log.warning(
                    "OpenVAS task %s at %.0f%% after base timeout — extending %ss",
                    external_id,
                    progress,
                    grace_sec,
                )
                time.sleep(poll_sec)
                continue

            # Final harvest: prefer partial results over hard failure near completion.
            if progress >= near_pct or (last_details.get("vulnerabilities") or []):
                return _harvest_partial(f"timed out after {timeout_sec}s (+grace={grace_used})")
            raise TimeoutError(
                f"OpenVAS task {external_id} did not finish within {timeout_sec}s "
                f"(last progress={progress:.0f}%)"
            )
        time.sleep(poll_sec)


def openvas_ip_chunks(hosts: list[str], workers: int) -> list[list[str]]:
    """One client IP per OpenVAS task when more than one worker is available."""
    clean = [str(h).strip() for h in hosts if str(h).strip()]
    if not clean:
        return []
    if int(workers or 1) <= 1 or len(clean) <= 1:
        return [clean]
    return [[h] for h in clean]


def merge_openvas_details(parts: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine per-IP OpenVAS reports into one ingest payload."""
    if not parts:
        return {"info": {"status": "failed"}, "vulnerabilities": [], "stub": False}
    if len(parts) == 1:
        return parts[0]
    vulns: list[dict[str, Any]] = []
    messages: list[str] = []
    reasons: list[str] = []
    progresses: list[float] = []
    stub_all = True
    any_partial = False
    for details in parts:
        if not details.get("stub"):
            stub_all = False
        vulns.extend(details.get("vulnerabilities") or [])
        if details.get("message"):
            messages.append(str(details["message"]))
        if details.get("partial"):
            any_partial = True
            if details.get("partial_reason"):
                reasons.append(str(details["partial_reason"]))
        info = details.get("info") if isinstance(details.get("info"), dict) else {}
        try:
            progresses.append(float(info.get("progress") or 0))
        except (TypeError, ValueError):
            pass
    avg = sum(progresses) / len(progresses) if progresses else 0.0
    out: dict[str, Any] = {
        "stub": stub_all,
        "info": {"status": "completed", "progress": avg},
        "vulnerabilities": vulns,
        "message": "; ".join(messages)[:1000] if messages else None,
        "parallel_ip_tasks": len(parts),
    }
    if any_partial:
        out["partial"] = True
        out["partial_reason"] = (
            "; ".join(reasons)[:500] if reasons else "one or more IP tasks were partial"
        )
    return out


def _launch_openvas_ip_tasks(
    client: Any,
    *,
    scan_job_id: str,
    hosts: list[str],
    port_range: str | None,
    workers: int,
) -> list[dict[str, Any]]:
    chunks = openvas_ip_chunks(hosts, workers)
    if not chunks:
        return []

    def _one(idx: int, chunk: list[str]) -> dict[str, Any]:
        name = (
            f"orch-{scan_job_id[:8]}-openvas"
            if len(chunks) == 1
            else f"orch-{scan_job_id[:8]}-ip{idx}"
        )
        created = client.create_scan(
            name=name,
            targets=",".join(chunk),
            port_range=port_range,
        )
        scan_obj = created.get("scan") or {}
        stub = bool(created.get("stub"))
        eid = str(scan_obj.get("id") or f"stub-{scan_job_id[:8]}-{idx}")
        return {
            "hosts": list(chunk),
            "external_id": eid,
            "stub": stub or eid.startswith("stub-"),
            "created": created,
        }

    if len(chunks) == 1:
        return [_one(0, chunks[0])]
    launched: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(max(1, int(workers)), len(chunks))) as pool:
        futs = [pool.submit(_one, i, chunk) for i, chunk in enumerate(chunks)]
        for fut in as_completed(futs):
            launched.append(fut.result())
    launched.sort(key=lambda row: str((row.get("hosts") or [""])[0]))
    log.info(
        "OpenVAS launched %d parallel IP task(s) for job %s (workers=%s)",
        len(launched),
        scan_job_id,
        workers,
    )
    return launched


def _wait_for_openvas_many(
    client: Any,
    tasks: list[dict[str, Any]],
    *,
    on_progress: Callable[[float, str], None] | None = None,
) -> dict[str, Any]:
    if not tasks:
        return {"info": {"status": "failed"}, "vulnerabilities": [], "stub": False}
    if len(tasks) == 1:
        row = tasks[0]
        return _wait_for_openvas(
            client,
            str(row["external_id"]),
            host_count=max(1, len(row.get("hosts") or [])),
            on_progress=on_progress,
        )

    progress_by_id: dict[str, float] = {}

    def _wrapped(eid: str, hosts: list[str]) -> dict[str, Any]:
        def _cb(progress: float, status: str) -> None:
            progress_by_id[eid] = float(progress)
            if on_progress:
                vals = list(progress_by_id.values())
                avg = sum(vals) / len(vals) if vals else progress
                on_progress(avg, status)

        return _wait_for_openvas(
            client,
            eid,
            host_count=max(1, len(hosts)),
            on_progress=_cb,
        )

    parts: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
        futs = [
            pool.submit(_wrapped, str(row["external_id"]), list(row.get("hosts") or []))
            for row in tasks
        ]
        for fut in as_completed(futs):
            parts.append(fut.result())
    return merge_openvas_details(parts)


def _persist_external_scan_id(db, scan_job_id: str, external_id: str) -> None:
    execute(
        db,
        """UPDATE vuln_scan_jobs
              SET external_scan_id = :eid, updated_at = NOW()
            WHERE id = CAST(:id AS uuid)""",
        {"eid": str(external_id), "id": scan_job_id},
    )


def _openvas_port_range_for_targets(hosts: list[str]) -> tuple[str, dict[str, list[int]]]:
    from app.services.greenbone_gmp import (
        parse_tcp_ports_from_range,
        ports_to_gvm_range,
        probe_open_tcp_ports,
        FAST_TARGET_PORT_RANGE,
    )

    probed = probe_open_tcp_ports(hosts, parse_tcp_ports_from_range(FAST_TARGET_PORT_RANGE))
    open_ports = sorted({p for ports in probed.values() for p in ports})
    if open_ports:
        return ports_to_gvm_range(open_ports), probed
    return "T:22,80,443,445,3389,8080", probed


def reap_orphaned_openvas_job(
    db,
    *,
    scan_job_id: str,
    job: dict[str, Any],
    scanner_url: str = "",
) -> dict[str, Any] | None:
    """Stop leftover GVM tasks after a worker crash and return harvested details."""
    prefix = f"orch-{str(scan_job_id)[:8]}"
    client = get_scanner_client(edition="openvas", base_url=scanner_url)
    finder = getattr(client, "find_tasks", None)
    if not callable(finder) or not getattr(client, "configured", False):
        return None
    try:
        tasks = finder(name_contains=prefix) or []
    except Exception as exc:
        log.warning("Could not list OpenVAS tasks for %s: %s", scan_job_id, exc)
        return None
    if not tasks:
        return None
    running = [t for t in tasks if str(t.get("status") or "").lower() in {"running", "requested", "queued", "new"}]
    chosen_list = running or list(tasks)
    stop = getattr(client, "stop_scan", None)
    parts: list[dict[str, Any]] = []
    ids: list[str] = []
    for chosen in chosen_list:
        task_id = str(chosen.get("id") or "")
        if not task_id:
            continue
        log.warning(
            "Reaping orphaned OpenVAS task %s (%s %s%%) for job %s",
            task_id,
            chosen.get("status"),
            chosen.get("progress"),
            scan_job_id,
        )
        if callable(stop):
            try:
                stop(task_id)
            except Exception as exc:
                log.warning("Stop orphaned OpenVAS task %s failed: %s", task_id, exc)
        try:
            details = client.scan_details(task_id)
        except Exception as exc:
            log.warning("Harvest orphaned OpenVAS task %s failed: %s", task_id, exc)
            continue
        if not isinstance(details, dict):
            continue
        details = dict(details)
        details["partial"] = True
        details["partial_reason"] = (
            f"reaped orphaned task {task_id} at {chosen.get('progress')}% ({chosen.get('status')})"
        )
        parts.append(details)
        ids.append(task_id)
    if not parts:
        return None
    merged = merge_openvas_details(parts)
    merged["partial"] = True
    if ids:
        _persist_external_scan_id(db, scan_job_id, ",".join(ids))
        merged["external_scan_id"] = ",".join(ids)
    return merged


def run_orchestrated_scan(
    db,
    *,
    schema_name: str,
    job: dict,
    scan_job_id: str,
    targets: list[dict],
    scanner_url: str = "",
    scanner_edition: str | None = None,
    custom_checks: list[dict] | None = None,
) -> dict[str, Any]:
    """Execute the multi-engine pipeline and ingest only genuine findings."""
    active_targets = [t["target"] for t in targets if not t.get("excluded")]
    if not active_targets:
        return {"status": "failed", "error": "no targets"}

    execute(
        db,
        """UPDATE vuln_scan_jobs SET status = 'running', error = NULL,
           started_at = COALESCE(started_at, NOW()), updated_at = NOW()
           WHERE id = CAST(:id AS uuid)""",
        {"id": scan_job_id},
    )
    db.commit()

    case_id = str(job["case_id"])
    credentialed = any(t.get("credential_ref") for t in targets)
    pipeline = resolve_pipeline(job)
    settings = get_settings()
    allow_stub = bool(getattr(settings, "vuln_allow_stub_findings", False))
    engine_results: list[dict[str, Any]] = []
    total_findings = 0
    required_failures: list[str] = []
    all_failures: list[str] = []
    real_completed = 0
    overlap = bool(getattr(settings, "vuln_orch_overlap_enabled", True))
    deferred_openvas: dict[str, Any] | None = None

    _merge_orchestration(
        db,
        scan_job_id,
        {
            "target_progress": {
                str(t): {"status": "pending", "activity": "Queued", "engines": {}}
                for t in active_targets
            },
            "live_progress": {"label": "Starting scanners", "pct": 10},
        },
    )
    db.commit()

    def _openvas_progress(progress: float, status: str, ips: list[str]) -> None:
        label = f"OpenVAS {progress:.0f}%"
        if status and status not in {"running", "requested"}:
            label = f"OpenVAS {status} ({progress:.0f}%)"
        _set_targets_activity(
            db,
            scan_job_id,
            ips,
            status="scanning",
            activity=f"OpenVAS vulnerability scan ({progress:.0f}%)",
            engine="openvas",
            engine_status="running",
        )
        _merge_orchestration(
            db,
            scan_job_id,
            {"live_progress": {"label": label, "openvas_pct": progress, "running_engines": ["openvas"]}},
        )
        db.commit()

    def _run_aux_engine(engine: str, engine_targets: list[str], target_str: str) -> dict[str, Any]:
        from app.services.vuln_capacity import scanner_engine_lock, vuln_target_workers

        aux = get_aux_scanner(engine)
        activity = {
            "nmap": "Nmap port discovery",
            "nuclei": "Nuclei CVE templates",
            "zap": "ZAP web scan",
            "owasp_zap": "ZAP web scan",
            "wazuh": "Wazuh endpoint inventory",
            "trivy": "Trivy image scan",
        }.get(engine, f"Running {engine}")

        if engine == "nmap" or len(engine_targets) <= 1 or engine in {"wazuh", "trivy"}:
            _set_targets_activity(
                db,
                scan_job_id,
                engine_targets,
                status="scanning",
                activity=activity,
                engine=engine,
                engine_status="running",
            )
            _merge_orchestration(db, scan_job_id, {"live_progress": {"label": activity, "running_engines": [engine]}})
            db.commit()
            with scanner_engine_lock(engine):
                details = aux.run_scan(targets=target_str, name=f"orch-{scan_job_id[:8]}")
            done_status = "skipped" if (details.get("info") or {}).get("status") == "skipped" else "completed"
            _set_targets_activity(
                db,
                scan_job_id,
                engine_targets,
                status="scanning",
                activity=f"{engine} {done_status}",
                engine=engine,
                engine_status=done_status,
            )
            db.commit()
            return details

        workers = 1 if engine in {"zap", "owasp_zap"} else vuln_target_workers()
        _set_targets_activity(
            db,
            scan_job_id,
            engine_targets,
            status="scanning",
            activity=f"{activity} (parallel)" if workers > 1 else activity,
            engine=engine,
            engine_status="running",
        )
        _merge_orchestration(
            db,
            scan_job_id,
            {
                "live_progress": {
                    "label": f"{activity} on {len(engine_targets)} IPs",
                    "running_engines": [engine],
                }
            },
        )
        db.commit()

        merged_vulns: list[dict[str, Any]] = []
        messages: list[str] = []
        any_live = False

        def _scan_one(host: str) -> tuple[str, dict[str, Any]]:
            return host, aux.run_scan(targets=host, name=f"orch-{scan_job_id[:8]}-{host}")

        if workers <= 1:
            pairs = [_scan_one(h) for h in engine_targets]
        else:
            pairs = []
            with ThreadPoolExecutor(max_workers=min(workers, len(engine_targets))) as pool:
                futs = {pool.submit(_scan_one, h): h for h in engine_targets}
                for fut in as_completed(futs):
                    pairs.append(fut.result())

        for host, details in pairs:
            if not details.get("stub"):
                any_live = True
            merged_vulns.extend(details.get("vulnerabilities") or [])
            if details.get("message"):
                messages.append(str(details["message"]))
            done_status = "skipped" if (details.get("info") or {}).get("status") == "skipped" else "completed"
            _set_targets_activity(
                db,
                scan_job_id,
                [host],
                status="scanning",
                activity=f"{engine} {done_status}",
                engine=engine,
                engine_status=done_status,
            )
        db.commit()
        return {
            "stub": not any_live,
            "info": {"status": "completed", "engine": engine},
            "vulnerabilities": merged_vulns,
            "message": "; ".join(messages)[:1000] if messages else None,
        }

    def _ingest_completed_engine(
        *,
        engine: str,
        role: str | None,
        required: bool,
        engine_targets: list[str],
        details: dict[str, Any],
    ) -> None:
        nonlocal total_findings, real_completed
        vulns = details.get("vulnerabilities") or []
        if details.get("stub") and not allow_stub:
            reason = details.get("message") or f"{engine} returned stub/test data; live engine unavailable"
            state = "failed" if required else "skipped"
            _record_engine_run(
                db,
                scan_job_id=scan_job_id,
                engine=engine,
                role=role,
                status=state,
                error=reason,
                metadata={"stub": True, "ingested": False},
            )
            engine_results.append({"engine": engine, "status": state, "error": reason, "stub": True})
            if state == "failed":
                all_failures.append(f"{engine}: {reason}")
                required_failures.append(f"{engine}: {reason}")
            return

        fc = ingest_engine_results(
            db,
            case_id=case_id,
            scan_job_id=scan_job_id,
            engine=engine,
            targets=engine_targets,
            vulnerabilities=vulns,
            credentialed=credentialed,
        )
        total_findings += fc
        partial = bool(details.get("partial"))
        is_openvas = engine in {"openvas", "greenbone", "gvm"}
        # Required OpenVAS that was cut short with nothing to ingest is a failure,
        # not a "completed clean" scan of the client network.
        empty_partial_required = required and partial and fc == 0 and is_openvas
        # A finished OpenVAS report with zero rows (including Log/Info) almost
        # always means the scanner never assessed the host — not a clean bill.
        empty_live_required = required and (not partial) and fc == 0 and is_openvas and not details.get("stub")
        if empty_partial_required or empty_live_required:
            reason = str(
                details.get("partial_reason")
                or details.get("message")
                or (
                    "OpenVAS finished with no report rows — host was not assessed "
                    "(unreachable from scanner, empty feed, or results failed to load)"
                    if empty_live_required
                    else "OpenVAS stopped early with no findings — scan did not finish"
                )
            )
            all_failures.append(f"{engine}: {reason}")
            required_failures.append(f"{engine}: {reason}")
            _record_engine_run(
                db,
                scan_job_id=scan_job_id,
                engine=engine,
                role=role,
                status="failed",
                findings_count=0,
                error=reason[:500],
                metadata={
                    "stub": False,
                    "partial": partial,
                    "partial_reason": reason,
                    "empty_report": True,
                },
            )
            engine_results.append(
                {
                    "engine": engine,
                    "findings": 0,
                    "status": "failed",
                    "stub": False,
                    "partial": partial,
                    "error": reason,
                }
            )
            _set_targets_activity(
                db,
                scan_job_id,
                engine_targets,
                status="failed",
                activity="OpenVAS produced no results",
                engine=engine,
                engine_status="failed",
            )
            return

        real_completed += 0 if details.get("stub") else 1
        meta = {"stub": bool(details.get("stub", False))}
        if partial:
            meta["partial"] = True
            meta["partial_reason"] = details.get("partial_reason")
            all_failures.append(
                f"{engine}: partial results ({details.get('partial_reason') or 'timed out near completion'})"
            )
        _record_engine_run(
            db,
            scan_job_id=scan_job_id,
            engine=engine,
            role=role,
            status="completed",
            findings_count=fc,
            metadata=meta,
            error=str(details.get("partial_reason") or "")[:500] if partial else None,
        )
        engine_results.append(
            {
                "engine": engine,
                "findings": fc,
                "status": "completed",
                "stub": bool(details.get("stub", False)),
                "partial": partial,
            }
        )
        if is_openvas:
            _set_targets_activity(
                db,
                scan_job_id,
                engine_targets,
                status="completed",
                activity="Completed",
                engine=engine,
                engine_status="completed",
            )

    def _finish_deferred_openvas() -> None:
        nonlocal deferred_openvas, total_findings, real_completed
        pending = deferred_openvas
        if not pending:
            return
        deferred_openvas = None
        engine = str(pending["engine"])
        role = pending.get("role")
        required = bool(pending.get("required"))
        engine_targets = list(pending.get("engine_targets") or [])
        client = pending["client"]
        external_id = str(pending.get("external_id") or "")
        pending_tasks = list(pending.get("tasks") or [])
        if not pending_tasks and external_id:
            pending_tasks = [
                {"external_id": eid, "hosts": engine_targets}
                for eid in str(external_id).split(",")
                if eid.strip()
            ]
        try:
            details = _wait_for_openvas_many(
                client,
                pending_tasks,
                on_progress=lambda p, s, ips=engine_targets: _openvas_progress(p, s, ips),
            )
            _ingest_completed_engine(
                engine=engine,
                role=role,
                required=required,
                engine_targets=engine_targets,
                details=details,
            )
        except Exception as exc:
            log.exception("deferred engine %s failed for job %s", engine, scan_job_id)
            harvested = 0
            if "timed out" in str(exc).lower():
                try:
                    parts: list[dict[str, Any]] = []
                    for row in pending_tasks or [{"external_id": external_id}]:
                        eid = str(row.get("external_id") or "").strip()
                        if not eid or eid.startswith("stub-"):
                            continue
                        part = client.scan_details(eid)
                        if isinstance(part, dict):
                            parts.append(part)
                    details = merge_openvas_details(parts) if parts else {}
                    vulns = (details or {}).get("vulnerabilities") or []
                    if vulns:
                        harvested = ingest_engine_results(
                            db,
                            case_id=case_id,
                            scan_job_id=scan_job_id,
                            engine=engine,
                            targets=engine_targets,
                            vulnerabilities=vulns,
                            credentialed=credentialed,
                        )
                        total_findings += harvested
                        real_completed += 1
                except Exception as harvest_exc:
                    log.warning("OpenVAS timeout harvest failed: %s", harvest_exc)
            _record_engine_run(
                db,
                scan_job_id=scan_job_id,
                engine=engine,
                role=role,
                status="completed" if harvested else "failed",
                findings_count=harvested,
                error=str(exc),
                metadata={"harvested_after_timeout": bool(harvested), "deferred": True},
            )
            message = f"{engine}: {exc}"
            all_failures.append(message)
            if required and not harvested:
                required_failures.append(message)
            engine_results.append(
                {
                    "engine": engine,
                    "status": "completed" if harvested else "failed",
                    "error": str(exc),
                    "findings": harvested,
                    "partial": bool(harvested),
                }
            )
        finally:
            db.commit()

    for step in pipeline:
        engine = (step.get("engine") or "openvas").lower()
        role = step.get("role")
        required = bool(step.get("required", engine in {"openvas", "greenbone", "gvm"}))
        engine_target_rows = _target_rows_for_engine(engine, targets)
        engine_targets = [str(t["target"]) for t in engine_target_rows]

        if not engine_targets:
            reason = f"No applicable targets for {engine} (target types do not match engine role)"
            _record_engine_run(
                db,
                scan_job_id=scan_job_id,
                engine=engine,
                role=role,
                status="skipped",
                error=reason,
                metadata={"target_types": sorted({str(t.get('target_type') or 'host') for t in targets})},
            )
            engine_results.append({"engine": engine, "status": "skipped", "reason": reason})
            db.commit()
            continue

        target_str = ",".join(engine_targets)
        execute(
            db,
            """INSERT INTO vuln_scan_engine_runs
               (scan_job_id, engine, role, status, started_at)
               VALUES (CAST(:jid AS uuid), :engine, :role, 'running', NOW())""",
            {"jid": scan_job_id, "engine": engine, "role": role},
        )
        db.commit()

        external_id: str | None = None
        try:
            if engine in {"openvas", "greenbone", "gvm", "nessus", "tenable"}:
                client = get_scanner_client(
                    edition=engine if engine != "tenable" else "nessus",
                    base_url=scanner_url,
                )
                harvested = None
                if engine in {"openvas", "greenbone", "gvm"}:
                    stale = fetchone(
                        db,
                        """SELECT id FROM vuln_scan_engine_runs
                           WHERE scan_job_id = CAST(:jid AS uuid)
                             AND lower(engine) IN ('openvas', 'greenbone', 'gvm')
                             AND lower(status) = 'running'
                             AND started_at < NOW() - INTERVAL '90 seconds'
                           ORDER BY started_at ASC LIMIT 1""",
                        {"jid": scan_job_id},
                    )
                    if stale:
                        harvested = reap_orphaned_openvas_job(
                            db,
                            scan_job_id=scan_job_id,
                            job=job,
                            scanner_url=scanner_url,
                        )
                launched: list[dict[str, Any]] = []
                created: dict[str, Any] = {}
                if harvested:
                    details = harvested
                    external_id = str((harvested.get("external_scan_id") or "") or "")
                    created_stub = False
                else:
                    port_range = None
                    if engine in {"openvas", "greenbone", "gvm"}:
                        port_range, probed = _openvas_port_range_for_targets(engine_targets)
                        open_n = sum(len(v) for v in probed.values())
                        _set_targets_activity(
                            db,
                            scan_job_id,
                            engine_targets,
                            status="scanning",
                            activity=f"OpenVAS on {open_n} open port(s) ({port_range})",
                            engine="openvas",
                            engine_status="running",
                        )
                        db.commit()
                        from app.services.vuln_capacity import vuln_openvas_ip_workers

                        launched = _launch_openvas_ip_tasks(
                            client,
                            scan_job_id=scan_job_id,
                            hosts=engine_targets,
                            port_range=port_range,
                            workers=vuln_openvas_ip_workers(),
                        )
                        created = (launched[0].get("created") if launched else {}) or {}
                        created_stub = bool(launched) and all(row.get("stub") for row in launched)
                        ids = [str(row.get("external_id") or "") for row in launched if row.get("external_id")]
                        external_id = ",".join(ids)
                    else:
                        created = client.create_scan(
                            name=f"orch-{scan_job_id[:8]}-{engine}",
                            targets=target_str,
                            port_range=port_range,
                        )
                        scan_obj = created.get("scan") or {}
                        created_stub = bool(created.get("stub"))
                        external_id = str(scan_obj.get("id") or f"stub-{scan_job_id[:8]}")
                    live_ids = [
                        eid for eid in str(external_id or "").split(",") if eid and not eid.startswith("stub-")
                    ]
                    if live_ids:
                        _persist_external_scan_id(db, scan_job_id, ",".join(live_ids))
                        db.commit()
                if harvested:
                    pass
                elif created_stub or str(external_id or "").startswith("stub-"):
                    details = {
                        "stub": True,
                        "info": {"status": "completed"},
                        "vulnerabilities": [],
                        "message": created.get("message") or "Greenbone returned stub mode",
                    }
                    if allow_stub:
                        details = client.scan_details(str(external_id).split(",")[0])
                        details = enrich_stub_scan_details(
                            details,
                            credentialed=credentialed,
                            custom_checks=custom_checks,
                        )
                elif not harvested and overlap and engine in {"openvas", "greenbone", "gvm"}:
                    # Start OpenVAS now; run nuclei/zap/etc while it works, then wait.
                    deferred_openvas = {
                        "client": client,
                        "external_id": external_id,
                        "tasks": launched
                        or [
                            {"external_id": eid, "hosts": engine_targets}
                            for eid in str(external_id).split(",")
                            if eid.strip()
                        ],
                        "engine": engine,
                        "role": role,
                        "required": required,
                        "engine_targets": engine_targets,
                    }
                    _set_targets_activity(
                        db,
                        scan_job_id,
                        engine_targets,
                        status="scanning",
                        activity=(
                            f"OpenVAS vulnerability scan ({len(launched)} IP task(s))"
                            if len(launched) > 1
                            else "OpenVAS vulnerability scan (started)"
                        ),
                        engine="openvas",
                        engine_status="running",
                    )
                    _merge_orchestration(
                        db,
                        scan_job_id,
                        {
                            "live_progress": {
                                "label": (
                                    f"OpenVAS running {len(launched)} IP task(s) — overlapping other engines"
                                    if len(launched) > 1
                                    else "OpenVAS running — overlapping other engines"
                                ),
                                "openvas_pct": 1,
                                "running_engines": ["openvas"],
                            }
                        },
                    )
                    log.info(
                        "OpenVAS task %s started — overlapping subsequent engines for job %s",
                        external_id,
                        scan_job_id,
                    )
                    db.commit()
                    continue
                elif not harvested:
                    # create_scan() already starts GMP tasks. Wait for the real
                    # task to reach a terminal state before ingesting results.
                    wait_tasks = launched or [
                        {"external_id": eid, "hosts": engine_targets}
                        for eid in str(external_id or "").split(",")
                        if eid.strip()
                    ]
                    details = _wait_for_openvas_many(
                        client,
                        wait_tasks,
                        on_progress=lambda p, s, ips=engine_targets: _openvas_progress(p, s, ips),
                    )
            else:
                details = _run_aux_engine(engine, engine_targets, target_str)

            _ingest_completed_engine(
                engine=engine,
                role=role,
                required=required,
                engine_targets=engine_targets,
                details=details,
            )
        except Exception as exc:
            log.exception("engine %s failed for job %s", engine, scan_job_id)
            # Last-chance harvest for OpenVAS timeouts (older workers / race).
            harvested = 0
            if engine in {"openvas", "greenbone", "gvm"} and "timed out" in str(exc).lower():
                try:
                    client = get_scanner_client(edition=engine, base_url=scanner_url)
                    if external_id and not str(external_id).startswith("stub-"):
                        parts: list[dict[str, Any]] = []
                        for eid in str(external_id).split(","):
                            eid = eid.strip()
                            if not eid or eid.startswith("stub-"):
                                continue
                            part = client.scan_details(eid)
                            if isinstance(part, dict):
                                parts.append(part)
                        details = merge_openvas_details(parts) if parts else {}
                        vulns = (details or {}).get("vulnerabilities") or []
                        if vulns:
                            harvested = ingest_engine_results(
                                db,
                                case_id=case_id,
                                scan_job_id=scan_job_id,
                                engine=engine,
                                targets=engine_targets,
                                vulnerabilities=vulns,
                                credentialed=credentialed,
                            )
                            total_findings += harvested
                            real_completed += 1
                except Exception as harvest_exc:
                    log.warning("OpenVAS timeout harvest failed: %s", harvest_exc)
            _record_engine_run(
                db,
                scan_job_id=scan_job_id,
                engine=engine,
                role=role,
                status="completed" if harvested else "failed",
                findings_count=harvested,
                error=str(exc),
                metadata={"harvested_after_timeout": bool(harvested)},
            )
            message = f"{engine}: {exc}"
            all_failures.append(message)
            if required and not harvested:
                required_failures.append(message)
            engine_results.append(
                {
                    "engine": engine,
                    "status": "completed" if harvested else "failed",
                    "error": str(exc),
                    "findings": harvested,
                    "partial": bool(harvested),
                }
            )
        finally:
            db.commit()

    # Finish OpenVAS after overlapping fast engines have run.
    _finish_deferred_openvas()

    correlated = correlate_case_findings(db, case_id=case_id)
    # Prefer completed when any real engine produced results — do not discard
    # nmap/OpenVAS findings because a required engine timed out late.
    if real_completed == 0 and (required_failures or total_findings == 0):
        overall_status = "failed"
    elif required_failures and total_findings == 0:
        overall_status = "failed"
    else:
        overall_status = "completed"

    error_summary = "; ".join(all_failures)[:2000] if all_failures else None
    final_activity = "Completed" if overall_status == "completed" else overall_status
    _set_targets_activity(
        db,
        scan_job_id,
        active_targets,
        status="completed" if overall_status == "completed" else overall_status,
        activity=final_activity,
    )
    _merge_orchestration(
        db,
        scan_job_id,
        {"live_progress": {"label": final_activity, "openvas_pct": 100 if overall_status == "completed" else None}},
    )
    execute(
        db,
        """UPDATE vuln_scan_jobs
           SET status = :status, completed_at = NOW(), updated_at = NOW(), error = :error
           WHERE id = CAST(:id AS uuid)""",
        {"id": scan_job_id, "status": overall_status, "error": error_summary},
    )
    if overall_status == "completed":
        try:
            from app.services.vuln_brd import record_scan_result

            record_scan_result(
                db,
                scan_job_id=scan_job_id,
                hosts_attempted=len(active_targets),
                hosts_assessed=len(active_targets),
                credential_success=1 if credentialed else 0,
                result_json={
                    "assessment_complete": True,
                    "assessed_hosts": list(active_targets),
                    "skipped_hosts": [],
                    "engines": engine_results,
                    "findings_ingested": total_findings,
                    "source": "central_orchestrator",
                },
            )
        except Exception:
            log.warning("orchestrated scan_result write skipped for %s", scan_job_id, exc_info=True)
    db.commit()
    return {
        "status": overall_status,
        "scan_job_id": scan_job_id,
        "engines": engine_results,
        "findings_ingested": total_findings,
        "correlations": correlated,
        "error": error_summary,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def terminate_scan_job_processes(job: dict[str, Any]) -> dict[str, Any]:
    """Stop leftover OpenVAS tasks and revoke the Celery worker for this job."""
    job_id = str(job.get("id") or "")
    stopped_gvm: list[str] = []
    revoked = 0

    client = None
    try:
        client = get_scanner_client(edition="openvas", base_url="")
    except Exception:
        client = None

    ids: list[str] = []
    external = str(job.get("external_scan_id") or "").strip()
    if external and not external.startswith("stub-"):
        ids.append(external)
    if client is not None and job_id:
        finder = getattr(client, "find_tasks", None)
        if callable(finder):
            try:
                for task in finder(name_contains=f"orch-{job_id[:8]}") or []:
                    tid = str(task.get("id") or "").strip()
                    if tid:
                        ids.append(tid)
            except Exception:
                log.warning("Could not list OpenVAS tasks while stopping job %s", job_id, exc_info=True)
    stop = getattr(client, "stop_scan", None) if client is not None else None
    for tid in dict.fromkeys(ids):
        if not callable(stop):
            break
        try:
            stop(tid)
            stopped_gvm.append(tid)
        except Exception:
            log.warning("Stop OpenVAS task %s failed for job %s", tid, job_id, exc_info=True)

    if job_id:
        try:
            from app.celery_vuln import celery
        except Exception:
            celery = None
        if celery is not None:
            try:
                insp = celery.control.inspect(timeout=2.0)
                buckets = []
                for getter in (insp.active, insp.reserved, insp.scheduled):
                    try:
                        buckets.append(getter() or {})
                    except Exception:
                        buckets.append({})
                seen: set[str] = set()
                needle = job_id.lower()
                short = job_id[:8].lower()
                for data in buckets:
                    for tasks in (data or {}).values():
                        for item in tasks or []:
                            tid = str(item.get("id") or "")
                            if not tid or tid in seen:
                                continue
                            args = item.get("args") or []
                            kwargs = item.get("kwargs") or {}
                            hay = " ".join(str(x) for x in list(args) + list(kwargs.values())).lower()
                            if needle in hay or short in hay:
                                celery.control.revoke(tid, terminate=True, signal="SIGTERM")
                                seen.add(tid)
                                revoked += 1
            except Exception:
                log.warning("Celery revoke failed for scan job %s", job_id, exc_info=True)

    return {"stopped_openvas": stopped_gvm, "revoked_celery": revoked}


def scan_job_target_rows(db, job: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-IP status, live activity, and severity counts for Scan Details."""
    job_id = str(job.get("id") or "")
    job_status = str(job.get("status") or "").lower()
    job_done = job_status in {"completed", "failed", "cancelled"}
    orch = _orch_dict(job)
    live_map = orch.get("target_progress") if isinstance(orch.get("target_progress"), dict) else {}

    target_rows = fetchall(
        db,
        """SELECT target, excluded FROM vuln_scan_targets
           WHERE scan_job_id = CAST(:jid AS uuid)
           ORDER BY target""",
        {"jid": job_id},
    )
    agg = fetchall(
        db,
        f"""
        SELECT COALESCE(
                 NULLIF(trim(a.primary_ip), ''),
                 NULLIF(trim(a.hostname), ''),
                 NULLIF(trim(f.risk_factors_json->>'host'), ''),
                 NULLIF(trim(f.risk_factors_json->>'hostname'), '')
               ) AS host,
               {aetheris_severity_sql("f")} AS severity,
               COUNT(*)::int AS count
          FROM vuln_findings f
          LEFT JOIN vuln_assets a ON a.id = f.asset_id
         WHERE f.scan_job_id = CAST(:jid AS uuid)
         GROUP BY 1, 2
        """,
        {"jid": job_id},
    )
    counts: dict[str, dict[str, int]] = {}
    extra_hosts: set[str] = set()
    for row in agg:
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        extra_hosts.add(host)
        sev = str(row.get("severity") or "info").lower()
        if sev not in {"critical", "high", "medium", "low", "info"}:
            sev = "info"
        bucket = counts.setdefault(host, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        bucket[sev] += int(row.get("count") or 0)

    ordered: list[str] = []
    excluded: dict[str, bool] = {}
    for t in target_rows:
        ip = str(t.get("target") or "").strip()
        if not ip:
            continue
        ordered.append(ip)
        excluded[ip] = bool(t.get("excluded"))
    for host in sorted(extra_hosts):
        if host not in excluded:
            ordered.append(host)
            excluded[host] = False

    out: list[dict[str, Any]] = []
    for ip in ordered:
        state = live_map.get(ip) if isinstance(live_map.get(ip), dict) else {}
        status = str(state.get("status") or ("completed" if job_done and job_status == "completed" else "pending"))
        if job_done and status in {"scanning", "pending", "running"}:
            status = "completed" if job_status == "completed" else job_status
        activity = str(state.get("activity") or "")
        if status == "completed":
            activity = "Completed"
        elif status == "incomplete" and not activity:
            activity = "Incomplete — scan coverage degraded"
        elif not activity:
            activity = "Waiting"
        try:
            progress = float(state.get("progress_pct", 100 if status in {"completed", "incomplete"} else 0))
        except (TypeError, ValueError, OverflowError):
            progress = 0.0
        if not math.isfinite(progress):
            progress = 0.0
        progress_pct = max(0, min(99 if status in {"scanning", "running"} else 100, int(progress)))
        c = counts.get(ip) or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        out.append(
            {
                "ip": ip,
                "status": status,
                "activity": activity,
                "progress_pct": progress_pct,
                "critical": c["critical"],
                "high": c["high"],
                "medium": c["medium"],
                "low": c["low"],
                "info": c.get("info", 0),
                "engines": state.get("engines") if isinstance(state.get("engines"), dict) else {},
                "excluded": excluded.get(ip, False),
            }
        )
    return out
